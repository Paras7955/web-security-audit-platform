from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.auth_profiles import validate_auth_profile_secret_settings
from app.core.config import settings
from app.core.validation import validate_runtime_settings
from app.db.session import SessionLocal, check_database_ready
from app.models import (
    AiExplanationCache,
    AiRequestLog,
    ApiRateLimitLog,
    AuthProfile,
    Finding,
    RiskScore,
    Scan,
    WorkerHeartbeat,
)
from app.repo_scanner.adapters import verify_repo_tools
from app.risk import COMPLETED_SCAN_STATUSES, SCORING_MODEL_VERSION, calculate_scan_risk_score
from app.security.auth import validate_auth_settings


@dataclass(frozen=True)
class MaintenanceResult:
    action: str
    apply: bool
    candidates: int
    changed: int
    detail: str


def verify_configuration(*, apply: bool) -> MaintenanceResult:
    if not apply:
        return MaintenanceResult("verify", False, 1, 0, "Would validate configuration, database head, and scanner versions.")
    validate_auth_settings(settings)
    validate_auth_profile_secret_settings(settings)
    validate_runtime_settings(settings)
    check_database_ready()
    verify_repo_tools(settings)
    return MaintenanceResult("verify", True, 1, 1, "Configuration, database head, and scanner versions are valid.")


def cleanup_orphan_artifacts(db: Session, *, artifact_root: str | Path, apply: bool) -> MaintenanceResult:
    scans_root = Path(artifact_root).resolve() / "scans"
    if not scans_root.exists():
        return MaintenanceResult("orphan-artifacts", apply, 0, 0, "No scan artifact directory exists.")
    if scans_root.is_symlink() or not scans_root.is_dir():
        raise ValueError("Scan artifact root must be a real directory.")
    known_scan_ids = set(db.scalars(select(Scan.id)).all())
    candidates = [
        child
        for child in scans_root.iterdir()
        if child.is_dir() and not child.is_symlink() and child.name not in known_scan_ids
    ]
    changed = 0
    if apply:
        for candidate in candidates:
            resolved = candidate.resolve()
            if scans_root != resolved and scans_root not in resolved.parents:
                raise ValueError("Orphan artifact path escaped the artifact root.")
            shutil.rmtree(resolved)
            changed += 1
    return MaintenanceResult(
        "orphan-artifacts",
        apply,
        len(candidates),
        changed,
        "Orphan scan artifact directories are deleted only with --apply.",
    )


def prune_operational_data(db: Session, *, older_than_days: int, apply: bool) -> MaintenanceResult:
    if older_than_days < 1:
        raise ValueError("older-than-days must be at least 1.")
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    models = (AiRequestLog, ApiRateLimitLog, AiExplanationCache, WorkerHeartbeat)
    candidates = sum(len(db.scalars(select(model.id).where(model.created_at < cutoff)).all()) for model in models)
    changed = 0
    if apply:
        for model in models:
            result = db.execute(delete(model).where(model.created_at < cutoff))
            changed += int(getattr(result, "rowcount", 0) or 0)
        db.commit()
    return MaintenanceResult(
        "prune-operational",
        apply,
        candidates,
        changed,
        "Only AI request/cache, API rate-limit, and worker heartbeat records are eligible; audit and scan history are never pruned.",
    )


def backfill_legacy_risk_scores(db: Session, *, apply: bool) -> MaintenanceResult:
    scans = list(db.scalars(select(Scan).where(Scan.status.in_(COMPLETED_SCAN_STATUSES))).all())
    missing: list[tuple[Scan, list[Finding]]] = []
    for scan in scans:
        exists = db.scalar(
            select(RiskScore.id).where(
                RiskScore.workspace_id == scan.workspace_id,
                RiskScore.scan_id == scan.id,
                RiskScore.scoring_model_version == SCORING_MODEL_VERSION,
            )
        )
        if exists is None:
            findings = list(
                db.scalars(
                    select(Finding).where(Finding.workspace_id == scan.workspace_id, Finding.scan_id == scan.id)
                ).all()
            )
            missing.append((scan, findings))
    if apply:
        for scan, findings in missing:
            calculated = calculate_scan_risk_score(scan, findings)
            db.add(
                RiskScore(
                    id=str(uuid4()),
                    workspace_id=scan.workspace_id,
                    target_id=scan.target_id,
                    scan_id=scan.id,
                    scoring_model_version=calculated.scoring_model_version,
                    score=calculated.score,
                    label=calculated.label,
                    input_summary=calculated.input_summary,
                )
            )
        db.commit()
    return MaintenanceResult(
        "backfill-risk",
        apply,
        len(missing),
        len(missing) if apply else 0,
        "Missing risk-v1 rows are generated only with --apply; GET requests remain read-only.",
    )


def reencrypt_auth_profiles(db: Session, *, apply: bool) -> MaintenanceResult:
    previous_key = (settings.auth_profile_previous_secret_key or "").strip()
    if not previous_key:
        raise ValueError("AUTH_PROFILE_PREVIOUS_SECRET_KEY is required for re-encryption.")
    previous = Fernet(previous_key.encode("ascii"))
    current = Fernet(settings.auth_profile_secret_key.strip().encode("ascii"))
    profiles = list(
        db.scalars(
            select(AuthProfile).where(AuthProfile.revoked_at.is_(None), AuthProfile.encrypted_secret.is_not(None))
        ).all()
    )
    transformed: list[tuple[AuthProfile, str]] = []
    try:
        for profile in profiles:
            encrypted_secret = profile.encrypted_secret
            if not encrypted_secret:
                continue
            ciphertext = encrypted_secret.encode("ascii")
            try:
                plaintext = previous.decrypt(ciphertext)
            except InvalidToken:
                try:
                    current.decrypt(ciphertext)
                    continue
                except InvalidToken:
                    raise
            transformed.append((profile, current.encrypt(plaintext).decode("ascii")))
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise ValueError("An auth profile could not be decrypted with the previous key; no changes were applied.") from exc
    if apply:
        for profile, encrypted_secret in transformed:
            profile.encrypted_secret = encrypted_secret
            profile.rotated_at = datetime.now(UTC)
            profile.rotation_count += 1
            db.add(profile)
        db.commit()
    return MaintenanceResult(
        "reencrypt-auth-profiles",
        apply,
        len(transformed),
        len(transformed) if apply else 0,
        "Active auth-profile ciphertext is re-encrypted only with --apply; plaintext is never printed.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ScopeHarbor dry-run-first maintenance utility")
    parser.add_argument(
        "action",
        choices=("verify", "orphan-artifacts", "prune-operational", "backfill-risk", "reencrypt-auth-profiles"),
    )
    parser.add_argument("--apply", action="store_true", help="Apply the planned action. Without this flag, no state changes.")
    parser.add_argument("--older-than-days", type=int, default=30)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.action == "verify":
        result = verify_configuration(apply=args.apply)
    else:
        with SessionLocal() as db:
            if args.action == "orphan-artifacts":
                result = cleanup_orphan_artifacts(db, artifact_root=settings.artifact_root, apply=args.apply)
            elif args.action == "prune-operational":
                result = prune_operational_data(db, older_than_days=args.older_than_days, apply=args.apply)
            elif args.action == "backfill-risk":
                result = backfill_legacy_risk_scores(db, apply=args.apply)
            else:
                result = reencrypt_auth_profiles(db, apply=args.apply)
    print(json.dumps(asdict(result), sort_keys=True))


if __name__ == "__main__":
    main()
