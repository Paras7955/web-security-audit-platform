from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.contracts import ScanStatus, ScanStep
from app.findings.service import persist_normalized_findings
from app.models import Scan
from app.scans.artifacts import ensure_scan_artifact_dir
from app.scanner.passive import run_passive_scan
from app.security.allowlist import ScanAllowlist
from app.zap.passive import run_zap_passive_scan


class ScanLifecycleError(ValueError):
    pass


def claim_next_queued_scan(db: Session) -> Scan | None:
    statement = (
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED.value)
        .order_by(Scan.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    scan = db.scalars(statement).first()
    if scan is None:
        return None

    update_scan_progress(
        db,
        scan,
        status=ScanStatus.VALIDATING,
        current_step=ScanStep.TARGET_VALIDATION,
        status_message="Worker claimed scan and is validating lifecycle inputs.",
        progress_percent=5,
        started_at=datetime.now(UTC),
    )
    return scan


def run_internal_lifecycle_job(db: Session, scan: Scan, artifact_root: str) -> None:
    try:
        validate_phase3_lifecycle_scan(scan)
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.VALIDATING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Validated target record for Phase 3 internal lifecycle job.",
            progress_percent=15,
        )

        artifact_dir = ensure_scan_artifact_dir(artifact_root, scan.id)
        (artifact_dir / "internal_lifecycle.txt").write_text(
            "Phase 3 internal lifecycle job only. No scanner findings were generated.\n",
            encoding="utf-8",
        )

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Exercising queued-to-running scan lifecycle. No crawler runs in Phase 3.",
            progress_percent=40,
        )
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Exercising worker progress updates. No passive checks run in Phase 3.",
            progress_percent=65,
        )
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.NORMALIZING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Completing internal lifecycle without findings.",
            progress_percent=85,
        )
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.COMPLETED,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Phase 3 internal lifecycle job completed. Scanner execution starts in later phases.",
            progress_percent=100,
            completed_at=datetime.now(UTC),
        )
    except Exception as exc:
        mark_scan_failed(db, scan, exc)


def run_passive_scan_job(
    db: Session,
    scan: Scan,
    artifact_root: str,
    allowlist: ScanAllowlist,
    zap_base_url: str | None = None,
) -> None:
    try:
        validate_passive_lifecycle_scan(scan)
        if scan.target is None:
            raise ScanLifecycleError("Scan target no longer exists.")
        allowlist_target = allowlist.get_target(scan.target.allowlist_id)
        if allowlist_target is None:
            raise ScanLifecycleError("Scan target is not present in the allowlist.")

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.VALIDATING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Validated target and allowlist entry for passive scan.",
            progress_percent=10,
        )
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.CUSTOM_CRAWL,
            status_message="Running bounded passive crawl with guarded requests.",
            progress_percent=30,
        )

        result = run_passive_scan(
            scan_id=scan.id,
            target_url=scan.target.base_url,
            allowlist_target=allowlist_target,
            artifact_root=artifact_root,
        )

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.CUSTOM_CHECKS,
            status_message=f"Completed passive checks for {len(result.pages)} crawled pages.",
            progress_percent=70,
        )

        zap_findings = ()
        zap_errors = ()
        if zap_base_url:
            update_scan_progress(
                db,
                scan,
                status=ScanStatus.RUNNING,
                current_step=ScanStep.ZAP_PASSIVE,
                status_message="Running scoped ZAP passive analysis for allowlisted URLs.",
                progress_percent=76,
            )
            zap_result = run_zap_passive_scan(
                scan_id=scan.id,
                target_url=scan.target.base_url,
                allowlist_target=allowlist_target,
                zap_base_url=zap_base_url,
                observed_urls=tuple(page.url for page in result.pages),
            )
            zap_findings = zap_result.findings
            zap_errors = zap_result.errors

        all_findings = tuple(result.findings) + tuple(zap_findings)
        all_errors = tuple(result.errors) + tuple(zap_errors)
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.NORMALIZING,
            current_step=ScanStep.NORMALIZING_FINDINGS,
            status_message=f"Persisting {len(all_findings)} normalized passive findings.",
            progress_percent=85,
        )

        persist_normalized_findings(
            db,
            scan_id=scan.id,
            findings=list(all_findings),
            artifact_root=artifact_root,
        )

        terminal_status = ScanStatus.COMPLETED_WITH_WARNINGS if all_errors else ScanStatus.COMPLETED
        status_message = (
            f"Passive scan completed with {len(all_findings)} findings and {len(all_errors)} warning(s)."
            if all_errors
            else f"Passive scan completed with {len(all_findings)} findings."
        )
        update_scan_progress(
            db,
            scan,
            status=terminal_status,
            current_step=ScanStep.NORMALIZING_FINDINGS,
            status_message=status_message,
            progress_percent=100,
            completed_at=datetime.now(UTC),
        )
    except Exception as exc:
        mark_scan_failed(db, scan, exc)


def validate_phase3_lifecycle_scan(scan: Scan) -> None:
    validate_passive_lifecycle_scan(scan)


def validate_passive_lifecycle_scan(scan: Scan) -> None:
    if scan.mode != "passive":
        raise ScanLifecycleError("Worker only supports passive scan jobs in this phase.")
    if scan.target is None:
        raise ScanLifecycleError("Scan target no longer exists.")
    if not scan.target.permission_confirmed:
        raise ScanLifecycleError("Scan target authorization is not confirmed.")


def update_scan_progress(
    db: Session,
    scan: Scan,
    *,
    status: ScanStatus,
    current_step: ScanStep | None,
    status_message: str,
    progress_percent: int,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> None:
    scan.status = status.value
    scan.current_step = current_step.value if current_step else None
    scan.status_message = status_message
    scan.progress_percent = progress_percent
    if started_at is not None:
        scan.started_at = started_at
    if completed_at is not None:
        scan.completed_at = completed_at
    db.add(scan)
    db.commit()
    db.refresh(scan)


def mark_scan_failed(db: Session, scan: Scan, exc: Exception) -> None:
    scan.status = ScanStatus.FAILED.value
    scan.status_message = "Scan worker job failed."
    scan.progress_percent = min(scan.progress_percent or 0, 99)
    scan.completed_at = datetime.now(UTC)
    scan.error_code = "scan_worker_failed"
    scan.error_detail = str(exc)
    db.add(scan)
    db.commit()
    db.refresh(scan)
