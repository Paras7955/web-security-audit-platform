from datetime import UTC, datetime, timedelta
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth_profiles import AuthProfileError, build_scanner_auth_material
from app.core.config import settings
from app.core.contracts import DEFAULT_LIMITS, ScanMode, ScanStatus, ScanStep
from app.findings.service import persist_normalized_findings
from app.models import AuthProfile, Scan, ScannerToolRun
from app.repo_scanner.adapters import ToolReceipt, run_repository_scan
from app.repo_scanner.paths import resolve_stored_repo_path
from app.repo_scanner.staging import StagedRepository, StagingLimits
from app.risk import persist_scan_risk_score
from app.scans.artifacts import ensure_scan_artifact_dir
from app.scanner.passive import run_passive_scan
from app.security.allowlist import ScanAllowlist
from app.zap.active import run_zap_active_demo_scan
from app.zap.client_spider import ZapClientSpiderCancelled, run_zap_client_spider_scan
from app.zap.passive import run_zap_passive_scan


class ScanLifecycleError(ValueError):
    pass


class ScanCancelledError(ScanLifecycleError):
    pass


class ScanDeadlineExceeded(ScanLifecycleError):
    code = "scan_deadline_exceeded"


ZAP_DAEMON_LOCK_KEY = 9001


def claim_next_queued_scan(db: Session, *, worker_id: str | None = None) -> Scan | None:
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
    if scan.status == ScanStatus.QUEUED.value and scan.cancellation_requested_at is not None:
        mark_scan_cancelled(db, scan, "Queued scan was cancelled before worker start.")
        return None

    now = datetime.now(UTC)
    scan.lease_owner = worker_id or settings.worker_id
    scan.lease_heartbeat_at = now
    scan.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
    scan.attempt_count += 1
    update_scan_progress(
        db,
        scan,
        status=ScanStatus.VALIDATING,
        current_step=ScanStep.TARGET_VALIDATION,
        status_message="Worker claimed scan and is validating lifecycle inputs.",
        progress_percent=5,
        started_at=now,
    )
    return scan


def recover_stale_scan_leases(db: Session) -> int:
    stale = list(
        db.scalars(
            select(Scan)
            .where(
                Scan.status.in_(
                    {
                        ScanStatus.VALIDATING.value,
                        ScanStatus.RUNNING.value,
                        ScanStatus.NORMALIZING.value,
                    }
                ),
                Scan.lease_expires_at.is_not(None),
                Scan.lease_expires_at < datetime.now(UTC),
            )
            .with_for_update(skip_locked=True)
        ).all()
    )
    for scan in stale:
        mark_scan_failed_code(db, scan, code="worker_interrupted", message="Scanner worker interrupted before completion.")
    return len(stale)


def run_passive_scan_job(
    db: Session,
    scan: Scan,
    artifact_root: str,
    allowlist: ScanAllowlist,
    zap_base_url: str | None = None,
) -> None:
    try:
        validate_scan_job(scan)
        check_scan_cancelled(db, scan)
        if scan.target is None:
            raise ScanLifecycleError("Scan target no longer exists.")
        allowlist_target = allowlist.get_target(scan.target.allowlist_id)
        if allowlist_target is None:
            raise ScanLifecycleError("Scan target is not present in the allowlist.")
        active_demo = scan.mode == ScanMode.ACTIVE_DEMO.value
        modern_web_crawl = scan.mode == ScanMode.MODERN_WEB_CRAWL.value
        if scan.mode not in set(allowlist_target.allowed_modes):
            raise ScanLifecycleError("Scan mode is no longer allowed for this target.")
        auth_headers = load_scan_auth_headers(db, scan)
        if active_demo:
            if not allowlist_target.local_demo:
                raise ScanLifecycleError("Active Demo scan target must be a local/demo allowlist target.")
            if not zap_base_url:
                raise ScanLifecycleError("Active Demo scans require a configured ZAP daemon.")
        if modern_web_crawl:
            if not allowlist_target.local_demo:
                raise ScanLifecycleError("Modern web crawl target must be a local/demo allowlist target.")
            if not zap_base_url:
                raise ScanLifecycleError("Modern web crawls require a configured ZAP daemon.")

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.VALIDATING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message=f"Validated target and allowlist entry for {format_scan_mode(scan.mode)} scan.",
            progress_percent=10,
        )
        check_scan_cancelled(db, scan)
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
            auth_headers=auth_headers,
        )
        check_scan_cancelled(db, scan)

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
        active_findings = ()
        active_errors = ()
        client_spider_findings = ()
        client_spider_errors = ()
        if zap_base_url:
            update_scan_progress(
                db,
                scan,
                status=ScanStatus.RUNNING,
                current_step=ScanStep.ZAP_PASSIVE,
                status_message="Running scoped ZAP passive analysis for allowlisted URLs.",
                progress_percent=76,
            )
            with zap_daemon_lock(db):
                check_scan_cancelled(db, scan)
                zap_result = run_zap_passive_scan(
                    scan_id=scan.id,
                    target_url=scan.target.base_url,
                    allowlist_target=allowlist_target,
                    zap_base_url=zap_base_url,
                    observed_urls=tuple(page.url for page in result.pages),
                )
            zap_findings = zap_result.findings
            zap_errors = zap_result.errors

            if active_demo:
                check_scan_cancelled(db, scan)
                update_scan_progress(
                    db,
                    scan,
                    status=ScanStatus.RUNNING,
                    current_step=ScanStep.ZAP_ACTIVE,
                    status_message="Running bounded ZAP Active Demo scan against the local/demo target.",
                    progress_percent=82,
                )
                with zap_daemon_lock(db):
                    check_scan_cancelled(db, scan)
                    active_result = run_zap_active_demo_scan(
                        scan_id=scan.id,
                        target_url=scan.target.base_url,
                        allowlist_target=allowlist_target,
                        zap_base_url=zap_base_url,
                    )
                active_findings = active_result.findings
                active_errors = active_result.errors

            if modern_web_crawl:
                check_scan_cancelled(db, scan)
                update_scan_progress(
                    db,
                    scan,
                    status=ScanStatus.RUNNING,
                    current_step=ScanStep.ZAP_CLIENT_SPIDER,
                    status_message="Running bounded ZAP Client Spider against the local/demo target.",
                    progress_percent=82,
                )
                with zap_daemon_lock(db):
                    check_scan_cancelled(db, scan)
                    client_spider_result = run_zap_client_spider_scan(
                        scan_id=scan.id,
                        target_url=scan.target.base_url,
                        allowlist_target=allowlist_target,
                        zap_base_url=zap_base_url,
                        should_cancel=lambda: cancellation_requested(db, scan),
                    )
                client_spider_findings = client_spider_result.findings
                client_spider_errors = client_spider_result.errors

        all_findings = tuple(result.findings) + tuple(zap_findings) + tuple(active_findings) + tuple(client_spider_findings)
        all_errors = tuple(result.errors) + tuple(zap_errors) + tuple(active_errors) + tuple(client_spider_errors)
        check_scan_cancelled(db, scan)
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.NORMALIZING,
            current_step=ScanStep.NORMALIZING_FINDINGS,
            status_message=f"Persisting {len(all_findings)} normalized {format_scan_mode(scan.mode)} findings.",
            progress_percent=85,
        )

        persisted_findings = persist_normalized_findings(
            db,
            scan_id=scan.id,
            findings=list(all_findings),
            artifact_root=artifact_root,
        )
        persist_scan_risk_score(db, scan, persisted_findings)
        check_scan_cancelled(db, scan)

        terminal_status = ScanStatus.COMPLETED_WITH_WARNINGS if all_errors else ScanStatus.COMPLETED
        status_message = (
            f"{format_scan_mode(scan.mode)} scan completed with {len(all_findings)} findings and {len(all_errors)} warning(s)."
            if all_errors
            else f"{format_scan_mode(scan.mode)} scan completed with {len(all_findings)} findings."
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
    except (ScanCancelledError, ZapClientSpiderCancelled):
        if scan.status != ScanStatus.CANCELLED.value:
            mark_scan_cancelled(db, scan, "Scan cancellation request was honored during browser cleanup.")
        return
    except Exception as exc:
        mark_scan_failed(db, scan, exc)


def run_repo_scan_job(
    db: Session,
    scan: Scan,
    artifact_root: str,
    repo_scan_root: str,
    allowlist: ScanAllowlist,
) -> None:
    try:
        validate_scan_job(scan)
        check_scan_cancelled(db, scan)
        if scan.mode != ScanMode.REPO.value:
            raise ScanLifecycleError("Repo scan worker only supports repo scan jobs.")
        if scan.target is None:
            raise ScanLifecycleError("Scan target no longer exists.")
        allowlist_target = allowlist.get_target(scan.target.allowlist_id)
        if allowlist_target is None:
            raise ScanLifecycleError("Scan target is not present in the allowlist.")
        if scan.mode not in set(allowlist_target.allowed_modes):
            raise ScanLifecycleError("Scan mode is no longer allowed for this target.")

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.VALIDATING,
            current_step=ScanStep.TARGET_VALIDATION,
            status_message="Validating configured local repo path for repo scan.",
            progress_percent=10,
        )
        check_scan_cancelled(db, scan)
        repo_path = resolve_stored_repo_path(scan.target.repo_path, repo_scan_root=repo_scan_root)
        ensure_scan_artifact_dir(artifact_root, scan.id)

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.REPO_SECRETS_SCAN,
            status_message="Staging bounded regular files and running Gitleaks with full redaction.",
            progress_percent=35,
        )
        limits = StagingLimits(
            max_files=settings.repo_max_files,
            max_file_bytes=settings.repo_max_file_bytes,
            max_total_bytes=settings.repo_max_total_bytes,
        )
        with StagedRepository(repo_path, Path(settings.repo_staging_root), limits) as staged:
            result = run_repository_scan(staged.root, settings)
        check_scan_cancelled(db, scan)

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.REPO_DEPENDENCY_SCAN,
            status_message="Completed offline dependency analysis without package execution.",
            progress_percent=65,
        )
        persist_tool_receipts(db, scan, result.receipts)
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.NORMALIZING,
            current_step=ScanStep.NORMALIZING_FINDINGS,
            status_message=f"Persisting {len(result.findings)} normalized repo findings.",
            progress_percent=85,
        )
        persisted_findings = persist_normalized_findings(
            db,
            scan_id=scan.id,
            findings=list(result.findings),
            artifact_root=artifact_root,
        )
        persist_scan_risk_score(db, scan, persisted_findings)
        check_scan_cancelled(db, scan)

        terminal_status = ScanStatus.COMPLETED_WITH_WARNINGS if result.warning_codes else ScanStatus.COMPLETED
        status_message = (
            f"Repo scan completed with {len(result.findings)} findings and {len(result.warning_codes)} warning(s)."
            if result.warning_codes
            else f"Repo scan completed with {len(result.findings)} findings."
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
    except ScanCancelledError:
        return
    except Exception as exc:
        mark_scan_failed(db, scan, exc)


@contextmanager
def zap_daemon_lock(db: Session):
    db.execute(text("SELECT pg_advisory_lock(:lock_key)"), {"lock_key": ZAP_DAEMON_LOCK_KEY})
    try:
        yield
    finally:
        db.execute(text("SELECT pg_advisory_unlock(:lock_key)"), {"lock_key": ZAP_DAEMON_LOCK_KEY})


def validate_scan_job(scan: Scan) -> None:
    if scan.mode == ScanMode.AJAX_SHORT.value:
        error = ScanLifecycleError("Historical AJAX Short jobs are retired.")
        error.code = "retired_profile"  # type: ignore[attr-defined]
        raise error
    if scan.mode not in {
        ScanMode.PASSIVE.value,
        ScanMode.ACTIVE_DEMO.value,
        ScanMode.MODERN_WEB_CRAWL.value,
        ScanMode.REPO.value,
    }:
        raise ScanLifecycleError("Worker does not support this scan profile.")
    if scan.target is None:
        raise ScanLifecycleError("Scan target no longer exists.")
    if scan.workspace_id != scan.target.workspace_id:
        raise ScanLifecycleError("Scan workspace does not match target workspace.")
    if not scan.created_by_user_id:
        raise ScanLifecycleError("Scan is missing persisted user context.")
    if not scan.target.permission_confirmed:
        raise ScanLifecycleError("Scan target authorization is not confirmed.")
    if scan.auth_profile_id is not None and scan.mode != ScanMode.PASSIVE.value:
        raise ScanLifecycleError("Auth profiles are currently supported only for passive-web scans.")


def load_scan_auth_headers(db: Session, scan: Scan) -> dict[str, str] | None:
    if scan.auth_profile_id is None:
        return None
    profile = db.scalar(
        select(AuthProfile).where(
            AuthProfile.id == scan.auth_profile_id,
            AuthProfile.workspace_id == scan.workspace_id,
        )
    )
    if profile is None:
        raise ScanLifecycleError("Scan auth profile is not available in this workspace.")
    try:
        return build_scanner_auth_material(profile).headers
    except AuthProfileError as exc:
        error = ScanLifecycleError("Scan auth profile is unavailable.")
        error.code = "auth_profile_invalid"  # type: ignore[attr-defined]
        raise error from exc


def format_scan_mode(mode: str) -> str:
    if mode == ScanMode.ACTIVE_DEMO.value:
        return "Active Demo"
    if mode == ScanMode.MODERN_WEB_CRAWL.value:
        return "Modern Web Crawl"
    if mode == ScanMode.AJAX_SHORT.value:
        return "Retired AJAX Short"
    if mode == ScanMode.REPO.value:
        return "Repo"
    return "Passive"


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
        scan.lease_owner = None
        scan.lease_expires_at = None
        scan.lease_heartbeat_at = None
    elif scan.lease_owner:
        now = datetime.now(UTC)
        scan.lease_heartbeat_at = now
        scan.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
    db.add(scan)
    db.commit()
    db.refresh(scan)


def check_scan_cancelled(db: Session, scan: Scan) -> None:
    db.refresh(scan)
    if scan.started_at is not None:
        started_at = scan.started_at if scan.started_at.tzinfo is not None else scan.started_at.replace(tzinfo=UTC)
        if datetime.now(UTC) > started_at + timedelta(seconds=int(DEFAULT_LIMITS["scan_timeout_seconds"])):
            raise ScanDeadlineExceeded("Scan exceeded its configured deadline.")
    if scan.cancellation_requested_at is None:
        return
    mark_scan_cancelled(db, scan, "Scan cancellation request was honored at a worker checkpoint.")
    raise ScanCancelledError("Scan cancellation request was honored.")


def cancellation_requested(db: Session, scan: Scan) -> bool:
    db.refresh(scan)
    return scan.cancellation_requested_at is not None


def mark_scan_cancelled(db: Session, scan: Scan, message: str) -> None:
    scan.status = ScanStatus.CANCELLED.value
    scan.status_message = message
    scan.progress_percent = min(scan.progress_percent or 0, 99)
    scan.completed_at = datetime.now(UTC)
    scan.error_code = None
    scan.error_detail = None
    scan.lease_owner = None
    scan.lease_expires_at = None
    scan.lease_heartbeat_at = None
    db.add(scan)
    db.commit()
    db.refresh(scan)


def mark_scan_failed(db: Session, scan: Scan, exc: Exception) -> None:
    code = str(getattr(exc, "code", "scan_worker_failed"))
    if code not in {
        "auth_profile_invalid",
        "client_spider_failed",
        "repo_limit_exceeded",
        "repo_staging_failed",
        "repo_tool_failed",
        "repo_tool_output_invalid",
        "repo_tool_timeout",
        "repo_tool_unavailable",
        "retired_profile",
        "scan_deadline_exceeded",
        "scan_worker_failed",
        "target_validation_failed",
        "worker_interrupted",
    }:
        code = "scan_worker_failed"
    mark_scan_failed_code(db, scan, code=code, message="Scan worker job failed safely.")


def mark_scan_failed_code(db: Session, scan: Scan, *, code: str, message: str) -> None:
    scan.status = ScanStatus.FAILED.value
    scan.status_message = message
    scan.progress_percent = min(scan.progress_percent or 0, 99)
    scan.completed_at = datetime.now(UTC)
    scan.error_code = code
    scan.error_detail = None
    scan.lease_owner = None
    scan.lease_expires_at = None
    scan.lease_heartbeat_at = None
    db.add(scan)
    db.commit()
    db.refresh(scan)


def persist_tool_receipts(db: Session, scan: Scan, receipts: tuple[ToolReceipt, ...]) -> None:
    for receipt in receipts:
        run = db.scalar(
            select(ScannerToolRun).where(
                ScannerToolRun.scan_id == scan.id,
                ScannerToolRun.tool_name == receipt.tool_name,
            )
        )
        if run is None:
            run = ScannerToolRun(
                id=str(uuid4()),
                workspace_id=scan.workspace_id,
                scan_id=scan.id,
                tool_name=receipt.tool_name,
            )
        run.tool_version = receipt.tool_version
        run.status = receipt.status
        run.warning_code = receipt.warning_code
        run.finding_count = receipt.finding_count
        run.started_at = receipt.started_at
        run.completed_at = receipt.completed_at
        db.add(run)
    db.commit()
