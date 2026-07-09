from datetime import UTC, datetime
from contextlib import contextmanager

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth_profiles import AuthProfileError, build_scanner_auth_material
from app.core.contracts import ScanMode, ScanStatus, ScanStep
from app.findings.service import persist_normalized_findings
from app.models import AuthProfile, Scan
from app.repo_scanner.paths import validate_repo_path
from app.repo_scanner.stubs import run_repo_stub_scan
from app.scans.artifacts import ensure_scan_artifact_dir
from app.scanner.passive import run_passive_scan
from app.security.allowlist import ScanAllowlist
from app.zap.active import run_zap_active_demo_scan
from app.zap.ajax import run_zap_ajax_short_scan
from app.zap.passive import run_zap_passive_scan


class ScanLifecycleError(ValueError):
    pass


class ScanCancelledError(ScanLifecycleError):
    pass


ZAP_DAEMON_LOCK_KEY = 9001


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
    if scan.status == ScanStatus.QUEUED.value and scan.cancellation_requested_at is not None:
        mark_scan_cancelled(db, scan, "Queued scan was cancelled before worker start.")
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
        validate_scan_job(scan)
        check_scan_cancelled(db, scan)
        if scan.target is None:
            raise ScanLifecycleError("Scan target no longer exists.")
        allowlist_target = allowlist.get_target(scan.target.allowlist_id)
        if allowlist_target is None:
            raise ScanLifecycleError("Scan target is not present in the allowlist.")
        active_demo = scan.mode == ScanMode.ACTIVE_DEMO.value
        ajax_short = scan.mode == ScanMode.AJAX_SHORT.value
        if scan.mode not in set(allowlist_target.allowed_modes):
            raise ScanLifecycleError("Scan mode is no longer allowed for this target.")
        auth_headers = load_scan_auth_headers(db, scan)
        if active_demo:
            if not allowlist_target.local_demo:
                raise ScanLifecycleError("Active Demo scan target must be a local/demo allowlist target.")
            if not zap_base_url:
                raise ScanLifecycleError("Active Demo scans require a configured ZAP daemon.")
        if ajax_short:
            if not allowlist_target.local_demo:
                raise ScanLifecycleError("AJAX Short scan target must be a local/demo allowlist target.")
            if not zap_base_url:
                raise ScanLifecycleError("AJAX Short scans require a configured ZAP daemon.")

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
        ajax_findings = ()
        ajax_errors = ()
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

            if ajax_short:
                check_scan_cancelled(db, scan)
                update_scan_progress(
                    db,
                    scan,
                    status=ScanStatus.RUNNING,
                    current_step=ScanStep.ZAP_AJAX,
                    status_message="Running bounded ZAP AJAX Short crawl against the local/demo target.",
                    progress_percent=82,
                )
                with zap_daemon_lock(db):
                    check_scan_cancelled(db, scan)
                    ajax_result = run_zap_ajax_short_scan(
                        scan_id=scan.id,
                        target_url=scan.target.base_url,
                        allowlist_target=allowlist_target,
                        zap_base_url=zap_base_url,
                    )
                ajax_findings = ajax_result.findings
                ajax_errors = ajax_result.errors

        all_findings = tuple(result.findings) + tuple(zap_findings) + tuple(active_findings) + tuple(ajax_findings)
        all_errors = tuple(result.errors) + tuple(zap_errors) + tuple(active_errors) + tuple(ajax_errors)
        check_scan_cancelled(db, scan)
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.NORMALIZING,
            current_step=ScanStep.NORMALIZING_FINDINGS,
            status_message=f"Persisting {len(all_findings)} normalized {format_scan_mode(scan.mode)} findings.",
            progress_percent=85,
        )

        persist_normalized_findings(
            db,
            scan_id=scan.id,
            findings=list(all_findings),
            artifact_root=artifact_root,
        )
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
    except ScanCancelledError:
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
        repo_path = validate_repo_path(scan.target.repo_path, repo_scan_root=repo_scan_root)
        ensure_scan_artifact_dir(artifact_root, scan.id)

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.REPO_SECRETS_SCAN,
            status_message="Running deterministic secret scanner adapter stub.",
            progress_percent=35,
        )
        result = run_repo_stub_scan(repo_path=repo_path)
        check_scan_cancelled(db, scan)

        update_scan_progress(
            db,
            scan,
            status=ScanStatus.RUNNING,
            current_step=ScanStep.REPO_DEPENDENCY_SCAN,
            status_message="Running deterministic dependency scanner adapter stub.",
            progress_percent=65,
        )
        update_scan_progress(
            db,
            scan,
            status=ScanStatus.NORMALIZING,
            current_step=ScanStep.NORMALIZING_FINDINGS,
            status_message=f"Persisting {len(result.findings)} normalized repo findings.",
            progress_percent=85,
        )
        persist_normalized_findings(
            db,
            scan_id=scan.id,
            findings=list(result.findings),
            artifact_root=artifact_root,
        )
        check_scan_cancelled(db, scan)

        terminal_status = ScanStatus.COMPLETED_WITH_WARNINGS if result.errors else ScanStatus.COMPLETED
        status_message = (
            f"Repo scan completed with {len(result.findings)} findings and {len(result.errors)} warning(s)."
            if result.errors
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


def validate_phase3_lifecycle_scan(scan: Scan) -> None:
    validate_scan_job(scan)


@contextmanager
def zap_daemon_lock(db: Session):
    db.execute(text("SELECT pg_advisory_lock(:lock_key)"), {"lock_key": ZAP_DAEMON_LOCK_KEY})
    try:
        yield
    finally:
        db.execute(text("SELECT pg_advisory_unlock(:lock_key)"), {"lock_key": ZAP_DAEMON_LOCK_KEY})


def validate_scan_job(scan: Scan) -> None:
    if scan.mode not in {ScanMode.PASSIVE.value, ScanMode.ACTIVE_DEMO.value, ScanMode.AJAX_SHORT.value, ScanMode.REPO.value}:
        raise ScanLifecycleError("Worker only supports passive, Active Demo, AJAX Short, and Repo scan jobs in this phase.")
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
        raise ScanLifecycleError(str(exc)) from exc


def format_scan_mode(mode: str) -> str:
    if mode == ScanMode.ACTIVE_DEMO.value:
        return "Active Demo"
    if mode == ScanMode.AJAX_SHORT.value:
        return "AJAX Short"
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
    db.add(scan)
    db.commit()
    db.refresh(scan)


def check_scan_cancelled(db: Session, scan: Scan) -> None:
    db.refresh(scan)
    if scan.cancellation_requested_at is None:
        return
    mark_scan_cancelled(db, scan, "Scan cancellation request was honored at a worker checkpoint.")
    raise ScanCancelledError("Scan cancellation request was honored.")


def mark_scan_cancelled(db: Session, scan: Scan, message: str) -> None:
    scan.status = ScanStatus.CANCELLED.value
    scan.status_message = message
    scan.progress_percent = min(scan.progress_percent or 0, 99)
    scan.completed_at = datetime.now(UTC)
    scan.error_code = None
    scan.error_detail = None
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
