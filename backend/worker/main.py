import logging
import time

from sqlalchemy import text

from app.auth_profiles import validate_auth_profile_secret_settings
from app.core.config import settings
from app.core.validation import validate_runtime_settings
from app.db.session import engine
from app.db.session import SessionLocal
from app.db.session import check_database_ready
from app.core.contracts import ScanMode
from app.core.logging import configure_logging, log_event
from app.ops.heartbeat import record_worker_heartbeat
from app.repo_scanner.adapters import verify_repo_tools
from app.scans.lifecycle import claim_next_queued_scan, recover_stale_scan_leases, run_passive_scan_job, run_repo_scan_job
from app.security.allowlist import load_allowlist
from app.security.auth import validate_auth_settings


logger = logging.getLogger("scopeharbor.worker")


def wait_for_database(max_attempts: int = 30) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return
        except Exception as exc:
            if attempt == max_attempts:
                raise RuntimeError("Postgres did not become ready") from exc
            time.sleep(2)


def main() -> None:
    configure_logging()
    validate_worker_startup()
    wait_for_database()
    check_database_ready()
    log_event(logger, "worker_ready", worker_id=settings.worker_id)
    while True:
        with SessionLocal() as db:
            record_worker_heartbeat(db, worker_id=settings.worker_id, status="polling")
            recover_stale_scan_leases(db)
            scan = claim_next_queued_scan(db, worker_id=settings.worker_id)
            if scan is not None:
                log_event(logger, "scan_claimed", worker_id=settings.worker_id, scan_id=scan.id)
                record_worker_heartbeat(db, worker_id=settings.worker_id, status="processing", current_scan_id=scan.id)
                allowlist = load_allowlist(settings.allowlist_path)
                if scan.mode == ScanMode.REPO.value:
                    run_repo_scan_job(db, scan, settings.artifact_root, settings.repo_scan_root, allowlist)
                else:
                    run_passive_scan_job(db, scan, settings.artifact_root, allowlist, zap_base_url=settings.zap_base_url)
                record_worker_heartbeat(db, worker_id=settings.worker_id, status="polling")
                continue
        time.sleep(5)


def validate_worker_startup() -> None:
    validate_auth_settings(settings)
    validate_auth_profile_secret_settings(settings)
    validate_runtime_settings(settings)
    verify_repo_tools(settings)


if __name__ == "__main__":
    main()
