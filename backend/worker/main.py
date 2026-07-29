import logging
import threading
import time
from types import TracebackType

from app.auth_profiles import validate_auth_profile_secret_settings
from app.core.config import settings
from app.core.contracts import ScanMode
from app.core.logging import configure_logging, log_event
from app.core.validation import validate_runtime_settings
from app.db.session import SessionLocal, check_database_ready, engine
from app.ops.heartbeat import record_worker_heartbeat
from app.repo_scanner.adapters import verify_repo_tools
from app.scans.lifecycle import (
    ScanLeaseLostError,
    claim_next_queued_scan,
    recover_stale_scan_leases,
    renew_scan_lease,
    run_passive_scan_job,
    run_repo_scan_job,
)
from app.security.allowlist import load_allowlist
from app.security.auth import validate_auth_settings
from sqlalchemy import text

logger = logging.getLogger("scopeharbor.worker")


class ScanExecutionMonitor:
    def __init__(
        self,
        *,
        scan_id: str,
        worker_id: str,
        interval_seconds: float | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.worker_id = worker_id
        self.interval_seconds = interval_seconds or max(
            1.0,
            min(settings.worker_lease_seconds, settings.worker_stale_after_seconds) / 3,
        )
        self._stop = threading.Event()
        self._lease_lost = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"scan-lease-{scan_id[:12]}",
            daemon=True,
        )

    def __enter__(self) -> "ScanExecutionMonitor":
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_seconds + 1))

    def checkpoint(self) -> None:
        if self._lease_lost.is_set():
            raise ScanLeaseLostError("Scan worker no longer owns this execution lease.")

    def renew_now(self) -> bool:
        with SessionLocal() as db:
            renewed = renew_scan_lease(
                db,
                scan_id=self.scan_id,
                worker_id=self.worker_id,
            )
            if not renewed:
                return False
            record_worker_heartbeat(
                db,
                worker_id=self.worker_id,
                status="processing",
                current_scan_id=self.scan_id,
            )
            return True

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                renewed = self.renew_now()
            except Exception:
                renewed = False
            if not renewed:
                self._lease_lost.set()
                return


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
                with ScanExecutionMonitor(scan_id=scan.id, worker_id=settings.worker_id) as execution:
                    if scan.mode == ScanMode.REPO.value:
                        run_repo_scan_job(
                            db,
                            scan,
                            settings.artifact_root,
                            settings.repo_scan_root,
                            execution_checkpoint=execution.checkpoint,
                        )
                    else:
                        allowlist = load_allowlist(settings.allowlist_path)
                        run_passive_scan_job(
                            db,
                            scan,
                            settings.artifact_root,
                            allowlist,
                            zap_base_url=settings.zap_base_url,
                            execution_checkpoint=execution.checkpoint,
                        )
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
