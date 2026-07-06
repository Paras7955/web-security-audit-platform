import time

from sqlalchemy import text

from app.auth_profiles import validate_auth_profile_secret_settings
from app.core.config import settings
from app.db.session import engine
from app.db.session import SessionLocal
from app.core.contracts import ScanMode
from app.scans.lifecycle import claim_next_queued_scan, run_passive_scan_job, run_repo_scan_job
from app.security.allowlist import load_allowlist


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
    validate_worker_startup()
    wait_for_database()
    print("Worker ready. Polling database-backed scan jobs.", flush=True)
    while True:
        with SessionLocal() as db:
            scan = claim_next_queued_scan(db)
            if scan is not None:
                print(f"Processing scan {scan.id}", flush=True)
                allowlist = load_allowlist(settings.allowlist_path)
                if scan.mode == ScanMode.REPO.value:
                    run_repo_scan_job(db, scan, settings.artifact_root, settings.repo_scan_root, allowlist)
                else:
                    run_passive_scan_job(db, scan, settings.artifact_root, allowlist, zap_base_url=settings.zap_base_url)
                continue
        time.sleep(5)


def validate_worker_startup() -> None:
    validate_auth_profile_secret_settings(settings)


if __name__ == "__main__":
    main()
