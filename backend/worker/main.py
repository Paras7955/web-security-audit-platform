import time
from urllib.request import urlopen

from sqlalchemy import text

from app.core.config import settings
from app.db.session import engine
from app.db.session import SessionLocal
from app.scans.lifecycle import claim_next_queued_scan, run_internal_lifecycle_job


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


def wait_for_zap(max_attempts: int = 30) -> None:
    version_url = f"{settings.zap_base_url}/JSON/core/view/version/"
    for attempt in range(1, max_attempts + 1):
        try:
            with urlopen(version_url, timeout=3) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            if attempt == max_attempts:
                raise RuntimeError("ZAP did not become ready") from exc
            time.sleep(2)


def main() -> None:
    wait_for_database()
    wait_for_zap()
    print("Worker ready. Polling database-backed scan jobs.", flush=True)
    while True:
        with SessionLocal() as db:
            scan = claim_next_queued_scan(db)
            if scan is not None:
                print(f"Processing scan {scan.id}", flush=True)
                run_internal_lifecycle_job(db, scan, settings.artifact_root)
                continue
        time.sleep(5)


if __name__ == "__main__":
    main()
