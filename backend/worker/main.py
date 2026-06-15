import time
from urllib.request import urlopen

from sqlalchemy import text

from app.core.config import settings
from app.db.session import engine


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
    print("Worker ready. Scan polling starts in Phase 3.", flush=True)
    while True:
        time.sleep(30)


if __name__ == "__main__":
    main()

