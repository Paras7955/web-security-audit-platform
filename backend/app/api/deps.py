from collections.abc import Generator

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.security.allowlist import ScanAllowlist, load_allowlist


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_scan_allowlist() -> ScanAllowlist:
    return load_allowlist(settings.allowlist_path)

