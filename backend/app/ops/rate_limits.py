from datetime import UTC, datetime, timedelta
from hashlib import blake2b
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models import ApiRateLimitLog
from app.security.auth import AuthenticatedPrincipal


def enforce_api_rate_limit(
    db: Session,
    principal: AuthenticatedPrincipal,
    *,
    action: str,
    max_requests: int,
    window_seconds: int,
) -> None:
    lock_rate_limit_scope(db, principal, action)
    allowed = not is_limited(
        db,
        principal,
        action=action,
        max_requests=max_requests,
        window_seconds=window_seconds,
    )
    db.add(
        ApiRateLimitLog(
            id=str(uuid4()),
            workspace_id=principal.workspace_id,
            user_id=principal.user_id,
            action=action,
            allowed=allowed,
        )
    )
    if not allowed:
        db.commit()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded for this action.")
    db.flush()


def lock_rate_limit_scope(db: Session, principal: AuthenticatedPrincipal, action: str) -> None:
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        return
    digest = blake2b(
        f"{principal.workspace_id}:{principal.user_id}:{action}".encode(),
        digest_size=8,
    ).digest()
    lock_key = int.from_bytes(digest, byteorder="big", signed=True)
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": lock_key})


def is_limited(
    db: Session,
    principal: AuthenticatedPrincipal,
    *,
    action: str,
    max_requests: int,
    window_seconds: int,
) -> bool:
    if max_requests <= 0:
        return True
    if window_seconds <= 0:
        return False
    cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
    count = db.scalar(
        select(func.count())
        .select_from(ApiRateLimitLog)
        .where(
            ApiRateLimitLog.workspace_id == principal.workspace_id,
            ApiRateLimitLog.user_id == principal.user_id,
            ApiRateLimitLog.action == action,
            ApiRateLimitLog.allowed.is_(True),
            ApiRateLimitLog.created_at >= cutoff,
        )
    )
    return int(count or 0) >= max_requests
