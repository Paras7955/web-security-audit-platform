from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
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
    rows = db.scalars(
        select(ApiRateLimitLog).where(
            ApiRateLimitLog.workspace_id == principal.workspace_id,
            ApiRateLimitLog.user_id == principal.user_id,
            ApiRateLimitLog.action == action,
            ApiRateLimitLog.allowed.is_(True),
            ApiRateLimitLog.created_at >= cutoff,
        )
    ).all()
    return len(rows) >= max_requests
