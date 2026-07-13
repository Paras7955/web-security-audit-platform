from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import and_, or_, select, text
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import AuditLogRead, CursorPage, HealthComponentRead, PlatformHealthRead
from app.core.config import settings
from app.models import AuditLog, WorkerHeartbeat
from app.ops.heartbeat import queue_depth
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["ops"])


@router.get("/ops/health", response_model=PlatformHealthRead)
def platform_health(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> PlatformHealthRead:
    database = database_status(db)
    worker = worker_status(db)
    zap = zap_status()
    artifact_root = artifact_root_status()
    components = (database, worker, zap, artifact_root)
    overall = "ok" if all(component.status == "ok" for component in components) else "degraded"
    return PlatformHealthRead(
        status=overall,
        database=database,
        worker=worker,
        queue_depth=queue_depth(db),
        zap=zap,
        artifact_root=artifact_root,
    )


@router.get("/audit-logs", response_model=CursorPage[AuditLogRead])
def list_audit_logs(
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[AuditLogRead]:
    statement = select(AuditLog).where(AuditLog.workspace_id == principal.workspace_id)
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                AuditLog.created_at < page.cursor_created_at,
                and_(AuditLog.created_at == page.cursor_created_at, AuditLog.id < page.cursor_id),
            )
        )
    rows = list(db.scalars(statement.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[AuditLogRead.model_validate(entry) for entry in visible], next_cursor=next_cursor)


def database_status(db: Session) -> HealthComponentRead:
    try:
        db.execute(text("SELECT 1"))
        return HealthComponentRead(status="ok", detail="database reachable")
    except Exception:
        return HealthComponentRead(status="degraded", detail="database unavailable")


def worker_status(db: Session) -> HealthComponentRead:
    heartbeat = db.scalar(select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).limit(1))
    if heartbeat is None:
        return HealthComponentRead(status="degraded", detail="no worker heartbeat recorded")
    last_seen = heartbeat.last_seen_at
    if not isinstance(last_seen, datetime):
        return HealthComponentRead(status="degraded", detail="worker heartbeat timestamp missing")
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age_seconds = (datetime.now(UTC) - last_seen).total_seconds()
    if age_seconds > settings.worker_stale_after_seconds:
        return HealthComponentRead(status="degraded", detail=f"worker heartbeat stale after {int(age_seconds)} seconds")
    return HealthComponentRead(status="ok", detail="worker responding")


def zap_status() -> HealthComponentRead:
    try:
        response = httpx.get(
            f"{settings.zap_base_url}/JSON/core/view/version/",
            headers={"X-ZAP-API-Key": settings.zap_api_key},
            timeout=settings.health_zap_timeout_seconds,
        )
        response.raise_for_status()
        return HealthComponentRead(status="ok", detail="zap reachable")
    except Exception:
        return HealthComponentRead(status="degraded", detail="zap unavailable")


def artifact_root_status() -> HealthComponentRead:
    path = Path(settings.artifact_root)
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            return HealthComponentRead(status="degraded", detail="artifact root is not a directory")
        marker = path / ".healthcheck"
        marker.write_text("ok", encoding="utf-8")
        marker.unlink(missing_ok=True)
        return HealthComponentRead(status="ok", detail="artifact root writable")
    except Exception:
        return HealthComponentRead(status="degraded", detail="artifact root unavailable")
