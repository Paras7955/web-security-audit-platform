from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import AuditLogRead, HealthComponentRead, PlatformHealthRead
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


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    limit: int = 100,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    bounded_limit = max(1, min(limit, 200))
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.workspace_id == principal.workspace_id)
            .order_by(AuditLog.created_at.desc())
            .limit(bounded_limit)
        ).all()
    )


def database_status(db: Session) -> HealthComponentRead:
    try:
        db.execute(text("SELECT 1"))
        return HealthComponentRead(status="ok", detail="database reachable")
    except Exception as exc:
        return HealthComponentRead(status="degraded", detail=str(exc))


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
    return HealthComponentRead(status="ok", detail=f"{heartbeat.worker_id} {heartbeat.status}")


def zap_status() -> HealthComponentRead:
    try:
        response = httpx.get(f"{settings.zap_base_url}/JSON/core/view/version/", timeout=settings.health_zap_timeout_seconds)
        response.raise_for_status()
        return HealthComponentRead(status="ok", detail="zap reachable")
    except Exception as exc:
        return HealthComponentRead(status="degraded", detail=str(exc))


def artifact_root_status() -> HealthComponentRead:
    path = Path(settings.artifact_root)
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            return HealthComponentRead(status="degraded", detail="artifact root is not a directory")
        marker = path / ".healthcheck"
        marker.write_text("ok", encoding="utf-8")
        marker.unlink(missing_ok=True)
        return HealthComponentRead(status="ok", detail=str(path))
    except Exception as exc:
        return HealthComponentRead(status="degraded", detail=str(exc))
