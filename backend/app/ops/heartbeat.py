from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.contracts import ScanStatus
from app.models import Scan, WorkerHeartbeat


def queue_depth(db: Session) -> int:
    return int(db.scalar(select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.QUEUED.value)) or 0)


def record_worker_heartbeat(
    db: Session,
    *,
    worker_id: str,
    status: str,
    current_scan_id: str | None = None,
) -> WorkerHeartbeat:
    heartbeat = db.scalar(select(WorkerHeartbeat).where(WorkerHeartbeat.worker_id == worker_id))
    now = datetime.now(UTC)
    if heartbeat is None:
        heartbeat = WorkerHeartbeat(
            id=str(uuid4()),
            worker_id=worker_id,
            status=status,
            current_scan_id=current_scan_id,
            queue_depth=queue_depth(db),
            last_seen_at=now,
        )
    else:
        heartbeat.status = status
        heartbeat.current_scan_id = current_scan_id
        heartbeat.queue_depth = queue_depth(db)
        heartbeat.last_seen_at = now
    db.add(heartbeat)
    db.commit()
    db.refresh(heartbeat)
    return heartbeat
