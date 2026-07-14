from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import AuditLog
from app.security.auth import AuthenticatedPrincipal
from app.security.sanitization import sanitize_metadata


def record_audit_event(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    *,
    event_type: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> AuditLog:
    if principal is None:
        raise ValueError("Audit events require authenticated workspace context.")
    event = AuditLog(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        user_id=principal.user_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=safe_metadata(metadata or {}),
    )
    db.add(event)
    return event


def safe_metadata(metadata: dict[str, object]) -> dict[str, object]:
    result = sanitize_metadata(metadata)
    return result if isinstance(result, dict) else {}
