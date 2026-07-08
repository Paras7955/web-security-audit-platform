from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import AuditLog
from app.security.auth import AuthenticatedPrincipal


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
    safe: dict[str, object] = {}
    for key, value in metadata.items():
        normalized_key = str(key)
        if "secret" in normalized_key.lower() or "token" in normalized_key.lower() or "key" in normalized_key.lower():
            safe[normalized_key] = "[REDACTED]"
            continue
        if isinstance(value, str):
            safe[normalized_key] = value[:500]
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[normalized_key] = value
        elif isinstance(value, list):
            safe[normalized_key] = [str(item)[:200] for item in value[:20]]
        else:
            safe[normalized_key] = str(value)[:500]
    return safe
