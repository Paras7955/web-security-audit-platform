from app.core.config import settings
from app.security.auth import ensure_user_workspace_identity
from sqlalchemy.orm import Session

DEV_USER_ID = settings.dev_auth_user_id
DEV_WORKSPACE_ID = settings.dev_auth_workspace_id
DEV_AUTH_HEADERS = {"Authorization": f"Bearer {settings.dev_auth_token}"}


def ensure_dev_principal(db: Session) -> None:
    ensure_user_workspace_identity(
        db,
        user_id=DEV_USER_ID,
        workspace_id=DEV_WORKSPACE_ID,
        provider="dev",
        provider_subject=settings.dev_auth_subject,
        display_name="Dev User",
        workspace_name="Dev Workspace",
    )
