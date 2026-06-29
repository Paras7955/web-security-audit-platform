from sqlalchemy.orm import Session

from app.security.auth import ensure_user_workspace_identity


DEV_USER_ID = "dev-user"
DEV_WORKSPACE_ID = "dev-workspace"
DEV_AUTH_HEADERS = {"Authorization": "Bearer dev-token"}


def ensure_dev_principal(db: Session) -> None:
    ensure_user_workspace_identity(
        db,
        user_id=DEV_USER_ID,
        workspace_id=DEV_WORKSPACE_ID,
        provider="dev",
        provider_subject=DEV_USER_ID,
        display_name="Dev User",
        workspace_name="Dev Workspace",
    )
