from dataclasses import dataclass
from uuid import uuid4

import jwt
from jwt import PyJWKClient, PyJWTError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.models import AuthIdentity, PlatformUser, Workspace


class AuthConfigurationError(ValueError):
    pass


class AuthError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    user_id: str
    workspace_id: str
    provider: str
    provider_subject: str


def validate_auth_settings(config: Settings = settings) -> None:
    auth_mode = normalize(config.auth_mode)
    app_env = normalize(config.app_env)
    provider = normalize(config.auth_provider)
    has_oidc_config = any(
        value
        for value in (
            config.auth_oidc_issuer,
            config.auth_oidc_audience,
            config.auth_oidc_jwks_url,
        )
    )

    if auth_mode not in {"dev", "required"}:
        raise AuthConfigurationError("AUTH_MODE must be dev or required.")
    if auth_mode == "dev":
        if app_env in {"production", "prod"}:
            raise AuthConfigurationError("AUTH_MODE=dev cannot run when APP_ENV is production.")
        if provider != "dev":
            raise AuthConfigurationError("AUTH_PROVIDER must be dev when AUTH_MODE=dev.")
        if has_oidc_config:
            raise AuthConfigurationError("Dev auth and production OIDC auth settings cannot coexist.")
        if not config.dev_auth_token.strip():
            raise AuthConfigurationError("DEV_AUTH_TOKEN is required when AUTH_MODE=dev.")
        return

    if not provider:
        raise AuthConfigurationError("AUTH_PROVIDER is required when AUTH_MODE=required.")
    if provider == "dev":
        raise AuthConfigurationError("AUTH_PROVIDER=dev is not allowed when AUTH_MODE=required.")
    if not config.auth_oidc_issuer or not config.auth_oidc_audience or not config.auth_oidc_jwks_url:
        raise AuthConfigurationError("AUTH_MODE=required needs AUTH_OIDC_ISSUER, AUTH_OIDC_AUDIENCE, and AUTH_OIDC_JWKS_URL.")


def authenticate_bearer_token(token: str, db: Session, config: Settings = settings) -> AuthenticatedPrincipal:
    validate_auth_settings(config)
    if normalize(config.auth_mode) == "dev":
        return authenticate_dev_token(token, db, config)
    return authenticate_oidc_token(token, db, config)


def authenticate_dev_token(token: str, db: Session, config: Settings) -> AuthenticatedPrincipal:
    if token != config.dev_auth_token:
        raise AuthError("Invalid bearer token.")
    provider = "dev"
    subject = config.dev_auth_subject
    user_id = config.dev_auth_user_id
    workspace_id = config.dev_auth_workspace_id
    ensure_user_workspace_identity(
        db,
        user_id=user_id,
        workspace_id=workspace_id,
        provider=provider,
        provider_subject=subject,
        display_name="Dev User",
        workspace_name="Dev Workspace",
    )
    return AuthenticatedPrincipal(
        user_id=user_id,
        workspace_id=workspace_id,
        provider=provider,
        provider_subject=subject,
    )


def authenticate_oidc_token(token: str, db: Session, config: Settings) -> AuthenticatedPrincipal:
    if not config.auth_oidc_jwks_url or not config.auth_oidc_issuer or not config.auth_oidc_audience:
        raise AuthConfigurationError("OIDC auth is not fully configured.")

    try:
        jwk_client = PyJWKClient(config.auth_oidc_jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.auth_oidc_audience,
            issuer=config.auth_oidc_issuer,
        )
    except PyJWTError as exc:
        raise AuthError("Invalid bearer token.") from exc
    except Exception as exc:
        raise AuthError("OIDC token validation failed.") from exc
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthError("OIDC token is missing a subject.")

    provider = normalize(config.auth_provider)
    identity = db.scalar(
        select(AuthIdentity).where(
            AuthIdentity.provider == provider,
            AuthIdentity.provider_subject == subject,
        )
    )
    if identity is not None:
        workspace = db.scalar(select(Workspace).where(Workspace.owner_user_id == identity.user_id).order_by(Workspace.created_at.asc()))
        if workspace is None:
            workspace = Workspace(id=str(uuid4()), owner_user_id=identity.user_id, name="Default Workspace")
            db.add(workspace)
            db.commit()
            db.refresh(workspace)
        return AuthenticatedPrincipal(
            user_id=identity.user_id,
            workspace_id=workspace.id,
            provider=provider,
            provider_subject=subject,
        )

    user_id = str(uuid4())
    workspace_id = str(uuid4())
    display_name = str(claims.get("name") or claims.get("email") or "Authenticated User")
    ensure_user_workspace_identity(
        db,
        user_id=user_id,
        workspace_id=workspace_id,
        provider=provider,
        provider_subject=subject,
        display_name=display_name,
        workspace_name="Default Workspace",
    )
    return AuthenticatedPrincipal(
        user_id=user_id,
        workspace_id=workspace_id,
        provider=provider,
        provider_subject=subject,
    )


def ensure_user_workspace_identity(
    db: Session,
    *,
    user_id: str,
    workspace_id: str,
    provider: str,
    provider_subject: str,
    display_name: str,
    workspace_name: str,
) -> None:
    user = db.get(PlatformUser, user_id)
    if user is None:
        db.add(PlatformUser(id=user_id, display_name=display_name))
        db.flush()

    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        db.add(Workspace(id=workspace_id, owner_user_id=user_id, name=workspace_name))
        db.flush()

    identity = db.scalar(
        select(AuthIdentity).where(
            AuthIdentity.provider == provider,
            AuthIdentity.provider_subject == provider_subject,
        )
    )
    if identity is None:
        db.add(
            AuthIdentity(
                id=str(uuid4()),
                user_id=user_id,
                provider=provider,
                provider_subject=provider_subject,
            )
        )
    db.commit()


def normalize(value: str) -> str:
    return value.strip().lower()
