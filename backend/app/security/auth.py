import secrets
from dataclasses import dataclass
from functools import lru_cache
from uuid import uuid4

import jwt
from jwt import PyJWKClient, PyJWTError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.models import AuthIdentity, PlatformUser, Workspace
from app.security.sanitization import sanitize_text


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
        if app_env != "local":
            raise AuthConfigurationError("AUTH_MODE=dev is allowed only when APP_ENV=local.")
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
    if not secrets.compare_digest(token.encode("utf-8"), config.dev_auth_token.encode("utf-8")):
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
        jwk_client = oidc_jwk_client(config.auth_oidc_jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.auth_oidc_audience,
            issuer=config.auth_oidc_issuer,
            options={"require": ["sub", "exp", "iat"]},
            leeway=30,
        )
    except PyJWTError as exc:
        raise AuthError("Invalid bearer token.") from exc
    except Exception as exc:
        raise AuthError("OIDC token validation failed.") from exc
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > 300:
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

    display_name = sanitize_text(
        claims.get("name") or claims.get("email") or "Authenticated User",
        maximum=200,
    ) or "Authenticated User"
    return provision_oidc_principal(db, provider=provider, subject=subject, display_name=display_name)


@lru_cache(maxsize=8)
def oidc_jwk_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url, cache_keys=True, max_cached_keys=16, lifespan=300)


def provision_oidc_principal(
    db: Session,
    *,
    provider: str,
    subject: str,
    display_name: str,
) -> AuthenticatedPrincipal:
    display_name = sanitize_text(display_name, maximum=200) or "Authenticated User"
    user_id = str(uuid4())
    workspace_id = str(uuid4())
    try:
        with db.begin_nested():
            db.add(PlatformUser(id=user_id, display_name=display_name))
            db.flush()
            db.add(Workspace(id=workspace_id, owner_user_id=user_id, name="Default Workspace"))
            db.flush()
            db.add(
                AuthIdentity(
                    id=str(uuid4()),
                    user_id=user_id,
                    provider=provider,
                    provider_subject=subject,
                )
            )
            db.flush()
        db.commit()
    except IntegrityError:
        db.rollback()
        identity = db.scalar(
            select(AuthIdentity).where(
                AuthIdentity.provider == provider,
                AuthIdentity.provider_subject == subject,
            )
        )
        if identity is None:
            raise AuthError("Identity provisioning could not be completed safely.") from None
        workspace = db.scalar(
            select(Workspace).where(Workspace.owner_user_id == identity.user_id).order_by(Workspace.created_at.asc())
        )
        if workspace is None:
            raise AuthError("Identity provisioning could not be completed safely.") from None
        user_id = identity.user_id
        workspace_id = workspace.id
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
    try:
        user, workspace, identity = load_expected_identity_state(
            db,
            user_id=user_id,
            workspace_id=workspace_id,
            provider=provider,
            provider_subject=provider_subject,
        )
        validate_expected_identity_state(workspace=workspace, identity=identity, user_id=user_id)

        if user is None:
            db.add(PlatformUser(id=user_id, display_name=sanitize_text(display_name, maximum=200) or "User"))
            db.flush()

        if workspace is None:
            db.add(
                Workspace(
                    id=workspace_id,
                    owner_user_id=user_id,
                    name=sanitize_text(workspace_name, maximum=200) or "Workspace",
                )
            )
            db.flush()

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
    except IntegrityError:
        # Parallel first requests can race while provisioning the fixed local
        # identity. The losing transaction is safe only when the committed
        # winner created the exact state this request expected.
        db.rollback()
        user, workspace, identity = load_expected_identity_state(
            db,
            user_id=user_id,
            workspace_id=workspace_id,
            provider=provider,
            provider_subject=provider_subject,
        )
        if user is None or workspace is None or identity is None:
            raise AuthError("Identity provisioning could not be completed safely.") from None
        validate_expected_identity_state(workspace=workspace, identity=identity, user_id=user_id)


def load_expected_identity_state(
    db: Session,
    *,
    user_id: str,
    workspace_id: str,
    provider: str,
    provider_subject: str,
) -> tuple[PlatformUser | None, Workspace | None, AuthIdentity | None]:
    user = db.get(PlatformUser, user_id)
    workspace = db.get(Workspace, workspace_id)
    identity = db.scalar(
        select(AuthIdentity).where(
            AuthIdentity.provider == provider,
            AuthIdentity.provider_subject == provider_subject,
        )
    )
    return user, workspace, identity


def validate_expected_identity_state(
    *,
    workspace: Workspace | None,
    identity: AuthIdentity | None,
    user_id: str,
) -> None:
    if workspace is not None and workspace.owner_user_id != user_id:
        raise AuthError("Identity provisioning could not be completed safely.")
    if identity is not None and identity.user_id != user_id:
        raise AuthError("Identity provisioning could not be completed safely.")


def normalize(value: str) -> str:
    return value.strip().lower()
