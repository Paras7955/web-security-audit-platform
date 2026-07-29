from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import AuthProfileCreate, AuthProfileRead, AuthProfileRotate, CursorPage
from app.auth_profiles import AuthProfileError, encrypt_secret, secret_hint, validate_profile_input
from app.core.config import Settings, settings
from app.models import AuthProfile, Scan, Target
from app.ops.audit import record_audit_event
from app.security.auth import AuthenticatedPrincipal
from app.security.sanitization import sanitize_text

router = APIRouter(prefix="/auth-profiles", tags=["auth-profiles"])

NONTERMINAL_SCAN_STATUSES = {"queued", "validating", "running", "normalizing"}


@router.post("", response_model=AuthProfileRead, status_code=status.HTTP_201_CREATED)
def create_auth_profile(
    payload: AuthProfileCreate,
    request: Request,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AuthProfileRead:
    require_secure_credential_transport(request)
    label = (sanitize_text(payload.label, maximum=200) or "").strip()
    if not label:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Auth profile label is required.")
    try:
        profile_type, header_name, secret = validate_profile_input(
            profile_type=payload.profile_type,
            header_name=payload.header_name,
            secret=payload.secret,
        )
        encrypted_secret = encrypt_secret(secret)
    except AuthProfileError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    profile = AuthProfile(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        label=label,
        profile_type=profile_type,
        header_name=header_name,
        encrypted_secret=encrypted_secret,
        secret_hint=secret_hint(secret),
    )
    db.add(profile)
    record_audit_event(
        db,
        principal,
        event_type="auth_profile.created",
        resource_type="auth_profile",
        resource_id=profile.id,
        metadata={"profile_type": profile_type, "header_name": header_name},
    )
    db.commit()
    db.refresh(profile)
    return auth_profile_to_read(profile)


@router.get("", response_model=CursorPage[AuthProfileRead])
def list_auth_profiles(
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[AuthProfileRead]:
    statement = select(AuthProfile).where(AuthProfile.workspace_id == principal.workspace_id)
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                AuthProfile.created_at < page.cursor_created_at,
                and_(AuthProfile.created_at == page.cursor_created_at, AuthProfile.id < page.cursor_id),
            )
        )
    rows = list(
        db.scalars(statement.order_by(AuthProfile.created_at.desc(), AuthProfile.id.desc()).limit(page.limit + 1)).all()
    )
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[auth_profile_to_read(profile) for profile in visible], next_cursor=next_cursor)


@router.get("/{auth_profile_id}", response_model=AuthProfileRead)
def get_auth_profile(
    auth_profile_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AuthProfileRead:
    profile = db.scalar(select(AuthProfile).where(AuthProfile.id == auth_profile_id, AuthProfile.workspace_id == principal.workspace_id))
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Auth profile not found.")
    return auth_profile_to_read(profile)


@router.post("/{auth_profile_id}/rotate", response_model=AuthProfileRead)
def rotate_auth_profile(
    auth_profile_id: str,
    payload: AuthProfileRotate,
    request: Request,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AuthProfileRead:
    require_secure_credential_transport(request)
    profile = _locked_profile(db, auth_profile_id, principal.workspace_id)
    if profile.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Revoked auth profiles cannot be rotated.")
    _reject_in_use(db, profile)
    try:
        _, _, secret = validate_profile_input(
            profile_type=profile.profile_type,
            header_name=profile.header_name,
            secret=payload.secret,
        )
        profile.encrypted_secret = encrypt_secret(secret)
    except AuthProfileError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    profile.secret_hint = secret_hint(secret)
    profile.rotated_at = datetime.now(UTC)
    profile.rotation_count += 1
    db.add(profile)
    record_audit_event(
        db,
        principal,
        event_type="auth_profile.rotated",
        resource_type="auth_profile",
        resource_id=profile.id,
        metadata={"rotation_count": profile.rotation_count},
    )
    db.commit()
    db.refresh(profile)
    return auth_profile_to_read(profile)


@router.post("/{auth_profile_id}/revoke", response_model=AuthProfileRead)
def revoke_auth_profile(
    auth_profile_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AuthProfileRead:
    profile = _locked_profile(db, auth_profile_id, principal.workspace_id)
    if profile.revoked_at is not None:
        return auth_profile_to_read(profile)
    _reject_in_use(db, profile)
    now = datetime.now(UTC)
    profile.encrypted_secret = None
    profile.secret_hint = "revoked"  # noqa: S105 - metadata tombstone, never a credential
    profile.revoked_at = now
    profile.revoked_by_user_id = principal.user_id
    db.execute(
        update(Target)
        .where(Target.workspace_id == principal.workspace_id, Target.auth_profile_id == profile.id)
        .values(auth_profile_id=None, auth_profile_attached_at=None)
    )
    db.add(profile)
    record_audit_event(
        db,
        principal,
        event_type="auth_profile.revoked",
        resource_type="auth_profile",
        resource_id=profile.id,
        metadata={"targets_detached": True},
    )
    db.commit()
    db.refresh(profile)
    return auth_profile_to_read(profile)


def _locked_profile(db: Session, profile_id: str, workspace_id: str) -> AuthProfile:
    profile = db.scalar(
        select(AuthProfile)
        .where(AuthProfile.id == profile_id, AuthProfile.workspace_id == workspace_id)
        .with_for_update()
    )
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Auth profile not found.")
    return profile


def _reject_in_use(db: Session, profile: AuthProfile) -> None:
    in_use = db.scalar(
        select(Scan.id).where(
            Scan.workspace_id == profile.workspace_id,
            Scan.auth_profile_id == profile.id,
            Scan.status.in_(NONTERMINAL_SCAN_STATUSES),
        ).limit(1)
    )
    if in_use is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Auth profile cannot change while a nonterminal scan references it.",
        )


def auth_profile_to_read(profile: AuthProfile) -> AuthProfileRead:
    return AuthProfileRead(
        id=profile.id,
        label=profile.label,
        profile_type=profile.profile_type,
        header_name=profile.header_name,
        secret_hint=profile.secret_hint,
        status="revoked" if profile.revoked_at is not None else "active",
        rotated_at=profile.rotated_at,
        revoked_at=profile.revoked_at,
        rotation_count=profile.rotation_count,
        created_at=profile.created_at,
    )


def require_secure_credential_transport(request: Request, config: Settings = settings) -> None:
    """Reject plaintext credential submission outside the local-only workflow."""

    if request.url.scheme.lower() == "https" or _is_local_request(request, config):
        return
    if _trusted_forwarded_scheme(request, config) == "https":
        return

    error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Target credential secrets require HTTPS unless ScopeHarbor is accessed through its local-only endpoint.",
    )
    error.code = "credential_https_required"  # type: ignore[attr-defined]
    raise error


def _is_local_request(request: Request, config: Settings) -> bool:
    client_host = request.client.host if request.client is not None else ""
    try:
        if ip_address(client_host).is_loopback:
            return True
    except ValueError:
        pass

    # Docker Desktop may expose a loopback-bound host port through a bridge IP.
    # This exception is limited to explicit local mode and an exact local Host.
    return config.app_env.strip().lower() == "local" and request.url.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
        "testserver",
    }


def _trusted_forwarded_scheme(request: Request, config: Settings) -> str | None:
    client_host = request.client.host if request.client is not None else ""
    try:
        normalized_client = ip_address(client_host).compressed
    except ValueError:
        return None
    if normalized_client not in config.trusted_proxy_ips:
        return None

    # The nearest trusted proxy is the final hop. Operators must configure that
    # proxy to replace, rather than preserve, externally supplied scheme values.
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    nearest_scheme = forwarded_proto.rsplit(",", 1)[-1].strip().lower()
    return nearest_scheme if nearest_scheme in {"http", "https"} else None
