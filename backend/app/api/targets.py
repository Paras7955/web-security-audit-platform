from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db, get_scan_allowlist
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import CursorPage, TargetAuthProfileUpdate, TargetCreate, TargetRead, TargetRepoPathUpdate, TargetValidationRead
from app.core.config import settings
from app.core.contracts import SCAN_PROFILES, ScanMode
from app.models import AuthProfile, Target
from app.ops.audit import record_audit_event
from app.repo_scanner.paths import RepoPathError, repo_path_for_storage
from app.security.allowlist import ScanAllowlist
from app.security.auth import AuthenticatedPrincipal
from app.security.sanitization import sanitize_text
from app.security.ssrf import SsrfGuardError, validate_destination
from app.security.target_url import TargetUrlError, match_allowlisted_target

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/validate", response_model=TargetValidationRead)
def validate_target(
    target_url: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetValidationRead:
    match = validate_allowed_target_url(target_url, allowlist)
    target = match.allowlist_target
    return TargetValidationRead(
        allowlist_id=target.id,
        name=target.name,
        base_url=target.base_url,
        available_scan_profile_ids=available_scan_profile_ids(target.allowed_modes),
        max_redirects=target.max_redirects,
        local_demo=target.local_demo,
    )


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetRead:
    if not payload.permission_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission confirmation is required before creating a scan target.",
        )
    auth_profile_id = require_workspace_auth_profile(db, payload.auth_profile_id, principal)

    match = validate_allowed_target_url(payload.target_url, allowlist)
    allowlist_target = match.allowlist_target
    repo_path = payload.repo_path.strip() if payload.repo_path else None
    if repo_path is not None:
        try:
            repo_path = repo_path_for_storage(repo_path, repo_scan_root=settings.repo_scan_root)
        except RepoPathError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    target = Target(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        allowlist_id=allowlist_target.id,
        name=sanitize_text(allowlist_target.name, maximum=200) or "Allowlisted target",
        base_url=match.url.normalized_url,
        permission_confirmed=True,
        authorization_confirmed_at=datetime.now(UTC),
        repo_path=repo_path,
        auth_profile_id=auth_profile_id,
        auth_profile_attached_at=datetime.now(UTC) if auth_profile_id else None,
    )
    db.add(target)
    record_audit_event(
        db,
        principal,
        event_type="target.created",
        resource_type="target",
        resource_id=target.id,
        metadata={"allowlist_id": allowlist_target.id, "has_repo_path": repo_path is not None, "has_auth_profile": auth_profile_id is not None},
    )
    db.commit()
    db.refresh(target)
    return target_to_read(target, allowlist)


@router.get("", response_model=CursorPage[TargetRead])
def list_targets(
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> CursorPage[TargetRead]:
    statement = select(Target).where(Target.workspace_id == principal.workspace_id)
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                Target.created_at < page.cursor_created_at,
                and_(Target.created_at == page.cursor_created_at, Target.id < page.cursor_id),
            )
        )
    targets = list(db.scalars(statement.order_by(Target.created_at.desc(), Target.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(targets, page.limit)
    return CursorPage(items=[target_to_read(target, allowlist) for target in visible], next_cursor=next_cursor)


@router.patch("/{target_id}/repo-path", response_model=TargetRead)
def update_target_repo_path(
    target_id: str,
    payload: TargetRepoPathUpdate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetRead:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.workspace_id == principal.workspace_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    repo_path = payload.repo_path.strip() if payload.repo_path else None
    if repo_path is not None:
        try:
            repo_path = repo_path_for_storage(repo_path, repo_scan_root=settings.repo_scan_root)
        except RepoPathError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    target.repo_path = repo_path
    db.add(target)
    record_audit_event(
        db,
        principal,
        event_type="target.repo_path_updated",
        resource_type="target",
        resource_id=target.id,
        metadata={"has_repo_path": repo_path is not None},
    )
    db.commit()
    db.refresh(target)
    return target_to_read(target, allowlist)


@router.patch("/{target_id}/auth-profile", response_model=TargetRead)
def update_target_auth_profile(
    target_id: str,
    payload: TargetAuthProfileUpdate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetRead:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.workspace_id == principal.workspace_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    target.auth_profile_id = require_workspace_auth_profile(db, payload.auth_profile_id, principal)
    target.auth_profile_attached_at = datetime.now(UTC) if target.auth_profile_id else None
    db.add(target)
    record_audit_event(
        db,
        principal,
        event_type="target.auth_profile_updated",
        resource_type="target",
        resource_id=target.id,
        metadata={"has_auth_profile": target.auth_profile_id is not None},
    )
    db.commit()
    db.refresh(target)
    return target_to_read(target, allowlist)


@router.get("/{target_id}", response_model=TargetRead)
def get_target(
    target_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetRead:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.workspace_id == principal.workspace_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    return target_to_read(target, allowlist)


def validate_allowed_target_url(target_url: str, allowlist: ScanAllowlist):
    try:
        match = match_allowlisted_target(target_url, allowlist)
        validate_destination(match.url, match.allowlist_target)
        return match
    except (TargetUrlError, SsrfGuardError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


def require_workspace_auth_profile(db: Session, auth_profile_id: str | None, principal: AuthenticatedPrincipal) -> str | None:
    if auth_profile_id is None:
        return None
    profile = db.scalar(select(AuthProfile).where(AuthProfile.id == auth_profile_id, AuthProfile.workspace_id == principal.workspace_id))
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Auth profile not found.")
    if profile.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Revoked auth profiles cannot be attached to targets.")
    return profile.id


def target_to_read(target: Target, allowlist: ScanAllowlist) -> TargetRead:
    allowlist_target = allowlist.get_target(target.allowlist_id)
    profile_ids = available_scan_profile_ids(allowlist_target.allowed_modes) if allowlist_target else []
    return TargetRead(
        id=target.id,
        allowlist_id=target.allowlist_id,
        name=target.name,
        base_url=target.base_url,
        permission_confirmed=target.permission_confirmed,
        has_repo_path=target.repo_path is not None,
        auth_profile_id=target.auth_profile_id,
        available_scan_profile_ids=profile_ids,
        created_at=target.created_at,
    )


def available_scan_profile_ids(allowed_modes: Iterable[ScanMode]) -> list[str]:
    allowed = {mode.value for mode in allowed_modes}
    return [profile.id for profile in SCAN_PROFILES if profile.mode.value in allowed]
