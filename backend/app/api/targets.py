from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db, get_scan_allowlist
from app.api.schemas import TargetAuthProfileUpdate, TargetCreate, TargetRead, TargetRepoPathUpdate, TargetValidationRead
from app.core.config import settings
from app.models import AuthProfile, Target
from app.security.auth import AuthenticatedPrincipal
from app.repo_scanner.paths import RepoPathError, validate_repo_path
from app.security.allowlist import ScanAllowlist
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
        allowed_modes=[mode.value for mode in target.allowed_modes],
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

    target = Target(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        allowlist_id=allowlist_target.id,
        name=allowlist_target.name,
        base_url=match.url.normalized_url,
        permission_confirmed=True,
        repo_path=payload.repo_path,
        auth_profile_id=auth_profile_id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target_to_read(target, allowlist)


@router.get("", response_model=list[TargetRead])
def list_targets(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> list[TargetRead]:
    targets = db.scalars(
        select(Target)
        .where(Target.workspace_id == principal.workspace_id)
        .order_by(Target.created_at.desc())
    ).all()
    return [target_to_read(target, allowlist) for target in targets]


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
            validate_repo_path(repo_path, repo_scan_root=settings.repo_scan_root)
        except RepoPathError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    target.repo_path = repo_path
    db.add(target)
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
    db.add(target)
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
    return profile.id


def target_to_read(target: Target, allowlist: ScanAllowlist) -> TargetRead:
    allowlist_target = allowlist.get_target(target.allowlist_id)
    allowed_modes = [mode.value for mode in allowlist_target.allowed_modes] if allowlist_target else []
    return TargetRead(
        id=target.id,
        allowlist_id=target.allowlist_id,
        name=target.name,
        base_url=target.base_url,
        permission_confirmed=target.permission_confirmed,
        repo_path=target.repo_path,
        auth_profile_id=target.auth_profile_id,
        allowed_modes=allowed_modes,
        created_at=target.created_at,
    )
