from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db, get_scan_allowlist
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import (
    CursorPage,
    TargetAuthProfileUpdate,
    TargetCreate,
    TargetPolicyRead,
    TargetRead,
    TargetReauthorize,
    TargetRepoPathUpdate,
    TargetValidationCreate,
    TargetValidationRead,
)
from app.core.config import settings
from app.core.contracts import SCAN_PROFILES, ScanMode, ScanStatus
from app.models import AuthProfile, Scan, Target
from app.ops.audit import record_audit_event
from app.repo_scanner.paths import RepoPathError, repo_path_for_storage
from app.security.allowlist import AllowlistTarget, ScanAllowlist, ScanEngine
from app.security.auth import AuthenticatedPrincipal
from app.security.sanitization import sanitize_text
from app.security.ssrf import SsrfGuardError, validate_destination
from app.security.target_url import TargetUrlError, match_allowlisted_target

router = APIRouter(prefix="/targets", tags=["targets"])
TERMINAL_SCAN_STATUSES = {
    ScanStatus.COMPLETED.value,
    ScanStatus.COMPLETED_WITH_WARNINGS.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELLED.value,
}


@router.get("/policies", response_model=list[TargetPolicyRead])
def list_target_policies(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> list[TargetPolicyRead]:
    del principal
    return [policy_to_read(target) for target in allowlist.targets]


@router.get("/validate", response_model=TargetValidationRead, deprecated=True)
def validate_target(
    target_url: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetValidationRead:
    del principal
    match = validate_allowed_target_url(target_url, allowlist)
    return validation_to_read(match.allowlist_target)


@router.post("/validate", response_model=TargetValidationRead)
def validate_target_json(
    payload: TargetValidationCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetValidationRead:
    del principal
    match = validate_allowed_target_url(payload.target_url, allowlist)
    return validation_to_read(match.allowlist_target)


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
        policy_fingerprint=allowlist_target.policy_fingerprint,
        policy_scope_base_url=allowlist_target.base_url,
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


@router.post("/{target_id}/reauthorize", response_model=TargetRead)
def reauthorize_target(
    target_id: str,
    payload: TargetReauthorize,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> TargetRead:
    if not payload.permission_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission confirmation is required before reauthorizing a target.",
        )
    target = db.scalar(
        select(Target)
        .where(
            Target.id == target_id,
            Target.workspace_id == principal.workspace_id,
            Target.archived_at.is_(None),
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    policy = allowlist.get_target(target.allowlist_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The target policy no longer exists; create a new target.",
        )
    if target.policy_scope_base_url not in {None, policy.base_url}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target origin or base-path policy changed; create a new target.",
        )
    try:
        match = match_allowlisted_target(target.base_url, allowlist)
    except TargetUrlError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target origin or base-path policy changed; create a new target.",
        ) from exc
    if match.allowlist_target.id != target.allowlist_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target origin or base-path policy changed; create a new target.",
        )
    validate_destination(match.url, policy)
    target.permission_confirmed = True
    target.authorization_confirmed_at = datetime.now(UTC)
    target.policy_fingerprint = policy.policy_fingerprint
    target.policy_scope_base_url = policy.base_url
    record_audit_event(
        db,
        principal,
        event_type="target.reauthorized",
        resource_type="target",
        resource_id=target.id,
        metadata={"allowlist_id": target.allowlist_id},
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
    statement = select(Target).where(
        Target.workspace_id == principal.workspace_id,
        Target.archived_at.is_(None),
    )
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
    target = db.scalar(
        select(Target)
        .where(
            Target.id == target_id,
            Target.workspace_id == principal.workspace_id,
            Target.archived_at.is_(None),
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    active_scan = db.scalar(
        select(Scan.id)
        .where(
            Scan.workspace_id == principal.workspace_id,
            Scan.target_id == target.id,
            ~Scan.status.in_(TERMINAL_SCAN_STATUSES),
        )
        .order_by(Scan.id.asc())
        .with_for_update()
        .limit(1)
    )
    if active_scan is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Repository compatibility path cannot change while a scan is active.",
        )

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
    preliminary = db.scalar(
        select(Target).where(
            Target.id == target_id,
            Target.workspace_id == principal.workspace_id,
            Target.archived_at.is_(None),
        )
    )
    if preliminary is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    profile_ids = sorted(
        {
            profile_id
            for profile_id in (preliminary.auth_profile_id, payload.auth_profile_id)
            if profile_id is not None
        }
    )
    locked_profiles = {
        profile.id: profile
        for profile in db.scalars(
            select(AuthProfile)
            .where(
                AuthProfile.workspace_id == principal.workspace_id,
                AuthProfile.id.in_(profile_ids),
            )
            .order_by(AuthProfile.id.asc())
            .with_for_update()
        ).all()
    } if profile_ids else {}
    target = db.scalar(
        select(Target)
        .where(
            Target.id == target_id,
            Target.workspace_id == principal.workspace_id,
            Target.archived_at.is_(None),
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    if target.auth_profile_id != preliminary.auth_profile_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target authorization changed concurrently; retry the request.",
        )
    if payload.auth_profile_id is not None:
        profile = locked_profiles.get(payload.auth_profile_id)
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Auth profile not found.")
        if profile.revoked_at is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Revoked auth profiles cannot be attached to targets.",
            )
    active_scan = db.scalar(
        select(Scan.id)
        .where(
            Scan.workspace_id == principal.workspace_id,
            Scan.target_id == target.id,
            ~Scan.status.in_(TERMINAL_SCAN_STATUSES),
        )
        .order_by(Scan.id.asc())
        .with_for_update()
        .limit(1)
    )
    if active_scan is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target authorization cannot change while a scan is active.",
        )
    target.auth_profile_id = payload.auth_profile_id
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
    target = db.scalar(
        select(Target).where(
            Target.id == target_id,
            Target.workspace_id == principal.workspace_id,
            Target.archived_at.is_(None),
        )
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    return target_to_read(target, allowlist)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_target(
    target_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Response:
    target = db.scalar(
        select(Target)
        .where(
            Target.id == target_id,
            Target.workspace_id == principal.workspace_id,
            Target.archived_at.is_(None),
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    active_scan_id = db.scalar(
        select(Scan.id).where(
            Scan.target_id == target.id,
            Scan.workspace_id == principal.workspace_id,
            ~Scan.status.in_(TERMINAL_SCAN_STATUSES),
        )
    )
    if active_scan_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target cannot be removed while a scan is active. Cancel or finish the scan first.",
        )

    target.archived_at = datetime.now(UTC)
    target.archived_by_user_id = principal.user_id
    target.permission_confirmed = False
    target.authorization_confirmed_at = None
    target.repo_path = None
    target.auth_profile_id = None
    target.auth_profile_attached_at = None
    db.add(target)
    record_audit_event(
        db,
        principal,
        event_type="target.archived",
        resource_type="target",
        resource_id=target.id,
        metadata={"allowlist_id": target.allowlist_id, "history_preserved": True},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def validate_allowed_target_url(target_url: str, allowlist: ScanAllowlist):
    parsed = urlsplit(target_url.strip())
    if parsed.query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configured target roots must not contain a query.",
        )
    try:
        match = match_allowlisted_target(target_url, allowlist)
        validate_destination(match.url, match.allowlist_target)
        return match
    except (TargetUrlError, SsrfGuardError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


def require_workspace_auth_profile(db: Session, auth_profile_id: str | None, principal: AuthenticatedPrincipal) -> str | None:
    if auth_profile_id is None:
        return None
    profile = db.scalar(
        select(AuthProfile)
        .where(
            AuthProfile.id == auth_profile_id,
            AuthProfile.workspace_id == principal.workspace_id,
        )
        .with_for_update()
    )
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Auth profile not found.")
    if profile.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Revoked auth profiles cannot be attached to targets.")
    return profile.id


def target_to_read(target: Target, allowlist: ScanAllowlist) -> TargetRead:
    allowlist_target = allowlist.get_target(target.allowlist_id)
    policy_status = target_policy_status(target, allowlist_target)
    profile_ids = profile_ids_for_policy(allowlist_target) if policy_status == "current" and allowlist_target else []
    scope_path = allowlist_target.base_path if allowlist_target is not None else (urlsplit(target.base_url).path or "/")
    return TargetRead(
        id=target.id,
        allowlist_id=target.allowlist_id,
        name=target.name,
        base_url=target.base_url,
        permission_confirmed=target.permission_confirmed,
        has_repo_path=target.repo_path is not None,
        auth_profile_id=target.auth_profile_id,
        available_scan_profile_ids=profile_ids,
        zap_required_scan_profile_ids=zap_required_profile_ids(allowlist_target) if policy_status == "current" and allowlist_target else [],
        connection_class=allowlist_target.connection.kind if allowlist_target is not None else "unavailable",
        scope_path=scope_path,
        tls_trust=allowlist_target.tls.trust if allowlist_target is not None else "unavailable",
        policy_status=policy_status,
        policy_fingerprint=target.policy_fingerprint,
        created_at=target.created_at,
    )


def target_policy_status(target: Target, policy: AllowlistTarget | None) -> str:
    if policy is None:
        return "missing"
    if (
        target.policy_fingerprint is None
        or target.policy_scope_base_url is None
        or target.policy_scope_base_url != policy.base_url
        or target.policy_fingerprint != policy.policy_fingerprint
    ):
        return "stale"
    return "current"


def validation_to_read(target: AllowlistTarget) -> TargetValidationRead:
    return TargetValidationRead(
        allowlist_id=target.id,
        name=target.name,
        base_url=target.base_url,
        available_scan_profile_ids=profile_ids_for_policy(target),
        zap_required_scan_profile_ids=zap_required_profile_ids(target),
        max_redirects=target.max_redirects,
        local_demo=target.local_demo,
        connection_class=target.connection.kind,
        scope_path=target.base_path,
        tls_trust=target.tls.trust,
        policy_fingerprint=target.policy_fingerprint,
    )


def policy_to_read(target: AllowlistTarget) -> TargetPolicyRead:
    return TargetPolicyRead(
        allowlist_id=target.id,
        name=target.name,
        base_url=target.base_url,
        connection_class=target.connection.kind,
        scope_path=target.base_path,
        tls_trust=target.tls.trust,
        available_scan_profile_ids=profile_ids_for_policy(target),
        zap_required_scan_profile_ids=zap_required_profile_ids(target),
        max_redirects=target.max_redirects,
        disposable_demo=target.disposable_demo,
        policy_fingerprint=target.policy_fingerprint,
    )


def profile_ids_for_policy(target: AllowlistTarget) -> list[str]:
    configured = set(target.profile_engines)
    return [profile.id for profile in SCAN_PROFILES if profile.id in configured]


def zap_required_profile_ids(target: AllowlistTarget) -> list[str]:
    zap_engines = {ScanEngine.ZAP_PASSIVE, ScanEngine.ZAP_ACTIVE, ScanEngine.ZAP_CLIENT_SPIDER}
    return [
        profile.id
        for profile in SCAN_PROFILES
        if profile.id in target.profile_engines
        and bool(set(target.engines_for_profile(profile.id)) & zap_engines)
    ]


def available_scan_profile_ids(allowed_modes: Iterable[ScanMode]) -> list[str]:
    allowed = {mode.value for mode in allowed_modes}
    return [profile.id for profile in SCAN_PROFILES if profile.mode.value in allowed]
