from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db, get_scan_allowlist
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import CursorPage, ScanCreate, ScannerToolRunRead, ScanRead
from app.core.config import settings
from app.core.contracts import ScanMode, ScanProfile, ScanStatus, ScanStep, scan_profile_for_id
from app.models import AuthProfile, RepositoryAsset, Scan, ScannerToolRun, Target
from app.ops.audit import record_audit_event
from app.ops.rate_limits import enforce_api_rate_limit
from app.repo_scanner.paths import RepoPathError, resolve_stored_repo_path
from app.scans.failures import safe_scan_failure
from app.security.allowlist import ScanAllowlist
from app.security.auth import AuthenticatedPrincipal
from app.security.ssrf import SsrfGuardError, validate_destination
from app.security.target_url import TargetUrlError, match_allowlisted_target

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> ScanRead:
    enforce_api_rate_limit(
        db,
        principal,
        action="scan_create",
        max_requests=settings.scan_create_rate_limit_max_requests,
        window_seconds=settings.api_rate_limit_window_seconds,
    )
    profile = resolve_scan_profile(payload)
    require_acknowledgements(profile, payload.acknowledgements)
    target: Target | None = None
    repository_asset: RepositoryAsset | None = None
    repo_path_snapshot: str | None = None
    policy_fingerprint: str | None = None
    auth_profile_id: str | None = None

    if payload.repository_asset_id is not None:
        if not profile.requires_repo_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="repository_asset_id may be used only with the repository scan profile.",
            )
        repository_asset = get_repository_asset_for_scan(db, payload.repository_asset_id, principal.workspace_id)
        repo_path_snapshot = validate_repository_asset_scope(repository_asset)
    else:
        target = get_target_for_scan(db, payload.target_id or "", principal.workspace_id)
        if profile.requires_repo_path:
            repository_asset = compatibility_repository_asset(db, target, principal)
            repo_path_snapshot = validate_repository_asset_scope(repository_asset)
        else:
            policy_fingerprint = validate_web_scan_profile(profile, target, allowlist)
            auth_profile_id = target.auth_profile_id

    scan = Scan(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        target_id=(
            target.id
            if target is not None and repository_asset is None
            else None
        ),
        repository_asset_id=repository_asset.id if repository_asset is not None else None,
        repo_path_snapshot=repo_path_snapshot,
        target_policy_fingerprint=policy_fingerprint,
        acknowledgements_snapshot=sorted(payload.acknowledgements),
        authorization_snapshot=authorization_snapshot(
            target=target,
            repository_asset=repository_asset,
            policy_fingerprint=policy_fingerprint,
        ),
        auth_profile_id=auth_profile_id,
        scan_profile_id=profile.id,
        mode=profile.mode.value,
        status=ScanStatus.QUEUED.value,
        current_step=ScanStep.TARGET_VALIDATION.value,
        status_message=f"Queued for scanner worker using the {profile.label} profile.",
        progress_percent=0,
    )
    db.add(scan)
    record_audit_event(
        db,
        principal,
        event_type="scan.created",
        resource_type="scan",
        resource_id=scan.id,
        metadata={
            "target_id": (
                target.id
                if target is not None and repository_asset is None
                else None
            ),
            "repository_asset_id": repository_asset.id if repository_asset is not None else None,
            "scan_profile_id": profile.id,
        },
    )
    db.commit()
    db.refresh(scan)
    return scan_to_read(scan)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ScanRead:
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id)
        .with_for_update()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    terminal_statuses = {
        ScanStatus.COMPLETED.value,
        ScanStatus.COMPLETED_WITH_WARNINGS.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }
    if scan.status in terminal_statuses:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Terminal scans cannot be cancelled.")

    if scan.cancellation_requested_at is not None:
        return scan_to_read(scan)

    previous_status = scan.status
    now = datetime.now(UTC)
    scan.cancellation_requested_at = now
    scan.cancellation_requested_by_user_id = principal.user_id
    if scan.status == ScanStatus.QUEUED.value:
        scan.status = ScanStatus.CANCELLED.value
        scan.status_message = "Queued scan cancelled before worker start."
        scan.progress_percent = min(scan.progress_percent or 0, 99)
        scan.completed_at = now
    else:
        scan.status_message = "Cancellation requested. Worker will stop at the next safe checkpoint."
    db.add(scan)
    record_audit_event(
        db,
        principal,
        event_type="scan.cancel_requested",
        resource_type="scan",
        resource_id=scan.id,
        metadata={"previous_status": previous_status, "target_id": scan.target_id},
    )
    db.commit()
    db.refresh(scan)
    return scan_to_read(scan)


@router.get("", response_model=CursorPage[ScanRead])
def list_scans(
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[ScanRead]:
    statement = select(Scan).where(Scan.workspace_id == principal.workspace_id)
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                Scan.created_at < page.cursor_created_at,
                and_(Scan.created_at == page.cursor_created_at, Scan.id < page.cursor_id),
            )
        )
    rows = list(db.scalars(statement.order_by(Scan.created_at.desc(), Scan.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[scan_to_read(scan) for scan in visible], next_cursor=next_cursor)


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ScanRead:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan_to_read(scan)


@router.get("/{scan_id}/tool-runs", response_model=CursorPage[ScannerToolRunRead])
def list_scan_tool_runs(
    scan_id: str,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[ScannerToolRunRead]:
    if db.scalar(select(Scan.id).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    statement = select(ScannerToolRun).where(
        ScannerToolRun.scan_id == scan_id,
        ScannerToolRun.workspace_id == principal.workspace_id,
    )
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                ScannerToolRun.created_at < page.cursor_created_at,
                and_(ScannerToolRun.created_at == page.cursor_created_at, ScannerToolRun.id < page.cursor_id),
            )
        )
    rows = list(
        db.scalars(statement.order_by(ScannerToolRun.created_at.desc(), ScannerToolRun.id.desc()).limit(page.limit + 1)).all()
    )
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[ScannerToolRunRead.model_validate(tool_run) for tool_run in visible], next_cursor=next_cursor)


def resolve_scan_profile(payload: ScanCreate) -> ScanProfile:
    profile = scan_profile_for_id(payload.scan_profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported scan profile.")
    return profile


def validate_scan_profile(
    profile: ScanProfile,
    target: Target,
    allowlist: ScanAllowlist,
    *,
    acknowledgements: set[str],
) -> ScanMode:
    mode = profile.mode

    allowlist_target = allowlist.get_target(target.allowlist_id)
    allowed_modes = set(allowlist_target.allowed_modes) if allowlist_target else set()
    if mode not in allowed_modes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan profile is not allowed for this target.")

    if profile.local_demo_only:
        if allowlist_target is None or not allowlist_target.local_demo:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{profile.label} scans are local/demo allowlist only.")

    missing_acknowledgements = profile.required_acknowledgements - acknowledgements
    if missing_acknowledgements:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required acknowledgements: {', '.join(sorted(missing_acknowledgements))}.",
        )

    if profile.requires_repo_path:
        try:
            resolve_stored_repo_path(target.repo_path, repo_scan_root=settings.repo_scan_root)
        except RepoPathError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if target.auth_profile_id is not None and mode != ScanMode.PASSIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Auth profiles are currently supported only for passive-web scans.",
        )

    revalidate_target_record(target, allowlist)
    return mode


def require_acknowledgements(profile: ScanProfile, acknowledgements: set[str]) -> None:
    missing_acknowledgements = profile.required_acknowledgements - acknowledgements
    if missing_acknowledgements:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required acknowledgements: {', '.join(sorted(missing_acknowledgements))}.",
        )


def get_target_for_scan(db: Session, target_id: str, workspace_id: str) -> Target:
    preliminary = db.scalar(
        select(Target).where(
            Target.id == target_id,
            Target.workspace_id == workspace_id,
            Target.archived_at.is_(None),
        )
    )
    if preliminary is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    auth_profile = None
    if preliminary.auth_profile_id is not None:
        auth_profile = db.scalar(
            select(AuthProfile)
            .where(
                AuthProfile.id == preliminary.auth_profile_id,
                AuthProfile.workspace_id == workspace_id,
            )
            .with_for_update()
        )
    target = db.scalar(
        select(Target)
        .where(
            Target.id == target_id,
            Target.workspace_id == workspace_id,
            Target.archived_at.is_(None),
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    if target.auth_profile_id != preliminary.auth_profile_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target authorization changed concurrently; retry the scan.",
        )
    if target.auth_profile_id is not None and (auth_profile is None or auth_profile.revoked_at is not None):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target authorization profile is unavailable.",
        )
    if not target.permission_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target authorization is not confirmed.")
    return target


def get_repository_asset_for_scan(db: Session, repository_asset_id: str, workspace_id: str) -> RepositoryAsset:
    asset = db.scalar(
        select(RepositoryAsset)
        .where(
            RepositoryAsset.id == repository_asset_id,
            RepositoryAsset.workspace_id == workspace_id,
            RepositoryAsset.archived_at.is_(None),
        )
        .with_for_update()
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository asset not found.")
    if not asset.permission_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Repository authorization is not confirmed.")
    return asset


def validate_repository_asset_scope(asset: RepositoryAsset) -> str:
    try:
        resolve_stored_repo_path(asset.relative_path, repo_scan_root=settings.repo_scan_root)
    except RepoPathError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return asset.relative_path


def compatibility_repository_asset(
    db: Session,
    target: Target,
    principal: AuthenticatedPrincipal,
) -> RepositoryAsset:
    if target.repo_path is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repo scans require a configured repository path.",
        )
    try:
        resolve_stored_repo_path(target.repo_path, repo_scan_root=settings.repo_scan_root)
    except RepoPathError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    asset = db.scalar(
        select(RepositoryAsset)
        .where(
            RepositoryAsset.workspace_id == principal.workspace_id,
            RepositoryAsset.relative_path == target.repo_path,
        )
        .with_for_update()
    )
    now = datetime.now(UTC)
    if asset is None:
        asset = RepositoryAsset(
            id=str(uuid4()),
            workspace_id=principal.workspace_id,
            created_by_user_id=principal.user_id,
            name=f"{target.name} repository"[:200],
            relative_path=target.repo_path,
            permission_confirmed=True,
            authorization_confirmed_at=now,
        )
        db.add(asset)
        db.flush()
    elif asset.archived_at is not None:
        asset.archived_at = None
        asset.archived_by_user_id = None
        asset.permission_confirmed = True
        asset.authorization_confirmed_at = now
    return asset


def validate_web_scan_profile(profile: ScanProfile, target: Target, allowlist: ScanAllowlist) -> str | None:
    mode = validate_scan_profile(profile, target, allowlist, acknowledgements=set(profile.required_acknowledgements))
    if mode == ScanMode.REPO:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Repository scans require a repository asset.")
    allowlist_target = allowlist.get_target(target.allowlist_id)
    fingerprint = str(getattr(allowlist_target, "policy_fingerprint", "") or "") or None
    policy_scope_base_url = str(getattr(allowlist_target, "base_url", "") or "") or None
    if (
        target.policy_fingerprint is None
        or target.policy_scope_base_url is None
        or fingerprint is None
        or policy_scope_base_url is None
        or target.policy_fingerprint != fingerprint
        or target.policy_scope_base_url != policy_scope_base_url
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target policy changed and must be reauthorized before launching another scan.",
        )
    return fingerprint


def authorization_snapshot(
    *,
    target: Target | None,
    repository_asset: RepositoryAsset | None,
    policy_fingerprint: str | None,
) -> dict[str, object]:
    if repository_asset is not None:
        return {
            "subject_type": "repository_asset",
            "subject_id": repository_asset.id,
            "relative_path": repository_asset.relative_path,
            "authorized_at": (
                repository_asset.authorization_confirmed_at.isoformat()
                if repository_asset.authorization_confirmed_at is not None
                else None
            ),
        }
    if target is None:
        return {}
    return {
        "subject_type": "web_target",
        "subject_id": target.id,
        "target_url": target.base_url,
        "allowlist_id": target.allowlist_id,
        "policy_fingerprint": policy_fingerprint,
        "auth_profile_id": target.auth_profile_id,
        "authorized_at": target.authorization_confirmed_at.isoformat() if target.authorization_confirmed_at is not None else None,
    }


def scan_to_read(scan: Scan) -> ScanRead:
    subject_type = "repository_asset" if scan.repository_asset_id is not None else "web_target"
    subject_id = scan.repository_asset_id or scan.target_id or ""
    return ScanRead(
        id=scan.id,
        target_id=scan.target_id,
        repository_asset_id=scan.repository_asset_id,
        subject_type=subject_type,
        subject_id=subject_id,
        scan_profile_id=scan.scan_profile_id,
        status=scan.status,
        current_step=scan.current_step,
        status_message=scan.status_message,
        progress_percent=scan.progress_percent,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        cancellation_requested_at=scan.cancellation_requested_at,
        failure=safe_scan_failure(scan.error_code, scan.status),
        created_at=scan.created_at,
    )


def revalidate_target_record(target: Target, allowlist: ScanAllowlist) -> None:
    try:
        match = match_allowlisted_target(target.base_url, allowlist)
        if match.allowlist_target.id != target.allowlist_id:
            raise TargetUrlError("target record no longer matches its allowlist entry")
        validate_destination(match.url, match.allowlist_target)
    except (TargetUrlError, SsrfGuardError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
