from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db, get_scan_allowlist
from app.api.schemas import ScanCreate, ScanRead
from app.core.contracts import ScanMode, ScanProfile, ScanStatus, ScanStep, default_scan_profile_for_mode, scan_profile_for_id
from app.core.config import settings
from app.models import Scan, Target
from app.repo_scanner.paths import RepoPathError, validate_repo_path
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
    target = db.scalar(select(Target).where(Target.id == payload.target_id, Target.workspace_id == principal.workspace_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    if not target.permission_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target authorization is not confirmed.")

    profile = resolve_scan_profile(payload)
    mode = validate_scan_profile(
        profile,
        target,
        allowlist,
        active_demo_acknowledged=payload.active_demo_acknowledged,
        ajax_short_acknowledged=payload.ajax_short_acknowledged,
    )
    scan = Scan(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        target_id=target.id,
        scan_profile_id=profile.id,
        mode=mode.value,
        status=ScanStatus.QUEUED.value,
        current_step=ScanStep.TARGET_VALIDATION.value,
        status_message=f"Queued for {mode.value} scanner worker using {profile.label} profile.",
        progress_percent=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanRead])
def list_scans(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[ScanRead]:
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.workspace_id == principal.workspace_id)
            .order_by(Scan.created_at.desc())
        ).all()
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ScanRead:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


def resolve_scan_profile(payload: ScanCreate) -> ScanProfile:
    profile: ScanProfile | None = None
    if payload.scan_profile_id is not None:
        profile = scan_profile_for_id(payload.scan_profile_id)
        if profile is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported scan profile.")

    if payload.mode is not None:
        try:
            mode = ScanMode(payload.mode)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported scan mode.") from exc
        mode_profile = default_scan_profile_for_mode(mode.value)
        if mode_profile is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported scan mode.") from None
        if profile is not None and profile.mode != mode:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan mode does not match scan profile.")
        profile = profile or mode_profile

    if profile is None:
        profile = scan_profile_for_id("passive-web")
        if profile is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Default scan profile is not configured.")
    return profile


def validate_scan_profile(
    profile: ScanProfile,
    target: Target,
    allowlist: ScanAllowlist,
    *,
    active_demo_acknowledged: bool,
    ajax_short_acknowledged: bool,
) -> ScanMode:
    mode = profile.mode

    allowlist_target = allowlist.get_target(target.allowlist_id)
    allowed_modes = set(allowlist_target.allowed_modes) if allowlist_target else set()
    if mode not in allowed_modes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan profile is not allowed for this target.")

    if profile.local_demo_only:
        if allowlist_target is None or not allowlist_target.local_demo:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{profile.label} scans are local/demo allowlist only.")

    if profile.requires_active_demo_acknowledgement:
        if not active_demo_acknowledged:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Active Demo scans require explicit acknowledgement.",
            )

    if profile.requires_ajax_short_acknowledgement:
        if not ajax_short_acknowledged:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AJAX Short scans require explicit acknowledgement.",
            )

    if profile.requires_repo_path:
        try:
            validate_repo_path(target.repo_path, repo_scan_root=settings.repo_scan_root)
        except RepoPathError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    revalidate_target_record(target, allowlist)
    return mode


def revalidate_target_record(target: Target, allowlist: ScanAllowlist) -> None:
    try:
        match = match_allowlisted_target(target.base_url, allowlist)
        if match.allowlist_target.id != target.allowlist_id:
            raise TargetUrlError("target record no longer matches its allowlist entry")
        validate_destination(match.url, match.allowlist_target)
    except (TargetUrlError, SsrfGuardError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
