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
from app.models import Scan, ScannerToolRun, Target
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
        acknowledgements=payload.acknowledgements,
    )
    scan = Scan(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        target_id=target.id,
        auth_profile_id=target.auth_profile_id,
        scan_profile_id=profile.id,
        mode=mode.value,
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
        metadata={"target_id": target.id, "scan_profile_id": profile.id},
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


def scan_to_read(scan: Scan) -> ScanRead:
    return ScanRead(
        id=scan.id,
        target_id=scan.target_id,
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
