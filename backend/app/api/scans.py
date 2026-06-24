from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_scan_allowlist
from app.api.schemas import ScanCreate, ScanRead
from app.core.contracts import ScanMode, ScanStatus, ScanStep
from app.models import Scan, Target
from app.security.allowlist import ScanAllowlist

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    allowlist: ScanAllowlist = Depends(get_scan_allowlist),
) -> ScanRead:
    target = db.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    if not target.permission_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target authorization is not confirmed.")

    mode = validate_scan_mode(payload.mode, target, allowlist, active_demo_acknowledged=payload.active_demo_acknowledged)
    scan = Scan(
        id=str(uuid4()),
        target_id=target.id,
        mode=mode.value,
        status=ScanStatus.QUEUED.value,
        current_step=ScanStep.TARGET_VALIDATION.value,
        status_message=f"Queued for {mode.value} scanner worker.",
        progress_percent=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanRead])
def list_scans(db: Session = Depends(get_db)) -> list[ScanRead]:
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc())).all())


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanRead:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


def validate_scan_mode(
    raw_mode: str,
    target: Target,
    allowlist: ScanAllowlist,
    *,
    active_demo_acknowledged: bool,
) -> ScanMode:
    try:
        mode = ScanMode(raw_mode)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported scan mode.") from exc

    allowlist_target = allowlist.get_target(target.allowlist_id)
    allowed_modes = set(allowlist_target.allowed_modes) if allowlist_target else set()
    if mode not in allowed_modes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan mode is not allowed for this target.")

    if mode is ScanMode.ACTIVE_DEMO:
        if allowlist_target is None or not allowlist_target.local_demo:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active Demo scans are local/demo allowlist only.")
        if not active_demo_acknowledged:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Active Demo scans require explicit acknowledgement.",
            )
        return mode

    if mode is not ScanMode.PASSIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only passive and Active Demo scans are available before Phase 9C.",
        )
    return mode
