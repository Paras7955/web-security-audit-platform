from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import FindingRead
from app.models import Finding, Scan
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["findings"])


@router.get("/scans/{scan_id}/findings", response_model=list[FindingRead])
def list_scan_findings(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[FindingRead]:
    if db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    statement = (
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.workspace_id == principal.workspace_id)
        .order_by(Finding.severity.asc(), Finding.created_at.asc())
    )
    return list(db.scalars(statement).all())


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> FindingRead:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.workspace_id == principal.workspace_id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding
