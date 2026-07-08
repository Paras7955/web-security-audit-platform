from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import ReportArtifactRead
from app.core.config import settings
from app.models import ReportArtifact, Scan
from app.reports.service import (
    ReportGenerationError,
    generate_report_artifacts,
    list_report_artifacts,
    read_report_artifact,
)
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["reports"])


@router.post("/scans/{scan_id}/reports", response_model=list[ReportArtifactRead], status_code=status.HTTP_201_CREATED)
def generate_reports(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[ReportArtifactRead]:
    require_workspace_scan(db, scan_id, principal)
    try:
        artifacts = generate_report_artifacts(
            db,
            scan_id=scan_id,
            workspace_id=principal.workspace_id,
            user_id=principal.user_id,
            artifact_root=settings.artifact_root,
            ai_provider=settings.ai_provider,
            openai_api_key=settings.openai_api_key,
            openai_model=settings.openai_model,
        )
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    return [to_report_read(artifact) for artifact in artifacts]


@router.get("/scans/{scan_id}/reports", response_model=list[ReportArtifactRead])
def list_reports(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[ReportArtifactRead]:
    require_workspace_scan(db, scan_id, principal)
    try:
        artifacts = list_report_artifacts(db, scan_id=scan_id, workspace_id=principal.workspace_id)
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    return [to_report_read(artifact) for artifact in artifacts]


@router.get("/reports/{report_id}")
def view_report(
    report_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Response:
    artifact = db.scalar(select(ReportArtifact).where(ReportArtifact.id == report_id, ReportArtifact.workspace_id == principal.workspace_id))
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    try:
        content = read_report_artifact(db, artifact, artifact_root=settings.artifact_root, workspace_id=principal.workspace_id)
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    media_type = "text/html; charset=utf-8" if artifact.report_type == "html" else "text/markdown; charset=utf-8"
    return Response(content=content, media_type=media_type)


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> PlainTextResponse:
    artifact = db.scalar(select(ReportArtifact).where(ReportArtifact.id == report_id, ReportArtifact.workspace_id == principal.workspace_id))
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    try:
        content = read_report_artifact(db, artifact, artifact_root=settings.artifact_root, workspace_id=principal.workspace_id)
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    extension = "html" if artifact.report_type == "html" else "md"
    return PlainTextResponse(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="scan-{artifact.scan_id}-report.{extension}"'},
    )


def to_report_read(artifact: ReportArtifact) -> ReportArtifactRead:
    return ReportArtifactRead(
        id=artifact.id,
        scan_id=artifact.scan_id,
        report_type=artifact.report_type,
        view_url=f"/reports/{artifact.id}",
        download_url=f"/reports/{artifact.id}/download",
        created_at=artifact.created_at,
    )


def report_error(error: ReportGenerationError) -> HTTPException:
    detail = str(error)
    if detail.endswith("not found.") or detail == "Scan not found.":
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def require_workspace_scan(db: Session, scan_id: str, principal: AuthenticatedPrincipal) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
