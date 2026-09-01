from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import CursorPage, ReportArtifactRead
from app.core.config import settings
from app.models import ReportArtifact, Scan
from app.ops.audit import record_audit_event
from app.ops.rate_limits import enforce_api_rate_limit
from app.reports.service import (
    ReportGenerationError,
    generate_report_artifacts,
    read_report_artifact,
    validate_report_artifact_read_eligibility,
)
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["reports"])


@router.post("/scans/{scan_id}/reports", response_model=CursorPage[ReportArtifactRead], status_code=status.HTTP_201_CREATED)
def generate_reports(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[ReportArtifactRead]:
    enforce_api_rate_limit(
        db,
        principal,
        action="report_generation",
        max_requests=settings.report_generation_rate_limit_max_requests,
        window_seconds=settings.api_rate_limit_window_seconds,
    )
    require_workspace_scan(db, scan_id, principal)
    try:
        artifacts = generate_report_artifacts(
            db,
            scan_id=scan_id,
            workspace_id=principal.workspace_id,
            artifact_root=settings.artifact_root,
        )
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    record_audit_event(
        db,
        principal,
        event_type="report.generated",
        resource_type="scan",
        resource_id=scan_id,
        metadata={"artifact_count": len(artifacts)},
    )
    db.commit()
    return CursorPage(items=[to_report_read(artifact) for artifact in artifacts], next_cursor=None)


@router.get("/scans/{scan_id}/reports", response_model=CursorPage[ReportArtifactRead])
def list_reports(
    scan_id: str,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[ReportArtifactRead]:
    scan = require_workspace_scan(db, scan_id, principal)
    try:
        validate_report_artifact_read_eligibility(scan)
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    statement = select(ReportArtifact).where(
        ReportArtifact.scan_id == scan_id,
        ReportArtifact.workspace_id == principal.workspace_id,
    )
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                ReportArtifact.created_at < page.cursor_created_at,
                and_(ReportArtifact.created_at == page.cursor_created_at, ReportArtifact.id < page.cursor_id),
            )
        )
    artifacts = list(db.scalars(statement.order_by(ReportArtifact.created_at.desc(), ReportArtifact.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(artifacts, page.limit)
    return CursorPage(items=[to_report_read(artifact) for artifact in visible], next_cursor=next_cursor)


@router.get("/reports/{report_id}")
def view_report(
    report_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Response:
    artifact = db.scalar(
        select(ReportArtifact).where(ReportArtifact.id == report_id, ReportArtifact.workspace_id == principal.workspace_id)
    )
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    try:
        content = read_report_artifact(db, artifact, artifact_root=settings.artifact_root, workspace_id=principal.workspace_id)
    except ReportGenerationError as exc:
        raise report_error(exc) from exc
    media_type = "text/html; charset=utf-8" if artifact.report_type == "html" else "text/markdown; charset=utf-8"
    headers = {}
    if artifact.report_type == "html":
        headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> PlainTextResponse:
    artifact = db.scalar(
        select(ReportArtifact).where(ReportArtifact.id == report_id, ReportArtifact.workspace_id == principal.workspace_id)
    )
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
        view_url=f"/api/v1/reports/{artifact.id}",
        download_url=f"/api/v1/reports/{artifact.id}/download",
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
