from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import CursorPage, RepositoryAssetCreate, RepositoryAssetRead
from app.core.config import settings
from app.core.contracts import ScanStatus
from app.models import RepositoryAsset, Scan
from app.ops.audit import record_audit_event
from app.repo_scanner.paths import RepoPathError, repo_path_for_storage
from app.security.auth import AuthenticatedPrincipal
from app.security.sanitization import sanitize_text

router = APIRouter(prefix="/repository-assets", tags=["repository-assets"])
TERMINAL_SCAN_STATUSES = {
    ScanStatus.COMPLETED.value,
    ScanStatus.COMPLETED_WITH_WARNINGS.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELLED.value,
}


@router.post("", response_model=RepositoryAssetRead, status_code=status.HTTP_201_CREATED)
def create_repository_asset(
    payload: RepositoryAssetCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> RepositoryAsset:
    if not payload.permission_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission confirmation is required before creating a repository asset.",
        )
    try:
        relative_path = repo_path_for_storage(payload.repo_path, repo_scan_root=settings.repo_scan_root)
    except RepoPathError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    existing = db.scalar(
        select(RepositoryAsset)
        .where(
            RepositoryAsset.workspace_id == principal.workspace_id,
            RepositoryAsset.relative_path == relative_path,
        )
        .with_for_update()
    )
    now = datetime.now(UTC)
    if existing is not None:
        if existing.archived_at is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Repository asset already exists.")
        existing.name = sanitize_text(payload.name, maximum=200) or "Repository"
        existing.permission_confirmed = True
        existing.authorization_confirmed_at = now
        existing.archived_at = None
        existing.archived_by_user_id = None
        asset = existing
        event_type = "repository_asset.restored"
    else:
        asset = RepositoryAsset(
            id=str(uuid4()),
            workspace_id=principal.workspace_id,
            created_by_user_id=principal.user_id,
            name=sanitize_text(payload.name, maximum=200) or "Repository",
            relative_path=relative_path,
            permission_confirmed=True,
            authorization_confirmed_at=now,
        )
        db.add(asset)
        event_type = "repository_asset.created"

    record_audit_event(
        db,
        principal,
        event_type=event_type,
        resource_type="repository_asset",
        resource_id=asset.id,
        metadata={"has_authorized_path": True},
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=CursorPage[RepositoryAssetRead])
def list_repository_assets(
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[RepositoryAssetRead]:
    statement = select(RepositoryAsset).where(
        RepositoryAsset.workspace_id == principal.workspace_id,
        RepositoryAsset.archived_at.is_(None),
    )
    if page.cursor_created_at is not None and page.cursor_id is not None:
        statement = statement.where(
            or_(
                RepositoryAsset.created_at < page.cursor_created_at,
                and_(
                    RepositoryAsset.created_at == page.cursor_created_at,
                    RepositoryAsset.id < page.cursor_id,
                ),
            )
        )
    rows = list(
        db.scalars(
            statement.order_by(RepositoryAsset.created_at.desc(), RepositoryAsset.id.desc()).limit(page.limit + 1)
        ).all()
    )
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(
        items=[RepositoryAssetRead.model_validate(asset) for asset in visible],
        next_cursor=next_cursor,
    )


@router.get("/{repository_asset_id}", response_model=RepositoryAssetRead)
def get_repository_asset(
    repository_asset_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> RepositoryAsset:
    asset = db.scalar(
        select(RepositoryAsset).where(
            RepositoryAsset.id == repository_asset_id,
            RepositoryAsset.workspace_id == principal.workspace_id,
            RepositoryAsset.archived_at.is_(None),
        )
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository asset not found.")
    return asset


@router.delete("/{repository_asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_repository_asset(
    repository_asset_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Response:
    asset = db.scalar(
        select(RepositoryAsset)
        .where(
            RepositoryAsset.id == repository_asset_id,
            RepositoryAsset.workspace_id == principal.workspace_id,
            RepositoryAsset.archived_at.is_(None),
        )
        .with_for_update()
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository asset not found.")
    active_scan_id = db.scalar(
        select(Scan.id).where(
            Scan.workspace_id == principal.workspace_id,
            Scan.repository_asset_id == asset.id,
            ~Scan.status.in_(TERMINAL_SCAN_STATUSES),
        )
    )
    if active_scan_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Repository asset cannot be archived while a scan is active.",
        )
    asset.archived_at = datetime.now(UTC)
    asset.archived_by_user_id = principal.user_id
    asset.permission_confirmed = False
    asset.authorization_confirmed_at = None
    record_audit_event(
        db,
        principal,
        event_type="repository_asset.archived",
        resource_type="repository_asset",
        resource_id=asset.id,
        metadata={},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
