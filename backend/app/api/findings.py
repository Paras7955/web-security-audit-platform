from collections import defaultdict
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.pagination import PageRequest, page_items, page_request
from app.api.schemas import (
    CursorPage,
    FindingLifecycleUpdate,
    FindingRead,
    SuppressionRuleCreate,
    SuppressionRuleRead,
    TagAssignmentCreate,
    TagAssignmentRead,
    TagCreate,
    TagRead,
)
from app.finding_management import (
    normalize_resource_type,
    normalize_status,
    normalize_suppression_severity,
    normalize_suppression_source_tool,
    occurrence_state_for_read,
    scan_subject,
    subject_filters,
    suppression_rule_is_active,
    sync_occurrence_state,
    tags_for_resource,
)
from app.models import (
    Finding,
    FindingOccurrenceState,
    FindingState,
    ReportArtifact,
    RepositoryAsset,
    RiskScore,
    Scan,
    SuppressionRule,
    Tag,
    TagAssignment,
    Target,
)
from app.ops.audit import record_audit_event
from app.risk import SCORING_MODEL_VERSION
from app.security.auth import AuthenticatedPrincipal
from app.security.sanitization import sanitize_text

router = APIRouter(tags=["findings"])


@router.get("/scans/{scan_id}/findings", response_model=CursorPage[FindingRead])
def list_scan_findings(
    scan_id: str,
    severity: str | None = None,
    confidence: str | None = None,
    scanner: str | None = None,
    owasp: str | None = None,
    cwe: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    lifecycle_status: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    suppressed: bool | None = None,
    tag_id: str | None = None,
    risk_min: int | None = None,
    risk_max: int | None = None,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[FindingRead]:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    return query_findings(
        db,
        principal,
        scan_id=scan_id,
        severity=severity,
        confidence=confidence,
        scanner=scanner,
        owasp=owasp,
        cwe=cwe,
        created_after=created_after,
        created_before=created_before,
        lifecycle_status=lifecycle_status or status_filter,
        suppressed=suppressed,
        tag_id=tag_id,
        risk_min=risk_min,
        risk_max=risk_max,
        page=page,
    )


@router.get("/findings", response_model=CursorPage[FindingRead])
def list_findings(
    target_id: str | None = None,
    repository_asset_id: str | None = None,
    scan_profile_id: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    scanner: str | None = None,
    owasp: str | None = None,
    cwe: str | None = None,
    lifecycle_status: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    suppressed: bool | None = None,
    tag_id: str | None = None,
    risk_min: int | None = None,
    risk_max: int | None = None,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[FindingRead]:
    if target_id is not None and db.scalar(select(Target.id).where(Target.id == target_id, Target.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    if repository_asset_id is not None and db.scalar(
        select(RepositoryAsset.id).where(
            RepositoryAsset.id == repository_asset_id,
            RepositoryAsset.workspace_id == principal.workspace_id,
        )
    ) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository asset not found.")
    if target_id is not None and repository_asset_id is not None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Filter by only one subject.")

    return query_findings(
        db,
        principal,
        target_id=target_id,
        repository_asset_id=repository_asset_id,
        scan_profile_id=scan_profile_id,
        created_after=created_after,
        created_before=created_before,
        severity=severity,
        confidence=confidence,
        scanner=scanner,
        owasp=owasp,
        cwe=cwe,
        lifecycle_status=lifecycle_status or status_filter,
        suppressed=suppressed,
        tag_id=tag_id,
        risk_min=risk_min,
        risk_max=risk_max,
        page=page,
    )


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> FindingRead:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.workspace_id == principal.workspace_id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    scan = db.scalar(select(Scan).where(Scan.id == finding.scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return serialize_finding(db, finding, scan)


@router.patch("/findings/{finding_id}/lifecycle", response_model=FindingRead)
def update_finding_lifecycle(
    finding_id: str,
    payload: FindingLifecycleUpdate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> FindingRead:
    try:
        lifecycle_status = normalize_status(payload.lifecycle_status)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.workspace_id == principal.workspace_id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    scan = db.scalar(select(Scan).where(Scan.id == finding.scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    target_id, repository_asset_id = scan_subject(scan)
    state = db.scalar(
        select(FindingState).where(
            FindingState.workspace_id == principal.workspace_id,
            *subject_filters(FindingState, scan),
            FindingState.dedupe_key == finding.dedupe_key,
        )
    )
    if state is None:
        state = FindingState(
            id=str(uuid4()),
            workspace_id=principal.workspace_id,
            target_id=target_id,
            repository_asset_id=repository_asset_id,
            dedupe_key=finding.dedupe_key,
            updated_by_user_id=principal.user_id,
        )
        db.add(state)
    state.lifecycle_status = lifecycle_status
    state.updated_by_user_id = principal.user_id
    db.flush()

    matching_findings = list(
        db.scalars(
            select(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Finding.workspace_id == principal.workspace_id,
                Scan.workspace_id == principal.workspace_id,
                Scan.target_id == target_id,
                Scan.repository_asset_id == repository_asset_id,
                Finding.dedupe_key == finding.dedupe_key,
            )
        ).all()
    )
    for matching in matching_findings:
        matching_scan = db.scalar(
            select(Scan).where(Scan.id == matching.scan_id, Scan.workspace_id == principal.workspace_id)
        )
        if matching_scan is not None:
            sync_occurrence_state(db, matching, matching_scan, principal.user_id)

    record_audit_event(
        db,
        principal,
        event_type="finding.lifecycle_updated",
        resource_type="finding",
        resource_id=finding.id,
        metadata={
            "subject_type": "target" if target_id is not None else "repository_asset",
            "subject_id": target_id or repository_asset_id,
            "dedupe_key": finding.dedupe_key,
            "lifecycle_status": lifecycle_status,
        },
    )
    db.commit()
    db.refresh(finding)
    return serialize_finding(db, finding, scan)


@router.post("/suppressions", response_model=SuppressionRuleRead, status_code=status.HTTP_201_CREATED)
def create_suppression_rule(
    payload: SuppressionRuleCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> SuppressionRule:
    subject_type = "target" if payload.target_id is not None else "repository_asset"
    subject_id = payload.target_id or payload.repository_asset_id
    if subject_id is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Suppression subject is required.")
    ensure_resource_access(db, principal.workspace_id, subject_type, subject_id)
    try:
        severity = normalize_suppression_severity(payload.severity)
        source_tool = normalize_suppression_source_tool(payload.source_tool)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    rule = SuppressionRule(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        target_id=payload.target_id,
        repository_asset_id=payload.repository_asset_id,
        dedupe_key=sanitize_text(payload.dedupe_key, maximum=500),
        severity=severity,
        source_tool=source_tool,
        reason=(sanitize_text(payload.reason, maximum=2000) or "").strip() or "Suppression reason redacted.",
        created_by_user_id=principal.user_id,
        expires_at=payload.expires_at,
    )
    db.add(rule)
    db.flush()

    findings = list(
        db.scalars(
            select(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Finding.workspace_id == principal.workspace_id,
                Scan.workspace_id == principal.workspace_id,
                Scan.target_id == payload.target_id,
                Scan.repository_asset_id == payload.repository_asset_id,
            )
        ).all()
    )
    for finding in findings:
        scan = db.scalar(select(Scan).where(Scan.id == finding.scan_id, Scan.workspace_id == principal.workspace_id))
        if scan is not None:
            sync_occurrence_state(db, finding, scan, principal.user_id)

    record_audit_event(
        db,
        principal,
        event_type="suppression.created",
        resource_type="suppression",
        resource_id=rule.id,
        metadata={
            "subject_type": subject_type,
            "subject_id": subject_id,
            "dedupe_key": rule.dedupe_key,
            "severity": severity,
            "source_tool": source_tool,
        },
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/suppressions", response_model=CursorPage[SuppressionRuleRead])
def list_suppression_rules(
    target_id: str | None = None,
    repository_asset_id: str | None = None,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[SuppressionRuleRead]:
    if target_id is not None and repository_asset_id is not None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Filter by only one subject.")
    statement = select(SuppressionRule).where(SuppressionRule.workspace_id == principal.workspace_id)
    if target_id is not None:
        statement = statement.where(SuppressionRule.target_id == target_id)
    if repository_asset_id is not None:
        statement = statement.where(SuppressionRule.repository_asset_id == repository_asset_id)
    statement = apply_cursor(statement, SuppressionRule, page)
    rows = list(db.scalars(statement.order_by(SuppressionRule.created_at.desc(), SuppressionRule.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[SuppressionRuleRead.model_validate(rule) for rule in visible], next_cursor=next_cursor)


@router.post("/suppressions/{suppression_id}/revoke", response_model=SuppressionRuleRead)
def revoke_suppression_rule(
    suppression_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> SuppressionRule:
    rule = db.scalar(
        select(SuppressionRule)
        .where(
            SuppressionRule.id == suppression_id,
            SuppressionRule.workspace_id == principal.workspace_id,
        )
        .with_for_update()
    )
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression rule not found.")
    if rule.revoked_at is None:
        rule.revoked_at = datetime.now(UTC)
        rule.revoked_by_user_id = principal.user_id
        findings = list(
            db.scalars(
                select(Finding)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(
                    Finding.workspace_id == principal.workspace_id,
                    Scan.workspace_id == principal.workspace_id,
                    Scan.target_id == rule.target_id,
                    Scan.repository_asset_id == rule.repository_asset_id,
                )
            ).all()
        )
        for finding in findings:
            scan = db.scalar(
                select(Scan).where(Scan.id == finding.scan_id, Scan.workspace_id == principal.workspace_id)
            )
            if scan is not None:
                sync_occurrence_state(db, finding, scan, principal.user_id)
        record_audit_event(
            db,
            principal,
            event_type="suppression.revoked",
            resource_type="suppression",
            resource_id=rule.id,
            metadata={},
        )
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/tags", response_model=TagRead, status_code=status.HTTP_201_CREATED)
def create_tag(
    payload: TagCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Tag:
    label = (sanitize_text(payload.label, maximum=80) or "").strip() or "redacted-tag"
    existing = db.scalar(select(Tag).where(Tag.workspace_id == principal.workspace_id, Tag.label == label))
    if existing is not None:
        if existing.archived_at is not None:
            existing.archived_at = None
            existing.archived_by_user_id = None
            record_audit_event(
                db,
                principal,
                event_type="tag.restored",
                resource_type="tag",
                resource_id=existing.id,
                metadata={},
            )
            db.commit()
            db.refresh(existing)
        return existing
    tag = Tag(id=str(uuid4()), workspace_id=principal.workspace_id, label=label, created_by_user_id=principal.user_id)
    db.add(tag)
    record_audit_event(
        db,
        principal,
        event_type="tag.created",
        resource_type="tag",
        resource_id=tag.id,
        metadata={"label": label},
    )
    db.commit()
    db.refresh(tag)
    return tag


@router.get("/tags", response_model=CursorPage[TagRead])
def list_tags(
    include_archived: bool = False,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[TagRead]:
    statement = select(Tag).where(Tag.workspace_id == principal.workspace_id)
    if not include_archived:
        statement = statement.where(Tag.archived_at.is_(None))
    statement = apply_cursor(statement, Tag, page)
    rows = list(db.scalars(statement.order_by(Tag.created_at.desc(), Tag.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[TagRead.model_validate(tag) for tag in visible], next_cursor=next_cursor)


@router.post("/tags/{tag_id}/archive", response_model=TagRead)
def archive_tag(
    tag_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Tag:
    tag = db.scalar(
        select(Tag).where(Tag.id == tag_id, Tag.workspace_id == principal.workspace_id).with_for_update()
    )
    if tag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found.")
    if tag.archived_at is None:
        tag.archived_at = datetime.now(UTC)
        tag.archived_by_user_id = principal.user_id
        record_audit_event(
            db,
            principal,
            event_type="tag.archived",
            resource_type="tag",
            resource_id=tag.id,
            metadata={},
        )
    db.commit()
    db.refresh(tag)
    return tag


@router.post("/tags/assignments", response_model=TagAssignmentRead, status_code=status.HTTP_201_CREATED)
def create_tag_assignment(
    payload: TagAssignmentCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> TagAssignment:
    tag = db.scalar(select(Tag).where(Tag.id == payload.tag_id, Tag.workspace_id == principal.workspace_id))
    if tag is None or tag.archived_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found.")
    try:
        resource_type = normalize_resource_type(payload.resource_type)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    ensure_resource_access(db, principal.workspace_id, resource_type, payload.resource_id)

    existing = db.scalar(
        select(TagAssignment).where(
            TagAssignment.workspace_id == principal.workspace_id,
            TagAssignment.tag_id == tag.id,
            TagAssignment.resource_type == resource_type,
            TagAssignment.resource_id == payload.resource_id,
        )
    )
    if existing is not None:
        return existing
    assignment = TagAssignment(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        tag_id=tag.id,
        resource_type=resource_type,
        resource_id=payload.resource_id,
        created_by_user_id=principal.user_id,
    )
    db.add(assignment)
    record_audit_event(
        db,
        principal,
        event_type="tag.assigned",
        resource_type=resource_type,
        resource_id=payload.resource_id,
        metadata={"tag_id": tag.id},
    )
    db.commit()
    db.refresh(assignment)
    return assignment


@router.delete("/tags/assignments/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tag_assignment(
    assignment_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Response:
    assignment = db.scalar(
        select(TagAssignment)
        .where(
            TagAssignment.id == assignment_id,
            TagAssignment.workspace_id == principal.workspace_id,
        )
        .with_for_update()
    )
    if assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag assignment not found.")
    resource_type = assignment.resource_type
    resource_id = assignment.resource_id
    tag_id = assignment.tag_id
    db.delete(assignment)
    record_audit_event(
        db,
        principal,
        event_type="tag.unassigned",
        resource_type=resource_type,
        resource_id=resource_id,
        metadata={"tag_id": tag_id},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/tags/assignments", response_model=CursorPage[TagAssignmentRead])
def list_tag_assignments(
    resource_type: str | None = None,
    resource_id: str | None = None,
    page: PageRequest = Depends(page_request),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CursorPage[TagAssignmentRead]:
    statement = select(TagAssignment).where(TagAssignment.workspace_id == principal.workspace_id)
    if resource_type is not None:
        try:
            statement = statement.where(TagAssignment.resource_type == normalize_resource_type(resource_type))
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    if resource_id is not None:
        statement = statement.where(TagAssignment.resource_id == resource_id)
    statement = apply_cursor(statement, TagAssignment, page)
    rows = list(db.scalars(statement.order_by(TagAssignment.created_at.desc(), TagAssignment.id.desc()).limit(page.limit + 1)).all())
    visible, next_cursor = page_items(rows, page.limit)
    return CursorPage(items=[TagAssignmentRead.model_validate(assignment) for assignment in visible], next_cursor=next_cursor)


def query_findings(
    db: Session,
    principal: AuthenticatedPrincipal,
    *,
    scan_id: str | None = None,
    target_id: str | None = None,
    repository_asset_id: str | None = None,
    scan_profile_id: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    scanner: str | None = None,
    owasp: str | None = None,
    cwe: str | None = None,
    lifecycle_status: str | None = None,
    suppressed: bool | None = None,
    tag_id: str | None = None,
    risk_min: int | None = None,
    risk_max: int | None = None,
    page: PageRequest,
) -> CursorPage[FindingRead]:
    if lifecycle_status is not None:
        try:
            lifecycle_status = normalize_status(lifecycle_status)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    if risk_min is not None and not 0 <= risk_min <= 100:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="risk_min must be between 0 and 100.")
    if risk_max is not None and not 0 <= risk_max <= 100:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="risk_max must be between 0 and 100.")
    if risk_min is not None and risk_max is not None and risk_min > risk_max:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="risk_min must not exceed risk_max.")

    subject_state_join = and_(
        FindingState.workspace_id == principal.workspace_id,
        FindingState.dedupe_key == Finding.dedupe_key,
        or_(
            and_(
                Scan.target_id.is_not(None),
                FindingState.target_id == Scan.target_id,
                FindingState.repository_asset_id.is_(None),
            ),
            and_(
                Scan.repository_asset_id.is_not(None),
                FindingState.repository_asset_id == Scan.repository_asset_id,
                FindingState.target_id.is_(None),
            ),
        ),
    )
    statement = (
        select(Finding)
        .join(
            Scan,
            and_(
                Scan.id == Finding.scan_id,
                Scan.workspace_id == principal.workspace_id,
            ),
        )
        .outerjoin(
            FindingOccurrenceState,
            and_(
                FindingOccurrenceState.finding_id == Finding.id,
                FindingOccurrenceState.workspace_id == principal.workspace_id,
            ),
        )
        .outerjoin(FindingState, subject_state_join)
        .outerjoin(
            SuppressionRule,
            and_(
                SuppressionRule.id == FindingOccurrenceState.suppression_rule_id,
                SuppressionRule.workspace_id == principal.workspace_id,
            ),
        )
        .where(Finding.workspace_id == principal.workspace_id)
    )
    if scan_id is not None:
        statement = statement.where(Finding.scan_id == scan_id)
    if target_id is not None:
        statement = statement.where(Scan.target_id == target_id)
    if repository_asset_id is not None:
        statement = statement.where(Scan.repository_asset_id == repository_asset_id)
    if scan_profile_id is not None:
        statement = statement.where(Scan.scan_profile_id == scan_profile_id)
    if created_after is not None:
        statement = statement.where(Finding.created_at >= created_after)
    if created_before is not None:
        statement = statement.where(Finding.created_at <= created_before)
    if severity is not None:
        statement = statement.where(Finding.severity == severity)
    if confidence is not None:
        statement = statement.where(Finding.confidence == confidence)
    if scanner is not None:
        statement = statement.where(func.lower(Finding.source_tool) == scanner.strip().lower())
    if owasp is not None:
        statement = statement.where(func.lower(Finding.owasp_category) == owasp.strip().lower())
    if cwe is not None:
        statement = statement.where(func.lower(Finding.cwe) == cwe.strip().lower())

    active_suppression = and_(
        FindingOccurrenceState.suppressed.is_(True),
        SuppressionRule.id.is_not(None),
        SuppressionRule.revoked_at.is_(None),
        or_(SuppressionRule.expires_at.is_(None), SuppressionRule.expires_at > func.now()),
    )
    effective_suppressed = case((active_suppression, True), else_=False)
    effective_lifecycle = case(
        (active_suppression, "suppressed"),
        else_=func.coalesce(
            FindingState.lifecycle_status,
            FindingOccurrenceState.lifecycle_status,
            "open",
        ),
    )
    if lifecycle_status is not None:
        statement = statement.where(effective_lifecycle == lifecycle_status)
    if suppressed is not None:
        statement = statement.where(effective_suppressed == suppressed)
    if tag_id is not None:
        tag_match = (
            select(TagAssignment.id)
            .where(
                TagAssignment.workspace_id == principal.workspace_id,
                TagAssignment.tag_id == tag_id,
                or_(
                    and_(TagAssignment.resource_type == "scan", TagAssignment.resource_id == Scan.id),
                    and_(
                        TagAssignment.resource_type == "target",
                        Scan.target_id.is_not(None),
                        TagAssignment.resource_id == Scan.target_id,
                    ),
                    and_(
                        TagAssignment.resource_type == "repository_asset",
                        Scan.repository_asset_id.is_not(None),
                        TagAssignment.resource_id == Scan.repository_asset_id,
                    ),
                ),
            )
            .exists()
        )
        statement = statement.where(tag_match)
    if risk_min is not None or risk_max is not None:
        risk_filters = [
            RiskScore.workspace_id == principal.workspace_id,
            RiskScore.scan_id == Scan.id,
            RiskScore.scoring_model_version == SCORING_MODEL_VERSION,
        ]
        if risk_min is not None:
            risk_filters.append(RiskScore.score >= risk_min)
        if risk_max is not None:
            risk_filters.append(RiskScore.score <= risk_max)
        statement = statement.where(select(RiskScore.id).where(*risk_filters).exists())

    statement = apply_cursor(statement, Finding, page)
    findings_with_lookahead = list(
        db.scalars(statement.order_by(Finding.created_at.desc(), Finding.id.desc()).limit(page.limit + 1)).all()
    )
    findings_raw, next_cursor = page_items(findings_with_lookahead, page.limit)
    findings = list(findings_raw)
    scan_ids = {finding.scan_id for finding in findings}
    finding_ids = {finding.id for finding in findings}
    scans_by_id = {
        scan.id: scan
        for scan in db.scalars(
            select(Scan).where(
                Scan.workspace_id == principal.workspace_id,
                Scan.id.in_(scan_ids),
            )
        ).all()
    } if scan_ids else {}
    target_ids = {scan.target_id for scan in scans_by_id.values() if scan.target_id is not None}
    repository_asset_ids = {
        scan.repository_asset_id for scan in scans_by_id.values() if scan.repository_asset_id is not None
    }
    tag_labels = tag_labels_by_resource(
        db,
        principal.workspace_id,
        target_ids,
        repository_asset_ids,
        scan_ids,
    )
    occurrence_lookup = occurrence_display_lookup(db, principal.workspace_id, findings, scans_by_id, finding_ids)

    rows: list[FindingRead] = []
    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)
        if scan is None:
            continue
        scan_target_id, scan_repository_asset_id = scan_subject(scan)
        subject_tag_labels = (
            tag_labels[("target", scan_target_id)]
            if scan_target_id is not None
            else tag_labels[("repository_asset", scan_repository_asset_id or "")]
        )
        row = serialize_finding(
            db,
            finding,
            scan,
            tags=sorted(
                tag_labels[("scan", scan.id)]
                | subject_tag_labels
            ),
            occurrence=occurrence_lookup.get(finding.id),
        )
        rows.append(row)
    return CursorPage(items=rows, next_cursor=next_cursor)


def serialize_finding(
    db: Session,
    finding: Finding,
    scan: Scan,
    tags: list[str] | None = None,
    occurrence: FindingOccurrenceState | None = None,
) -> FindingRead:
    if occurrence is None:
        occurrence = occurrence_state_for_read(db, finding, scan)
    labels = tags
    if labels is None:
        subject_type = "target" if scan.target_id is not None else "repository_asset"
        subject_id = scan.target_id or scan.repository_asset_id
        labels = sorted(
            {
                tag.label
                for tag in [
                    *(
                        tags_for_resource(db, finding.workspace_id, subject_type, subject_id)
                        if subject_id is not None
                        else []
                    ),
                    *tags_for_resource(db, finding.workspace_id, "scan", scan.id),
                ]
            }
        )
    return FindingRead(
        id=finding.id,
        scan_id=finding.scan_id,
        target_id=scan.target_id,
        repository_asset_id=scan.repository_asset_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        affected_url=finding.affected_url,
        affected_file=finding.affected_file,
        evidence=finding.evidence,
        source_tool=finding.source_tool,
        scanner_rule_id=finding.scanner_rule_id,
        dedupe_key=finding.dedupe_key,
        owasp_category=finding.owasp_category,
        cwe=finding.cwe,
        reproduction_steps=finding.reproduction_steps,
        remediation=finding.remediation,
        false_positive_notes=finding.false_positive_notes,
        lifecycle_status=occurrence.lifecycle_status if occurrence is not None else "open",
        suppressed=occurrence.suppressed if occurrence is not None else False,
        suppression_rule_id=occurrence.suppression_rule_id if occurrence is not None else None,
        tags=labels,
        created_at=finding.created_at,
    )


def apply_cursor(statement, model, page: PageRequest):
    if page.cursor_created_at is None or page.cursor_id is None:
        return statement
    return statement.where(
        or_(
            model.created_at < page.cursor_created_at,
            and_(model.created_at == page.cursor_created_at, model.id < page.cursor_id),
        )
    )


def ensure_resource_access(db: Session, workspace_id: str, resource_type: str, resource_id: str) -> None:
    if resource_type == "target":
        exists = db.scalar(select(Target.id).where(Target.id == resource_id, Target.workspace_id == workspace_id))
    elif resource_type == "repository_asset":
        exists = db.scalar(
            select(RepositoryAsset.id).where(
                RepositoryAsset.id == resource_id,
                RepositoryAsset.workspace_id == workspace_id,
            )
        )
    elif resource_type == "scan":
        exists = db.scalar(select(Scan.id).where(Scan.id == resource_id, Scan.workspace_id == workspace_id))
    else:
        exists = db.scalar(select(ReportArtifact.id).where(ReportArtifact.id == resource_id, ReportArtifact.workspace_id == workspace_id))
    if exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag resource not found.")


def tag_labels_by_resource(
    db: Session,
    workspace_id: str,
    target_ids: set[str],
    repository_asset_ids: set[str],
    scan_ids: set[str],
) -> defaultdict[tuple[str, str], set[str]]:
    labels: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    resource_ids = target_ids | repository_asset_ids | scan_ids
    if not resource_ids:
        return labels
    rows = db.execute(
        select(TagAssignment.resource_type, TagAssignment.resource_id, Tag.label)
        .join(Tag, Tag.id == TagAssignment.tag_id)
        .where(
            TagAssignment.workspace_id == workspace_id,
            TagAssignment.resource_type.in_(("target", "repository_asset", "scan")),
            TagAssignment.resource_id.in_(resource_ids),
        )
    ).all()
    for resource_type, resource_id, label in rows:
        labels[(resource_type, resource_id)].add(label)
    return labels


def occurrence_display_lookup(
    db: Session,
    workspace_id: str,
    findings: list[Finding],
    scans_by_id: dict[str, Scan],
    finding_ids: set[str],
) -> dict[str, FindingOccurrenceState]:
    if not finding_ids:
        return {}
    persisted = {
        occurrence.finding_id: occurrence
        for occurrence in db.scalars(
            select(FindingOccurrenceState).where(
                FindingOccurrenceState.workspace_id == workspace_id,
                FindingOccurrenceState.finding_id.in_(finding_ids),
            )
        ).all()
    }
    suppression_ids = {item.suppression_rule_id for item in persisted.values() if item.suppression_rule_id is not None}
    suppression_rules = {
        rule.id: rule
        for rule in db.scalars(
            select(SuppressionRule).where(
                SuppressionRule.workspace_id == workspace_id,
                SuppressionRule.id.in_(suppression_ids),
            )
        ).all()
    } if suppression_ids else {}
    state_keys = {
        (
            scans_by_id[finding.scan_id].target_id,
            scans_by_id[finding.scan_id].repository_asset_id,
            finding.dedupe_key,
        )
        for finding in findings
        if finding.scan_id in scans_by_id
    }
    states = {
        (state.target_id, state.repository_asset_id, state.dedupe_key): state
        for state in db.scalars(
            select(FindingState).where(
                FindingState.workspace_id == workspace_id,
                or_(
                    FindingState.target_id.in_({key[0] for key in state_keys if key[0] is not None}),
                    FindingState.repository_asset_id.in_(
                        {key[1] for key in state_keys if key[1] is not None}
                    ),
                ),
                FindingState.dedupe_key.in_({key[2] for key in state_keys}),
            )
        ).all()
    } if state_keys else {}

    display: dict[str, FindingOccurrenceState] = {}
    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)
        if scan is None:
            continue
        occurrence = persisted.get(finding.id)
        state = states.get((scan.target_id, scan.repository_asset_id, finding.dedupe_key))
        if occurrence is None:
            if state is None:
                continue
            display[finding.id] = FindingOccurrenceState(
                id="",
                workspace_id=workspace_id,
                finding_id=finding.id,
                lifecycle_status=state.lifecycle_status,
                suppressed=False,
                suppression_rule_id=None,
            )
            continue
        if occurrence.suppressed and occurrence.suppression_rule_id is not None:
            rule = suppression_rules.get(occurrence.suppression_rule_id)
            if rule is not None and not suppression_rule_is_active(rule):
                display[finding.id] = FindingOccurrenceState(
                    id=occurrence.id,
                    workspace_id=occurrence.workspace_id,
                    finding_id=occurrence.finding_id,
                    lifecycle_status=state.lifecycle_status if state is not None else "open",
                    suppressed=False,
                    suppression_rule_id=None,
                )
                continue
        display[finding.id] = occurrence
    return display
