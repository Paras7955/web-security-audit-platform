from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import (
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
    sync_occurrence_state,
    tags_for_resource,
)
from app.models import Finding, FindingState, ReportArtifact, RiskScore, Scan, SuppressionRule, Tag, TagAssignment, Target
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["findings"])


@router.get("/scans/{scan_id}/findings", response_model=list[FindingRead])
def list_scan_findings(
    scan_id: str,
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
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[FindingRead]:
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
        lifecycle_status=lifecycle_status or status_filter,
        suppressed=suppressed,
        tag_id=tag_id,
        risk_min=risk_min,
        risk_max=risk_max,
    )


@router.get("/findings", response_model=list[FindingRead])
def list_findings(
    target_id: str | None = None,
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
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[FindingRead]:
    if target_id is not None and db.scalar(select(Target.id).where(Target.id == target_id, Target.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    return query_findings(
        db,
        principal,
        target_id=target_id,
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
    row = serialize_finding(db, finding, scan, principal.user_id)
    db.commit()
    return row


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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.workspace_id == principal.workspace_id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    scan = db.scalar(select(Scan).where(Scan.id == finding.scan_id, Scan.workspace_id == principal.workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    state = db.scalar(
        select(FindingState).where(
            FindingState.workspace_id == principal.workspace_id,
            FindingState.target_id == scan.target_id,
            FindingState.dedupe_key == finding.dedupe_key,
        )
    )
    if state is None:
        state = FindingState(
            id=str(uuid4()),
            workspace_id=principal.workspace_id,
            target_id=scan.target_id,
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
                Scan.target_id == scan.target_id,
                Finding.dedupe_key == finding.dedupe_key,
            )
        ).all()
    )
    for matching in matching_findings:
        matching_scan = db.get(Scan, matching.scan_id)
        if matching_scan is not None:
            sync_occurrence_state(db, matching, matching_scan, principal.user_id)

    db.commit()
    db.refresh(finding)
    row = serialize_finding(db, finding, scan, principal.user_id)
    db.commit()
    return row


@router.post("/suppressions", response_model=SuppressionRuleRead, status_code=status.HTTP_201_CREATED)
def create_suppression_rule(
    payload: SuppressionRuleCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> SuppressionRule:
    if db.scalar(select(Target.id).where(Target.id == payload.target_id, Target.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    rule = SuppressionRule(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        target_id=payload.target_id,
        dedupe_key=payload.dedupe_key.strip() if payload.dedupe_key else None,
        severity=payload.severity.strip().lower() if payload.severity else None,
        source_tool=payload.source_tool.strip() if payload.source_tool else None,
        reason=payload.reason.strip(),
        created_by_user_id=principal.user_id,
        expires_at=payload.expires_at,
    )
    db.add(rule)

    findings = list(
        db.scalars(
            select(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Finding.workspace_id == principal.workspace_id, Scan.target_id == payload.target_id)
        ).all()
    )
    for finding in findings:
        scan = db.get(Scan, finding.scan_id)
        if scan is not None:
            sync_occurrence_state(db, finding, scan, principal.user_id)

    db.commit()
    db.refresh(rule)
    return rule


@router.get("/suppressions", response_model=list[SuppressionRuleRead])
def list_suppression_rules(
    target_id: str | None = None,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[SuppressionRule]:
    statement = select(SuppressionRule).where(SuppressionRule.workspace_id == principal.workspace_id)
    if target_id is not None:
        statement = statement.where(SuppressionRule.target_id == target_id)
    return list(db.scalars(statement.order_by(SuppressionRule.created_at.desc())).all())


@router.post("/tags", response_model=TagRead, status_code=status.HTTP_201_CREATED)
def create_tag(
    payload: TagCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Tag:
    label = payload.label.strip()
    existing = db.scalar(select(Tag).where(Tag.workspace_id == principal.workspace_id, Tag.label == label))
    if existing is not None:
        return existing
    tag = Tag(id=str(uuid4()), workspace_id=principal.workspace_id, label=label, created_by_user_id=principal.user_id)
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return tag


@router.get("/tags", response_model=list[TagRead])
def list_tags(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[Tag]:
    return list(db.scalars(select(Tag).where(Tag.workspace_id == principal.workspace_id).order_by(Tag.label.asc())).all())


@router.post("/tags/assignments", response_model=TagAssignmentRead, status_code=status.HTTP_201_CREATED)
def create_tag_assignment(
    payload: TagAssignmentCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> TagAssignment:
    tag = db.scalar(select(Tag).where(Tag.id == payload.tag_id, Tag.workspace_id == principal.workspace_id))
    if tag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found.")
    try:
        resource_type = normalize_resource_type(payload.resource_type)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
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
    db.commit()
    db.refresh(assignment)
    return assignment


@router.get("/tags/assignments", response_model=list[TagAssignmentRead])
def list_tag_assignments(
    resource_type: str | None = None,
    resource_id: str | None = None,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[TagAssignment]:
    statement = select(TagAssignment).where(TagAssignment.workspace_id == principal.workspace_id)
    if resource_type is not None:
        try:
            statement = statement.where(TagAssignment.resource_type == normalize_resource_type(resource_type))
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if resource_id is not None:
        statement = statement.where(TagAssignment.resource_id == resource_id)
    return list(db.scalars(statement.order_by(TagAssignment.created_at.desc())).all())


def query_findings(
    db: Session,
    principal: AuthenticatedPrincipal,
    *,
    scan_id: str | None = None,
    target_id: str | None = None,
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
) -> list[FindingRead]:
    statement = (
        select(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Finding.scan_id == scan_id, Finding.workspace_id == principal.workspace_id)
        .order_by(Finding.severity.asc(), Finding.created_at.asc())
    )
    if scan_id is None:
        statement = select(Finding).join(Scan, Scan.id == Finding.scan_id).where(Finding.workspace_id == principal.workspace_id)
    if target_id is not None:
        statement = statement.where(Scan.target_id == target_id)
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
        statement = statement.where(Finding.source_tool == scanner)
    if owasp is not None:
        statement = statement.where(Finding.owasp_category == owasp)
    if cwe is not None:
        statement = statement.where(Finding.cwe == cwe)

    findings = list(db.scalars(statement.order_by(Finding.severity.asc(), Finding.created_at.asc())).all())
    rows: list[FindingRead] = []
    for finding in findings:
        scan = db.get(Scan, finding.scan_id)
        if scan is None:
            continue
        row = serialize_finding(db, finding, scan, principal.user_id)
        if lifecycle_status is not None and row.lifecycle_status != lifecycle_status:
            continue
        if suppressed is not None and row.suppressed is not suppressed:
            continue
        if tag_id is not None and not finding_has_tag(db, principal.workspace_id, scan.target_id, scan.id, tag_id):
            continue
        if not scan_risk_in_range(db, principal.workspace_id, scan.id, risk_min, risk_max):
            continue
        rows.append(row)
    db.commit()
    return rows


def serialize_finding(db: Session, finding: Finding, scan: Scan, user_id: str) -> FindingRead:
    occurrence = sync_occurrence_state(db, finding, scan, user_id)
    labels = sorted(
        {
            tag.label
            for tag in [
                *tags_for_resource(db, finding.workspace_id, "target", scan.target_id),
                *tags_for_resource(db, finding.workspace_id, "scan", scan.id),
            ]
        }
    )
    return FindingRead(
        id=finding.id,
        scan_id=finding.scan_id,
        target_id=scan.target_id,
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
        redaction_applied=finding.redaction_applied,
        raw_artifact_ref=finding.raw_artifact_ref,
        lifecycle_status=occurrence.lifecycle_status,
        suppressed=occurrence.suppressed,
        suppression_rule_id=occurrence.suppression_rule_id,
        tags=labels,
        created_at=finding.created_at,
    )


def ensure_resource_access(db: Session, workspace_id: str, resource_type: str, resource_id: str) -> None:
    if resource_type == "target":
        exists = db.scalar(select(Target.id).where(Target.id == resource_id, Target.workspace_id == workspace_id))
    elif resource_type == "scan":
        exists = db.scalar(select(Scan.id).where(Scan.id == resource_id, Scan.workspace_id == workspace_id))
    else:
        exists = db.scalar(select(ReportArtifact.id).where(ReportArtifact.id == resource_id, ReportArtifact.workspace_id == workspace_id))
    if exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag resource not found.")


def finding_has_tag(db: Session, workspace_id: str, target_id: str, scan_id: str, tag_id: str) -> bool:
    assignment = db.scalar(
        select(TagAssignment.id).where(
            TagAssignment.workspace_id == workspace_id,
            TagAssignment.tag_id == tag_id,
            TagAssignment.resource_type.in_(("target", "scan")),
            TagAssignment.resource_id.in_((target_id, scan_id)),
        )
    )
    return assignment is not None


def scan_risk_in_range(db: Session, workspace_id: str, scan_id: str, risk_min: int | None, risk_max: int | None) -> bool:
    if risk_min is None and risk_max is None:
        return True
    score = db.scalar(
        select(RiskScore.score)
        .where(RiskScore.workspace_id == workspace_id, RiskScore.scan_id == scan_id)
        .order_by(RiskScore.created_at.desc())
        .limit(1)
    )
    if score is None:
        return False
    if risk_min is not None and score < risk_min:
        return False
    return not (risk_max is not None and score > risk_max)
