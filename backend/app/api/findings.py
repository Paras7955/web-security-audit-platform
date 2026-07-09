from collections import defaultdict
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
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
    normalize_suppression_severity,
    normalize_suppression_source_tool,
    normalize_status,
    occurrence_state_for_read,
    suppression_rule_is_active,
    sync_occurrence_state,
    tags_for_resource,
)
from app.models import Finding, FindingOccurrenceState, FindingState, ReportArtifact, RiskScore, Scan, SuppressionRule, Tag, TagAssignment, Target
from app.ops.audit import record_audit_event
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
    created_after: datetime | None = None,
    created_before: datetime | None = None,
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
        created_after=created_after,
        created_before=created_before,
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

    record_audit_event(
        db,
        principal,
        event_type="finding.lifecycle_updated",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"target_id": scan.target_id, "dedupe_key": finding.dedupe_key, "lifecycle_status": lifecycle_status},
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
    if db.scalar(select(Target.id).where(Target.id == payload.target_id, Target.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    try:
        severity = normalize_suppression_severity(payload.severity)
        source_tool = normalize_suppression_source_tool(payload.source_tool)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    rule = SuppressionRule(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        target_id=payload.target_id,
        dedupe_key=payload.dedupe_key.strip() if payload.dedupe_key else None,
        severity=severity,
        source_tool=source_tool,
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

    record_audit_event(
        db,
        principal,
        event_type="suppression.created",
        resource_type="suppression",
        resource_id=rule.id,
        metadata={"target_id": payload.target_id, "dedupe_key": rule.dedupe_key, "severity": severity, "source_tool": source_tool},
    )
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
        statement = statement.where(func.lower(Finding.source_tool) == scanner.strip().lower())
    if owasp is not None:
        statement = statement.where(func.lower(Finding.owasp_category) == owasp.strip().lower())
    if cwe is not None:
        statement = statement.where(func.lower(Finding.cwe) == cwe.strip().lower())

    findings = list(db.scalars(statement.order_by(Finding.severity.asc(), Finding.created_at.asc())).all())
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
    target_ids = {scan.target_id for scan in scans_by_id.values()}
    tag_labels = tag_labels_by_resource(db, principal.workspace_id, target_ids, scan_ids)
    tagged_resource_ids = tagged_resources_for_filter(db, principal.workspace_id, tag_id) if tag_id is not None else set()
    risk_scores = latest_risk_scores_by_scan(db, principal.workspace_id, scan_ids) if risk_min is not None or risk_max is not None else {}
    occurrence_lookup = occurrence_display_lookup(db, principal.workspace_id, findings, scans_by_id, finding_ids)

    rows: list[FindingRead] = []
    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)
        if scan is None:
            continue
        row = serialize_finding(
            db,
            finding,
            scan,
            tags=sorted(tag_labels[("target", scan.target_id)] | tag_labels[("scan", scan.id)]),
            occurrence=occurrence_lookup.get(finding.id),
        )
        if lifecycle_status is not None and row.lifecycle_status != lifecycle_status:
            continue
        if suppressed is not None and row.suppressed is not suppressed:
            continue
        if tag_id is not None and ("target", scan.target_id) not in tagged_resource_ids and ("scan", scan.id) not in tagged_resource_ids:
            continue
        if not scan_risk_in_range(risk_scores, scan.id, risk_min, risk_max):
            continue
        rows.append(row)
    return rows


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
        lifecycle_status=occurrence.lifecycle_status if occurrence is not None else "open",
        suppressed=occurrence.suppressed if occurrence is not None else False,
        suppression_rule_id=occurrence.suppression_rule_id if occurrence is not None else None,
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


def scan_risk_in_range(scores_by_scan_id: dict[str, int], scan_id: str, risk_min: int | None, risk_max: int | None) -> bool:
    if risk_min is None and risk_max is None:
        return True
    score = scores_by_scan_id.get(scan_id)
    if score is None:
        return False
    if risk_min is not None and score < risk_min:
        return False
    return not (risk_max is not None and score > risk_max)


def tag_labels_by_resource(
    db: Session,
    workspace_id: str,
    target_ids: set[str],
    scan_ids: set[str],
) -> defaultdict[tuple[str, str], set[str]]:
    labels: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    resource_ids = target_ids | scan_ids
    if not resource_ids:
        return labels
    rows = db.execute(
        select(TagAssignment.resource_type, TagAssignment.resource_id, Tag.label)
        .join(Tag, Tag.id == TagAssignment.tag_id)
        .where(
            TagAssignment.workspace_id == workspace_id,
            TagAssignment.resource_type.in_(("target", "scan")),
            TagAssignment.resource_id.in_(resource_ids),
        )
    ).all()
    for resource_type, resource_id, label in rows:
        labels[(resource_type, resource_id)].add(label)
    return labels


def tagged_resources_for_filter(db: Session, workspace_id: str, tag_id: str) -> set[tuple[str, str]]:
    rows = db.execute(
        select(TagAssignment.resource_type, TagAssignment.resource_id).where(
            TagAssignment.workspace_id == workspace_id,
            TagAssignment.tag_id == tag_id,
            TagAssignment.resource_type.in_(("target", "scan")),
        )
    ).all()
    return {(resource_type, resource_id) for resource_type, resource_id in rows}


def latest_risk_scores_by_scan(db: Session, workspace_id: str, scan_ids: set[str]) -> dict[str, int]:
    if not scan_ids:
        return {}
    scores: dict[str, int] = {}
    rows = db.scalars(
        select(RiskScore)
        .where(RiskScore.workspace_id == workspace_id, RiskScore.scan_id.in_(scan_ids))
        .order_by(RiskScore.scan_id.asc(), RiskScore.created_at.desc())
    ).all()
    for score in rows:
        if score.scan_id is not None and score.scan_id not in scores:
            scores[score.scan_id] = score.score
    return scores


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
        for rule in db.scalars(select(SuppressionRule).where(SuppressionRule.id.in_(suppression_ids))).all()
    } if suppression_ids else {}
    state_keys = {
        (workspace_id, scans_by_id[finding.scan_id].target_id, finding.dedupe_key)
        for finding in findings
        if finding.scan_id in scans_by_id
    }
    states = {
        (state.workspace_id, state.target_id, state.dedupe_key): state
        for state in db.scalars(
            select(FindingState).where(
                FindingState.workspace_id == workspace_id,
                FindingState.target_id.in_({key[1] for key in state_keys}),
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
        state = states.get((workspace_id, scan.target_id, finding.dedupe_key))
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
