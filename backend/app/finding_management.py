from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.models import Finding, FindingOccurrenceState, FindingState, Scan, SuppressionRule, Tag, TagAssignment
from app.security.sanitization import sanitize_text

LIFECYCLE_STATUSES = {"open", "confirmed", "in_progress", "resolved", "suppressed", "false_positive"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
RESOURCE_TYPES = {"target", "repository_asset", "scan", "report"}


def normalize_status(value: str) -> str:
    status = value.strip().lower()
    if status not in LIFECYCLE_STATUSES:
        raise ValueError("Unsupported lifecycle status.")
    return status


def normalize_resource_type(value: str) -> str:
    resource_type = value.strip().lower()
    if resource_type not in RESOURCE_TYPES:
        raise ValueError("Unsupported tag resource type.")
    return resource_type


def normalize_suppression_severity(value: str | None) -> str | None:
    if value is None:
        return None
    severity = value.strip().lower()
    if severity not in SEVERITIES:
        raise ValueError("Unsupported suppression severity.")
    return severity


def normalize_suppression_source_tool(value: str | None) -> str | None:
    if value is None:
        return None
    source_tool = (sanitize_text(value, maximum=100) or "").strip().lower()
    if not source_tool:
        raise ValueError("Suppression source tool must not be blank.")
    return source_tool


def scan_subject(scan: Scan) -> tuple[str | None, str | None]:
    if (scan.target_id is None) == (scan.repository_asset_id is None):
        raise RuntimeError("Scan must have exactly one authorized subject.")
    return scan.target_id, scan.repository_asset_id


def subject_filters(
    model: type[FindingState] | type[SuppressionRule],
    scan: Scan,
) -> tuple[ColumnElement[bool], ColumnElement[bool]]:
    target_id, repository_asset_id = scan_subject(scan)
    return model.target_id == target_id, model.repository_asset_id == repository_asset_id


def get_or_create_finding_state(db: Session, finding: Finding, scan: Scan, user_id: str) -> FindingState:
    target_id, repository_asset_id = scan_subject(scan)
    state = db.scalar(
        select(FindingState).where(
            FindingState.workspace_id == finding.workspace_id,
            *subject_filters(FindingState, scan),
            FindingState.dedupe_key == finding.dedupe_key,
        )
    )
    if state is not None:
        return state

    state = FindingState(
        id=str(uuid4()),
        workspace_id=finding.workspace_id,
        target_id=target_id,
        repository_asset_id=repository_asset_id,
        dedupe_key=finding.dedupe_key,
        lifecycle_status="open",
        updated_by_user_id=user_id,
    )
    db.add(state)
    db.flush()
    return state


def get_or_create_occurrence_state(db: Session, finding: Finding) -> FindingOccurrenceState:
    occurrence = db.scalar(
        select(FindingOccurrenceState).where(
            FindingOccurrenceState.finding_id == finding.id,
            FindingOccurrenceState.workspace_id == finding.workspace_id,
        )
    )
    if occurrence is not None:
        return occurrence

    occurrence = FindingOccurrenceState(
        id=str(uuid4()),
        workspace_id=finding.workspace_id,
        finding_id=finding.id,
        lifecycle_status="open",
        suppressed=False,
    )
    db.add(occurrence)
    db.flush()
    return occurrence


def initialize_finding_management_state(db: Session, finding: Finding, scan: Scan) -> FindingOccurrenceState:
    occurrence = sync_occurrence_state(db, finding, scan, scan.created_by_user_id)
    db.flush()
    return occurrence


def active_suppression_for_finding(db: Session, finding: Finding, scan: Scan) -> SuppressionRule | None:
    rules = list(
        db.scalars(
            select(SuppressionRule)
            .where(
                SuppressionRule.workspace_id == finding.workspace_id,
                *subject_filters(SuppressionRule, scan),
            )
            .order_by(SuppressionRule.created_at.desc())
        ).all()
    )
    for rule in rules:
        if not suppression_rule_is_active(rule):
            continue
        if rule.dedupe_key is not None and rule.dedupe_key != finding.dedupe_key:
            continue
        if rule.severity is not None and rule.severity != finding.severity:
            continue
        if rule.source_tool is not None and rule.source_tool != finding.source_tool.lower():
            continue
        return rule
    return None


def sync_occurrence_state(db: Session, finding: Finding, scan: Scan, user_id: str) -> FindingOccurrenceState:
    state = get_or_create_finding_state(db, finding, scan, user_id)
    occurrence = get_or_create_occurrence_state(db, finding)
    rule = active_suppression_for_finding(db, finding, scan)
    occurrence.suppressed = rule is not None
    occurrence.suppression_rule_id = rule.id if rule is not None else None
    occurrence.lifecycle_status = "suppressed" if rule is not None else state.lifecycle_status
    return occurrence


def occurrence_state_for_read(db: Session, finding: Finding, scan: Scan) -> FindingOccurrenceState | None:
    occurrence = db.scalar(
        select(FindingOccurrenceState).where(
            FindingOccurrenceState.finding_id == finding.id,
            FindingOccurrenceState.workspace_id == finding.workspace_id,
        )
    )
    if occurrence is not None:
        if occurrence.suppressed and occurrence.suppression_rule_id is not None:
            rule = db.scalar(
                select(SuppressionRule).where(
                    SuppressionRule.id == occurrence.suppression_rule_id,
                    SuppressionRule.workspace_id == finding.workspace_id,
                )
            )
            if rule is not None and not suppression_rule_is_active(rule):
                state = db.scalar(
                    select(FindingState).where(
                        FindingState.workspace_id == finding.workspace_id,
                        *subject_filters(FindingState, scan),
                        FindingState.dedupe_key == finding.dedupe_key,
                    )
                )
                return FindingOccurrenceState(
                    id=occurrence.id,
                    workspace_id=occurrence.workspace_id,
                    finding_id=occurrence.finding_id,
                    lifecycle_status=state.lifecycle_status if state is not None else "open",
                    suppressed=False,
                    suppression_rule_id=None,
                )
        return occurrence

    state = db.scalar(
        select(FindingState).where(
            FindingState.workspace_id == finding.workspace_id,
            *subject_filters(FindingState, scan),
            FindingState.dedupe_key == finding.dedupe_key,
        )
    )
    if state is None:
        return None
    return FindingOccurrenceState(
        id="",
        workspace_id=finding.workspace_id,
        finding_id=finding.id,
        lifecycle_status=state.lifecycle_status,
        suppressed=False,
        suppression_rule_id=None,
    )


def suppression_rule_is_active(rule: SuppressionRule) -> bool:
    if rule.revoked_at is not None:
        return False
    expires_at = rule.expires_at
    if expires_at is None:
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at > datetime.now(UTC)


def tags_for_resource(db: Session, workspace_id: str, resource_type: str, resource_id: str) -> list[Tag]:
    return list(
        db.scalars(
            select(Tag)
            .join(TagAssignment, TagAssignment.tag_id == Tag.id)
            .where(
                TagAssignment.workspace_id == workspace_id,
                TagAssignment.resource_type == resource_type,
                TagAssignment.resource_id == resource_id,
                Tag.workspace_id == workspace_id,
            )
            .order_by(Tag.label.asc())
        ).all()
    )
