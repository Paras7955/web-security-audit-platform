import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.contracts import ScanStatus, scan_profile_for_values
from app.models import AiExplanationCache, AiRequestLog, Finding, FindingOccurrenceState, FindingState, ReportArtifact, Scan, SuppressionRule
from app.risk import SCORING_MODEL_VERSION, calculate_scan_risk_score


SEVERITY_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}
CONFIDENCE_PRIORITY = {
    "confirmed": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}
EVIDENCE_PROVIDER_CAP = 1000
ELIGIBLE_SCAN_STATUSES = {
    ScanStatus.COMPLETED.value,
    ScanStatus.COMPLETED_WITH_WARNINGS.value,
}


class AiExplanationError(ValueError):
    pass


class AiRateLimitExceeded(AiExplanationError):
    pass


@dataclass(frozen=True)
class SafeFindingInput:
    id: str
    title: str
    severity: str
    confidence: str
    affected_url: str | None
    affected_file: str | None
    evidence: str | None
    source_tool: str
    scanner_rule_id: str | None
    owasp_category: str | None
    cwe: str | None
    reproduction_steps: str | None
    remediation: str | None
    redaction_applied: bool

    def location(self) -> str:
        return self.affected_url or self.affected_file or "global"

    def to_provider_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": self.location(),
            "evidence": self.evidence,
            "source_tool": self.source_tool,
            "scanner_rule_id": self.scanner_rule_id,
            "owasp_category": self.owasp_category,
            "cwe": self.cwe,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "redaction_applied": self.redaction_applied,
        }


@dataclass(frozen=True)
class FindingExplanation:
    finding_id: str
    priority: int
    summary: str
    why_it_matters: str
    recommended_action: str
    owasp_mapping: str
    limitations: str


@dataclass(frozen=True)
class ExplanationGroup:
    label: str
    count: int
    finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class AiExplanationResult:
    scan_id: str
    provider: str
    fallback_used: bool
    provider_error: str | None
    summary: str
    executive_summary: str
    risk_score_explanation: str
    scoring_model_version: str
    input_fingerprint: str | None
    cache_hit: bool
    groups: tuple[ExplanationGroup, ...]
    explanations: tuple[FindingExplanation, ...]


class AiProvider(Protocol):
    provider_name: str

    def explain(self, *, scan_id: str, findings: tuple[SafeFindingInput, ...]) -> AiExplanationResult:
        ...


class TemplateAiProvider:
    provider_name = "template"

    def explain(self, *, scan_id: str, findings: tuple[SafeFindingInput, ...]) -> AiExplanationResult:
        explanations = tuple(template_explanation(finding) for finding in prioritize_findings(findings))
        groups = build_groups(findings)
        return AiExplanationResult(
            scan_id=scan_id,
            provider=self.provider_name,
            fallback_used=False,
            provider_error=None,
            summary=build_summary(findings),
            executive_summary="",
            risk_score_explanation="",
            scoring_model_version=SCORING_MODEL_VERSION,
            input_fingerprint=None,
            cache_hit=False,
            groups=groups,
            explanations=explanations,
        )


class OpenAiProvider:
    provider_name = "openai"

    def __init__(self, *, api_key: str | None, model: str | None, timeout_seconds: float = 20.0) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def explain(self, *, scan_id: str, findings: tuple[SafeFindingInput, ...]) -> AiExplanationResult:
        if not self.api_key:
            raise AiExplanationError("OPENAI_API_KEY is required for AI_PROVIDER=openai.")
        if not self.model:
            raise AiExplanationError("OPENAI_MODEL is required for AI_PROVIDER=openai.")

        payload = {
            "model": self.model,
            "input": [
                {
                    "role": "system",
                    "content": (
                        "You explain existing defensive web security findings. "
                        "Use only the provided normalized, redacted finding data. "
                        "Do not invent vulnerabilities, affected assets, evidence, or scan coverage."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "scan_id": scan_id,
                            "findings": [finding.to_provider_dict() for finding in findings],
                            "required_json_shape": {
                                "summary": "string",
                                "explanations": [
                                    {
                                        "finding_id": "string",
                                        "summary": "string",
                                        "why_it_matters": "string",
                                        "recommended_action": "string",
                                        "owasp_mapping": "string",
                                        "limitations": "string",
                                    }
                                ],
                            },
                        },
                        sort_keys=True,
                    ),
                },
            ],
            "text": {"format": {"type": "json_object"}},
        }
        response = httpx.post(
            "https://api.openai.com/v1/responses",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return parse_openai_response(scan_id=scan_id, findings=findings, body=response.json(), provider_name=self.provider_name)


def generate_ai_explanations(
    db: Session,
    *,
    scan_id: str,
    workspace_id: str | None = None,
    user_id: str | None = None,
    action: str = "interactive_ai_explanations",
    provider_name: str,
    openai_api_key: str | None,
    openai_model: str | None,
    cache_enabled: bool | None = None,
    cache_context_version: str | None = None,
    rate_limit_window_seconds: int | None = None,
    rate_limit_max_requests: int | None = None,
) -> AiExplanationResult:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise AiExplanationError("Scan not found.")
    if workspace_id is not None and scan.workspace_id != workspace_id:
        raise AiExplanationError("Scan not found.")
    profile = scan_profile_for_values(scan.scan_profile_id, scan.mode)
    if profile is None or not profile.ai_enabled:
        raise AiExplanationError("AI explanations can only be generated for passive and Active Demo scans.")
    if scan.status not in ELIGIBLE_SCAN_STATUSES:
        raise AiExplanationError("AI explanations can only be generated for completed scans.")

    template_provider = TemplateAiProvider()
    provider = build_provider(provider_name=provider_name, openai_api_key=openai_api_key, openai_model=openai_model)
    normalized_action = normalize_action(action)
    model_label = openai_model or ""
    config_hash = ai_config_hash(provider_name=provider.provider_name, model=model_label)
    raw_findings = load_findings(db, scan_id=scan_id, workspace_id=scan.workspace_id)
    safe_findings = tuple(safe_finding_input(finding) for finding in raw_findings)
    fingerprint = build_ai_input_fingerprint(
        db,
        scan=scan,
        findings=raw_findings,
        safe_findings=safe_findings,
        cache_context_version=cache_context_version,
    )
    use_cache = settings.ai_cache_enabled if cache_enabled is None else cache_enabled
    if use_cache:
        cached = load_cached_explanation(
            db,
            scan=scan,
            action=normalized_action,
            provider=provider.provider_name,
            model=model_label,
            config_hash=config_hash,
            input_fingerprint=fingerprint,
        )
        if cached is not None:
            log_ai_request(
                db,
                workspace_id=scan.workspace_id,
                user_id=user_id,
                action=normalized_action,
                provider=provider.provider_name,
                model=model_label,
                config_hash=config_hash,
                input_fingerprint=fingerprint,
                cache_hit=True,
                allowed=True,
            )
            return replace_result_metadata(result_from_cache(cached.payload), input_fingerprint=fingerprint, cache_hit=True)

    max_requests = settings.ai_rate_limit_max_requests if rate_limit_max_requests is None else rate_limit_max_requests
    window_seconds = settings.ai_rate_limit_window_seconds if rate_limit_window_seconds is None else rate_limit_window_seconds
    if is_rate_limited(
        db,
        workspace_id=scan.workspace_id,
        user_id=user_id,
        action=normalized_action,
        provider=provider.provider_name,
        model=model_label,
        config_hash=config_hash,
        window_seconds=window_seconds,
        max_requests=max_requests,
    ):
        log_ai_request(
            db,
            workspace_id=scan.workspace_id,
            user_id=user_id,
            action=normalized_action,
            provider=provider.provider_name,
            model=model_label,
            config_hash=config_hash,
            input_fingerprint=fingerprint,
            cache_hit=False,
            allowed=False,
        )
        raise AiRateLimitExceeded("AI rate limit exceeded for this workspace and action.")

    try:
        result = provider.explain(scan_id=scan_id, findings=safe_findings)
    except Exception as exc:
        fallback = template_provider.explain(scan_id=scan_id, findings=safe_findings)
        result = AiExplanationResult(
            scan_id=fallback.scan_id,
            provider=fallback.provider,
            fallback_used=provider.provider_name != template_provider.provider_name,
            provider_error=str(exc),
            summary=fallback.summary,
            executive_summary=fallback.executive_summary,
            risk_score_explanation=fallback.risk_score_explanation,
            scoring_model_version=fallback.scoring_model_version,
            input_fingerprint=fallback.input_fingerprint,
            cache_hit=fallback.cache_hit,
            groups=fallback.groups,
            explanations=fallback.explanations,
        )
    result = enrich_result(result, scan=scan, findings=raw_findings, input_fingerprint=fingerprint, cache_hit=False)
    if use_cache:
        store_cached_explanation(
            db,
            scan=scan,
            user_id=user_id,
            action=normalized_action,
            provider=provider.provider_name,
            model=model_label,
            config_hash=config_hash,
            input_fingerprint=fingerprint,
            result=result,
        )
    log_ai_request(
        db,
        workspace_id=scan.workspace_id,
        user_id=user_id,
        action=normalized_action,
        provider=provider.provider_name,
        model=model_label,
        config_hash=config_hash,
        input_fingerprint=fingerprint,
        cache_hit=False,
        allowed=True,
    )
    return result


def build_provider(*, provider_name: str, openai_api_key: str | None, openai_model: str | None) -> AiProvider:
    normalized_provider = provider_name.strip().lower()
    if normalized_provider == "template":
        return TemplateAiProvider()
    if normalized_provider == "openai":
        return OpenAiProvider(api_key=openai_api_key, model=openai_model)
    raise AiExplanationError("AI_PROVIDER must be template or openai.")


def load_safe_findings(db: Session, *, scan_id: str, workspace_id: str) -> tuple[SafeFindingInput, ...]:
    return tuple(safe_finding_input(finding) for finding in load_findings(db, scan_id=scan_id, workspace_id=workspace_id))


def load_findings(db: Session, *, scan_id: str, workspace_id: str) -> list[Finding]:
    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.workspace_id == workspace_id)
        .order_by(Finding.created_at.asc())
    ).all()
    return list(findings)


def safe_finding_input(finding: Finding) -> SafeFindingInput:
    redaction_confirmed = bool(finding.redaction_applied)
    return SafeFindingInput(
        id=finding.id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        affected_url=sanitize_provider_url(finding.affected_url),
        affected_file=finding.affected_file,
        evidence=truncate_text(finding.evidence, EVIDENCE_PROVIDER_CAP) if redaction_confirmed else None,
        source_tool=finding.source_tool,
        scanner_rule_id=finding.scanner_rule_id,
        owasp_category=finding.owasp_category,
        cwe=finding.cwe,
        reproduction_steps=finding.reproduction_steps if redaction_confirmed else None,
        remediation=finding.remediation if redaction_confirmed else None,
        redaction_applied=redaction_confirmed,
    )


def prioritize_findings(findings: tuple[SafeFindingInput, ...]) -> tuple[SafeFindingInput, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                SEVERITY_PRIORITY.get(finding.severity, 0),
                CONFIDENCE_PRIORITY.get(finding.confidence, 0),
                finding.title.lower(),
            ),
            reverse=True,
        )
    )


def build_groups(findings: tuple[SafeFindingInput, ...]) -> tuple[ExplanationGroup, ...]:
    groups: list[ExplanationGroup] = []
    for severity in ("critical", "high", "medium", "low", "info"):
        ids = tuple(finding.id for finding in findings if finding.severity == severity)
        if ids:
            groups.append(ExplanationGroup(label=f"{severity} severity", count=len(ids), finding_ids=ids))
    return tuple(groups)


def build_summary(findings: tuple[SafeFindingInput, ...]) -> str:
    if not findings:
        return "No normalized findings were recorded for this scan."
    high_priority = [finding for finding in findings if finding.severity in {"critical", "high"}]
    if high_priority:
        return f"{len(findings)} normalized findings were recorded, including {len(high_priority)} high-priority finding(s)."
    return f"{len(findings)} normalized findings were recorded. Review medium and lower severity items for defense-in-depth improvements."


def template_explanation(finding: SafeFindingInput) -> FindingExplanation:
    priority = SEVERITY_PRIORITY.get(finding.severity, 0) * 10 + CONFIDENCE_PRIORITY.get(finding.confidence, 0)
    mapping = finding.owasp_category or finding.cwe or "not mapped"
    recommended_action = finding.remediation or default_remediation(finding)
    return FindingExplanation(
        finding_id=finding.id,
        priority=priority,
        summary=f"{finding.severity.title()} finding: {finding.title} at {finding.location()}.",
        why_it_matters=why_it_matters(finding),
        recommended_action=recommended_action,
        owasp_mapping=mapping,
        limitations="This explanation is based only on normalized, redacted scanner findings and does not add new vulnerability claims.",
    )


def why_it_matters(finding: SafeFindingInput) -> str:
    if finding.severity in {"critical", "high"}:
        return "This should be reviewed early because the scanner classified the impact as high priority."
    if finding.severity == "medium":
        return "This may weaken application defenses and should be reviewed with the affected component owner."
    return "This is useful for hardening and reducing security ambiguity, even if immediate exploitability is not established."


def default_remediation(finding: SafeFindingInput) -> str:
    if finding.cwe == "CWE-693":
        return "Review and apply the missing or weak protection mechanism for the affected response or component."
    if finding.owasp_category:
        return f"Review controls related to {finding.owasp_category} and validate the fix with a follow-up passive scan."
    return "Review the affected location, confirm the finding, apply the relevant secure configuration or code change, and rescan."


def parse_openai_response(
    *,
    scan_id: str,
    findings: tuple[SafeFindingInput, ...],
    body: dict[str, object],
    provider_name: str,
) -> AiExplanationResult:
    raw_text = body.get("output_text")
    if not isinstance(raw_text, str):
        raw_text = extract_response_text(body)
    parsed = json.loads(raw_text)
    if not isinstance(parsed, dict):
        raise AiExplanationError("OpenAI response was not a JSON object.")

    by_id = {finding.id: finding for finding in findings}
    explanations: list[FindingExplanation] = []
    raw_explanations = parsed.get("explanations", [])
    if not isinstance(raw_explanations, list):
        raise AiExplanationError("OpenAI response explanations must be a list.")
    for item in raw_explanations:
        if not isinstance(item, dict):
            continue
        finding_id = item.get("finding_id")
        if not isinstance(finding_id, str) or finding_id not in by_id:
            continue
        template = template_explanation(by_id[finding_id])
        explanations.append(
            FindingExplanation(
                finding_id=finding_id,
                priority=template.priority,
                summary=str(item.get("summary") or template.summary),
                why_it_matters=str(item.get("why_it_matters") or template.why_it_matters),
                recommended_action=str(item.get("recommended_action") or template.recommended_action),
                owasp_mapping=str(item.get("owasp_mapping") or template.owasp_mapping),
                limitations=str(item.get("limitations") or template.limitations),
            )
        )

    if len(explanations) != len(findings):
        explained_ids = {explanation.finding_id for explanation in explanations}
        explanations.extend(template_explanation(finding) for finding in findings if finding.id not in explained_ids)

    summary = parsed.get("summary")
    return AiExplanationResult(
        scan_id=scan_id,
        provider=provider_name,
        fallback_used=False,
        provider_error=None,
        summary=str(summary) if summary else build_summary(findings),
        executive_summary="",
        risk_score_explanation="",
        scoring_model_version=SCORING_MODEL_VERSION,
        input_fingerprint=None,
        cache_hit=False,
        groups=build_groups(findings),
        explanations=tuple(sorted(explanations, key=lambda explanation: explanation.priority, reverse=True)),
    )


def enrich_result(
    result: AiExplanationResult,
    *,
    scan: Scan,
    findings: list[Finding],
    input_fingerprint: str,
    cache_hit: bool,
) -> AiExplanationResult:
    calculated = calculate_scan_risk_score(scan, findings)
    return AiExplanationResult(
        scan_id=result.scan_id,
        provider=result.provider,
        fallback_used=result.fallback_used,
        provider_error=result.provider_error,
        summary=result.summary,
        executive_summary=build_executive_summary(findings, calculated.score, calculated.label),
        risk_score_explanation=build_risk_score_explanation(calculated.input_summary, calculated.score, calculated.label),
        scoring_model_version=calculated.scoring_model_version,
        input_fingerprint=input_fingerprint,
        cache_hit=cache_hit,
        groups=result.groups,
        explanations=result.explanations,
    )


def replace_result_metadata(result: AiExplanationResult, *, input_fingerprint: str, cache_hit: bool) -> AiExplanationResult:
    return AiExplanationResult(
        scan_id=result.scan_id,
        provider=result.provider,
        fallback_used=result.fallback_used,
        provider_error=result.provider_error,
        summary=result.summary,
        executive_summary=result.executive_summary,
        risk_score_explanation=result.risk_score_explanation,
        scoring_model_version=result.scoring_model_version,
        input_fingerprint=input_fingerprint,
        cache_hit=cache_hit,
        groups=result.groups,
        explanations=result.explanations,
    )


def build_executive_summary(findings: list[Finding], score: int, label: str) -> str:
    if not findings:
        return f"Risk is {score}/100 ({label}) with no normalized findings recorded for this scan."
    critical_high = sum(1 for finding in findings if finding.severity in {"critical", "high"})
    return f"Risk is {score}/100 ({label}) across {len(findings)} normalized finding(s), including {critical_high} critical/high item(s)."


def build_risk_score_explanation(input_summary: dict[str, object], score: int, label: str) -> str:
    severity_counts = input_summary.get("severity_counts")
    if not isinstance(severity_counts, dict):
        return f"The deterministic {SCORING_MODEL_VERSION} model produced {score}/100 ({label}) from normalized finding inputs."
    critical = int(severity_counts.get("critical", 0) or 0)
    high = int(severity_counts.get("high", 0) or 0)
    medium = int(severity_counts.get("medium", 0) or 0)
    return (
        f"The deterministic {SCORING_MODEL_VERSION} model produced {score}/100 ({label}) "
        f"from severity and confidence weights: {critical} critical, {high} high, and {medium} medium finding(s)."
    )


def build_ai_input_fingerprint(
    db: Session,
    *,
    scan: Scan,
    findings: list[Finding],
    safe_findings: tuple[SafeFindingInput, ...],
    cache_context_version: str | None,
) -> str:
    finding_ids = [finding.id for finding in findings]
    states = load_state_inputs(db, scan=scan, findings=findings, finding_ids=finding_ids)
    report_artifacts = db.scalars(
        select(ReportArtifact)
        .where(ReportArtifact.workspace_id == scan.workspace_id, ReportArtifact.scan_id == scan.id)
        .order_by(ReportArtifact.report_type.asc(), ReportArtifact.created_at.asc())
    ).all()
    risk = calculate_scan_risk_score(scan, findings)
    payload = {
        "version": "ai-input-v1",
        "scan": {
            "id": scan.id,
            "target_id": scan.target_id,
            "mode": scan.mode,
            "scan_profile_id": scan.scan_profile_id,
            "status": scan.status,
            "completed_at": iso_or_none(scan.completed_at),
        },
        "findings": [finding.to_provider_dict() for finding in safe_findings],
        "management_state": states,
        "risk": {
            "scoring_model_version": risk.scoring_model_version,
            "score": risk.score,
            "label": risk.label,
            "input_summary": risk.input_summary,
        },
        "reports": [
            {
                "id": artifact.id,
                "report_type": artifact.report_type,
                "path": artifact.path,
                "created_at": iso_or_none(artifact.created_at),
            }
            for artifact in report_artifacts
        ],
        "cache_context_version": cache_context_version,
    }
    return stable_hash(payload)


def load_state_inputs(db: Session, *, scan: Scan, findings: list[Finding], finding_ids: list[str]) -> dict[str, object]:
    dedupe_keys = sorted({finding.dedupe_key for finding in findings if finding.dedupe_key})
    finding_states = db.scalars(
        select(FindingState)
        .where(
            FindingState.workspace_id == scan.workspace_id,
            FindingState.target_id == scan.target_id,
            FindingState.dedupe_key.in_(dedupe_keys),
        )
        .order_by(FindingState.dedupe_key.asc())
    ).all() if dedupe_keys else []
    occurrence_states = db.scalars(
        select(FindingOccurrenceState)
        .where(FindingOccurrenceState.workspace_id == scan.workspace_id, FindingOccurrenceState.finding_id.in_(finding_ids))
        .order_by(FindingOccurrenceState.finding_id.asc())
    ).all() if finding_ids else []
    suppression_rules = db.scalars(
        select(SuppressionRule)
        .where(SuppressionRule.workspace_id == scan.workspace_id, SuppressionRule.target_id == scan.target_id)
        .order_by(SuppressionRule.created_at.asc(), SuppressionRule.id.asc())
    ).all()
    now = datetime.now(UTC)
    return {
        "finding_states": [
            {
                "dedupe_key": state.dedupe_key,
                "lifecycle_status": state.lifecycle_status,
                "updated_at": iso_or_none(state.updated_at),
            }
            for state in finding_states
        ],
        "occurrence_states": [
            {
                "finding_id": state.finding_id,
                "lifecycle_status": state.lifecycle_status,
                "suppressed": state.suppressed,
                "suppression_rule_id": state.suppression_rule_id,
                "updated_at": iso_or_none(state.updated_at),
            }
            for state in occurrence_states
        ],
        "suppression_rules": [
            {
                "id": rule.id,
                "dedupe_key": rule.dedupe_key,
                "severity": rule.severity,
                "source_tool": rule.source_tool,
                "expires_at": iso_or_none(rule.expires_at),
                "expired": is_expired(rule.expires_at, now),
                "created_at": iso_or_none(rule.created_at),
            }
            for rule in suppression_rules
        ],
    }


def load_cached_explanation(
    db: Session,
    *,
    scan: Scan,
    action: str,
    provider: str,
    model: str,
    config_hash: str,
    input_fingerprint: str,
) -> AiExplanationCache | None:
    return db.scalar(
        select(AiExplanationCache).where(
            AiExplanationCache.workspace_id == scan.workspace_id,
            AiExplanationCache.scan_id == scan.id,
            AiExplanationCache.action == action,
            AiExplanationCache.provider == provider,
            AiExplanationCache.model == model,
            AiExplanationCache.config_hash == config_hash,
            AiExplanationCache.input_fingerprint == input_fingerprint,
        )
    )


def store_cached_explanation(
    db: Session,
    *,
    scan: Scan,
    user_id: str | None,
    action: str,
    provider: str,
    model: str,
    config_hash: str,
    input_fingerprint: str,
    result: AiExplanationResult,
) -> None:
    cache = AiExplanationCache(
        id=str(uuid4()),
        workspace_id=scan.workspace_id,
        scan_id=scan.id,
        action=action,
        provider=provider,
        model=model,
        config_hash=config_hash,
        input_fingerprint=input_fingerprint,
        payload=result_to_payload(result),
        created_by_user_id=user_id,
    )
    db.add(cache)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()


def is_rate_limited(
    db: Session,
    *,
    workspace_id: str,
    user_id: str | None,
    action: str,
    provider: str,
    model: str,
    config_hash: str,
    window_seconds: int,
    max_requests: int,
) -> bool:
    if max_requests <= 0:
        return True
    if window_seconds <= 0:
        return False
    cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
    query = select(AiRequestLog).where(
        AiRequestLog.workspace_id == workspace_id,
        AiRequestLog.action == action,
        AiRequestLog.provider == provider,
        AiRequestLog.model == model,
        AiRequestLog.config_hash == config_hash,
        AiRequestLog.cache_hit.is_(False),
        AiRequestLog.allowed.is_(True),
        AiRequestLog.created_at >= cutoff,
    )
    if user_id is not None:
        query = query.where(AiRequestLog.user_id == user_id)
    return len(db.scalars(query).all()) >= max_requests


def log_ai_request(
    db: Session,
    *,
    workspace_id: str,
    user_id: str | None,
    action: str,
    provider: str,
    model: str,
    config_hash: str,
    input_fingerprint: str | None,
    cache_hit: bool,
    allowed: bool,
) -> None:
    db.add(
        AiRequestLog(
            id=str(uuid4()),
            workspace_id=workspace_id,
            user_id=user_id,
            action=action,
            provider=provider,
            model=model,
            config_hash=config_hash,
            input_fingerprint=input_fingerprint,
            cache_hit=cache_hit,
            allowed=allowed,
        )
    )
    db.commit()


def result_to_payload(result: AiExplanationResult) -> dict[str, object]:
    return {
        "scan_id": result.scan_id,
        "provider": result.provider,
        "fallback_used": result.fallback_used,
        "provider_error": result.provider_error,
        "summary": result.summary,
        "executive_summary": result.executive_summary,
        "risk_score_explanation": result.risk_score_explanation,
        "scoring_model_version": result.scoring_model_version,
        "input_fingerprint": result.input_fingerprint,
        "cache_hit": result.cache_hit,
        "groups": [
            {"label": group.label, "count": group.count, "finding_ids": list(group.finding_ids)}
            for group in result.groups
        ],
        "explanations": [
            {
                "finding_id": explanation.finding_id,
                "priority": explanation.priority,
                "summary": explanation.summary,
                "why_it_matters": explanation.why_it_matters,
                "recommended_action": explanation.recommended_action,
                "owasp_mapping": explanation.owasp_mapping,
                "limitations": explanation.limitations,
            }
            for explanation in result.explanations
        ],
    }


def result_from_cache(payload: dict[str, object]) -> AiExplanationResult:
    return AiExplanationResult(
        scan_id=str(payload["scan_id"]),
        provider=str(payload["provider"]),
        fallback_used=bool(payload["fallback_used"]),
        provider_error=payload.get("provider_error") if isinstance(payload.get("provider_error"), str) else None,
        summary=str(payload["summary"]),
        executive_summary=str(payload.get("executive_summary") or ""),
        risk_score_explanation=str(payload.get("risk_score_explanation") or ""),
        scoring_model_version=str(payload.get("scoring_model_version") or SCORING_MODEL_VERSION),
        input_fingerprint=payload.get("input_fingerprint") if isinstance(payload.get("input_fingerprint"), str) else None,
        cache_hit=bool(payload.get("cache_hit")),
        groups=tuple(
            ExplanationGroup(
                label=str(group.get("label")),
                count=int(group.get("count") or 0),
                finding_ids=tuple(str(finding_id) for finding_id in group.get("finding_ids", [])),
            )
            for group in payload.get("groups", [])
            if isinstance(group, dict)
        ),
        explanations=tuple(
            FindingExplanation(
                finding_id=str(explanation.get("finding_id")),
                priority=int(explanation.get("priority") or 0),
                summary=str(explanation.get("summary") or ""),
                why_it_matters=str(explanation.get("why_it_matters") or ""),
                recommended_action=str(explanation.get("recommended_action") or ""),
                owasp_mapping=str(explanation.get("owasp_mapping") or ""),
                limitations=str(explanation.get("limitations") or ""),
            )
            for explanation in payload.get("explanations", [])
            if isinstance(explanation, dict)
        ),
    )


def ai_config_hash(*, provider_name: str, model: str) -> str:
    return stable_hash({"provider": provider_name, "model": model})


def normalize_action(value: str) -> str:
    return value.strip().lower().replace(" ", "_")[:80] or "interactive_ai_explanations"


def stable_hash(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")).hexdigest()


def iso_or_none(value: object | None) -> str | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def is_expired(value: object | None, now: datetime) -> bool:
    if not isinstance(value, datetime):
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value <= now


def extract_response_text(body: dict[str, object]) -> str:
    output = body.get("output")
    if not isinstance(output, list):
        raise AiExplanationError("OpenAI response did not include output text.")
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for content_item in content:
            if isinstance(content_item, dict) and isinstance(content_item.get("text"), str):
                return content_item["text"]
    raise AiExplanationError("OpenAI response did not include output text.")


def truncate_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[: limit - 24] + "\n[TRUNCATED FOR AI INPUT]"


def sanitize_provider_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
