import json
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.contracts import ScanMode, ScanStatus
from app.models import Finding, Scan


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
AI_EXPLANATION_SCAN_MODES = {
    ScanMode.PASSIVE.value,
    ScanMode.ACTIVE_DEMO.value,
}


class AiExplanationError(ValueError):
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
    provider_name: str,
    openai_api_key: str | None,
    openai_model: str | None,
) -> AiExplanationResult:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise AiExplanationError("Scan not found.")
    if workspace_id is not None and scan.workspace_id != workspace_id:
        raise AiExplanationError("Scan not found.")
    if scan.mode not in AI_EXPLANATION_SCAN_MODES:
        raise AiExplanationError("AI explanations can only be generated for passive and Active Demo scans.")
    if scan.status not in ELIGIBLE_SCAN_STATUSES:
        raise AiExplanationError("AI explanations can only be generated for completed scans.")

    safe_findings = load_safe_findings(db, scan_id=scan_id, workspace_id=scan.workspace_id)
    template_provider = TemplateAiProvider()
    provider = build_provider(provider_name=provider_name, openai_api_key=openai_api_key, openai_model=openai_model)
    try:
        return provider.explain(scan_id=scan_id, findings=safe_findings)
    except Exception as exc:
        fallback = template_provider.explain(scan_id=scan_id, findings=safe_findings)
        return AiExplanationResult(
            scan_id=fallback.scan_id,
            provider=fallback.provider,
            fallback_used=provider.provider_name != template_provider.provider_name,
            provider_error=str(exc),
            summary=fallback.summary,
            groups=fallback.groups,
            explanations=fallback.explanations,
        )


def build_provider(*, provider_name: str, openai_api_key: str | None, openai_model: str | None) -> AiProvider:
    normalized_provider = provider_name.strip().lower()
    if normalized_provider == "template":
        return TemplateAiProvider()
    if normalized_provider == "openai":
        return OpenAiProvider(api_key=openai_api_key, model=openai_model)
    raise AiExplanationError("AI_PROVIDER must be template or openai.")


def load_safe_findings(db: Session, *, scan_id: str, workspace_id: str) -> tuple[SafeFindingInput, ...]:
    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.workspace_id == workspace_id)
        .order_by(Finding.created_at.asc())
    ).all()
    return tuple(safe_finding_input(finding) for finding in findings)


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
        groups=build_groups(findings),
        explanations=tuple(sorted(explanations, key=lambda explanation: explanation.priority, reverse=True)),
    )


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
