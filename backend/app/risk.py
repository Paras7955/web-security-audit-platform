from collections import Counter
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.contracts import ScanStatus
from app.models import Finding, RiskScore, Scan


SCORING_MODEL_VERSION = "risk-v1"
COMPLETED_SCAN_STATUSES = {ScanStatus.COMPLETED.value, ScanStatus.COMPLETED_WITH_WARNINGS.value}

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 70,
    "medium": 35,
    "low": 15,
    "info": 5,
}
CONFIDENCE_MULTIPLIERS = {
    "confirmed": 1.0,
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
}
RISK_LABELS = (
    (75, "Critical"),
    (50, "High"),
    (20, "Moderate"),
    (0, "Low"),
)


@dataclass(frozen=True)
class CalculatedRiskScore:
    scoring_model_version: str
    score: int
    label: str
    input_summary: dict[str, object]


def calculate_scan_risk_score(scan: Scan, findings: list[Finding]) -> CalculatedRiskScore:
    severity_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    weighted_findings: list[dict[str, object]] = []
    weighted_total = 0.0

    for finding in dedupe_findings(findings):
        severity = normalize_bucket(finding.severity, "info")
        confidence = normalize_bucket(finding.confidence, "low")
        severity_counts[severity] += 1
        confidence_counts[confidence] += 1
        weighted_value = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["info"]) * CONFIDENCE_MULTIPLIERS.get(confidence, CONFIDENCE_MULTIPLIERS["low"])
        weighted_total += weighted_value
        weighted_findings.append(
            {
                "dedupe_key": finding.dedupe_key,
                "severity": severity,
                "confidence": confidence,
                "weighted_value": round(weighted_value, 2),
            }
        )

    score = min(100, int(round(weighted_total)))
    input_summary: dict[str, object] = {
        "finding_count": len(weighted_findings),
        "severity_counts": ordered_counts(severity_counts, SEVERITY_WEIGHTS.keys()),
        "confidence_counts": ordered_counts(confidence_counts, CONFIDENCE_MULTIPLIERS.keys()),
        "weighted_total": round(weighted_total, 2),
        "weighted_findings": weighted_findings,
        "scan_profile_id": scan.scan_profile_id,
        "mode": scan.mode,
        "lifecycle_adjustments": [],
        "suppression_adjustments": [],
    }
    return CalculatedRiskScore(
        scoring_model_version=SCORING_MODEL_VERSION,
        score=score,
        label=risk_label(score),
        input_summary=input_summary,
    )


def persist_scan_risk_score(db: Session, scan: Scan, findings: list[Finding]) -> RiskScore:
    calculated = calculate_scan_risk_score(scan, findings)
    existing = db.scalar(
        select(RiskScore).where(
            RiskScore.workspace_id == scan.workspace_id,
            RiskScore.target_id == scan.target_id,
            RiskScore.scan_id == scan.id,
            RiskScore.scoring_model_version == calculated.scoring_model_version,
        )
    )
    if existing is not None:
        return existing

    risk_score = RiskScore(
        id=str(uuid4()),
        workspace_id=scan.workspace_id,
        target_id=scan.target_id,
        scan_id=scan.id,
        scoring_model_version=calculated.scoring_model_version,
        score=calculated.score,
        label=calculated.label,
        input_summary=calculated.input_summary,
    )
    db.add(risk_score)
    db.commit()
    db.refresh(risk_score)
    return risk_score


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = finding.dedupe_key or finding.id
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def risk_label(score: int) -> str:
    for threshold, label in RISK_LABELS:
        if score >= threshold:
            return label
    return "Low"


def normalize_bucket(value: str | None, fallback: str) -> str:
    if value is None:
        return fallback
    return value.strip().lower() or fallback


def ordered_counts(counts: Counter[str], keys: object) -> dict[str, int]:
    ordered = {str(key): counts.get(str(key), 0) for key in keys}
    extras = sorted(key for key in counts if key not in ordered)
    for key in extras:
        ordered[key] = counts[key]
    return ordered
