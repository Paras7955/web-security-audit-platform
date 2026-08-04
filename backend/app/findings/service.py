import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.finding_management import initialize_finding_management_state
from app.findings.redaction import prepare_evidence_snippet
from app.findings.schemas import NormalizedFindingInput
from app.models import Finding, Scan
from app.security.sanitization import sanitize_relative_path, sanitize_text, sanitize_url

MAX_DEDUPE_KEY_LENGTH = 500


class FindingPersistenceError(ValueError):
    pass


def persist_normalized_findings(
    db: Session,
    *,
    workspace_id: str,
    scan_id: str,
    findings: list[NormalizedFindingInput],
) -> list[Finding]:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    if scan is None:
        raise FindingPersistenceError("scan not found")

    persisted: list[Finding] = []
    try:
        for finding_input in findings:
            evidence, _ = prepare_evidence_snippet(finding_input.evidence)
            reproduction_steps = sanitize_text(finding_input.reproduction_steps, maximum=16_384)
            remediation = sanitize_text(finding_input.remediation, maximum=16_384)
            false_positive_notes = sanitize_text(finding_input.false_positive_notes, maximum=16_384)
            title = sanitize_text(finding_input.title, maximum=300) or "Scanner finding"
            source_tool = sanitize_text(finding_input.source_tool, maximum=100) or "unknown"
            scanner_rule_id = sanitize_text(finding_input.scanner_rule_id, maximum=200)
            owasp_category = sanitize_text(finding_input.owasp_category, maximum=100)
            cwe = sanitize_text(finding_input.cwe, maximum=100)
            affected_url = sanitize_url(finding_input.affected_url)
            affected_file = sanitize_relative_path(finding_input.affected_file)
            safe_input = finding_input.model_copy(
                update={
                    "title": title,
                    "source_tool": source_tool,
                    "scanner_rule_id": scanner_rule_id,
                    "owasp_category": owasp_category,
                    "cwe": cwe,
                    "affected_url": affected_url,
                    "affected_file": affected_file,
                }
            )
            finding = Finding(
                id=str(uuid4()),
                workspace_id=scan.workspace_id,
                scan_id=scan_id,
                title=title,
                severity=finding_input.severity.value,
                confidence=finding_input.confidence.value,
                affected_url=affected_url,
                affected_file=affected_file,
                evidence=evidence,
                source_tool=source_tool,
                scanner_rule_id=scanner_rule_id,
                dedupe_key=(sanitize_text(finding_input.dedupe_key, maximum=MAX_DEDUPE_KEY_LENGTH) or build_dedupe_key(safe_input)),
                owasp_category=owasp_category,
                cwe=cwe,
                reproduction_steps=reproduction_steps,
                remediation=remediation,
                false_positive_notes=false_positive_notes,
                # This flag records that ScopeHarbor's own boundary ran. A
                # scanner-provided claim is deliberately ignored.
                redaction_applied=True,
            )
            db.add(finding)
            db.flush()
            initialize_finding_management_state(db, finding, scan)
            persisted.append(finding)

        db.commit()
    except Exception:
        db.rollback()
        raise

    for finding in persisted:
        db.refresh(finding)
    return persisted


def build_dedupe_key(finding: NormalizedFindingInput) -> str:
    location = finding.affected_url or finding.affected_file or "global"
    normalized_title = " ".join(finding.title.lower().split())
    cwe = (finding.cwe or "uncategorized").lower()
    raw_key = "|".join(
        [
            finding.source_tool.lower(),
            location.lower(),
            normalized_title,
            cwe,
        ]
    )
    if len(raw_key) <= MAX_DEDUPE_KEY_LENGTH:
        return raw_key

    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    source_tool = finding.source_tool.lower()[:40]
    cwe_segment = cwe[:60]
    return f"{source_tool}|hash:{digest}|{cwe_segment}"[:MAX_DEDUPE_KEY_LENGTH]
