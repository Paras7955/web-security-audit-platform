import hashlib
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.findings.redaction import prepare_evidence_snippet, redact_text
from app.findings.schemas import EvidenceArtifactInput, NormalizedFindingInput
from app.models import EvidenceArtifact, Finding, Scan


MAX_DEDUPE_KEY_LENGTH = 500


class FindingPersistenceError(ValueError):
    pass


def persist_normalized_findings(
    db: Session,
    *,
    scan_id: str,
    findings: list[NormalizedFindingInput],
    artifact_root: str | Path,
) -> list[Finding]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise FindingPersistenceError("scan not found")

    persisted: list[Finding] = []
    try:
        for finding_input in findings:
            raw_artifact = None
            if finding_input.raw_artifact is not None:
                raw_artifact = persist_evidence_artifact(
                    db,
                    scan=scan,
                    artifact=finding_input.raw_artifact,
                    artifact_root=artifact_root,
                )

            evidence, evidence_redacted = prepare_evidence_snippet(finding_input.evidence)
            reproduction_steps, reproduction_redacted = redact_text(finding_input.reproduction_steps)
            remediation, remediation_redacted = redact_text(finding_input.remediation)
            false_positive_notes, notes_redacted = redact_text(finding_input.false_positive_notes)
            finding = Finding(
                id=str(uuid4()),
                workspace_id=scan.workspace_id,
                scan_id=scan_id,
                title=finding_input.title,
                severity=finding_input.severity.value,
                confidence=finding_input.confidence.value,
                affected_url=finding_input.affected_url,
                affected_file=finding_input.affected_file,
                evidence=evidence,
                source_tool=finding_input.source_tool,
                scanner_rule_id=finding_input.scanner_rule_id,
                dedupe_key=finding_input.dedupe_key or build_dedupe_key(finding_input),
                owasp_category=finding_input.owasp_category,
                cwe=finding_input.cwe,
                reproduction_steps=reproduction_steps,
                remediation=remediation,
                false_positive_notes=false_positive_notes,
                redaction_applied=bool(
                    finding_input.redaction_applied
                    or evidence_redacted
                    or reproduction_redacted
                    or remediation_redacted
                    or notes_redacted
                ),
                raw_artifact_ref=raw_artifact.id if raw_artifact else None,
            )
            db.add(finding)
            persisted.append(finding)

        db.commit()
    except Exception:
        db.rollback()
        raise

    for finding in persisted:
        db.refresh(finding)
    return persisted


def persist_evidence_artifact(
    db: Session,
    *,
    scan: Scan,
    artifact: EvidenceArtifactInput,
    artifact_root: str | Path,
) -> EvidenceArtifact:
    path = validate_artifact_path(artifact.path, artifact_root)
    evidence_artifact = EvidenceArtifact(
        id=str(uuid4()),
        workspace_id=scan.workspace_id,
        created_by_user_id=scan.created_by_user_id,
        scan_id=scan.id,
        artifact_type=artifact.artifact_type,
        path=str(path),
        redaction_applied=artifact.redaction_applied,
    )
    db.add(evidence_artifact)
    return evidence_artifact


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


def validate_artifact_path(path: str, artifact_root: str | Path) -> Path:
    artifact_root_path = Path(artifact_root).resolve()
    candidate_path = Path(path)
    if not candidate_path.is_absolute():
        raise FindingPersistenceError("evidence artifact path must be absolute")
    candidate = candidate_path.resolve()
    if artifact_root_path != candidate and artifact_root_path not in candidate.parents:
        raise FindingPersistenceError("evidence artifact path must stay within artifact root")
    return candidate
