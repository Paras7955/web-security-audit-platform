from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.findings.redaction import prepare_evidence_snippet
from app.findings.schemas import EvidenceArtifactInput, NormalizedFindingInput
from app.models import EvidenceArtifact, Finding


class FindingPersistenceError(ValueError):
    pass


def persist_normalized_findings(
    db: Session,
    *,
    scan_id: str,
    findings: list[NormalizedFindingInput],
    artifact_root: str | Path,
) -> list[Finding]:
    persisted: list[Finding] = []
    for finding_input in findings:
        raw_artifact = None
        if finding_input.raw_artifact is not None:
            raw_artifact = persist_evidence_artifact(
                db,
                scan_id=scan_id,
                artifact=finding_input.raw_artifact,
                artifact_root=artifact_root,
            )

        evidence, evidence_redacted = prepare_evidence_snippet(finding_input.evidence)
        finding = Finding(
            id=str(uuid4()),
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
            reproduction_steps=finding_input.reproduction_steps,
            remediation=finding_input.remediation,
            false_positive_notes=finding_input.false_positive_notes,
            redaction_applied=bool(finding_input.redaction_applied or evidence_redacted),
            raw_artifact_ref=raw_artifact.id if raw_artifact else None,
        )
        db.add(finding)
        persisted.append(finding)

    db.commit()
    for finding in persisted:
        db.refresh(finding)
    return persisted


def persist_evidence_artifact(
    db: Session,
    *,
    scan_id: str,
    artifact: EvidenceArtifactInput,
    artifact_root: str | Path,
) -> EvidenceArtifact:
    path = validate_artifact_path(artifact.path, artifact_root)
    evidence_artifact = EvidenceArtifact(
        id=str(uuid4()),
        scan_id=scan_id,
        artifact_type=artifact.artifact_type,
        path=str(path),
        redaction_applied=artifact.redaction_applied,
    )
    db.add(evidence_artifact)
    db.commit()
    db.refresh(evidence_artifact)
    return evidence_artifact


def build_dedupe_key(finding: NormalizedFindingInput) -> str:
    location = finding.affected_url or finding.affected_file or "global"
    normalized_title = " ".join(finding.title.lower().split())
    cwe = (finding.cwe or "uncategorized").lower()
    return "|".join(
        [
            finding.source_tool.lower(),
            location.lower(),
            normalized_title,
            cwe,
        ]
    )


def validate_artifact_path(path: str, artifact_root: str | Path) -> Path:
    artifact_root_path = Path(artifact_root).resolve()
    candidate = Path(path).resolve()
    if artifact_root_path != candidate and artifact_root_path not in candidate.parents:
        raise FindingPersistenceError("evidence artifact path must stay within artifact root")
    return candidate
