import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from app.core.contracts import Confidence, Severity
from app.db.session import SessionLocal
from app.findings.redaction import EVIDENCE_SNIPPET_CAP, prepare_evidence_snippet, redact_text
from app.findings.schemas import EvidenceArtifactInput, NormalizedFindingInput
from app.findings.service import FindingPersistenceError, build_dedupe_key, persist_normalized_findings
from app.models import EvidenceArtifact, Finding, FindingOccurrenceState, FindingState, Scan, Target
from pydantic import ValidationError
from sqlalchemy import delete

from tests.fixtures.normalized_findings import GITLEAKS_FIXTURE, ZAP_FIXTURE


class FindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        with SessionLocal() as db:
            db.add(
                Target(
                    id=self.target_id,
                    allowlist_id="juice-shop",
                    name="OWASP Juice Shop",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            db.add(
                Scan(
                    id=self.scan_id,
                    target_id=self.target_id,
                    mode="passive",
                    status="completed",
                    current_step="normalizing_findings",
                    status_message="Ready for finding persistence tests.",
                    progress_percent=100,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            finding_ids = [row[0] for row in db.query(Finding.id).filter(Finding.scan_id == self.scan_id).all()]
            if finding_ids:
                db.execute(delete(FindingOccurrenceState).where(FindingOccurrenceState.finding_id.in_(finding_ids)))
            db.execute(delete(FindingState).where(FindingState.target_id == self.target_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(EvidenceArtifact).where(EvidenceArtifact.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_schema_validates_severity_and_confidence(self) -> None:
        finding = NormalizedFindingInput(
            title="Example finding",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            source_tool="zap",
        )
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.confidence.value, "high")

        with self.assertRaises(ValidationError):
            NormalizedFindingInput(
                title="Bad finding",
                severity="urgent",
                confidence="high",
                source_tool="zap",
            )

        with self.assertRaises(ValidationError):
            EvidenceArtifactInput(artifact_type="   ", path="   ")

    def test_redaction_and_evidence_cap_apply_before_persistence(self) -> None:
        evidence = "authorization: bearer super-secret-token\n" + ("A" * (EVIDENCE_SNIPPET_CAP + 100))
        redacted, applied = prepare_evidence_snippet(evidence)

        self.assertIsNotNone(redacted)
        self.assertTrue(applied)
        self.assertNotIn("super-secret-token", redacted)
        self.assertLessEqual(len(redacted.encode("utf-8")), EVIDENCE_SNIPPET_CAP)

    def test_redact_text_handles_cookie_and_secret_patterns(self) -> None:
        redacted, applied = redact_text("cookie: session=abc123\napi_key=secret-value")

        self.assertTrue(applied)
        self.assertIsNotNone(redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("secret-value", redacted)

    def test_dedupe_key_uses_source_location_title_and_cwe(self) -> None:
        finding = NormalizedFindingInput(
            title="  Missing  Content Security Policy ",
            severity="medium",
            confidence="high",
            affected_url="HTTP://juice-shop:3000/",
            source_tool="ZAP",
            cwe="CWE-693",
        )

        dedupe_key = build_dedupe_key(finding)

        self.assertEqual(dedupe_key, "zap|http://juice-shop:3000/|missing content security policy|cwe-693")

    def test_dedupe_key_is_bounded_for_long_valid_inputs(self) -> None:
        finding = NormalizedFindingInput(
            title="A" * 300,
            severity="medium",
            confidence="high",
            affected_url=f"http://juice-shop:3000/{'x' * 1800}",
            source_tool="zap",
            cwe="CWE-693",
        )

        dedupe_key = build_dedupe_key(finding)

        self.assertLessEqual(len(dedupe_key), 500)
        self.assertIn("hash:", dedupe_key)

    def test_persist_normalized_findings_stores_artifact_reference_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "scans" / self.scan_id / "raw.txt"
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            artifact_path.write_text("raw artifact", encoding="utf-8")

            finding_inputs = [
                NormalizedFindingInput(**ZAP_FIXTURE, raw_artifact=EvidenceArtifactInput(artifact_type="http_response", path=str(artifact_path))),
                NormalizedFindingInput(**GITLEAKS_FIXTURE),
            ]

            with SessionLocal() as db:
                persisted = persist_normalized_findings(
                    db,
                    scan_id=self.scan_id,
                    findings=finding_inputs,
                    artifact_root=temp_dir,
                )

            self.assertEqual(len(persisted), 2)
            self.assertEqual(persisted[0].scanner_rule_id, "10038")
            self.assertTrue(persisted[0].redaction_applied)
            self.assertIsNotNone(persisted[0].raw_artifact_ref)
            self.assertNotIn("abc123", persisted[0].evidence or "")
            self.assertLessEqual(len((persisted[0].evidence or "").encode("utf-8")), EVIDENCE_SNIPPET_CAP)
            self.assertNotIn("super-secret-key", persisted[1].evidence or "")
            self.assertEqual(persisted[1].scanner_rule_id, "generic-api-key")

            with SessionLocal() as db:
                occurrence_count = db.query(FindingOccurrenceState).filter(FindingOccurrenceState.finding_id.in_([item.id for item in persisted])).count()
                state_count = db.query(FindingState).filter(FindingState.target_id == self.target_id).count()
                self.assertEqual(occurrence_count, 2)
                self.assertEqual(state_count, 2)

    def test_artifact_path_must_stay_within_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            outside_path = Path(outside_dir) / "artifact.txt"
            outside_path.write_text("artifact", encoding="utf-8")

            with SessionLocal() as db, self.assertRaises(FindingPersistenceError):
                persist_normalized_findings(
                    db,
                    scan_id=self.scan_id,
                    findings=[
                        NormalizedFindingInput(
                            **ZAP_FIXTURE,
                            raw_artifact=EvidenceArtifactInput(artifact_type="http_response", path=str(outside_path)),
                        )
                    ],
                    artifact_root=temp_dir,
                )

    def test_persistence_rolls_back_artifacts_when_batch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            valid_artifact_path = Path(temp_dir) / "scans" / self.scan_id / "raw.txt"
            valid_artifact_path.parent.mkdir(parents=True, exist_ok=True)
            valid_artifact_path.write_text("raw artifact", encoding="utf-8")

            with SessionLocal() as db, self.assertRaises(FindingPersistenceError):
                persist_normalized_findings(
                    db,
                    scan_id=self.scan_id,
                    findings=[
                        NormalizedFindingInput(
                            **ZAP_FIXTURE,
                            raw_artifact=EvidenceArtifactInput(artifact_type="http_response", path=str(valid_artifact_path)),
                        ),
                        NormalizedFindingInput(
                            **GITLEAKS_FIXTURE,
                            raw_artifact=EvidenceArtifactInput(artifact_type="http_response", path="relative/path.txt"),
                        ),
                    ],
                    artifact_root=temp_dir,
                )

            with SessionLocal() as db:
                self.assertEqual(db.query(EvidenceArtifact).filter(EvidenceArtifact.scan_id == self.scan_id).count(), 0)
                self.assertEqual(db.query(Finding).filter(Finding.scan_id == self.scan_id).count(), 0)


if __name__ == "__main__":
    unittest.main()
