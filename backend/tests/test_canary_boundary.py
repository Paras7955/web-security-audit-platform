import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.ai.service import generate_ai_explanations
from app.db.session import SessionLocal
from app.findings.schemas import NormalizedFindingInput
from app.findings.service import persist_normalized_findings
from app.main import app
from app.models import (
    AiExplanationCache,
    AiRequestLog,
    AuditLog,
    Finding,
    FindingOccurrenceState,
    FindingState,
    ReportArtifact,
    Scan,
    Target,
)
from app.ops.audit import record_audit_event
from app.reports.service import generate_report_artifacts, read_report_artifact_file
from app.security.auth import AuthenticatedPrincipal
from fastapi.testclient import TestClient
from sqlalchemy import delete

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class CanaryBoundaryTests(unittest.TestCase):
    CANARY = "raw-secret-token"

    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(
                Target(
                    id=self.target_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    allowlist_id="juice-shop",
                    name="Canary boundary target",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            db.flush()
            db.add(
                Scan(
                    id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    target_id=self.target_id,
                    mode="passive",
                    scan_profile_id="passive-web",
                    status="completed",
                    current_step="normalizing_findings",
                    status_message="Completed.",
                    progress_percent=100,
                    attempt_count=0,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            finding_ids = list(db.scalars(Finding.__table__.select().with_only_columns(Finding.id).where(Finding.scan_id == self.scan_id)).all())
            if finding_ids:
                db.execute(delete(FindingOccurrenceState).where(FindingOccurrenceState.finding_id.in_(finding_ids)))
            db.execute(delete(FindingState).where(FindingState.target_id == self.target_id))
            db.execute(delete(ReportArtifact).where(ReportArtifact.scan_id == self.scan_id))
            db.execute(delete(AiExplanationCache).where(AiExplanationCache.scan_id == self.scan_id))
            db.execute(delete(AiRequestLog).where(AiRequestLog.workspace_id == DEV_WORKSPACE_ID, AiRequestLog.input_fingerprint.is_not(None)))
            db.execute(delete(AuditLog).where(AuditLog.resource_id == self.scan_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_canary_never_crosses_persistence_report_ai_audit_artifact_or_api_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                findings = persist_normalized_findings(
                    db,
                    scan_id=self.scan_id,
                    findings=[
                        NormalizedFindingInput(
                            title=f"Sensitive callback {self.CANARY}",
                            severity="high",
                            confidence="high",
                            affected_url=f"http://user:{self.CANARY}@juice-shop:3000/callback?token={self.CANARY}#fragment",
                            evidence=f"authorization: bearer {self.CANARY}",
                            source_tool="custom-passive",
                            scanner_rule_id="canary-boundary",
                            dedupe_key=f"canary:{self.CANARY}",
                            reproduction_steps=f"Visit /callback?token={self.CANARY}",
                            remediation=f"Remove {self.CANARY}.",
                            false_positive_notes=f"Never log {self.CANARY}.",
                            redaction_applied=False,
                        )
                    ],
                    artifact_root=temp_dir,
                )
                finding_id = findings[0].id
                principal = AuthenticatedPrincipal(
                    user_id=DEV_USER_ID,
                    workspace_id=DEV_WORKSPACE_ID,
                    provider="dev",
                    provider_subject=DEV_USER_ID,
                )
                record_audit_event(
                    db,
                    principal,
                    event_type="canary.boundary",
                    resource_type="scan",
                    resource_id=self.scan_id,
                    metadata={"authorization": self.CANARY, "url": f"http://juice-shop:3000/?token={self.CANARY}"},
                )
                db.commit()
                generate_ai_explanations(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    user_id=DEV_USER_ID,
                    provider_name="template",
                    openai_api_key=None,
                    openai_model=None,
                )
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    user_id=DEV_USER_ID,
                    artifact_root=temp_dir,
                    ai_provider="template",
                )
                persisted = db.get(Finding, finding_id)
                caches = db.query(AiExplanationCache).filter(AiExplanationCache.scan_id == self.scan_id).all()
                audit = db.query(AuditLog).filter(AuditLog.resource_id == self.scan_id).one()

                self.assertNotIn(self.CANARY, str(persisted.__dict__))
                self.assertTrue(caches)
                self.assertNotIn(self.CANARY, json.dumps([cache.payload for cache in caches], sort_keys=True))
                self.assertNotIn(self.CANARY, json.dumps(audit.metadata_json, sort_keys=True))
                for artifact in artifacts:
                    self.assertNotIn(self.CANARY, read_report_artifact_file(artifact, artifact_root=temp_dir))
                for file_path in Path(temp_dir).rglob("*"):
                    if file_path.is_file():
                        self.assertNotIn(self.CANARY.encode(), file_path.read_bytes())

            with patch("app.api.reports.settings.artifact_root", temp_dir):
                finding_response = self.client.get(f"/api/v1/findings/{finding_id}", headers=DEV_AUTH_HEADERS)
                report_list = self.client.get(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)
                ai_response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)
            self.assertEqual(finding_response.status_code, 200)
            self.assertEqual(report_list.status_code, 200)
            self.assertEqual(ai_response.status_code, 200)
            self.assertNotIn(self.CANARY, finding_response.text)
            self.assertNotIn(self.CANARY, report_list.text)
            self.assertNotIn(self.CANARY, ai_response.text)


if __name__ == "__main__":
    unittest.main()
