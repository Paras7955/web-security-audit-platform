from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.db.session import SessionLocal
from app.findings.schemas import NormalizedFindingInput
from app.findings.service import persist_normalized_findings
from app.main import app
from app.models import (
    Finding,
    FindingOccurrenceState,
    FindingState,
    AuthIdentity,
    PlatformUser,
    RiskScore,
    Scan,
    SuppressionRule,
    Tag,
    TagAssignment,
    Target,
    Workspace,
)
from app.security.auth import ensure_user_workspace_identity
from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class FindingManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.previous_scan_id = str(uuid4())
        self.scan_ids = [self.previous_scan_id, self.scan_id]
        self.finding_id = str(uuid4())
        self.previous_finding_id = str(uuid4())
        self.finding_ids = [self.previous_finding_id, self.finding_id]
        self.dedupe_key = f"custom-passive|{self.target_id}|missing-csp|cwe-693"
        self.tag_label = f"release-blocker-{self.target_id[:8]}"
        self.tag_ids: list[str] = []
        self.other_workspace_id = str(uuid4())
        self.other_user_id = str(uuid4())
        self.other_target_id = str(uuid4())

        with SessionLocal() as db:
            ensure_dev_principal(db)
            ensure_user_workspace_identity(
                db,
                user_id=self.other_user_id,
                workspace_id=self.other_workspace_id,
                provider="test",
                provider_subject=self.other_user_id,
                display_name="Other User",
                workspace_name="Other Workspace",
            )
            db.add(
                Target(
                    id=self.target_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    allowlist_id="juice-shop",
                    name="OWASP Juice Shop",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            db.add(
                Target(
                    id=self.other_target_id,
                    workspace_id=self.other_workspace_id,
                    created_by_user_id=self.other_user_id,
                    allowlist_id="juice-shop",
                    name="Other Juice Shop",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            for scan_id in (self.previous_scan_id, self.scan_id):
                db.add(
                    Scan(
                        id=scan_id,
                        workspace_id=DEV_WORKSPACE_ID,
                        created_by_user_id=DEV_USER_ID,
                        target_id=self.target_id,
                        mode="passive",
                        scan_profile_id="passive-web",
                        status="completed",
                        current_step="normalizing_findings",
                        status_message="Completed.",
                        progress_percent=100,
                    )
                )
            db.commit()
            db.add(
                RiskScore(
                    id=str(uuid4()),
                    workspace_id=DEV_WORKSPACE_ID,
                    target_id=self.target_id,
                    scan_id=self.scan_id,
                    scoring_model_version="risk-v1",
                    score=24,
                    label="Moderate",
                    input_summary={"severity_counts": {"low": 1}},
                )
            )
            db.add(self.make_finding(self.previous_finding_id, self.previous_scan_id, self.dedupe_key))
            db.add(self.make_finding(self.finding_id, self.scan_id, self.dedupe_key))
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(TagAssignment).where(TagAssignment.resource_id.in_([self.target_id, self.other_target_id, *self.scan_ids])))
            db.execute(delete(Tag).where(Tag.id.in_(self.tag_ids)))
            db.execute(delete(FindingOccurrenceState).where(FindingOccurrenceState.finding_id.in_(self.finding_ids)))
            db.execute(delete(FindingState).where(FindingState.target_id.in_([self.target_id, self.other_target_id])))
            db.execute(delete(SuppressionRule).where(SuppressionRule.target_id.in_([self.target_id, self.other_target_id])))
            db.execute(delete(RiskScore).where(RiskScore.scan_id.in_(self.scan_ids)))
            db.execute(delete(Finding).where(Finding.id.in_(self.finding_ids)))
            db.execute(delete(Scan).where(Scan.id.in_(self.scan_ids)))
            db.execute(delete(Target).where(Target.id.in_([self.target_id, self.other_target_id])))
            db.execute(delete(Workspace).where(Workspace.id == self.other_workspace_id))
            db.execute(delete(AuthIdentity).where(AuthIdentity.user_id == self.other_user_id))
            db.execute(delete(PlatformUser).where(PlatformUser.id == self.other_user_id))
            db.commit()

    def test_lifecycle_transition_applies_to_target_dedupe_identity_without_rewriting_occurrences(self) -> None:
        response = self.client.patch(
            f"/api/v1/findings/{self.finding_id}/lifecycle",
            headers=DEV_AUTH_HEADERS,
            json={"lifecycle_status": "confirmed"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["lifecycle_status"], "confirmed")

        previous = self.client.get(f"/api/v1/findings/{self.previous_finding_id}", headers=DEV_AUTH_HEADERS)
        self.assertEqual(previous.status_code, 200)
        self.assertEqual(previous.json()["lifecycle_status"], "confirmed")

        with SessionLocal() as db:
            persisted = db.get(Finding, self.previous_finding_id)
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.title, "Missing Content Security Policy")
            self.assertEqual(persisted.evidence, "Header was not present.")

    def test_suppression_marks_later_detected_finding_without_preventing_detection(self) -> None:
        suppression = self.client.post(
            "/api/v1/suppressions",
            headers=DEV_AUTH_HEADERS,
            json={
                "target_id": self.target_id,
                "dedupe_key": self.dedupe_key,
                "reason": "Accepted demo risk.",
            },
        )
        self.assertEqual(suppression.status_code, 201)
        self.assertEqual(suppression.json()["created_by_user_id"], DEV_USER_ID)

        later_scan_id = str(uuid4())
        self.scan_ids.append(later_scan_id)
        with SessionLocal() as db:
            db.add(
                Scan(
                    id=later_scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    target_id=self.target_id,
                    mode="passive",
                    scan_profile_id="passive-web",
                    status="completed",
                    progress_percent=100,
                )
            )
            db.commit()
            with tempfile.TemporaryDirectory() as temp_dir:
                persisted = persist_normalized_findings(
                    db,
                    scan_id=later_scan_id,
                    findings=[
                        NormalizedFindingInput(
                            title="Missing Content Security Policy",
                            severity="low",
                            confidence="high",
                            affected_url="http://juice-shop:3000/",
                            evidence="Header was not present.",
                            source_tool="custom-passive",
                            scanner_rule_id="header:content-security-policy",
                            dedupe_key=self.dedupe_key,
                            owasp_category="A05:2021",
                            cwe="CWE-693",
                            redaction_applied=False,
                        )
                    ],
                    artifact_root=temp_dir,
                )
            later_finding_id = persisted[0].id
            self.finding_ids.append(later_finding_id)

        response = self.client.get(f"/api/v1/scans/{later_scan_id}/findings", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["id"], later_finding_id)
        self.assertTrue(response.json()["items"][0]["suppressed"])
        self.assertEqual(response.json()["items"][0]["lifecycle_status"], "suppressed")

        with SessionLocal() as db:
            self.assertIsNotNone(db.get(Finding, later_finding_id))

    def test_expired_suppression_rule_is_not_applied(self) -> None:
        response = self.client.post(
            "/api/v1/suppressions",
            headers=DEV_AUTH_HEADERS,
            json={
                "target_id": self.target_id,
                "dedupe_key": self.dedupe_key,
                "reason": "Expired exception.",
                "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            },
        )
        self.assertEqual(response.status_code, 201)

        finding = self.client.get(f"/api/v1/findings/{self.finding_id}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(finding.status_code, 200)
        self.assertFalse(finding.json()["suppressed"])
        self.assertEqual(finding.json()["lifecycle_status"], "open")

    def test_applied_suppression_stops_applying_after_expiration(self) -> None:
        response = self.client.post(
            "/api/v1/suppressions",
            headers=DEV_AUTH_HEADERS,
            json={
                "target_id": self.target_id,
                "dedupe_key": self.dedupe_key,
                "reason": "Temporary exception.",
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            },
        )
        self.assertEqual(response.status_code, 201)
        rule_id = response.json()["id"]

        suppressed = self.client.get(f"/api/v1/findings/{self.finding_id}", headers=DEV_AUTH_HEADERS)
        self.assertTrue(suppressed.json()["suppressed"])

        with SessionLocal() as db:
            rule = db.get(SuppressionRule, rule_id)
            self.assertIsNotNone(rule)
            rule.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        unsuppressed = self.client.get(f"/api/v1/findings/{self.finding_id}", headers=DEV_AUTH_HEADERS)
        self.assertEqual(unsuppressed.status_code, 200)
        self.assertFalse(unsuppressed.json()["suppressed"])
        self.assertEqual(unsuppressed.json()["lifecycle_status"], "open")

    def test_suppression_rejects_invalid_match_fields(self) -> None:
        invalid_severity = self.client.post(
            "/api/v1/suppressions",
            headers=DEV_AUTH_HEADERS,
            json={
                "target_id": self.target_id,
                "dedupe_key": self.dedupe_key,
                "severity": "urgent",
                "reason": "Bad match field.",
            },
        )
        self.assertEqual(invalid_severity.status_code, 422)

        invalid_source = self.client.post(
            "/api/v1/suppressions",
            headers=DEV_AUTH_HEADERS,
            json={
                "target_id": self.target_id,
                "dedupe_key": self.dedupe_key,
                "source_tool": "   ",
                "reason": "Bad match field.",
            },
        )
        self.assertEqual(invalid_source.status_code, 422)

    def test_tags_are_workspace_scoped_and_can_filter_findings(self) -> None:
        tag = self.client.post("/api/v1/tags", headers=DEV_AUTH_HEADERS, json={"label": self.tag_label})
        self.assertEqual(tag.status_code, 201)
        tag_id = tag.json()["id"]
        self.tag_ids.append(tag_id)

        assignment = self.client.post(
            "/api/v1/tags/assignments",
            headers=DEV_AUTH_HEADERS,
            json={"tag_id": tag_id, "resource_type": "target", "resource_id": self.target_id},
        )
        self.assertEqual(assignment.status_code, 201)

        filtered = self.client.get(f"/api/v1/findings?tag_id={tag_id}", headers=DEV_AUTH_HEADERS)
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual({item["id"] for item in filtered.json()["items"]}, {self.previous_finding_id, self.finding_id})
        self.assertEqual(filtered.json()["items"][0]["tags"], [self.tag_label])

        cross_workspace_assignment = self.client.post(
            "/api/v1/tags/assignments",
            headers=DEV_AUTH_HEADERS,
            json={"tag_id": tag_id, "resource_type": "target", "resource_id": self.other_target_id},
        )
        self.assertEqual(cross_workspace_assignment.status_code, 404)

    def test_workspace_finding_filters_include_scan_profile_risk_and_normalized_fields(self) -> None:
        response = self.client.get(
            (
                "/api/v1/findings"
                f"?target_id={self.target_id}"
                "&scan_profile_id=passive-web"
                "&severity=low"
                "&confidence=high"
                "&scanner=custom-passive"
                "&owasp=A05:2021"
                "&cwe=CWE-693"
                "&risk_min=20"
                "&risk_max=30"
            ),
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["id"] for item in response.json()["items"]], [self.finding_id])

    def make_finding(self, finding_id: str, scan_id: str, dedupe_key: str) -> Finding:
        return Finding(
            id=finding_id,
            workspace_id=DEV_WORKSPACE_ID,
            scan_id=scan_id,
            title="Missing Content Security Policy",
            severity="low",
            confidence="high",
            affected_url="http://juice-shop:3000/",
            evidence="Header was not present.",
            source_tool="custom-passive",
            scanner_rule_id="header:content-security-policy",
            dedupe_key=dedupe_key,
            owasp_category="A05:2021",
            cwe="CWE-693",
            redaction_applied=False,
        )


if __name__ == "__main__":
    unittest.main()
