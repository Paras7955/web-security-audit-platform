import unittest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.db.session import SessionLocal
from app.main import app
from app.models import Finding, FindingOccurrenceState, FindingState, Scan, Target
from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class FindingsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.finding_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
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
                Scan(
                    id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    target_id=self.target_id,
                    mode="passive",
                    status="completed",
                    current_step="normalizing_findings",
                    status_message="Completed.",
                    progress_percent=100,
                )
            )
            db.commit()
            db.add(
                Finding(
                    id=self.finding_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    title="Missing Content Security Policy",
                    severity="low",
                    confidence="high",
                    affected_url="http://juice-shop:3000/",
                    evidence="Header was not present.",
                    source_tool="custom-passive",
                    scanner_rule_id="header:content-security-policy",
                    dedupe_key="custom-passive|http://juice-shop:3000/|missing content security policy|cwe-693",
                    cwe="CWE-693",
                    redaction_applied=False,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(FindingOccurrenceState).where(FindingOccurrenceState.finding_id == self.finding_id))
            db.execute(delete(FindingState).where(FindingState.target_id == self.target_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_list_scan_findings(self) -> None:
        response = self.client.get(f"/scans/{self.scan_id}/findings", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["id"], self.finding_id)
        self.assertEqual(body[0]["source_tool"], "custom-passive")

    def test_get_finding_detail(self) -> None:
        response = self.client.get(f"/findings/{self.finding_id}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scanner_rule_id"], "header:content-security-policy")

    def test_missing_scan_returns_404(self) -> None:
        response = self.client.get(f"/scans/{uuid4()}/findings", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 404)

    def test_missing_finding_returns_404(self) -> None:
        response = self.client.get(f"/findings/{uuid4()}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
