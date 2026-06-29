import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.core.config import Settings
from app.db.session import SessionLocal
from app.main import app
from app.models import AuthIdentity, Finding, PlatformUser, ReportArtifact, Scan, Target, Workspace
from app.security.auth import AuthConfigurationError, ensure_user_workspace_identity, validate_auth_settings
from tests.helpers import DEV_AUTH_HEADERS, ensure_dev_principal


class AuthWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.other_user_id = str(uuid4())
        self.other_workspace_id = str(uuid4())
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.finding_id = str(uuid4())
        self.report_id = str(uuid4())
        with tempfile.TemporaryDirectory() as temp_dir:
            self.report_path = Path(temp_dir) / "report.md"
            self.report_path.write_text("other workspace report", encoding="utf-8")
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
                        workspace_id=self.other_workspace_id,
                        created_by_user_id=self.other_user_id,
                        allowlist_id="juice-shop",
                        name="Other Target",
                        base_url="http://juice-shop:3000/",
                        permission_confirmed=True,
                    )
                )
                db.add(
                    Scan(
                        id=self.scan_id,
                        workspace_id=self.other_workspace_id,
                        created_by_user_id=self.other_user_id,
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
                        workspace_id=self.other_workspace_id,
                        scan_id=self.scan_id,
                        title="Other workspace finding",
                        severity="high",
                        confidence="high",
                        affected_url="http://juice-shop:3000/",
                        evidence="Header was not present.",
                        source_tool="custom-passive",
                        scanner_rule_id="header:content-security-policy",
                        dedupe_key="other-workspace-finding",
                        redaction_applied=True,
                    )
                )
                db.add(
                    ReportArtifact(
                        id=self.report_id,
                        workspace_id=self.other_workspace_id,
                        created_by_user_id=self.other_user_id,
                        scan_id=self.scan_id,
                        report_type="markdown",
                        path=str(self.report_path),
                    )
                )
                db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(ReportArtifact).where(ReportArtifact.id == self.report_id))
            db.execute(delete(Finding).where(Finding.id == self.finding_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.execute(delete(AuthIdentity).where(AuthIdentity.user_id == self.other_user_id))
            db.execute(delete(Workspace).where(Workspace.id == self.other_workspace_id))
            db.execute(delete(PlatformUser).where(PlatformUser.id == self.other_user_id))
            db.commit()

    def test_protected_routes_reject_missing_bearer_token(self) -> None:
        response = self.client.get("/targets")

        self.assertEqual(response.status_code, 401)
        self.assertIn("Bearer", response.json()["detail"])

    def test_workspace_scoped_routes_hide_other_workspace_records(self) -> None:
        routes = [
            ("get", f"/targets/{self.target_id}"),
            ("patch", f"/targets/{self.target_id}/repo-path"),
            ("post", "/scans"),
            ("get", f"/scans/{self.scan_id}"),
            ("get", f"/scans/{self.scan_id}/findings"),
            ("get", f"/findings/{self.finding_id}"),
            ("post", f"/scans/{self.scan_id}/reports"),
            ("get", f"/scans/{self.scan_id}/reports"),
            ("get", f"/reports/{self.report_id}"),
            ("get", f"/reports/{self.report_id}/download"),
            ("get", f"/scans/{self.scan_id}/ai-explanations"),
        ]

        for method, path in routes:
            if method == "patch":
                response = self.client.patch(path, json={"repo_path": None}, headers=DEV_AUTH_HEADERS)
            elif method == "post" and path == "/scans":
                response = self.client.post(path, json={"target_id": self.target_id, "mode": "passive"}, headers=DEV_AUTH_HEADERS)
            elif method == "post":
                response = self.client.post(path, headers=DEV_AUTH_HEADERS)
            else:
                response = self.client.get(path, headers=DEV_AUTH_HEADERS)
            self.assertEqual(response.status_code, 404, path)

        targets = self.client.get("/targets", headers=DEV_AUTH_HEADERS)
        scans = self.client.get("/scans", headers=DEV_AUTH_HEADERS)
        self.assertEqual(targets.status_code, 200)
        self.assertFalse(any(item["id"] == self.target_id for item in targets.json()))
        self.assertEqual(scans.status_code, 200)
        self.assertFalse(any(item["id"] == self.scan_id for item in scans.json()))

    def test_invalid_auth_configuration_fails_closed(self) -> None:
        invalid_configs = [
            Settings(app_env="production", auth_mode="dev", auth_provider="dev"),
            Settings(app_env="local", auth_mode="dev", auth_provider="dev", auth_oidc_issuer="https://issuer.example/"),
            Settings(app_env="local", auth_mode="required", auth_provider="dev"),
            Settings(app_env="local", auth_mode="required", auth_provider="auth0"),
        ]

        for config in invalid_configs:
            with self.assertRaises(AuthConfigurationError):
                validate_auth_settings(config)

        validate_auth_settings(
            Settings(
                app_env="production",
                auth_mode="required",
                auth_provider="auth0",
                auth_oidc_issuer="https://tenant.example/",
                auth_oidc_audience="security-audit-api",
                auth_oidc_jwks_url="https://tenant.example/.well-known/jwks.json",
            )
        )


if __name__ == "__main__":
    unittest.main()
