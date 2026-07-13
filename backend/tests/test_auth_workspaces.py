import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.auth_profiles import LOCAL_DEV_EXAMPLE_SECRET_KEY, AuthProfileError, validate_auth_profile_secret_settings
from app.core.config import Settings
from app.db.session import SessionLocal
from app.main import app
from app.models import AuthIdentity, Finding, PlatformUser, ReportArtifact, Scan, Target, Workspace
from app.security.auth import (
    AuthConfigurationError,
    AuthError,
    authenticate_oidc_token,
    ensure_user_workspace_identity,
    provision_oidc_principal,
    validate_auth_settings,
)
from fastapi.testclient import TestClient
from jwt import MissingRequiredClaimError
from sqlalchemy import delete, select

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
        response = self.client.get("/api/v1/targets")

        self.assertEqual(response.status_code, 401)
        self.assertIn("Bearer", response.json()["detail"])

    def test_workspace_scoped_routes_hide_other_workspace_records(self) -> None:
        routes = [
            ("get", f"/api/v1/targets/{self.target_id}"),
            ("patch", f"/api/v1/targets/{self.target_id}/repo-path"),
            ("post", "/api/v1/scans"),
            ("get", f"/api/v1/scans/{self.scan_id}"),
            ("get", f"/api/v1/scans/{self.scan_id}/findings"),
            ("get", f"/api/v1/findings/{self.finding_id}"),
            ("post", f"/api/v1/scans/{self.scan_id}/reports"),
            ("get", f"/api/v1/scans/{self.scan_id}/reports"),
            ("get", f"/api/v1/reports/{self.report_id}"),
            ("get", f"/api/v1/reports/{self.report_id}/download"),
            ("get", f"/api/v1/scans/{self.scan_id}/ai-explanations"),
        ]

        for method, path in routes:
            if method == "patch":
                response = self.client.patch(path, json={"repo_path": None}, headers=DEV_AUTH_HEADERS)
            elif method == "post" and path == "/api/v1/scans":
                response = self.client.post(
                    path,
                    json={"target_id": self.target_id, "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
                    headers=DEV_AUTH_HEADERS,
                )
            elif method == "post":
                response = self.client.post(path, headers=DEV_AUTH_HEADERS)
            else:
                response = self.client.get(path, headers=DEV_AUTH_HEADERS)
            self.assertEqual(response.status_code, 404, path)

        targets = self.client.get("/api/v1/targets", headers=DEV_AUTH_HEADERS)
        scans = self.client.get("/api/v1/scans", headers=DEV_AUTH_HEADERS)
        self.assertEqual(targets.status_code, 200)
        self.assertFalse(any(item["id"] == self.target_id for item in targets.json()["items"]))
        self.assertEqual(scans.status_code, 200)
        self.assertFalse(any(item["id"] == self.scan_id for item in scans.json()["items"]))

    def test_invalid_auth_configuration_fails_closed(self) -> None:
        invalid_configs = [
            Settings(app_env="production", auth_mode="dev", auth_provider="dev"),
            Settings(app_env="local", auth_mode="dev", auth_provider="dev", auth_oidc_issuer="https://issuer.example/"),
            Settings(app_env="local", auth_mode="required", auth_provider="dev"),
            Settings(app_env="local", auth_mode="required", auth_provider=" "),
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

    def test_invalid_auth_profile_secret_configuration_fails_closed(self) -> None:
        invalid_configs = [
            Settings(app_env="local", auth_profile_secret_key=""),
            Settings(app_env="local", auth_profile_secret_key="not-a-fernet-key"),
            Settings(app_env="production", auth_profile_secret_key=LOCAL_DEV_EXAMPLE_SECRET_KEY),
        ]

        for config in invalid_configs:
            with self.assertRaises(AuthProfileError):
                validate_auth_profile_secret_settings(config)

        validate_auth_profile_secret_settings(
            Settings(app_env="local", auth_profile_secret_key=LOCAL_DEV_EXAMPLE_SECRET_KEY)
        )

    def test_required_auth_runtime_token_errors_return_401(self) -> None:
        required_settings = Settings(
            app_env="production",
            auth_mode="required",
            auth_provider="auth0",
            auth_oidc_issuer="https://tenant.example/",
            auth_oidc_audience="security-audit-api",
            auth_oidc_jwks_url="https://tenant.example/.well-known/jwks.json",
        )

        with (
            patch("app.api.deps.settings.auth_mode", required_settings.auth_mode),
            patch("app.api.deps.settings.auth_provider", required_settings.auth_provider),
            patch("app.api.deps.settings.auth_oidc_issuer", required_settings.auth_oidc_issuer),
            patch("app.api.deps.settings.auth_oidc_audience", required_settings.auth_oidc_audience),
            patch("app.api.deps.settings.auth_oidc_jwks_url", required_settings.auth_oidc_jwks_url),
        ):
            response = self.client.get("/api/v1/targets", headers={"Authorization": "Bearer malformed-token"})

        self.assertEqual(response.status_code, 401)
        self.assertIn("token", response.json()["detail"].lower())

    def test_oidc_identity_reuses_existing_user_workspace(self) -> None:
        claims = {"sub": "auth0|stable-user", "name": "Stable User", "exp": 4_102_444_800, "iat": 1_700_000_000}
        oidc_settings = Settings(
            app_env="production",
            auth_mode="required",
            auth_provider="auth0",
            auth_oidc_issuer="https://tenant.example/",
            auth_oidc_audience="security-audit-api",
            auth_oidc_jwks_url="https://tenant.example/.well-known/jwks.json",
        )

        class SigningKey:
            key = "unused"

        try:
            with SessionLocal() as db, patch("app.security.auth.oidc_jwk_client") as jwk_client, patch(
                "app.security.auth.jwt.decode", return_value=claims
            ):
                jwk_client.return_value.get_signing_key_from_jwt.return_value = SigningKey()
                first = authenticate_oidc_token("token-one", db, oidc_settings)
                second = authenticate_oidc_token("token-two", db, oidc_settings)

                identities = db.scalars(
                    select(AuthIdentity).where(
                        AuthIdentity.provider == "auth0",
                        AuthIdentity.provider_subject == "auth0|stable-user",
                    )
                ).all()

            self.assertEqual(first.user_id, second.user_id)
            self.assertEqual(first.workspace_id, second.workspace_id)
            self.assertEqual(len(identities), 1)
        finally:
            with SessionLocal() as db:
                identity = db.scalar(
                    select(AuthIdentity).where(
                        AuthIdentity.provider == "auth0",
                        AuthIdentity.provider_subject == "auth0|stable-user",
                    )
                )
                if identity is not None:
                    user_id = identity.user_id
                    db.execute(delete(AuthIdentity).where(AuthIdentity.user_id == user_id))
                    db.execute(delete(Workspace).where(Workspace.owner_user_id == user_id))
                    db.execute(delete(PlatformUser).where(PlatformUser.id == user_id))
                    db.commit()

    def test_oidc_validation_requires_subject_expiry_and_issued_at_claims(self) -> None:
        oidc_settings = Settings(
            app_env="production",
            auth_mode="required",
            auth_provider="auth0",
            auth_oidc_issuer="https://tenant.example/",
            auth_oidc_audience="scopeharbor-api",
            auth_oidc_jwks_url="https://tenant.example/.well-known/jwks.json",
        )

        class SigningKey:
            key = "unused"

        for missing_claim in ("sub", "exp", "iat"):
            with (
                SessionLocal() as db,
                patch("app.security.auth.oidc_jwk_client") as jwk_client,
                patch("app.security.auth.jwt.decode", side_effect=MissingRequiredClaimError(missing_claim)) as decode,
                self.assertRaises(AuthError),
            ):
                jwk_client.return_value.get_signing_key_from_jwt.return_value = SigningKey()
                authenticate_oidc_token("token", db, oidc_settings)
            self.assertEqual(decode.call_args.kwargs["algorithms"], ["RS256"])
            self.assertEqual(set(decode.call_args.kwargs["options"]["require"]), {"sub", "exp", "iat"})

    def test_concurrent_first_login_provisions_one_identity_and_workspace(self) -> None:
        subject = f"auth0|race-{uuid4()}"

        def provision():
            with SessionLocal() as db:
                return provision_oidc_principal(db, provider="auth0", subject=subject, display_name="Race User")

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                principals = list(executor.map(lambda _item: provision(), range(2)))
            self.assertEqual({principal.user_id for principal in principals}, {principals[0].user_id})
            self.assertEqual({principal.workspace_id for principal in principals}, {principals[0].workspace_id})
            with SessionLocal() as db:
                identities = list(
                    db.scalars(
                        select(AuthIdentity).where(
                            AuthIdentity.provider == "auth0",
                            AuthIdentity.provider_subject == subject,
                        )
                    ).all()
                )
                self.assertEqual(len(identities), 1)
        finally:
            with SessionLocal() as db:
                identity = db.scalar(
                    select(AuthIdentity).where(
                        AuthIdentity.provider == "auth0",
                        AuthIdentity.provider_subject == subject,
                    )
                )
                if identity is not None:
                    user_id = identity.user_id
                    db.execute(delete(AuthIdentity).where(AuthIdentity.user_id == user_id))
                    db.execute(delete(Workspace).where(Workspace.owner_user_id == user_id))
                    db.execute(delete(PlatformUser).where(PlatformUser.id == user_id))
                    db.commit()


if __name__ == "__main__":
    unittest.main()
