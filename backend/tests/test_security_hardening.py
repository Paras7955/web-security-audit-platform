import ipaddress
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.core.config import Settings
from app.core.validation import RuntimeConfigurationError, validate_runtime_settings
from app.scans.artifacts import ArtifactPathError, ensure_scan_artifact_dir, scan_artifact_dir
from app.security.allowlist import AllowlistTarget
from app.security.auth import AuthError, authenticate_dev_token, authenticate_oidc_token
from app.security.sanitization import REDACTION_TOKEN, sanitize_metadata, sanitize_relative_path, sanitize_text, sanitize_url
from app.security.ssrf import SsrfGuardError, is_local_demo_network_address, resolve_host, validate_destination
from app.security.target_url import normalize_target_url


class SecurityHardeningTests(unittest.TestCase):
    def test_dev_token_comparison_rejects_different_lengths_and_values(self) -> None:
        config = Settings(_env_file=None, app_env="local", auth_mode="dev", auth_provider="dev", dev_auth_token="expected-token")
        for supplied in ("", "expected-tokeN", "much-longer-untrusted-token"):
            with self.assertRaises(AuthError):
                authenticate_dev_token(supplied, MagicMock(), config)

    def test_oidc_failures_are_operator_safe(self) -> None:
        incomplete = Settings(_env_file=None, app_env="production", auth_mode="required", auth_provider="auth0")
        with self.assertRaisesRegex(ValueError, "not fully configured"):
            authenticate_oidc_token("token", MagicMock(), incomplete)

        configured = Settings(
            _env_file=None,
            app_env="production",
            auth_mode="required",
            auth_provider="auth0",
            auth_oidc_issuer="https://issuer.example/",
            auth_oidc_audience="scopeharbor-api",
            auth_oidc_jwks_url="https://issuer.example/jwks.json",
        )
        with patch("app.security.auth.oidc_jwk_client", side_effect=RuntimeError("raw provider detail")):
            with self.assertRaisesRegex(AuthError, "validation failed") as raised:
                authenticate_oidc_token("token", MagicMock(), configured)
        self.assertNotIn("raw provider detail", str(raised.exception))

        signing_key = MagicMock(key="unused")
        for subject in (None, "", "x" * 301, 42):
            with (
                patch("app.security.auth.oidc_jwk_client") as client,
                patch("app.security.auth.jwt.decode", return_value={"sub": subject, "exp": 4_102_444_800, "iat": 1_700_000_000}),
                self.assertRaisesRegex(AuthError, "missing a subject"),
            ):
                client.return_value.get_signing_key_from_jwt.return_value = signing_key
                authenticate_oidc_token("token", MagicMock(), configured)

    def test_dns_resolution_and_destination_rules_fail_closed(self) -> None:
        with patch("app.security.ssrf.socket.getaddrinfo", side_effect=socket.gaierror("private resolver detail")):
            with self.assertRaisesRegex(SsrfGuardError, "could not be resolved"):
                resolve_host("juice-shop", 3000)
        with patch("app.security.ssrf.socket.getaddrinfo", return_value=[]):
            with self.assertRaisesRegex(SsrfGuardError, "no addresses"):
                resolve_host("juice-shop", 3000)
        with patch(
            "app.security.ssrf.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.20.0.12", 3000))],
        ):
            self.assertEqual(resolve_host("juice-shop", 3000), ["172.20.0.12"])

        local_target = AllowlistTarget.model_validate(
            {
                "id": "local",
                "name": "Local",
                "base_url": "http://juice-shop:3000",
                "schemes": ["http"],
                "hosts": ["juice-shop"],
                "ports": [3000],
                "allowed_modes": ["passive"],
                "max_redirects": 2,
                "local_demo": True,
            }
        )
        url = normalize_target_url("http://juice-shop:3000/")
        with self.assertRaises(SsrfGuardError):
            validate_destination(url, local_target, resolver=lambda _host, _port: [])

        for changed in (
            local_target.model_copy(update={"schemes": ["https"]}),
            local_target.model_copy(update={"hosts": ["other"]}),
            local_target.model_copy(update={"ports": [8080]}),
        ):
            with self.assertRaises(SsrfGuardError):
                validate_destination(url, changed, resolver=lambda _host, _port: ["172.20.0.12"])

        nonlocal_target = local_target.model_copy(update={"local_demo": False})
        with self.assertRaises(SsrfGuardError):
            validate_destination(url, nonlocal_target, resolver=lambda _host, _port: ["10.0.0.4"])
        self.assertTrue(is_local_demo_network_address(ipaddress.ip_address("fd00::1")))

    def test_persistence_sanitizers_cover_nested_and_malformed_inputs(self) -> None:
        self.assertIsNone(sanitize_url(None))
        self.assertIsNone(sanitize_url("ftp://example.test/file"))
        self.assertIsNone(sanitize_url("http://[invalid"))
        self.assertEqual(sanitize_url("HTTPS://User:pass@Example.Test:8443/a?secret=x#fragment"), "https://example.test:8443/a")
        self.assertIsNone(sanitize_text(None, maximum=50))
        self.assertEqual(sanitize_text("Authorization: Bearer canary", maximum=100), f"Authorization: Bearer {REDACTION_TOKEN}")
        self.assertNotIn("cookie-value", sanitize_text("Set-Cookie: sid=cookie-value", maximum=100) or "")
        self.assertEqual(sanitize_relative_path(None), None)
        self.assertEqual(sanitize_relative_path(""), "[PATH REDACTED]")
        self.assertEqual(sanitize_relative_path("src\\nested\\app.py"), "src/nested/app.py")

        deeply_nested: object = "value"
        for _ in range(6):
            deeply_nested = {"child": deeply_nested}
        sanitized = sanitize_metadata(
            {
                "password": "canary",
                "values": [*range(60)],
                "nested": deeply_nested,
                "number": 4,
                "enabled": True,
                "none": None,
            }
        )
        self.assertEqual(sanitized["password"], REDACTION_TOKEN)
        self.assertEqual(len(sanitized["values"]), 50)
        self.assertIn("[TRUNCATED]", str(sanitized))

    def test_artifact_paths_are_private_and_confined(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            created = ensure_scan_artifact_dir(root, "scan-id")
            self.assertTrue(created.is_dir())
            self.assertEqual(created.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(ArtifactPathError):
                scan_artifact_dir(root, "../../escape")

    def test_runtime_validation_rejects_unsafe_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            allowlist = root_path / "allowlist.yml"
            gitleaks = root_path / "gitleaks.toml"
            osv = root_path / "osv.toml"
            allowlist.write_text(
                "targets:\n  - id: demo\n    name: Demo\n    base_url: http://demo:3000\n"
                "    schemes: [http]\n    hosts: [demo]\n    ports: [3000]\n"
                "    allowed_modes: [passive]\n    max_redirects: 2\n    local_demo: true\n",
                encoding="utf-8",
            )
            gitleaks.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            osv.write_text("[IgnoredVulns]\n", encoding="utf-8")
            base = Settings(
                _env_file=None,
                zap_api_key="a" * 32,
                allowlist_path=str(allowlist),
                artifact_root=str(root_path / "artifacts"),
                repo_scan_root=str(root_path / "repos"),
                repo_staging_root=str(root_path / "staging"),
                gitleaks_config_path=str(gitleaks),
                osv_config_path=str(osv),
                osv_database_path=str(root_path / "osv-db"),
            )
            validate_runtime_settings(base)
            invalid = (
                base.model_copy(update={"zap_api_key": "short"}),
                base.model_copy(update={"zap_base_url": "https://zap:8080/path?key=x"}),
                base.model_copy(update={"repo_max_files": 0}),
                base.model_copy(update={"page_default_limit": 201}),
                base.model_copy(update={"repo_max_file_bytes": 20, "repo_max_total_bytes": 10}),
                base.model_copy(update={"worker_lease_seconds": 14}),
                base.model_copy(update={"gitleaks_config_path": str(root_path / "missing")}),
            )
            for config in invalid:
                with self.assertRaises(RuntimeConfigurationError):
                    validate_runtime_settings(config)


if __name__ == "__main__":
    unittest.main()
