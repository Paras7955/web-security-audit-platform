import json
import logging
import unittest

from app.api.schemas import AuditLogRead
from app.core.logging import SecretSafeJsonFormatter
from app.main import app
from app.security.sanitization import sanitize_metadata, sanitize_relative_path, sanitize_text, sanitize_url
from fastapi.testclient import TestClient


class PublicApiBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_product_contract_is_versioned_and_root_contract_is_gone(self) -> None:
        response = self.client.get("/api/v1/contracts")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["product"]["name"], "ScopeHarbor")
        self.assertNotIn("scan_modes", response.json())
        self.assertNotIn("scan_steps", response.json())
        self.assertTrue(all("mode" not in profile for profile in response.json()["scan_profiles"]))
        self.assertEqual(self.client.get("/contracts").status_code, 404)

    def test_security_headers_and_request_id_are_always_present(self) -> None:
        response = self.client.get("/health", headers={"X-Request-ID": "test-request-1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["x-request-id"], "test-request-1")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_oversized_body_returns_problem_details_without_parsing(self) -> None:
        response = self.client.post(
            "/api/v1/scans",
            content=b"x" * 1_048_577,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["content-type"], "application/problem+json")
        self.assertEqual(response.json()["code"], "request_body_too_large")


class PersistenceSanitizationTests(unittest.TestCase):
    def test_url_strips_userinfo_query_and_fragment(self) -> None:
        self.assertEqual(
            sanitize_url("http://user:password@example.test:8080/path?token=canary#fragment"),
            "http://example.test:8080/path",
        )

    def test_every_text_value_is_redacted_and_urls_are_minimized(self) -> None:
        value = "Authorization: Bearer canary https://example.test/a?secret=canary#x"
        result = sanitize_text(value, maximum=500)
        self.assertNotIn("canary", result or "")
        self.assertEqual(result, "Authorization: Bearer [REDACTED] https://example.test/a")

    def test_absolute_and_traversing_paths_are_not_exposed(self) -> None:
        self.assertEqual(sanitize_relative_path("/Users/example/project/.env"), "[PATH REDACTED]")
        self.assertEqual(sanitize_relative_path("../outside"), "[PATH REDACTED]")
        self.assertEqual(sanitize_relative_path("src/app.py"), "src/app.py")

    def test_metadata_redacts_sensitive_keys_recursively(self) -> None:
        result = sanitize_metadata({"details": {"api-key": "canary"}, "url": "http://x/a?q=1"})
        self.assertNotIn("canary", str(result))
        self.assertNotIn("?q=1", str(result))

    def test_structured_logs_strip_secrets_queries_and_raw_error_text(self) -> None:
        record = logging.LogRecord(
            name="scopeharbor.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="provider failed with raw-secret-token",
            args=(),
            exc_info=None,
        )
        record.scopeharbor_metadata = {
            "url": "http://juice-shop:3000/callback?token=raw-secret-token",
            "authorization": "Bearer raw-secret-token",
        }
        rendered = SecretSafeJsonFormatter().format(record)
        payload = json.loads(rendered)
        self.assertEqual(payload["authorization"], "[REDACTED]")
        self.assertNotIn("raw-secret-token", rendered)
        self.assertNotIn("?token=", rendered)

    def test_audit_projection_removes_internal_and_sensitive_metadata(self) -> None:
        projected = AuditLogRead.model_validate(
            {
                "id": "audit-1",
                "event_type": "scan.failed",
                "resource_type": "scan",
                "resource_id": "scan-1",
                "metadata_json": {
                    "mode": "repo",
                    "error_detail": "raw-secret-token",
                    "repo_path": "/Users/example/repo",
                    "safe_code": "worker_interrupted",
                },
                "created_at": "2026-07-13T00:00:00Z",
            }
        )
        self.assertEqual(projected.metadata_json, {"safe_code": "worker_interrupted"})


if __name__ == "__main__":
    unittest.main()
