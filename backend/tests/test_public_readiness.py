import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.security.sanitization import sanitize_metadata, sanitize_relative_path, sanitize_text, sanitize_url


class PublicApiBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_product_contract_is_versioned_and_root_contract_is_gone(self) -> None:
        response = self.client.get("/api/v1/contracts")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["product"]["name"], "ScopeHarbor")
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


if __name__ == "__main__":
    unittest.main()
