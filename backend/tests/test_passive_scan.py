import tempfile
import unittest
from pathlib import Path

from app.scanner.http_client import ScannerHttpResponse
from app.scanner.passive import run_passive_scan, validated_page_resolver
from app.security.allowlist import AllowlistTarget
from app.security.target_url import normalize_target_url

ALLOWLIST_TARGET = AllowlistTarget.model_validate(
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "base_url": "http://juice-shop:3000",
        "schemes": ["http"],
        "hosts": ["juice-shop"],
        "ports": [3000],
        "allowed_modes": ["passive", "active_demo", "ajax_short"],
        "max_redirects": 5,
        "local_demo": True,
    }
)


class FakeClient:
    def get(self, raw_url: str) -> ScannerHttpResponse:
        url = normalize_target_url(raw_url)
        body = "<a href='/login'>login</a>"
        headers = {"set-cookie": "session=abc123"}
        if url.path == "/login":
            body = "<form method='get'><input type='password'></form>"
            headers = {}
        if url.path == "/.env":
            body = "secret=value"
        return ScannerHttpResponse(
            url=url,
            status_code=200 if url.path in {"/", "/login", "/.env"} else 404,
            headers=headers,
            body=body,
            redirect_chain=(),
            connection_ip="172.20.0.10",
        )


class PassiveScanTests(unittest.TestCase):
    def test_passive_scan_crawls_and_checks_without_writing_a_summary_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_passive_scan(
                scan_id="scan-1",
                target_url="http://juice-shop:3000/",
                allowlist_target=ALLOWLIST_TARGET,
                artifact_root=temp_dir,
                client=FakeClient(),
            )

            self.assertGreaterEqual(len(result.pages), 2)
            self.assertTrue(any(finding.scanner_rule_id == "form:password-get" for finding in result.findings))
            self.assertTrue(any(finding.scanner_rule_id == "probe:/.env" for finding in result.findings))
            self.assertFalse((Path(temp_dir) / "scans" / "scan-1" / "passive_scan_summary.txt").exists())

            resolver = validated_page_resolver(result.pages, ALLOWLIST_TARGET)
            self.assertEqual(resolver("juice-shop", 3000), ["172.20.0.10"])
            self.assertEqual(resolver("other-service", 3000), [])
            self.assertEqual(resolver("juice-shop", 8080), [])


if __name__ == "__main__":
    unittest.main()
