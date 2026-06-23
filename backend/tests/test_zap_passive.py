import unittest

from app.core.contracts import Confidence, Severity
from app.security.allowlist import AllowlistTarget
from app.zap.passive import (
    ZapApiClient,
    context_regex,
    normalize_zap_alert,
    run_zap_passive_scan,
    scope_observed_urls,
)


ALLOWLIST_TARGET = AllowlistTarget.model_validate(
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "base_url": "http://juice-shop:3000",
        "schemes": ["http"],
        "hosts": ["juice-shop"],
        "ports": [3000],
        "allowed_modes": ["passive"],
        "max_redirects": 5,
        "local_demo": True,
    }
)


def resolver(host: str, port: int) -> list[str]:
    if host == "juice-shop" and port == 3000:
        return ["172.20.0.10"]
    return ["93.184.216.34"]


class ZapPassiveTests(unittest.TestCase):
    def test_scope_observed_urls_keeps_only_allowlisted_same_origin_urls(self) -> None:
        target = scope_observed_urls(
            target=scope_target("http://juice-shop:3000/"),
            allowlist_target=ALLOWLIST_TARGET,
            urls=(
                "http://juice-shop:3000/login",
                "http://juice-shop:3000/login",
                "http://evil.example.test/",
            ),
            resolver=resolver,
        )

        self.assertEqual(target, ("http://juice-shop:3000/", "http://juice-shop:3000/login"))

    def test_run_zap_passive_scan_scopes_session_and_accesses_urls_without_redirects(self) -> None:
        client = FakeZapClient()

        result = run_zap_passive_scan(
            scan_id="scan-1",
            target_url="http://juice-shop:3000/",
            allowlist_target=ALLOWLIST_TARGET,
            zap_base_url="http://zap:8080",
            observed_urls=("http://juice-shop:3000/login", "http://evil.example.test/"),
            client=client,
            resolver=resolver,
        )

        self.assertEqual(result.errors, ())
        self.assertEqual(result.submitted_urls, ("http://juice-shop:3000/", "http://juice-shop:3000/login"))
        self.assertEqual([call[0] for call in client.calls[:6]], ["new_session", "new_context", "include", "scope", "enable", "delete"])
        self.assertIn(("access", "http://juice-shop:3000/"), client.calls)
        self.assertIn(("access", "http://juice-shop:3000/login"), client.calls)
        self.assertEqual(result.findings[0].source_tool, "zap-passive")
        self.assertEqual(result.findings[0].scanner_rule_id, "10038")

    def test_run_zap_passive_scan_returns_warning_on_scope_error(self) -> None:
        result = run_zap_passive_scan(
            scan_id="scan-1",
            target_url="http://evil.example.test/",
            allowlist_target=ALLOWLIST_TARGET,
            zap_base_url="http://zap:8080",
            observed_urls=(),
            client=FakeZapClient(),
            resolver=resolver,
        )

        self.assertEqual(result.findings, ())
        self.assertEqual(result.submitted_urls, ())
        self.assertTrue(result.errors)

    def test_zap_alert_normalization_strips_url_query_and_credentials(self) -> None:
        finding = normalize_zap_alert(
            {
                "alert": "Content Security Policy Header Not Set",
                "risk": "Medium",
                "confidence": "High",
                "url": "http://user:pass@juice-shop:3000/callback?token=secret#frag",
                "evidence": "set-cookie: session=abc123",
                "pluginId": "10038",
                "cweid": "693",
                "solution": "Set a Content-Security-Policy header.",
            }
        )

        self.assertEqual(finding.title, "Content Security Policy Header Not Set")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(finding.affected_url, "http://juice-shop:3000/callback")
        self.assertNotIn("token=secret", str(finding))
        self.assertNotIn("user:pass", str(finding))
        self.assertEqual(finding.cwe, "CWE-693")
        self.assertEqual(finding.owasp_category, "A05:2021")

    def test_zap_api_access_url_disables_redirects(self) -> None:
        calls = []

        def handler(url, *, params, timeout):
            del timeout
            calls.append((url, params))
            return MockResponse({"Result": "OK"})

        with patch_httpx_get(handler):
            client = ZapApiClient(base_url="http://zap:8080")
            client.access_url(url="http://juice-shop:3000/")

        self.assertEqual(calls[0][0], "http://zap:8080/JSON/core/action/accessUrl/")
        self.assertEqual(calls[0][1]["followRedirects"], "false")

    def test_context_regex_scopes_to_exact_origin(self) -> None:
        regex = context_regex("http://juice-shop:3000/")

        self.assertRegex("http://juice-shop:3000/login", regex)
        self.assertNotRegex("http://juice-shop.evil.test:3000/login", regex)


def scope_target(url: str):
    from app.zap.passive import validate_zap_scope_url

    return validate_zap_scope_url(url, ALLOWLIST_TARGET, resolver=resolver)


class FakeZapClient:
    def __init__(self) -> None:
        self.calls = []

    def new_session(self, *, name: str) -> None:
        self.calls.append(("new_session", name))

    def new_context(self, *, name: str) -> str:
        self.calls.append(("new_context", name))
        return "1"

    def include_in_context(self, *, context_name: str, regex: str) -> None:
        self.calls.append(("include", context_name, regex))

    def set_context_in_scope(self, *, context_name: str, enabled: bool) -> None:
        self.calls.append(("scope", context_name, enabled))

    def enable_passive_scanner(self) -> None:
        self.calls.append(("enable",))

    def delete_all_alerts(self) -> None:
        self.calls.append(("delete",))

    def access_url(self, *, url: str) -> None:
        self.calls.append(("access", url))

    def records_to_scan(self) -> int:
        self.calls.append(("records",))
        return 0

    def alerts(self, *, base_url: str):
        self.calls.append(("alerts", base_url))
        return [
            {
                "alert": "Content Security Policy Header Not Set",
                "risk": "Medium",
                "confidence": "High",
                "url": "http://juice-shop:3000/",
                "pluginId": "10038",
                "cweid": "693",
            }
        ]


class MockResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self.payload


class patch_httpx_get:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.original = None

    def __enter__(self):
        import app.zap.passive

        self.original = app.zap.passive.httpx.get
        app.zap.passive.httpx.get = self.handler

    def __exit__(self, *args):
        import app.zap.passive

        app.zap.passive.httpx.get = self.original


if __name__ == "__main__":
    unittest.main()
