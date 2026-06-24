import unittest

from app.security.allowlist import AllowlistTarget
from app.zap.ajax import run_zap_ajax_short_scan
from app.zap.passive import ZapAlertPage


ALLOWLIST_TARGET = AllowlistTarget.model_validate(
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "base_url": "http://juice-shop:3000",
        "schemes": ["http"],
        "hosts": ["juice-shop"],
        "ports": [3000],
        "allowed_modes": ["passive", "ajax_short"],
        "max_redirects": 5,
        "local_demo": True,
    }
)
REMOTE_TARGET = AllowlistTarget.model_validate(
    {
        "id": "remote",
        "name": "Remote Example",
        "base_url": "https://owned.example.test",
        "schemes": ["https"],
        "hosts": ["owned.example.test"],
        "ports": [443],
        "allowed_modes": ["passive", "ajax_short"],
        "max_redirects": 2,
        "local_demo": False,
    }
)


def resolver(host: str, port: int) -> list[str]:
    if host == "juice-shop" and port == 3000:
        return ["172.20.0.10"]
    return ["93.184.216.34"]


class ZapAjaxShortTests(unittest.TestCase):
    def test_ajax_short_uses_pinned_local_demo_url_and_context(self) -> None:
        client = FakeAjaxZapClient()

        result = run_zap_ajax_short_scan(
            scan_id="scan-1",
            target_url="http://juice-shop:3000/",
            allowlist_target=ALLOWLIST_TARGET,
            zap_base_url="http://zap:8080",
            client=client,
            resolver=resolver,
        )

        self.assertEqual(result.errors, ())
        self.assertEqual(result.submitted_url, "http://juice-shop:3000/")
        self.assertIn(("ajax_scan", "http://172.20.0.10:3000/", "ajax-short-scan-1"), client.calls)
        self.assertEqual(result.findings[0].source_tool, "zap-ajax")
        self.assertEqual(result.findings[0].affected_url, "http://juice-shop:3000/search")

    def test_ajax_short_rejects_non_local_demo_allowlist_target(self) -> None:
        result = run_zap_ajax_short_scan(
            scan_id="scan-1",
            target_url="https://owned.example.test/",
            allowlist_target=REMOTE_TARGET,
            zap_base_url="http://zap:8080",
            client=FakeAjaxZapClient(),
            resolver=resolver,
        )

        self.assertEqual(result.findings, ())
        self.assertIsNone(result.submitted_url)
        self.assertIn("local/demo", result.errors[0])


class FakeAjaxZapClient:
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

    def set_ajax_max_duration(self, *, minutes: int) -> None:
        self.calls.append(("ajax_duration", minutes))

    def set_ajax_max_crawl_depth(self, *, depth: int) -> None:
        self.calls.append(("ajax_depth", depth))

    def ajax_scan(self, *, url: str, context_name: str) -> None:
        self.calls.append(("ajax_scan", url, context_name))

    def ajax_status(self) -> str:
        self.calls.append(("ajax_status",))
        return "stopped"

    def stop_ajax(self) -> None:
        self.calls.append(("ajax_stop",))

    def records_to_scan(self) -> int:
        self.calls.append(("records",))
        return 0

    def alerts(self, *, base_url: str) -> ZapAlertPage:
        self.calls.append(("alerts", base_url))
        return ZapAlertPage(
            truncated=False,
            alerts=(
                {
                    "alert": "ZAP AJAX Alert",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": "http://172.20.0.10:3000/search?q=secret",
                    "pluginId": "10038",
                    "cweid": "693",
                },
            ),
        )


if __name__ == "__main__":
    unittest.main()
