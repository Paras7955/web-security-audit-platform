import unittest

from app.security.allowlist import AllowlistTarget
from app.zap.client_spider import ZapClientSpiderCancelled, run_zap_client_spider_scan
from app.zap.passive import ZapAlertPage
from pydantic import ValidationError

ALLOWLIST_TARGET = AllowlistTarget.model_validate(
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "base_url": "http://juice-shop:3000",
        "schemes": ["http"],
        "hosts": ["juice-shop"],
        "ports": [3000],
        "allowed_modes": ["passive", "modern_web_crawl"],
        "max_redirects": 5,
        "local_demo": True,
    }
)
def resolver(host: str, port: int) -> list[str]:
    if host == "juice-shop" and port == 3000:
        return ["172.20.0.10"]
    return ["93.184.216.34"]


class ZapClientSpiderTests(unittest.TestCase):
    def test_client_spider_uses_pinned_url_and_strict_bounded_options(self) -> None:
        client = FakeClientSpider()
        result = run_zap_client_spider_scan(
            scan_id="scan-1",
            target_url="http://juice-shop:3000/",
            allowlist_target=ALLOWLIST_TARGET,
            zap_base_url="http://zap:8080",
            client=client,
            resolver=resolver,
        )

        self.assertEqual(result.errors, ())
        self.assertEqual(result.submitted_url, "http://juice-shop:3000/")
        self.assertIn(("scan", "http://172.20.0.10:3000/", "client-spider-scan-1", 2, 10, 1), client.calls)
        self.assertEqual(result.findings[0].source_tool, "zap-client-spider")
        self.assertEqual(result.findings[0].affected_url, "http://juice-shop:3000/search")
        self.assertNotIn(("stop", "7"), client.calls)

    def test_non_local_target_cannot_enter_client_spider_contract(self) -> None:
        with self.assertRaises(ValidationError):
            AllowlistTarget.model_validate(
                {
                    "id": "remote",
                    "name": "Non-local Example",
                    "base_url": "http://owned.example.test:8080",
                    "schemes": ["http"],
                    "hosts": ["owned.example.test"],
                    "ports": [8080],
                    "allowed_modes": ["modern_web_crawl"],
                    "max_redirects": 2,
                    "local_demo": False,
                }
            )

    def test_cancellation_stops_the_specific_client_spider(self) -> None:
        client = FakeClientSpider(status=25)
        with self.assertRaises(ZapClientSpiderCancelled):
            run_zap_client_spider_scan(
                scan_id="scan-1",
                target_url="http://juice-shop:3000/",
                allowlist_target=ALLOWLIST_TARGET,
                zap_base_url="http://zap:8080",
                client=client,
                resolver=resolver,
                should_cancel=lambda: True,
            )
        self.assertIn(("stop", "7"), client.calls)


class FakeClientSpider:
    def __init__(self, status: int = 100) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.status = status

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

    def client_spider_scan(self, *, url: str, context_name: str, max_crawl_depth: int, page_load_seconds: int, number_of_browsers: int) -> str:
        self.calls.append(("scan", url, context_name, max_crawl_depth, page_load_seconds, number_of_browsers))
        return "7"

    def client_spider_status(self, *, scan_id: str) -> int:
        self.calls.append(("status", scan_id))
        return self.status

    def stop_client_spider(self, *, scan_id: str) -> None:
        self.calls.append(("stop", scan_id))

    def records_to_scan(self) -> int:
        return 0

    def alerts(self, *, base_url: str) -> ZapAlertPage:
        self.calls.append(("alerts", base_url))
        return ZapAlertPage(
            truncated=False,
            alerts=(
                {
                    "alert": "Client-side alert",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": "http://172.20.0.10:3000/search?q=sensitive",
                    "pluginId": "10038",
                    "cweid": "693",
                },
            ),
        )


if __name__ == "__main__":
    unittest.main()
