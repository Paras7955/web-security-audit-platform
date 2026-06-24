import unittest

from app.security.allowlist import AllowlistTarget
from app.zap.active import run_zap_active_demo_scan
from app.zap.passive import ZapAlertPage


ALLOWLIST_TARGET = AllowlistTarget.model_validate(
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "base_url": "http://juice-shop:3000",
        "schemes": ["http"],
        "hosts": ["juice-shop"],
        "ports": [3000],
        "allowed_modes": ["passive", "active_demo"],
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
        "allowed_modes": ["passive", "active_demo"],
        "max_redirects": 2,
        "local_demo": False,
    }
)


def resolver(host: str, port: int) -> list[str]:
    if host == "juice-shop" and port == 3000:
        return ["172.20.0.10"]
    return ["93.184.216.34"]


class ZapActiveDemoTests(unittest.TestCase):
    def test_active_demo_scan_uses_pinned_local_demo_url_and_context(self) -> None:
        client = FakeActiveZapClient()

        result = run_zap_active_demo_scan(
            scan_id="scan-1",
            target_url="http://juice-shop:3000/",
            allowlist_target=ALLOWLIST_TARGET,
            zap_base_url="http://zap:8080",
            client=client,
            resolver=resolver,
        )

        self.assertEqual(result.errors, ())
        self.assertEqual(result.submitted_url, "http://juice-shop:3000/")
        self.assertIn(("access", "http://172.20.0.10:3000/"), client.calls)
        self.assertIn(("active_scan", "http://172.20.0.10:3000/", "1"), client.calls)
        self.assertEqual(result.findings[0].source_tool, "zap-active")
        self.assertEqual(result.findings[0].affected_url, "http://juice-shop:3000/")

    def test_active_demo_rejects_non_local_demo_allowlist_target(self) -> None:
        result = run_zap_active_demo_scan(
            scan_id="scan-1",
            target_url="https://owned.example.test/",
            allowlist_target=REMOTE_TARGET,
            zap_base_url="http://zap:8080",
            client=FakeActiveZapClient(),
            resolver=resolver,
        )

        self.assertEqual(result.findings, ())
        self.assertIsNone(result.submitted_url)
        self.assertIn("local/demo", result.errors[0])


class FakeActiveZapClient:
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

    def active_scan(self, *, url: str, context_id: str) -> str:
        self.calls.append(("active_scan", url, context_id))
        return "7"

    def active_scan_status(self, *, scan_id: str) -> int:
        self.calls.append(("active_status", scan_id))
        return 100

    def alerts(self, *, base_url: str) -> ZapAlertPage:
        self.calls.append(("alerts", base_url))
        return ZapAlertPage(
            truncated=False,
            alerts=(
                {
                    "alert": "ZAP Active Demo Alert",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": "http://172.20.0.10:3000/",
                    "pluginId": "40012",
                    "cweid": "79",
                },
            ),
        )


if __name__ == "__main__":
    unittest.main()
