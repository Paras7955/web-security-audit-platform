import unittest

from app.security.allowlist import ScanAllowlist
from app.security.target_url import TargetUrlError, match_allowlisted_target, normalize_target_url


ALLOWLIST = ScanAllowlist.model_validate(
    {
        "targets": [
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
        ]
    }
)


class TargetUrlTests(unittest.TestCase):
    def test_normalizes_allowed_url(self) -> None:
        normalized = normalize_target_url("http://juice-shop:3000")

        self.assertEqual(normalized.normalized_url, "http://juice-shop:3000/")
        self.assertEqual(normalized.host, "juice-shop")
        self.assertEqual(normalized.port, 3000)

    def test_matches_juice_shop_allowlist_entry(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        self.assertEqual(match.allowlist_target.id, "juice-shop")
        self.assertEqual([mode.value for mode in match.allowed_modes], ["passive", "active_demo", "ajax_short"])

    def test_wrong_port_is_rejected(self) -> None:
        with self.assertRaises(TargetUrlError):
            match_allowlisted_target("http://juice-shop:3001", ALLOWLIST)

    def test_non_http_scheme_is_rejected(self) -> None:
        for raw_url in ["file:///etc/passwd", "ftp://juice-shop:3000", "juice-shop:3000"]:
            with self.subTest(raw_url=raw_url):
                with self.assertRaises(TargetUrlError):
                    match_allowlisted_target(raw_url, ALLOWLIST)

    def test_public_url_is_rejected(self) -> None:
        with self.assertRaises(TargetUrlError):
            match_allowlisted_target("https://example.com", ALLOWLIST)

    def test_localhost_alias_is_rejected_unless_configured(self) -> None:
        with self.assertRaises(TargetUrlError):
            match_allowlisted_target("http://localhost:3000", ALLOWLIST)

    def test_credentials_are_rejected(self) -> None:
        with self.assertRaises(TargetUrlError):
            normalize_target_url("http://user:pass@juice-shop:3000")


if __name__ == "__main__":
    unittest.main()
