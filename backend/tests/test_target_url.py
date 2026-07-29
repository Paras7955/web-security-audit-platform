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
                "allowed_modes": ["passive", "active_demo", "ajax_short", "repo"],
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
        self.assertEqual([mode.value for mode in match.allowed_modes], ["passive", "active_demo", "ajax_short", "repo"])

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

    def test_base_path_scope_uses_segment_boundaries(self) -> None:
        allowlist = ScanAllowlist.model_validate(
            {
                "version": 2,
                "targets": [
                    {
                        "id": "scoped-app",
                        "name": "Scoped App",
                        "base_url": "http://scoped-app:8080/app",
                        "connection": {"kind": "compose_service", "host": "scoped-app", "port": 8080},
                        "profile_engines": {"passive-web": ["scopeharbor-passive"]},
                        "disposable_demo": False,
                        "max_redirects": 2,
                    }
                ],
            }
        )

        self.assertEqual(
            match_allowlisted_target("http://scoped-app:8080/app/page?q=1", allowlist).allowlist_target.id,
            "scoped-app",
        )
        for raw_url in (
            "http://scoped-app:8080/",
            "http://scoped-app:8080/application",
            "http://scoped-app:8080/other",
        ):
            with self.subTest(raw_url=raw_url), self.assertRaises(TargetUrlError):
                match_allowlisted_target(raw_url, allowlist)

    def test_ambiguous_request_paths_are_rejected_before_matching(self) -> None:
        for raw_url in (
            "http://juice-shop:3000/a//b",
            "http://juice-shop:3000/a/%2e%2e/b",
            "http://juice-shop:3000/a/%2fb",
            r"http://juice-shop:3000/a\b",
        ):
            with self.subTest(raw_url=raw_url), self.assertRaises(TargetUrlError):
                normalize_target_url(raw_url)


if __name__ == "__main__":
    unittest.main()
