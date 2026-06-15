import unittest

from app.security.allowlist import ScanAllowlist
from app.security.ssrf import SsrfGuardError, validate_destination
from app.security.target_url import match_allowlisted_target


def resolver_for(ips: list[str]):
    def resolve(_host: str, _port: int) -> list[str]:
        return ips

    return resolve


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
            },
            {
                "id": "owned-demo",
                "name": "Owned Demo",
                "base_url": "https://owned.example.test",
                "schemes": ["https"],
                "hosts": ["owned.example.test"],
                "ports": [443],
                "allowed_modes": ["passive"],
                "max_redirects": 5,
                "local_demo": False,
            },
        ]
    }
)


class SsrfGuardTests(unittest.TestCase):
    def test_exact_allowlisted_docker_target_accepts_private_resolution(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        result = validate_destination(match.url, match.allowlist_target, resolver_for(["172.20.0.10"]))

        self.assertEqual(result.resolved_ips, ("172.20.0.10",))

    def test_metadata_ip_is_always_blocked(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["169.254.169.254"]))

    def test_private_ip_for_non_local_demo_is_blocked(self) -> None:
        match = match_allowlisted_target("https://owned.example.test", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["10.0.0.5"]))

    def test_public_ip_for_exact_non_local_target_is_allowed(self) -> None:
        match = match_allowlisted_target("https://owned.example.test", ALLOWLIST)

        result = validate_destination(match.url, match.allowlist_target, resolver_for(["93.184.216.34"]))

        self.assertEqual(result.resolved_ips, ("93.184.216.34",))

    def test_all_resolved_ips_must_be_allowed(self) -> None:
        match = match_allowlisted_target("https://owned.example.test", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["93.184.216.34", "127.0.0.1"]))


if __name__ == "__main__":
    unittest.main()
