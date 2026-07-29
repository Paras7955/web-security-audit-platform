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
        ]
    }
)


class SsrfGuardTests(unittest.TestCase):
    def test_exact_allowlisted_docker_target_accepts_private_resolution(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        result = validate_destination(match.url, match.allowlist_target, resolver_for(["172.20.0.10"]))

        self.assertEqual(result.resolved_ips, ("172.20.0.10",))

    def test_local_demo_loopback_resolution_is_blocked(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["127.0.0.1"]))

    def test_local_demo_link_local_resolution_is_blocked(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["169.254.10.5"]))

    def test_metadata_ip_is_always_blocked(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["169.254.169.254"]))

    def test_public_resolution_for_local_service_is_blocked(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["93.184.216.34"]))

    def test_all_resolved_ips_must_be_allowed(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["93.184.216.34", "127.0.0.1"]))

    def test_public_addresses_are_denied_for_every_connection_policy(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)
        with self.assertRaises(SsrfGuardError):
            validate_destination(match.url, match.allowlist_target, resolver_for(["8.8.8.8"]))

    def test_host_gateway_requires_an_exact_expected_address(self) -> None:
        allowlist = ScanAllowlist.model_validate(
            {
                "version": 2,
                "targets": [
                    {
                        "id": "host-app",
                        "name": "Host App",
                        "base_url": "http://localhost:8080/",
                        "connection": {
                            "kind": "host_gateway",
                            "host": "scopeharbor-host",
                            "port": 18080,
                            "expected_ips": ["192.168.65.2"],
                        },
                        "profile_engines": {"passive-web": ["scopeharbor-passive"]},
                        "disposable_demo": False,
                        "max_redirects": 1,
                    }
                ],
            }
        )
        match = match_allowlisted_target("http://localhost:8080/", allowlist)

        destination = validate_destination(
            match.url,
            match.allowlist_target,
            resolver_for(["192.168.65.2"]),
        )
        self.assertEqual(destination.connection_host, "scopeharbor-host")
        self.assertEqual(destination.connection_port, 18080)
        self.assertEqual(destination.connection_ip, "192.168.65.2")
        for denied in ("192.168.65.3", "10.0.0.4", "8.8.8.8"):
            with self.subTest(denied=denied), self.assertRaises(SsrfGuardError):
                validate_destination(match.url, match.allowlist_target, resolver_for([denied]))


if __name__ == "__main__":
    unittest.main()
