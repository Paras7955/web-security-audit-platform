import unittest

from app.security.allowlist import ScanAllowlist
from app.security.redirects import RedirectValidationError, validate_redirect_chain, validate_redirect_location
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
                "max_redirects": 2,
                "local_demo": True,
            }
        ]
    }
)


class RedirectValidationTests(unittest.TestCase):
    def test_empty_redirect_location_is_rejected(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        for location in ("", "   "):
            with self.assertRaises(RedirectValidationError):
                validate_redirect_location(match.url, location, match.allowlist_target, resolver_for(["172.20.0.10"]))

    def test_same_target_relative_redirect_is_allowed(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000/login", ALLOWLIST)

        next_url, destination = validate_redirect_location(
            match.url,
            "/profile",
            match.allowlist_target,
            resolver_for(["172.20.0.10"]),
        )

        self.assertEqual(next_url.normalized_url, "http://juice-shop:3000/profile")
        self.assertEqual(destination.resolved_ips, ("172.20.0.10",))

    def test_redirect_to_public_url_is_rejected(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(RedirectValidationError):
            validate_redirect_location(match.url, "https://example.com", match.allowlist_target, resolver_for(["93.184.216.34"]))

    def test_redirect_to_metadata_ip_is_rejected(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(RedirectValidationError):
            validate_redirect_location(
                match.url,
                "http://juice-shop:3000/admin",
                match.allowlist_target,
                resolver_for(["169.254.169.254"]),
            )

    def test_redirect_chain_limit_is_enforced(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        with self.assertRaises(RedirectValidationError):
            validate_redirect_chain(
                match.url,
                ["/one", "/two", "/three"],
                match.allowlist_target,
                resolver_for(["172.20.0.10"]),
            )

    def test_relative_redirect_chain_is_validated(self) -> None:
        match = match_allowlisted_target("http://juice-shop:3000", ALLOWLIST)

        urls = validate_redirect_chain(match.url, ["/one", "../two"], match.allowlist_target, resolver_for(["172.20.0.10"]))

        self.assertEqual([url.normalized_url for url in urls], ["http://juice-shop:3000/one", "http://juice-shop:3000/two"])


if __name__ == "__main__":
    unittest.main()
