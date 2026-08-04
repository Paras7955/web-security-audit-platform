import unittest

from app.scanner.relay_capability import (
    RelayCapabilityError,
    ReplayGuard,
    create_relay_capability,
    verify_relay_capability,
)
from relay.main import RelayFetchRequest, redact_set_cookie_value, safe_response_headers

RELAY_SECRET = "relay-test-secret-that-is-at-least-thirty-two-bytes"


class RelayCapabilityTests(unittest.TestCase):
    def test_capability_is_exact_method_policy_url_and_single_use(self) -> None:
        token = create_relay_capability(
            secret=RELAY_SECRET,
            policy_id="local-app",
            raw_url="https://local.test:8443/app",
            now=100,
        )
        replay_guard = ReplayGuard()
        capability = verify_relay_capability(
            token,
            secret=RELAY_SECRET,
            policy_id="local-app",
            raw_url="https://local.test:8443/app",
            replay_guard=replay_guard,
            now=101,
        )
        self.assertEqual(capability.method, "GET")

        with self.assertRaises(RelayCapabilityError):
            verify_relay_capability(
                token,
                secret=RELAY_SECRET,
                policy_id="local-app",
                raw_url="https://local.test:8443/app",
                replay_guard=replay_guard,
                now=101,
            )

    def test_capability_rejects_expiry_policy_and_url_changes(self) -> None:
        token = create_relay_capability(
            secret=RELAY_SECRET,
            policy_id="local-app",
            raw_url="http://local.test:8080/app",
            ttl_seconds=10,
            now=100,
        )
        for policy_id, raw_url, now in (
            ("other", "http://local.test:8080/app", 101),
            ("local-app", "http://local.test:8080/admin", 101),
            ("local-app", "http://local.test:8080/app", 111),
        ):
            with self.subTest(policy_id=policy_id, raw_url=raw_url, now=now):
                with self.assertRaises(RelayCapabilityError):
                    verify_relay_capability(
                        token,
                        secret=RELAY_SECRET,
                        policy_id=policy_id,
                        raw_url=raw_url,
                        replay_guard=ReplayGuard(),
                        now=now,
                    )

    def test_capability_rejects_short_secret_and_excessive_ttl(self) -> None:
        with self.assertRaises(RelayCapabilityError):
            create_relay_capability(
                secret="short",
                policy_id="local-app",
                raw_url="http://local.test:8080/",
            )
        with self.assertRaises(RelayCapabilityError):
            create_relay_capability(
                secret=RELAY_SECRET,
                policy_id="local-app",
                raw_url="http://local.test:8080/",
                ttl_seconds=31,
            )


class RelayBoundaryTests(unittest.TestCase):
    def test_request_accepts_only_confined_auth_headers(self) -> None:
        request = RelayFetchRequest(
            capability="x" * 40,
            policy_id="local-app",
            url="http://local.test:8080/",
            headers={"Authorization": "Bearer redacted", "X-Api-Key": "redacted"},
        )
        self.assertEqual(len(request.headers), 2)
        for forbidden in (
            {"Cookie": "secret"},
            {"Proxy-Authorization": "secret"},
            {"Connection": "keep-alive"},
            {"X-Api-Key": "bad\r\ninjected"},
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(ValueError):
                    RelayFetchRequest(
                        capability="x" * 40,
                        policy_id="local-app",
                        url="http://local.test:8080/",
                        headers=forbidden,
                    )

    def test_response_headers_strip_hop_by_hop_and_unneeded_metadata(self) -> None:
        safe = safe_response_headers(
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'",
                "connection": "keep-alive",
                "server": "sensitive-version",
                "x-powered-by": "sensitive-framework",
            }
        )
        self.assertEqual(
            safe,
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'",
            },
        )

    def test_cookie_values_are_redacted_before_crossing_the_relay_boundary(self) -> None:
        projected = redact_set_cookie_value(
            "session=super-secret-cookie; HttpOnly; Secure; SameSite=Lax"
        )

        self.assertEqual(
            projected,
            "session=[REDACTED]; HttpOnly; Secure; SameSite=Lax",
        )
        self.assertNotIn("super-secret-cookie", projected)


if __name__ == "__main__":
    unittest.main()
