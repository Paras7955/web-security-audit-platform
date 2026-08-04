import asyncio
import json
import unittest

from app.api.middleware import PublicSafetyMiddleware
from app.scanner.cookies import parse_set_cookie_security
from app.scanner.relay_capability import (
    RelayCapabilityError,
    ReplayGuard,
    create_relay_capability,
    verify_relay_capability,
)
from app.scanner.relay_protocol import (
    decode_relay_body,
    encode_relay_body,
    relay_response_envelope_bytes_limit,
)
from fastapi.testclient import TestClient
from relay.main import (
    MAX_RELAY_REQUEST_BODY_BYTES,
    RelayFetchRequest,
    safe_response_headers,
)
from relay.main import (
    app as relay_app,
)

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
    def test_oversized_raw_request_body_is_rejected_before_json_parsing(self) -> None:
        response = TestClient(relay_app).post(
            "/v1/fetch",
            content=b"x" * (MAX_RELAY_REQUEST_BODY_BYTES + 1),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["code"], "request_body_too_large")

    def test_chunked_oversized_body_without_content_length_is_rejected(self) -> None:
        async def invoke() -> int:
            requests = iter(
                [
                    {
                        "type": "http.request",
                        "body": b"x" * (MAX_RELAY_REQUEST_BODY_BYTES // 2),
                        "more_body": True,
                    },
                    {
                        "type": "http.request",
                        "body": b"x" * (MAX_RELAY_REQUEST_BODY_BYTES // 2 + 1),
                        "more_body": False,
                    },
                ]
            )
            responses: list[dict[str, object]] = []

            async def receive() -> dict[str, object]:
                return next(requests)

            async def send(message: dict[str, object]) -> None:
                responses.append(message)

            async def drain_body(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
                del scope
                more_body = True
                while more_body:
                    message = await receive()
                    more_body = bool(message.get("more_body", False))
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b""})

            bounded_relay_edge = PublicSafetyMiddleware(
                drain_body,
                max_body_bytes=MAX_RELAY_REQUEST_BODY_BYTES,
            )
            await bounded_relay_edge(
                {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "http",
                    "path": "/v1/fetch",
                    "raw_path": b"/v1/fetch",
                    "query_string": b"",
                    "headers": [(b"content-type", b"application/json")],
                    "client": ("127.0.0.1", 12345),
                    "server": ("relay", 8001),
                },
                receive,
                send,
            )
            start = next(message for message in responses if message["type"] == "http.response.start")
            return int(start["status"])

        self.assertEqual(asyncio.run(invoke()), 413)

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

    def test_cookie_projection_discards_target_controlled_attributes(self) -> None:
        projected = parse_set_cookie_security(
            "session=secret; Path=/canary; Domain=canary.test; "
            "Priority=canary; Secure; SameSite=none; HttpOnly"
        )

        self.assertTrue(projected.http_only)
        self.assertTrue(projected.secure)
        self.assertEqual(projected.same_site, "None")
        self.assertNotIn("canary", repr(projected))
        self.assertNotIn("session", repr(projected))

    def test_cookie_projection_rejects_malformed_attributes(self) -> None:
        projected = parse_set_cookie_security(
            "session=secret; Secure=canary; HttpOnly=canary; SameSite=canary"
        )
        self.assertEqual(
            (projected.http_only, projected.secure, projected.same_site),
            (False, False, None),
        )

    def test_relay_body_projection_is_bounded_for_worst_case_text_expansion(self) -> None:
        source_limit = 65_536
        envelope_limit = relay_response_envelope_bytes_limit(
            body_bytes_limit=source_limit,
            max_redirects=10,
        )
        for body in ("\ufffd" * source_limit, "\x00" * source_limit):
            with self.subTest(character=repr(body[0])):
                encoded = encode_relay_body(body, source_bytes_limit=source_limit)
                envelope = json.dumps({"body_base64": encoded}).encode()
                self.assertLessEqual(len(envelope), envelope_limit)
                self.assertEqual(
                    decode_relay_body(encoded, source_bytes_limit=source_limit),
                    body,
                )


if __name__ == "__main__":
    unittest.main()
