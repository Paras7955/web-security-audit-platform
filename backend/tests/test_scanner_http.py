import ssl
import unittest

import httpcore
import httpx
from app.scanner.http_client import (
    GuardedHttpClient,
    PinnedHttpTransport,
    PinnedNetworkBackend,
    ScannerHttpError,
    build_ssl_context,
    decode_limited_body,
)
from app.scanner.relay_protocol import encode_relay_body
from app.security.allowlist import AllowlistTarget, ScanAllowlist
from app.security.ssrf import DestinationValidation, validate_destination
from app.security.target_url import normalize_target_url

ALLOWLIST_TARGET = AllowlistTarget.model_validate(
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
)
RELAY_SECRET = "relay-test-secret-that-is-at-least-thirty-two-bytes"

def resolver(_host: str, _port: int) -> list[str]:
    return ["172.20.0.10"]


class RecordingNetworkBackend(httpcore.NetworkBackend):
    def __init__(self, stream=None) -> None:
        self.calls: list[tuple[str, int, float | None]] = []
        self.stream = stream or object()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        del local_address, socket_options
        self.calls.append((host, port, timeout))
        return self.stream

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        del path, timeout, socket_options
        raise AssertionError("Unix sockets are not expected")


class RecordingNetworkStream(httpcore.NetworkStream):
    def __init__(self) -> None:
        self.server_hostname: str | None = None
        self.ssl_context: ssl.SSLContext | None = None
        self.writes: list[bytes] = []
        self.response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

    def read(self, max_bytes, timeout=None):
        del timeout
        chunk, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return chunk

    def write(self, buffer, timeout=None):
        del timeout
        self.writes.append(buffer)

    def close(self):
        return None

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        del timeout
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        return self

    def get_extra_info(self, info):
        if info == "is_readable":
            return False
        return None


class ScannerHttpTests(unittest.TestCase):
    def test_decode_limited_body_caps_bytes(self) -> None:
        body = decode_limited_body(b"abcdef", 3)

        self.assertEqual(body, "abc")

    def test_guard_rejects_unallowlisted_host_before_request(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            relay_base_url=None,
        )

        with self.assertRaises(ValueError):
            client.get("http://example.com")

    def test_http_client_ignores_proxy_environment(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            relay_base_url=None,
        )
        captured_kwargs: dict[str, object] = {}

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                captured_kwargs.update(kwargs)
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertIs(captured_kwargs["trust_env"], False)

    def test_http_client_connects_to_validated_ip_with_original_host_header(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            relay_base_url=None,
        )
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.status_code, 200)
        self.assertEqual(str(seen_requests[0].url), "http://juice-shop:3000/")
        self.assertEqual(seen_requests[0].headers["host"], "juice-shop:3000")

    def test_pinned_backend_dials_only_the_validated_connection_ip(self) -> None:
        backend = RecordingNetworkBackend()
        pinned = PinnedNetworkBackend(
            normalized_url=normalize_target_url("https://app.example.test:8443/"),
            destination=DestinationValidation(
                host="app.example.test",
                port=8443,
                connection_host="scopeharbor-host",
                connection_port=9443,
                resolved_ips=("192.168.65.2",),
            ),
            backend=backend,
        )

        pinned.connect_tcp("app.example.test", 8443, timeout=2.0)

        self.assertEqual(backend.calls, [("192.168.65.2", 9443, 2.0)])
        with self.assertRaises(httpcore.ConnectError):
            pinned.connect_tcp("other.example.test", 8443, timeout=2.0)

    def test_http_client_injects_auth_headers_without_overriding_host(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            default_headers={"Authorization": "Bearer scanner-token"},
            relay_base_url=None,
        )
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen_requests[0].headers["authorization"], "Bearer scanner-token")
        self.assertEqual(seen_requests[0].headers["host"], "juice-shop:3000")

    def test_https_transport_preserves_origin_for_host_and_sni_while_pinning_tcp(self) -> None:
        target = ScanAllowlist.model_validate(
            {
                "version": 2,
                "targets": [
                    {
                        "id": "owned-demo",
                        "name": "Owned Demo",
                        "base_url": "https://owned.example.test:8443/",
                        "connection": {
                            "kind": "host_gateway",
                            "host": "scopeharbor-host",
                            "port": 9443,
                            "expected_ips": ["192.168.65.2"],
                        },
                        "profile_engines": {"passive-web": ["scopeharbor-passive"]},
                        "disposable_demo": False,
                        "tls": {"trust": "system"},
                        "max_redirects": 2,
                    }
                ],
            }
        ).targets[0]
        normalized = normalize_target_url("https://owned.example.test:8443/")
        destination = validate_destination(
            normalized,
            target,
            resolver=lambda _host, _port: ["192.168.65.2"],
        )
        stream = RecordingNetworkStream()
        backend = RecordingNetworkBackend(stream)
        context = build_ssl_context(target)
        transport = PinnedHttpTransport(
            normalized_url=normalized,
            destination=destination,
            ssl_context=context,
            network_backend=backend,
        )

        with httpx.Client(transport=transport, trust_env=False) as client:
            response = client.get(normalized.normalized_url, headers={"Host": "owned.example.test:8443"})

        self.assertEqual(response.text, "ok")
        self.assertEqual(backend.calls[0][:2], ("192.168.65.2", 9443))
        self.assertEqual(stream.server_hostname, "owned.example.test")
        self.assertIs(stream.ssl_context, context)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIn(b"Host: owned.example.test:8443", b"".join(stream.writes))

    def test_response_body_is_capped_through_client(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            body_bytes_limit=3,
            relay_base_url=None,
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"abcdef")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.body, "abc")

    def test_relay_response_accepts_maximum_expansion_and_structured_cookies(self) -> None:
        source_limit = 65_536
        body = "\ufffd" * source_limit
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            body_bytes_limit=source_limit,
            relay_base_url="http://relay:8001",
            relay_secret=RELAY_SECRET,
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "url": "http://juice-shop:3000/",
                    "status_code": 200,
                    "headers": {"content-type": "text/plain"},
                    "body_base64": encode_relay_body(
                        body,
                        source_bytes_limit=source_limit,
                    ),
                    "redirect_chain": [],
                    "cookie_security": [
                        {"http_only": True, "secure": True, "same_site": "Lax"}
                    ],
                },
            )

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.body, body)
        self.assertEqual(len(response.cookie_security), 1)
        self.assertEqual(response.cookie_security[0].same_site, "Lax")

    def test_multiple_set_cookie_headers_are_reduced_to_security_attributes(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            relay_base_url=None,
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers=[
                    (b"set-cookie", b"session=abc; HttpOnly; Secure; SameSite=Lax"),
                    (b"set-cookie", b"theme=light"),
                ],
                content=b"ok",
            )

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(
            [
                (cookie.http_only, cookie.secure, cookie.same_site)
                for cookie in response.cookie_security
            ],
            [(True, True, "Lax"), (False, False, None)],
        )

    def test_manual_redirects_are_guarded(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            relay_base_url=None,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/login"})
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.url.path, "/login")
        self.assertEqual(response.redirect_chain, ("http://juice-shop:3000/login",))

    def test_redirect_limit_is_enforced(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            relay_base_url=None,
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "/"})

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        try:
            httpx.Client = MockClient
            with self.assertRaises(ScannerHttpError):
                client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client


if __name__ == "__main__":
    unittest.main()
