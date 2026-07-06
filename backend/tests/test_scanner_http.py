import unittest

import httpx

from app.scanner.http_client import GuardedHttpClient, ScannerHttpError, decode_limited_body
from app.security.allowlist import AllowlistTarget


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

HTTPS_ALLOWLIST_TARGET = AllowlistTarget.model_validate(
    {
        "id": "owned-demo",
        "name": "Owned Demo",
        "base_url": "https://owned.example.test",
        "schemes": ["https"],
        "hosts": ["owned.example.test"],
        "ports": [443],
        "allowed_modes": ["passive"],
        "max_redirects": 2,
        "local_demo": False,
    }
)


def resolver(_host: str, _port: int) -> list[str]:
    return ["172.20.0.10"]


def public_resolver(_host: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


class ScannerHttpTests(unittest.TestCase):
    def test_decode_limited_body_caps_bytes(self) -> None:
        body = decode_limited_body(b"abcdef", 3)

        self.assertEqual(body, "abc")

    def test_guard_rejects_unallowlisted_host_before_request(self) -> None:
        client = GuardedHttpClient(allowlist_target=ALLOWLIST_TARGET, timeout_seconds=1, resolver=resolver)

        with self.assertRaises(ValueError):
            client.get("http://example.com")

    def test_http_client_ignores_proxy_environment(self) -> None:
        client = GuardedHttpClient(allowlist_target=ALLOWLIST_TARGET, timeout_seconds=1, resolver=resolver)
        captured_kwargs: dict[str, object] = {}

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                captured_kwargs.update(kwargs)
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertIs(captured_kwargs["trust_env"], False)

    def test_http_client_connects_to_validated_ip_with_original_host_header(self) -> None:
        client = GuardedHttpClient(allowlist_target=ALLOWLIST_TARGET, timeout_seconds=1, resolver=resolver)
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.status_code, 200)
        self.assertEqual(str(seen_requests[0].url), "http://172.20.0.10:3000/")
        self.assertEqual(seen_requests[0].headers["host"], "juice-shop:3000")

    def test_http_client_injects_auth_headers_without_overriding_host(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            default_headers={"Authorization": "Bearer scanner-token"},
        )
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen_requests[0].headers["authorization"], "Bearer scanner-token")
        self.assertEqual(seen_requests[0].headers["host"], "juice-shop:3000")

    def test_https_scanner_connection_fails_closed_until_tls_pinning_is_supported(self) -> None:
        client = GuardedHttpClient(allowlist_target=HTTPS_ALLOWLIST_TARGET, timeout_seconds=1, resolver=public_resolver)

        with self.assertRaisesRegex(ScannerHttpError, "http targets only"):
            client.get("https://owned.example.test/")

    def test_response_body_is_capped_through_client(self) -> None:
        client = GuardedHttpClient(
            allowlist_target=ALLOWLIST_TARGET,
            timeout_seconds=1,
            resolver=resolver,
            body_bytes_limit=3,
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"abcdef")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.body, "abc")

    def test_multiple_set_cookie_headers_are_preserved(self) -> None:
        client = GuardedHttpClient(allowlist_target=ALLOWLIST_TARGET, timeout_seconds=1, resolver=resolver)

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
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(
            response.set_cookie_headers,
            ("session=abc; HttpOnly; Secure; SameSite=Lax", "theme=light"),
        )

    def test_manual_redirects_are_guarded(self) -> None:
        client = GuardedHttpClient(allowlist_target=ALLOWLIST_TARGET, timeout_seconds=1, resolver=resolver)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/login"})
            return httpx.Response(200, content=b"ok")

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            response = client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.url.path, "/login")
        self.assertEqual(response.redirect_chain, ("http://juice-shop:3000/login",))

    def test_redirect_limit_is_enforced(self) -> None:
        client = GuardedHttpClient(allowlist_target=ALLOWLIST_TARGET, timeout_seconds=1, resolver=resolver)

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "/"})

        original_client = httpx.Client

        class MockClient(httpx.Client):
            def __init__(self, *args, **kwargs):
                super().__init__(transport=httpx.MockTransport(handler), *args, **kwargs)

        try:
            httpx.Client = MockClient
            with self.assertRaises(ScannerHttpError):
                client.get("http://juice-shop:3000/")
        finally:
            httpx.Client = original_client


if __name__ == "__main__":
    unittest.main()
