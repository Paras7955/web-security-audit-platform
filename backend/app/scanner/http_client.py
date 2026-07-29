from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

import httpcore
import httpx

from app.core.config import settings
from app.scanner.relay_capability import RelayCapabilityError, create_relay_capability
from app.security.allowlist import AllowlistTarget, ScanAllowlist
from app.security.redirects import RedirectValidationError, validate_redirect_location
from app.security.ssrf import DestinationValidation, Resolver, resolve_host, validate_destination
from app.security.target_url import (
    NormalizedTargetUrl,
    TargetUrlError,
    match_allowlisted_target,
    normalize_target_url,
)


class ScannerHttpError(ValueError):
    pass


@dataclass(frozen=True)
class ScannerHttpResponse:
    url: NormalizedTargetUrl
    status_code: int
    headers: dict[str, str]
    body: str
    redirect_chain: tuple[str, ...]
    set_cookie_headers: tuple[str, ...] = ()


class GuardedHttpClient:
    def __init__(
        self,
        *,
        allowlist_target: AllowlistTarget,
        timeout_seconds: int,
        resolver: Resolver = resolve_host,
        body_bytes_limit: int = 65536,
        default_headers: dict[str, str] | None = None,
        relay_base_url: str | None = settings.scan_relay_url,
        relay_secret: str | None = settings.scan_relay_secret,
        execution_checkpoint: Callable[[], None] | None = None,
    ) -> None:
        self.allowlist_target = allowlist_target
        self.timeout_seconds = timeout_seconds
        self.resolver = resolver
        self.body_bytes_limit = body_bytes_limit
        self.default_headers = default_headers or {}
        self.relay_base_url = relay_base_url.rstrip("/") if relay_base_url else None
        self.relay_secret = relay_secret
        self.execution_checkpoint = execution_checkpoint

    def get(self, raw_url: str) -> ScannerHttpResponse:
        if self.execution_checkpoint is not None:
            self.execution_checkpoint()
        if self.relay_base_url is not None:
            return self._get_via_relay(raw_url)
        current_url, current_destination = self._validate_url(raw_url)
        redirect_chain: list[str] = []

        for _attempt in range(self.allowlist_target.max_redirects + 1):
            if self.execution_checkpoint is not None:
                self.execution_checkpoint()
            try:
                transport = PinnedHttpTransport(
                    normalized_url=current_url,
                    destination=current_destination,
                    ssl_context=build_ssl_context(self.allowlist_target),
                )
                with httpx.Client(
                    follow_redirects=False,
                    timeout=self.timeout_seconds,
                    trust_env=False,
                    transport=transport,
                ) as client:
                    request_url = build_pinned_request_url(current_url, current_destination)
                    with client.stream("GET", request_url, headers=self._request_headers(current_url)) as response:
                        if not is_redirect(response.status_code):
                            return ScannerHttpResponse(
                                url=current_url,
                                status_code=response.status_code,
                                headers={key.lower(): value for key, value in response.headers.items()},
                                body=decode_limited_body(read_limited_body(response, self.body_bytes_limit), self.body_bytes_limit),
                                redirect_chain=tuple(redirect_chain),
                                set_cookie_headers=tuple(response.headers.get_list("set-cookie")),
                            )

                        location = response.headers.get("location")
            except httpx.HTTPError as exc:
                raise ScannerHttpError(str(exc)) from exc

            if len(redirect_chain) >= self.allowlist_target.max_redirects:
                raise ScannerHttpError("redirect limit exceeded")
            try:
                next_url, next_destination = validate_redirect_location(
                    current_url,
                    location or "",
                    self.allowlist_target,
                    self.resolver,
                )
            except RedirectValidationError as exc:
                raise ScannerHttpError(str(exc)) from exc

            redirect_chain.append(urljoin(current_url.normalized_url, location or ""))
            current_url = next_url
            current_destination = next_destination

        raise ScannerHttpError("request did not complete")

    def _get_via_relay(self, raw_url: str) -> ScannerHttpResponse:
        try:
            match = match_allowlisted_target(
                raw_url,
                ScanAllowlist(targets=[self.allowlist_target]),
            )
            capability = create_relay_capability(
                secret=self.relay_secret or "",
                policy_id=self.allowlist_target.id,
                raw_url=match.url.normalized_url,
            )
        except (TargetUrlError, RelayCapabilityError, ValueError) as exc:
            raise ScannerHttpError("relay request authorization failed") from exc

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=self.timeout_seconds,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST",
                    f"{self.relay_base_url}/v1/fetch",
                    json={
                        "capability": capability,
                        "policy_id": self.allowlist_target.id,
                        "url": match.url.normalized_url,
                        "headers": self.default_headers,
                    },
                ) as response:
                    if response.status_code != 200:
                        raise ScannerHttpError("relay request was denied")
                    response_bytes = read_limited_body(
                        response,
                        self.body_bytes_limit + 65_536,
                    )
            payload = httpx.Response(
                status_code=200,
                content=response_bytes,
            ).json()
            if not isinstance(payload, dict):
                raise ScannerHttpError("relay response was invalid")
            returned_url = normalize_target_url(str(payload.get("url", "")))
            returned_match = match_allowlisted_target(
                returned_url.normalized_url,
                ScanAllowlist(targets=[self.allowlist_target]),
            )
            if returned_match.allowlist_target.id != self.allowlist_target.id:
                raise ScannerHttpError("relay response policy was invalid")
            headers = payload.get("headers")
            redirect_chain = payload.get("redirect_chain")
            set_cookie_headers = payload.get("set_cookie_headers")
            body = payload.get("body")
            status_code = payload.get("status_code")
            if (
                not isinstance(headers, dict)
                or not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items())
                or not isinstance(redirect_chain, list)
                or not all(isinstance(item, str) for item in redirect_chain)
                or not isinstance(set_cookie_headers, list)
                or not all(isinstance(item, str) for item in set_cookie_headers)
                or not isinstance(body, str)
                or not isinstance(status_code, int)
            ):
                raise ScannerHttpError("relay response was invalid")
            return ScannerHttpResponse(
                url=returned_url,
                status_code=status_code,
                headers=headers,
                body=body[: self.body_bytes_limit],
                redirect_chain=tuple(redirect_chain[: self.allowlist_target.max_redirects]),
                set_cookie_headers=tuple(set_cookie_headers[:4]),
            )
        except (httpx.HTTPError, ValueError) as exc:
            if isinstance(exc, ScannerHttpError):
                raise
            raise ScannerHttpError("relay request failed") from exc

    def _validate_url(self, raw_url: str) -> tuple[NormalizedTargetUrl, DestinationValidation]:
        normalized = normalize_target_url(raw_url)
        destination = validate_destination(normalized, self.allowlist_target, resolver=self.resolver)
        return normalized, destination

    def _request_headers(self, current_url: NormalizedTargetUrl) -> dict[str, str]:
        headers = dict(self.default_headers)
        headers["Host"] = build_host_header(current_url)
        return headers


def is_redirect(status_code: int) -> bool:
    return status_code in {301, 302, 303, 307, 308}


def decode_limited_body(content: bytes, body_bytes_limit: int) -> str:
    return content[:body_bytes_limit].decode("utf-8", errors="replace")


def build_pinned_request_url(normalized_url: NormalizedTargetUrl, destination: DestinationValidation) -> str:
    del destination
    return normalized_url.normalized_url


def build_host_header(normalized_url: NormalizedTargetUrl) -> str:
    return f"{normalized_url.host}:{normalized_url.port}"


def read_limited_body(response: httpx.Response, body_bytes_limit: int) -> bytes:
    body = bytearray()
    for chunk in response.iter_bytes():
        remaining = body_bytes_limit - len(body)
        if remaining <= 0:
            break
        body.extend(chunk[:remaining])
    return bytes(body)


def build_ssl_context(allowlist_target: AllowlistTarget) -> ssl.SSLContext:
    if allowlist_target.tls.trust == "system":
        context = ssl.create_default_context()
    else:
        ca_bundle_path = Path(allowlist_target.tls.ca_bundle_path or "")
        if not ca_bundle_path.is_file() or ca_bundle_path.is_symlink():
            raise ScannerHttpError("custom CA bundle is unavailable")
        try:
            context = ssl.create_default_context(cafile=str(ca_bundle_path))
        except (OSError, ssl.SSLError) as exc:
            raise ScannerHttpError("custom CA bundle is invalid") from exc
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class PinnedNetworkBackend(httpcore.NetworkBackend):
    def __init__(
        self,
        *,
        normalized_url: NormalizedTargetUrl,
        destination: DestinationValidation,
        backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.normalized_url = normalized_url
        self.destination = destination
        self.backend = backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        if host.lower() != self.normalized_url.host or port != self.normalized_url.port:
            raise httpcore.ConnectError("pinned transport rejected an unexpected origin")
        return self.backend.connect_tcp(
            self.destination.connection_ip,
            self.destination.connection_port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options=None):
        del path, timeout, socket_options
        raise httpcore.ConnectError("pinned transport does not support Unix sockets")

    def sleep(self, seconds: float) -> None:
        self.backend.sleep(seconds)


class PinnedHttpTransport(httpx.HTTPTransport):
    def __init__(
        self,
        *,
        normalized_url: NormalizedTargetUrl,
        destination: DestinationValidation,
        ssl_context: ssl.SSLContext,
        network_backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(
                normalized_url=normalized_url,
                destination=destination,
                backend=network_backend,
            ),
        )
