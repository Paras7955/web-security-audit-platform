from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from app.security.allowlist import AllowlistTarget
from app.security.redirects import RedirectValidationError, validate_redirect_location
from app.security.ssrf import DestinationValidation, Resolver, resolve_host, validate_destination
from app.security.target_url import NormalizedTargetUrl, normalize_target_url


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
    ) -> None:
        self.allowlist_target = allowlist_target
        self.timeout_seconds = timeout_seconds
        self.resolver = resolver
        self.body_bytes_limit = body_bytes_limit
        self.default_headers = default_headers or {}

    def get(self, raw_url: str) -> ScannerHttpResponse:
        current_url, current_destination = self._validate_url(raw_url)
        redirect_chain: list[str] = []

        with httpx.Client(follow_redirects=False, timeout=self.timeout_seconds, trust_env=False) as client:
            for _attempt in range(self.allowlist_target.max_redirects + 1):
                try:
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
                    next_url, _destination = validate_redirect_location(
                        current_url,
                        location or "",
                        self.allowlist_target,
                        self.resolver,
                    )
                except RedirectValidationError as exc:
                    raise ScannerHttpError(str(exc)) from exc

                redirect_chain.append(urljoin(current_url.normalized_url, location or ""))
                current_url = next_url
                current_destination = _destination

        raise ScannerHttpError("request did not complete")

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
    if normalized_url.scheme != "http":
        raise ScannerHttpError("pinned scanner connections currently support http targets only")

    parsed = urlparse(normalized_url.normalized_url)
    connection_host = destination.connection_ip
    if ":" in connection_host and not connection_host.startswith("["):
        connection_host = f"[{connection_host}]"
    return urlunparse((parsed.scheme, f"{connection_host}:{normalized_url.port}", parsed.path, "", parsed.query, ""))


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
