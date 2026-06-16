from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from app.security.allowlist import AllowlistTarget
from app.security.redirects import RedirectValidationError, validate_redirect_location
from app.security.ssrf import Resolver, resolve_host, validate_destination
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


class GuardedHttpClient:
    def __init__(
        self,
        *,
        allowlist_target: AllowlistTarget,
        timeout_seconds: int,
        resolver: Resolver = resolve_host,
        body_bytes_limit: int = 65536,
    ) -> None:
        self.allowlist_target = allowlist_target
        self.timeout_seconds = timeout_seconds
        self.resolver = resolver
        self.body_bytes_limit = body_bytes_limit

    def get(self, raw_url: str) -> ScannerHttpResponse:
        current_url = self._validate_url(raw_url)
        redirect_chain: list[str] = []

        with httpx.Client(follow_redirects=False, timeout=self.timeout_seconds) as client:
            for _attempt in range(self.allowlist_target.max_redirects + 1):
                response = client.get(current_url.normalized_url)
                if not is_redirect(response.status_code):
                    return ScannerHttpResponse(
                        url=current_url,
                        status_code=response.status_code,
                        headers={key.lower(): value for key, value in response.headers.items()},
                        body=decode_limited_body(response.content, self.body_bytes_limit),
                        redirect_chain=tuple(redirect_chain),
                    )

                location = response.headers.get("location")
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

        raise ScannerHttpError("request did not complete")

    def _validate_url(self, raw_url: str) -> NormalizedTargetUrl:
        normalized = normalize_target_url(raw_url)
        validate_destination(normalized, self.allowlist_target, resolver=self.resolver)
        return normalized


def is_redirect(status_code: int) -> bool:
    return status_code in {301, 302, 303, 307, 308}


def decode_limited_body(content: bytes, body_bytes_limit: int) -> str:
    return content[:body_bytes_limit].decode("utf-8", errors="replace")
