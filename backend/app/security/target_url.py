from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.core.contracts import ScanMode
from app.security.allowlist import (
    AllowlistError,
    AllowlistTarget,
    ScanAllowlist,
    canonical_scope_path,
    default_port,
    path_is_within_scope,
)


class TargetUrlError(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedTargetUrl:
    original_url: str
    normalized_url: str
    scheme: str
    host: str
    port: int
    path: str


@dataclass(frozen=True)
class TargetMatch:
    url: NormalizedTargetUrl
    allowlist_target: AllowlistTarget

    @property
    def allowed_modes(self) -> list[ScanMode]:
        return list(self.allowlist_target.allowed_modes)


def normalize_target_url(raw_url: str) -> NormalizedTargetUrl:
    if not raw_url or not raw_url.strip():
        raise TargetUrlError("target URL is required")

    parsed = urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetUrlError("target URL must use http or https")
    if not parsed.hostname:
        raise TargetUrlError("target URL must include a hostname")
    if parsed.username or parsed.password:
        raise TargetUrlError("target URL must not include credentials")
    if parsed.fragment:
        raise TargetUrlError("target URL must not include a fragment")

    try:
        port = parsed.port or default_port(scheme)
    except (ValueError, AllowlistError) as exc:
        raise TargetUrlError("target URL has an invalid port") from exc

    host = parsed.hostname.lower()
    try:
        path = canonical_scope_path(parsed.path or "/")
    except ValueError as exc:
        raise TargetUrlError(str(exc)) from exc
    query = f"?{parsed.query}" if parsed.query else ""
    netloc_host = f"[{host}]" if ":" in host else host
    normalized_url = urlunsplit((scheme, f"{netloc_host}:{port}", path, parsed.query, ""))

    return NormalizedTargetUrl(
        original_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        host=host,
        port=port,
        path=f"{path}{query}",
    )


def match_allowlisted_target(raw_url: str, allowlist: ScanAllowlist) -> TargetMatch:
    normalized = normalize_target_url(raw_url)
    matches: list[AllowlistTarget] = []
    for target in allowlist.targets:
        if (
            normalized.scheme in target.schemes
            and normalized.host in target.hosts
            and normalized.port in target.ports
            and path_is_within_scope(normalized.path.split("?", 1)[0], target.base_path)
        ):
            matches.append(target)

    if len(matches) == 1:
        return TargetMatch(url=normalized, allowlist_target=matches[0])
    if len(matches) > 1:
        raise TargetUrlError("target URL matches ambiguous allowlist policies")
    raise TargetUrlError("target URL is not in the scan allowlist")
