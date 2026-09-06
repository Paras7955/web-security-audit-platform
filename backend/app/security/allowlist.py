from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
from collections.abc import Iterable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit, urlunsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.contracts import ScanMode, scan_profile_for_id


class AllowlistError(ValueError):
    pass


class ScanEngine(StrEnum):
    SCOPEHARBOR_PASSIVE = "scopeharbor-passive"
    ZAP_PASSIVE = "zap-passive"
    ZAP_ACTIVE = "zap-active"
    ZAP_CLIENT_SPIDER = "zap-client-spider"
    REPOSITORY = "repository"


LEGACY_PROFILE_BY_MODE = {
    ScanMode.PASSIVE.value: "passive-web",
    ScanMode.ACTIVE_DEMO.value: "active-demo",
    ScanMode.MODERN_WEB_CRAWL.value: "modern-web-crawl",
    ScanMode.REPO.value: "repository",
}
LEGACY_ENGINES_BY_PROFILE = {
    "passive-web": [ScanEngine.SCOPEHARBOR_PASSIVE, ScanEngine.ZAP_PASSIVE],
    "active-demo": [ScanEngine.SCOPEHARBOR_PASSIVE, ScanEngine.ZAP_PASSIVE, ScanEngine.ZAP_ACTIVE],
    "modern-web-crawl": [
        ScanEngine.SCOPEHARBOR_PASSIVE,
        ScanEngine.ZAP_PASSIVE,
        ScanEngine.ZAP_CLIENT_SPIDER,
    ],
    "repository": [ScanEngine.REPOSITORY],
}
ALLOWED_ENGINES_BY_PROFILE = {
    profile_id: frozenset(engines)
    for profile_id, engines in LEGACY_ENGINES_BY_PROFILE.items()
}
REQUIRED_ENGINES_BY_PROFILE = {
    "passive-web": frozenset({ScanEngine.SCOPEHARBOR_PASSIVE}),
    "active-demo": frozenset(LEGACY_ENGINES_BY_PROFILE["active-demo"]),
    "modern-web-crawl": frozenset(LEGACY_ENGINES_BY_PROFILE["modern-web-crawl"]),
    "repository": frozenset({ScanEngine.REPOSITORY}),
}
DOCKER_SERVICE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
AMBIGUOUS_PERCENT_ENCODING = re.compile(r"%(?:00|2e|2f|5c)", re.IGNORECASE)
INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9a-fA-F]{2})")
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
UNIQUE_LOCAL_IPV6 = ipaddress.ip_network("fc00::/7")
MAX_CA_BUNDLE_BYTES = 1024 * 1024


class ComposeServiceConnection(BaseModel):
    kind: Literal["compose_service"]
    host: str = Field(min_length=1, max_length=63)
    port: int = Field(ge=1, le=65535)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("host")
    @classmethod
    def validate_host(cls, host: str) -> str:
        normalized = host.lower().strip()
        if not DOCKER_SERVICE_NAME.fullmatch(normalized):
            raise ValueError("compose_service host must be an exact Docker service name")
        return normalized


class HostGatewayConnection(BaseModel):
    kind: Literal["host_gateway"]
    host: str = Field(min_length=1, max_length=63)
    port: int = Field(ge=1, le=65535)
    expected_ips: list[str] = Field(min_length=1)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("host")
    @classmethod
    def validate_host(cls, host: str) -> str:
        normalized = host.lower().strip()
        if not DOCKER_SERVICE_NAME.fullmatch(normalized):
            raise ValueError("host_gateway host must be an exact Compose host-gateway alias")
        return normalized

    @field_validator("expected_ips")
    @classmethod
    def validate_expected_ips(cls, raw_ips: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw_ip in raw_ips:
            try:
                address = ipaddress.ip_address(raw_ip.strip())
            except ValueError as exc:
                raise ValueError("host_gateway expected_ips must contain exact IP addresses") from exc
            if not is_private_target_address(address):
                raise ValueError("host_gateway expected_ips must contain only RFC1918 or unique-local addresses")
            normalized.append(address.compressed)
        if len(normalized) != len(set(normalized)):
            raise ValueError("host_gateway expected_ips cannot contain duplicates")
        return sorted(normalized)


ConnectionPolicy = Annotated[
    ComposeServiceConnection | HostGatewayConnection,
    Field(discriminator="kind"),
]


class TlsPolicy(BaseModel):
    trust: Literal["system", "custom_ca"] = "system"
    ca_bundle_path: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_trust_material(self) -> TlsPolicy:
        if self.trust == "system" and self.ca_bundle_path is not None:
            raise ValueError("system TLS trust must not define ca_bundle_path")
        if self.trust == "custom_ca":
            if not self.ca_bundle_path:
                raise ValueError("custom_ca TLS trust requires ca_bundle_path")
            path = Path(self.ca_bundle_path)
            if not path.is_absolute():
                raise ValueError("custom CA bundle path must be absolute")
        return self


class AllowlistTarget(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=2048)
    connection: ConnectionPolicy
    profile_engines: dict[str, list[ScanEngine]] = Field(min_length=1)
    disposable_demo: bool = False
    tls: TlsPolicy = Field(default_factory=TlsPolicy)
    max_redirects: int = Field(ge=0, le=10)
    notes: str | None = None
    retired_modes: list[Literal[ScanMode.AJAX_SHORT]] = Field(default_factory=list, exclude=True, repr=False)
    legacy_mode_order: list[ScanMode] = Field(default_factory=list, exclude=True, repr=False)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def upgrade_legacy_target(cls, raw_value: object) -> object:
        if not isinstance(raw_value, Mapping):
            return raw_value
        if "connection" in raw_value:
            if "retired_modes" in raw_value or "legacy_mode_order" in raw_value:
                raise ValueError("v2 allowlist targets cannot set legacy compatibility fields")
            return raw_value

        value = dict(raw_value)
        raw_base_url = value.get("base_url")
        parsed = urlsplit(str(raw_base_url)) if raw_base_url is not None else None
        port = parsed.port or default_port(parsed.scheme) if parsed is not None else None
        host = parsed.hostname if parsed is not None else None
        modes = value.get("allowed_modes")
        if not isinstance(modes, list):
            return raw_value
        legacy_schemes = value.get("schemes")
        legacy_hosts = value.get("hosts")
        legacy_ports = value.get("ports")
        if (
            not isinstance(legacy_schemes, list)
            or len(legacy_schemes) != 1
            or str(legacy_schemes[0]).lower() != (parsed.scheme.lower() if parsed is not None else None)
        ):
            raise ValueError("legacy allowlist target must define one scheme matching base_url")
        if (
            not isinstance(legacy_hosts, list)
            or len(legacy_hosts) != 1
            or str(legacy_hosts[0]).lower().strip() != host
        ):
            raise ValueError("legacy allowlist target must define one exact host matching base_url")
        if not isinstance(legacy_ports, list) or legacy_ports != [port]:
            raise ValueError("legacy allowlist target must define one port matching base_url")

        disposable_demo = bool(value.get("local_demo", False))
        profile_engines: dict[str, list[ScanEngine]] = {}
        retired_modes: list[str] = []
        for raw_mode in modes:
            mode = str(raw_mode)
            if mode == ScanMode.AJAX_SHORT.value:
                retired_modes.append(mode)
                continue
            profile_id = LEGACY_PROFILE_BY_MODE.get(mode)
            if profile_id is not None:
                profile_engines[profile_id] = (
                    [ScanEngine.SCOPEHARBOR_PASSIVE]
                    if profile_id == "passive-web" and not disposable_demo
                    else list(LEGACY_ENGINES_BY_PROFILE[profile_id])
                )

        upgraded = {
            "id": value.get("id"),
            "name": value.get("name"),
            "base_url": raw_base_url,
            "connection": {
                "kind": "compose_service",
                "host": host,
                "port": port,
            },
            "profile_engines": profile_engines,
            "disposable_demo": disposable_demo,
            "tls": {"trust": "system"},
            "max_redirects": value.get("max_redirects"),
            "notes": value.get("notes"),
            "retired_modes": retired_modes,
            "legacy_mode_order": [str(mode) for mode in modes],
        }
        return upgraded

    @field_validator("base_url")
    @classmethod
    def validate_and_canonicalize_base_url(cls, base_url: str) -> str:
        try:
            parsed = urlsplit(base_url.strip())
            port = parsed.port or default_port(parsed.scheme.lower())
        except (ValueError, AllowlistError) as exc:
            raise ValueError("base_url is invalid") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("base_url must use http or https")
        if not parsed.hostname:
            raise ValueError("base_url must include an exact hostname")
        if parsed.username or parsed.password:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query or fragment")
        path = canonical_scope_path(parsed.path or "/")
        host = parsed.hostname.lower()
        netloc_host = f"[{host}]" if ":" in host else host
        serialized_path = "" if path == "/" else path
        return urlunsplit((parsed.scheme.lower(), f"{netloc_host}:{port}", serialized_path, "", ""))

    @field_validator("profile_engines")
    @classmethod
    def validate_profile_engines(
        cls,
        profile_engines: dict[str, list[ScanEngine]],
    ) -> dict[str, list[ScanEngine]]:
        normalized: dict[str, list[ScanEngine]] = {}
        for profile_id, engines in profile_engines.items():
            if scan_profile_for_id(profile_id) is None:
                raise ValueError(f"unknown scan profile in allowlist: {profile_id}")
            if not engines:
                raise ValueError(f"scan profile must declare at least one engine: {profile_id}")
            if len(engines) != len(set(engines)):
                raise ValueError(f"scan profile engines cannot contain duplicates: {profile_id}")
            allowed_engines = ALLOWED_ENGINES_BY_PROFILE.get(profile_id)
            if allowed_engines is None or not set(engines).issubset(allowed_engines):
                raise ValueError(f"scan profile declares an incompatible engine: {profile_id}")
            if not REQUIRED_ENGINES_BY_PROFILE[profile_id].issubset(engines):
                raise ValueError(f"scan profile is missing a required engine: {profile_id}")
            normalized[profile_id] = list(engines)
        return normalized

    @model_validator(mode="after")
    def validate_policy(self) -> AllowlistTarget:
        parsed = urlsplit(self.base_url)
        if "repository" in self.profile_engines and not self.legacy_mode_order:
            raise ValueError(
                "repository scans use separately authorized repository assets, not web target policies"
            )
        if self.connection.kind == "compose_service" and self.connection.host != parsed.hostname:
            # Compose aliases may intentionally differ only when the origin is a
            # virtual host. Require an explicit dotted/localhost origin in that case.
            origin_host = parsed.hostname or ""
            if "." not in origin_host and origin_host != "localhost":
                raise ValueError("compose_service connection host must match a simple origin host")
        if parsed.scheme == "http" and self.tls.trust != "system":
            raise ValueError("HTTP targets cannot declare custom TLS trust")
        zap_engines = {
            ScanEngine.ZAP_PASSIVE,
            ScanEngine.ZAP_ACTIVE,
            ScanEngine.ZAP_CLIENT_SPIDER,
        }
        if not self.disposable_demo and any(
            zap_engines.intersection(engines)
            for engines in self.profile_engines.values()
        ):
            raise ValueError("ZAP engines require disposable_demo=true")
        return self

    @property
    def schemes(self) -> list[str]:
        return [urlsplit(self.base_url).scheme]

    @property
    def hosts(self) -> list[str]:
        hostname = urlsplit(self.base_url).hostname
        return [hostname] if hostname is not None else []

    @property
    def ports(self) -> list[int]:
        parsed = urlsplit(self.base_url)
        return [parsed.port or default_port(parsed.scheme)]

    @property
    def allowed_modes(self) -> list[ScanMode]:
        if self.legacy_mode_order:
            return list(self.legacy_mode_order)
        modes: list[ScanMode] = []
        for profile_id in self.profile_engines:
            profile = scan_profile_for_id(profile_id)
            if profile is not None and profile.mode not in modes:
                modes.append(profile.mode)
        modes.extend(mode for mode in self.retired_modes if mode not in modes)
        return modes

    @property
    def local_demo(self) -> bool:
        return self.disposable_demo

    @property
    def base_path(self) -> str:
        return urlsplit(self.base_url).path or "/"

    @property
    def policy_fingerprint(self) -> str:
        ca_bundle_sha256 = None
        if self.tls.trust == "custom_ca":
            ca_bundle_sha256 = digest_custom_ca_bundle(Path(self.tls.ca_bundle_path or ""))
        projection = {
            "policy_version": 2,
            "id": self.id,
            "base_url": self.base_url,
            "connection": self.connection.model_dump(mode="json"),
            "profile_engines": {
                profile_id: sorted(engine.value for engine in engines)
                for profile_id, engines in sorted(self.profile_engines.items())
            },
            "disposable_demo": self.disposable_demo,
            "tls": self.tls.model_dump(mode="json"),
            "ca_bundle_sha256": ca_bundle_sha256,
            "max_redirects": self.max_redirects,
        }
        encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def engines_for_profile(self, profile_id: str) -> tuple[ScanEngine, ...]:
        return tuple(self.profile_engines.get(profile_id, ()))


class ScanAllowlist(BaseModel):
    version: Literal[2] = 2
    targets: list[AllowlistTarget] = Field(min_length=1)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def upgrade_legacy_document(cls, raw_value: object) -> object:
        if not isinstance(raw_value, Mapping):
            return raw_value
        upgraded = dict(raw_value)
        if upgraded.get("version") in {None, 1}:
            upgraded["version"] = 2
        return upgraded

    @model_validator(mode="after")
    def validate_unique_entries(self) -> ScanAllowlist:
        ids = [target.id for target in self.targets]
        duplicates = sorted({target_id for target_id in ids if ids.count(target_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate target ids: {duplicates}")

        for index, target in enumerate(self.targets):
            target_origin = origin_tuple(target.base_url)
            for other in self.targets[index + 1 :]:
                if target_origin != origin_tuple(other.base_url):
                    continue
                if path_is_within_scope(target.base_path, other.base_path) or path_is_within_scope(
                    other.base_path,
                    target.base_path,
                ):
                    raise ValueError(
                        f"ambiguous overlapping target base paths: {target.id}, {other.id}"
                    )
        return self

    def get_target(self, allowlist_id: str) -> AllowlistTarget | None:
        return next((target for target in self.targets if target.id == allowlist_id), None)


def default_port(scheme: str) -> int:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    raise AllowlistError(f"unsupported URL scheme: {scheme}")


def canonical_scope_path(path: str) -> str:
    if not path.startswith("/"):
        raise ValueError("URL path must be absolute")
    if "\\" in path or "\x00" in path or "//" in path:
        raise ValueError("URL path is ambiguous")
    if INVALID_PERCENT_ENCODING.search(path) or AMBIGUOUS_PERCENT_ENCODING.search(path):
        raise ValueError("URL path contains an ambiguous percent-encoding")
    decoded = unquote(path)
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("URL path must not contain dot segments")
    return path


def path_is_within_scope(path: str, base_path: str) -> bool:
    canonical_path = canonical_scope_path(path)
    canonical_base = canonical_scope_path(base_path)
    if canonical_base == "/":
        return True
    scope_root = canonical_base.rstrip("/")
    candidate = canonical_path.rstrip("/")
    return candidate == scope_root or canonical_path.startswith(f"{scope_root}/")


def origin_tuple(raw_url: str) -> tuple[str, str, int]:
    parsed = urlsplit(raw_url)
    hostname = parsed.hostname
    if hostname is None:
        raise AllowlistError("URL origin is missing a hostname")
    return parsed.scheme.lower(), hostname.lower(), parsed.port or default_port(parsed.scheme.lower())


def is_private_target_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in RFC1918_NETWORKS)
    return address in UNIQUE_LOCAL_IPV6


def load_allowlist(path: str | Path) -> ScanAllowlist:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw_config = yaml.safe_load(handle)
    except OSError as exc:
        raise AllowlistError(f"could not read allowlist config: {path}") from exc

    if not isinstance(raw_config, dict):
        raise AllowlistError("allowlist config must be a YAML mapping")

    try:
        allowlist = ScanAllowlist.model_validate(raw_config)
        validate_custom_ca_bundles(allowlist)
        return allowlist
    except ValueError as exc:
        raise AllowlistError(str(exc)) from exc


def validate_custom_ca_bundles(allowlist: ScanAllowlist) -> None:
    for target in allowlist.targets:
        if target.tls.trust != "custom_ca":
            continue
        path = Path(target.tls.ca_bundle_path or "")
        if not path.is_file() or path.is_symlink():
            raise AllowlistError("custom CA bundle must be a regular non-symlink file")
        try:
            if path.stat().st_size < 1 or path.stat().st_size > MAX_CA_BUNDLE_BYTES:
                raise AllowlistError("custom CA bundle size is invalid")
            ssl.create_default_context(cafile=str(path))
        except (OSError, ssl.SSLError) as exc:
            raise AllowlistError("custom CA bundle is invalid") from exc


def digest_custom_ca_bundle(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise AllowlistError("custom CA bundle must be a regular non-symlink file")
    try:
        size = path.stat().st_size
        if size < 1 or size > MAX_CA_BUNDLE_BYTES:
            raise AllowlistError("custom CA bundle size is invalid")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise AllowlistError("custom CA bundle could not be read") from exc


def ensure_unique(values: Iterable[str], label: str) -> None:
    items = list(values)
    duplicates = sorted({item for item in items if items.count(item) > 1})
    if duplicates:
        raise AllowlistError(f"duplicate {label}: {duplicates}")
