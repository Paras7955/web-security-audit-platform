from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.contracts import ScanMode


class AllowlistError(ValueError):
    pass


class AllowlistTarget(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=2048)
    schemes: list[str] = Field(min_length=1)
    hosts: list[str] = Field(min_length=1)
    ports: list[int] = Field(min_length=1)
    allowed_modes: list[ScanMode] = Field(min_length=1)
    max_redirects: int = Field(ge=0, le=10)
    local_demo: bool
    notes: str | None = None

    model_config = ConfigDict(frozen=True)

    @field_validator("schemes")
    @classmethod
    def validate_schemes(cls, schemes: list[str]) -> list[str]:
        normalized = [scheme.lower() for scheme in schemes]
        if len(normalized) != 1:
            raise ValueError("each allowlist target must define exactly one scheme")
        # The guarded client pins the validated destination IP. Safe TLS support
        # additionally requires correct SNI and certificate verification, which
        # is intentionally not declared until that transport exists.
        invalid = [scheme for scheme in normalized if scheme != "http"]
        if invalid:
            raise ValueError("ScopeHarbor 1.0 allowlist targets must use exact HTTP Docker service URLs")
        return normalized

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, hosts: list[str]) -> list[str]:
        normalized = [host.lower().strip() for host in hosts]
        if len(normalized) != 1:
            raise ValueError("each allowlist target must define exactly one host")
        if any(not host for host in normalized):
            raise ValueError("hosts cannot be empty")
        if any("*" in host for host in normalized):
            raise ValueError("wildcard hosts are not allowed")
        return normalized

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        if len(ports) != 1:
            raise ValueError("each allowlist target must define exactly one port")
        for port in ports:
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port: {port}")
        return ports

    @model_validator(mode="after")
    def validate_base_url(self) -> "AllowlistTarget":
        parsed = urlparse(self.base_url)
        if parsed.scheme not in self.schemes:
            raise ValueError("base_url scheme must be listed in schemes")
        if not parsed.hostname or parsed.hostname.lower() not in self.hosts:
            raise ValueError("base_url host must be listed in hosts")

        port = parsed.port or default_port(parsed.scheme)
        if port not in self.ports:
            raise ValueError("base_url port must be listed in ports")

        if parsed.username or parsed.password:
            raise ValueError("base_url must not contain credentials")
        if not self.local_demo:
            raise ValueError("ScopeHarbor 1.0 targets must be explicitly marked as local demo services")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", self.hosts[0]):
            raise ValueError("ScopeHarbor 1.0 target hosts must be exact Docker service names")
        return self


class ScanAllowlist(BaseModel):
    targets: list[AllowlistTarget] = Field(min_length=1)

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def validate_unique_entries(self) -> "ScanAllowlist":
        ids = [target.id for target in self.targets]
        duplicates = sorted({target_id for target_id in ids if ids.count(target_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate target ids: {duplicates}")

        endpoints = [
            (target.schemes[0], target.hosts[0], target.ports[0])
            for target in self.targets
        ]
        duplicate_endpoints = sorted({endpoint for endpoint in endpoints if endpoints.count(endpoint) > 1})
        if duplicate_endpoints:
            raise ValueError(f"duplicate allowlist endpoints: {duplicate_endpoints}")
        return self

    def get_target(self, allowlist_id: str) -> AllowlistTarget | None:
        return next((target for target in self.targets if target.id == allowlist_id), None)


def default_port(scheme: str) -> int:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    raise AllowlistError(f"unsupported URL scheme: {scheme}")


def load_allowlist(path: str | Path) -> ScanAllowlist:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw_config = yaml.safe_load(handle)
    except OSError as exc:
        raise AllowlistError(f"could not read allowlist config: {path}") from exc

    if not isinstance(raw_config, dict):
        raise AllowlistError("allowlist config must be a YAML mapping")

    try:
        return ScanAllowlist.model_validate(raw_config)
    except ValueError as exc:
        raise AllowlistError(str(exc)) from exc


def ensure_unique(values: Iterable[str], label: str) -> None:
    items = list(values)
    duplicates = sorted({item for item in items if items.count(item) > 1})
    if duplicates:
        raise AllowlistError(f"duplicate {label}: {duplicates}")
