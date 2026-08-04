from __future__ import annotations

from functools import lru_cache
from typing import Literal

from app.api.middleware import PublicSafetyMiddleware
from app.auth_profiles import ALLOWED_CUSTOM_HEADERS
from app.core.config import settings
from app.scanner.http_client import GuardedHttpClient, ScannerHttpError
from app.scanner.relay_capability import (
    RelayCapabilityError,
    ReplayGuard,
    validate_relay_secret,
    verify_relay_capability,
)
from app.scanner.relay_protocol import (
    MAX_RELAY_BODY_BYTES,
    MAX_RELAY_COOKIE_PROJECTIONS,
    MAX_RELAY_RESPONSE_HEADER_BYTES,
    MAX_RELAY_RESPONSE_HEADERS,
    MAX_RELAY_URL_LENGTH,
    encode_relay_body,
)
from app.security.allowlist import ScanAllowlist, load_allowlist
from app.security.target_url import TargetUrlError, match_allowlisted_target
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SAFE_RESPONSE_HEADERS = {
    "cache-control",
    "content-language",
    "content-security-policy",
    "content-type",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "location",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
}
MAX_REQUEST_HEADERS = 4
MAX_HEADER_NAME = 120
MAX_HEADER_VALUE = 4096
MAX_RELAY_REQUEST_BODY_BYTES = 64 * 1024


class RelayFetchRequest(BaseModel):
    capability: str = Field(min_length=40, max_length=4096)
    policy_id: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=MAX_RELAY_URL_LENGTH)
    headers: dict[str, str] = Field(default_factory=dict, max_length=MAX_REQUEST_HEADERS)

    model_config = ConfigDict(extra="forbid")

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        sanitized: dict[str, str] = {}
        for raw_name, raw_value in headers.items():
            name = raw_name.strip()
            value = raw_value.strip()
            lower_name = name.lower()
            if (
                not name
                or len(name) > MAX_HEADER_NAME
                or len(value) > MAX_HEADER_VALUE
                or "\r" in name
                or "\n" in name
                or "\r" in value
                or "\n" in value
                or lower_name in HOP_BY_HOP_HEADERS
                or (
                    lower_name != "authorization"
                    and lower_name not in ALLOWED_CUSTOM_HEADERS
                )
            ):
                raise ValueError("relay request contains an unsupported header")
            sanitized[name] = value
        return sanitized


class RelayCookieSecurity(BaseModel):
    http_only: bool
    secure: bool
    same_site: Literal["Lax", "None", "Strict"] | None

    model_config = ConfigDict(extra="forbid")


class RelayFetchResponse(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str]
    body_base64: str
    redirect_chain: list[str]
    cookie_security: list[RelayCookieSecurity]


app = FastAPI(
    title="ScopeHarbor Guarded Relay",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    PublicSafetyMiddleware,
    max_body_bytes=MAX_RELAY_REQUEST_BODY_BYTES,
)
replay_guard = ReplayGuard()


@lru_cache
def relay_allowlist() -> ScanAllowlist:
    return load_allowlist(settings.allowlist_path)


@app.on_event("startup")
def validate_relay_configuration() -> None:
    validate_relay_secret(settings.scan_relay_secret)
    if not 1 <= settings.scan_relay_body_bytes <= MAX_RELAY_BODY_BYTES:
        raise RuntimeError("SCAN_RELAY_BODY_BYTES is outside the relay safety limit.")
    relay_allowlist()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/fetch", response_model=RelayFetchResponse)
def fetch(payload: RelayFetchRequest) -> RelayFetchResponse:
    try:
        verify_relay_capability(
            payload.capability,
            secret=settings.scan_relay_secret,
            policy_id=payload.policy_id,
            raw_url=payload.url,
            replay_guard=replay_guard,
        )
        match = match_allowlisted_target(payload.url, relay_allowlist())
        if match.allowlist_target.id != payload.policy_id:
            raise RelayCapabilityError("relay policy mismatch")
        response = GuardedHttpClient(
            allowlist_target=match.allowlist_target,
            timeout_seconds=settings.scan_relay_request_timeout_seconds,
            body_bytes_limit=settings.scan_relay_body_bytes,
            default_headers=payload.headers,
            relay_base_url=None,
            relay_secret=None,
        ).get(payload.url)
    except (RelayCapabilityError, TargetUrlError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Relay request denied.",
        ) from None
    except ScannerHttpError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Relay request failed.",
        ) from None

    return RelayFetchResponse(
        url=response.url.normalized_url,
        status_code=response.status_code,
        headers=safe_response_headers(response.headers),
        body_base64=encode_relay_body(
            response.body,
            source_bytes_limit=settings.scan_relay_body_bytes,
        ),
        redirect_chain=list(response.redirect_chain),
        cookie_security=[
            RelayCookieSecurity(
                http_only=cookie.http_only,
                secure=cookie.secure,
                same_site=cookie.same_site,
            )
            for cookie in response.cookie_security[:MAX_RELAY_COOKIE_PROJECTIONS]
        ],
    )


def safe_response_headers(headers: dict[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    total = 0
    for name, value in headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS or lower_name not in SAFE_RESPONSE_HEADERS:
            continue
        bounded_name = lower_name[:MAX_HEADER_NAME]
        bounded_value = value[:MAX_HEADER_VALUE]
        projected = total + len(bounded_name.encode()) + len(bounded_value.encode())
        if (
            len(safe) >= MAX_RELAY_RESPONSE_HEADERS
            or projected > MAX_RELAY_RESPONSE_HEADER_BYTES
        ):
            break
        safe[bounded_name] = bounded_value
        total = projected
    return safe
