from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass


class RelayCapabilityError(ValueError):
    pass


@dataclass(frozen=True)
class RelayCapability:
    policy_id: str
    method: str
    url_sha256: str
    issued_at: int
    expires_at: int
    nonce: str


class ReplayGuard:
    def __init__(self, *, maximum_entries: int = 10_000) -> None:
        self.maximum_entries = maximum_entries
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, nonce: str, expires_at: int, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        with self._lock:
            self._seen = {
                seen_nonce: expiry
                for seen_nonce, expiry in self._seen.items()
                if expiry >= current
            }
            if nonce in self._seen:
                raise RelayCapabilityError("relay capability was already used")
            if len(self._seen) >= self.maximum_entries:
                raise RelayCapabilityError("relay replay guard is at capacity")
            self._seen[nonce] = expires_at


def create_relay_capability(
    *,
    secret: str,
    policy_id: str,
    raw_url: str,
    ttl_seconds: int = 20,
    now: int | None = None,
) -> str:
    key = validate_relay_secret(secret)
    issued_at = int(time.time()) if now is None else now
    if ttl_seconds < 1 or ttl_seconds > 30:
        raise RelayCapabilityError("relay capability TTL must be between 1 and 30 seconds")
    payload = {
        "exp": issued_at + ttl_seconds,
        "iat": issued_at,
        "jti": secrets.token_urlsafe(18),
        "method": "GET",
        "policy_id": policy_id,
        "url_sha256": hashlib.sha256(raw_url.encode("utf-8")).hexdigest(),
    }
    encoded_payload = _encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = _encode(hmac.digest(key, encoded_payload.encode("ascii"), "sha256"))
    return f"{encoded_payload}.{signature}"


def verify_relay_capability(
    token: str,
    *,
    secret: str,
    policy_id: str,
    raw_url: str,
    replay_guard: ReplayGuard,
    now: int | None = None,
) -> RelayCapability:
    key = validate_relay_secret(secret)
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        supplied_signature = _decode(encoded_signature)
        expected_signature = hmac.digest(key, encoded_payload.encode("ascii"), "sha256")
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise RelayCapabilityError("relay capability signature is invalid")
        payload = json.loads(_decode(encoded_payload))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if isinstance(exc, RelayCapabilityError):
            raise
        raise RelayCapabilityError("relay capability is malformed") from exc
    if not isinstance(payload, dict):
        raise RelayCapabilityError("relay capability is malformed")

    try:
        capability = RelayCapability(
            policy_id=str(payload["policy_id"]),
            method=str(payload["method"]),
            url_sha256=str(payload["url_sha256"]),
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
            nonce=str(payload["jti"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RelayCapabilityError("relay capability is malformed") from exc
    current = int(time.time()) if now is None else now
    if capability.method != "GET":
        raise RelayCapabilityError("relay capability method is invalid")
    if capability.policy_id != policy_id:
        raise RelayCapabilityError("relay capability policy is invalid")
    if not capability.nonce or len(capability.nonce) > 100:
        raise RelayCapabilityError("relay capability nonce is invalid")
    if capability.issued_at > current + 2:
        raise RelayCapabilityError("relay capability is not yet valid")
    if capability.expires_at < current:
        raise RelayCapabilityError("relay capability expired")
    if capability.expires_at - capability.issued_at > 30:
        raise RelayCapabilityError("relay capability lifetime is invalid")
    expected_url_hash = hashlib.sha256(raw_url.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(capability.url_sha256, expected_url_hash):
        raise RelayCapabilityError("relay capability URL is invalid")
    replay_guard.consume(capability.nonce, capability.expires_at, now=current)
    return capability


def validate_relay_secret(secret: str) -> bytes:
    encoded = secret.encode("utf-8")
    if len(encoded) < 32:
        raise RelayCapabilityError("SCAN_RELAY_SECRET must contain at least 32 bytes")
    return encoded


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(
        f"{value}{padding}",
        altchars=b"-_",
        validate=True,
    )
