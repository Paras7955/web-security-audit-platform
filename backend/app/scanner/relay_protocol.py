from __future__ import annotations

import base64
import binascii

MAX_RELAY_BODY_BYTES = 1_048_576
MAX_RELAY_COOKIE_PROJECTIONS = 4
MAX_RELAY_RESPONSE_HEADERS = 50
MAX_RELAY_RESPONSE_HEADER_BYTES = 16 * 1024
MAX_RELAY_URL_LENGTH = 4096
MAX_RELAY_REDIRECTS = 10
_MAX_JSON_SCALAR_EXPANSION = 6
_MAX_COOKIE_PROJECTION_BYTES = 256
_FIXED_ENVELOPE_BYTES = 8192


def encode_relay_body(body: str, *, source_bytes_limit: int) -> str:
    encoded = body.encode("utf-8")
    if len(body) > source_bytes_limit or len(encoded) > source_bytes_limit * 3:
        raise ValueError("relay body exceeds its source limit")
    return base64.b64encode(encoded).decode("ascii")


def decode_relay_body(value: str, *, source_bytes_limit: int) -> str:
    if len(value) > source_bytes_limit * 4:
        raise ValueError("relay body projection exceeds its limit")
    try:
        decoded = base64.b64decode(value, validate=True)
        body = decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("relay body projection is invalid") from exc
    if len(decoded) > source_bytes_limit * 3 or len(body) > source_bytes_limit:
        raise ValueError("relay body projection exceeds its limit")
    return body


def relay_response_envelope_bytes_limit(*, body_bytes_limit: int, max_redirects: int) -> int:
    bounded_redirects = min(max(max_redirects, 0), MAX_RELAY_REDIRECTS)
    body_projection = body_bytes_limit * 4
    header_projection = MAX_RELAY_RESPONSE_HEADER_BYTES * _MAX_JSON_SCALAR_EXPANSION
    url_projection = (
        MAX_RELAY_URL_LENGTH
        * (bounded_redirects + 1)
        * _MAX_JSON_SCALAR_EXPANSION
    )
    cookie_projection = MAX_RELAY_COOKIE_PROJECTIONS * _MAX_COOKIE_PROJECTION_BYTES
    return (
        body_projection
        + header_projection
        + url_projection
        + cookie_projection
        + _FIXED_ENVELOPE_BYTES
    )
