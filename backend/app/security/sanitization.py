from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit


REDACTION_TOKEN = "[REDACTED]"
SECRET_KEY_PARTS = ("authorization", "cookie", "credential", "password", "secret", "token", "api_key", "apikey")
SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)([^\s,;]+)"),
    re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|secret)\b\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)((?:set-)?cookie\s*:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(://)([^/@\s:]+):([^/@\s]+)@"),
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_url(value: str | None, *, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        port = f":{parsed.port}" if parsed.port else ""
        safe = urlunsplit((parsed.scheme.lower(), f"{parsed.hostname.lower()}{port}", parsed.path or "/", "", ""))
        return safe[:maximum]
    except (ValueError, UnicodeError):
        return None


def sanitize_text(value: object | None, *, maximum: int) -> str | None:
    if value is None:
        return None
    text = CONTROL_PATTERN.sub("", str(value))
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(_redact_match, text)
    text = URL_PATTERN.sub(lambda match: sanitize_url(match.group(0)) or "[URL REDACTED]", text)
    return text[:maximum]


def sanitize_relative_path(value: str | None, *, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    normalized = value.strip().replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        return "[PATH REDACTED]"
    safe_parts = [sanitize_text(part, maximum=255) or "_" for part in path.parts if part not in {"", "."}]
    return "/".join(safe_parts)[:maximum] or "."


def sanitize_metadata(value: object, *, depth: int = 0) -> Any:
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        safe: dict[str, object] = {}
        for raw_key, raw_value in list(value.items())[:50]:
            key = sanitize_text(raw_key, maximum=100) or "field"
            if any(part in key.lower().replace("-", "_") for part in SECRET_KEY_PARTS):
                safe[key] = REDACTION_TOKEN
            else:
                safe[key] = sanitize_metadata(raw_value, depth=depth + 1)
        return safe
    if isinstance(value, list):
        return [sanitize_metadata(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return sanitize_text(value, maximum=500)


def _redact_match(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 3 and match.group(1) == "://":
        return "://[REDACTED]@"
    prefix = match.group(1) if match.lastindex else ""
    return f"{prefix}{REDACTION_TOKEN}"
