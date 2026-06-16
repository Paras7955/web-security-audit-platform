import re

from app.core.contracts import DEFAULT_LIMITS


EVIDENCE_SNIPPET_CAP = int(DEFAULT_LIMITS["evidence_snippet_bytes"])
REDACTION_TOKEN = "[REDACTED]"

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s]+)"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)(set-cookie\s*:\s*)(.+)"),
    re.compile(r"(?i)(cookie\s*:\s*)(.+)"),
]


def redact_text(value: str | None) -> tuple[str | None, bool]:
    if value is None:
        return None, False

    redacted = value
    applied = False
    for pattern in SECRET_PATTERNS:
        updated = pattern.sub(_replace_secret_match, redacted)
        if updated != redacted:
            applied = True
            redacted = updated
    return redacted, applied


def prepare_evidence_snippet(value: str | None, max_bytes: int = EVIDENCE_SNIPPET_CAP) -> tuple[str | None, bool]:
    redacted, applied = redact_text(value)
    if redacted is None:
        return None, applied

    truncated = truncate_utf8(redacted, max_bytes)
    if truncated != redacted:
        applied = True
    return truncated, applied


def truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value

    clipped = encoded[:max_bytes]
    while True:
        try:
            return clipped.decode("utf-8")
        except UnicodeDecodeError:
            clipped = clipped[:-1]


def _replace_secret_match(match: re.Match[str]) -> str:
    if match.lastindex is None:
        return REDACTION_TOKEN
    if match.lastindex == 1:
        return f"{match.group(1)}{REDACTION_TOKEN}"
    return f"{match.group(1)}{REDACTION_TOKEN}"

