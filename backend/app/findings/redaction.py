from app.core.contracts import DEFAULT_LIMITS
from app.security.sanitization import REDACTION_TOKEN, sanitize_text


EVIDENCE_SNIPPET_CAP = int(DEFAULT_LIMITS["evidence_snippet_bytes"])
def redact_text(value: str | None) -> tuple[str | None, bool]:
    if value is None:
        return None, False

    redacted = sanitize_text(value, maximum=16_384)
    return redacted, redacted != value


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
