from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.security.sanitization import sanitize_metadata, sanitize_text


class SecretSafeJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        metadata = getattr(record, "scopeharbor_metadata", {})
        safe_metadata = sanitize_metadata(metadata) if isinstance(metadata, dict) else {}
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": sanitize_text(record.name, maximum=120) or "scopeharbor",
            "event": sanitize_text(record.getMessage(), maximum=200) or "event",
        }
        if isinstance(safe_metadata, dict):
            payload.update(safe_metadata)
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def configure_logging(level: int = logging.INFO) -> None:
    application_logger = logging.getLogger("scopeharbor")
    if any(getattr(handler, "scopeharbor_handler", False) for handler in application_logger.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(SecretSafeJsonFormatter())
    handler.scopeharbor_handler = True  # type: ignore[attr-defined]
    application_logger.addHandler(handler)
    application_logger.setLevel(level)
    application_logger.propagate = False


def log_event(logger: logging.Logger, event: str, **metadata: object) -> None:
    logger.info(event, extra={"scopeharbor_metadata": metadata})
