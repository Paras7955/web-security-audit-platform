from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException, Query

from app.core.config import settings


@dataclass(frozen=True)
class PageRequest:
    limit: int
    cursor_created_at: datetime | None
    cursor_id: str | None


def page_request(
    limit: int = Query(default=settings.page_default_limit, ge=1, le=settings.page_max_limit),
    cursor: str | None = Query(default=None, max_length=512),
) -> PageRequest:
    if cursor is None:
        return PageRequest(limit=limit, cursor_created_at=None, cursor_id=None)
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode((cursor + padding).encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
        created_at = datetime.fromisoformat(value["created_at"])
        item_id = str(value["id"])
        if created_at.tzinfo is None or not item_id or len(item_id) > 64:
            raise ValueError
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid pagination cursor.") from exc
    return PageRequest(limit=limit, cursor_created_at=created_at, cursor_id=item_id)


def encode_cursor(created_at: datetime, item_id: str) -> str:
    raw = json.dumps(
        {"created_at": created_at.isoformat(), "id": item_id}, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def page_items[CursorItemT](items: Sequence[CursorItemT], limit: int) -> tuple[list[CursorItemT], str | None]:
    if len(items) <= limit:
        return list(items), None
    visible = list(items[:limit])
    last = visible[-1]
    created_at = getattr(last, "created_at", None)
    item_id = getattr(last, "id", None)
    if not isinstance(created_at, datetime) or not isinstance(item_id, str):
        raise TypeError("Paginated items must expose datetime created_at and string id values.")
    return visible, encode_cursor(created_at, item_id)
