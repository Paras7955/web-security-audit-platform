from __future__ import annotations

import logging
from time import monotonic
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import log_event


logger = logging.getLogger("scopeharbor.http")


class PublicSafetyMiddleware:
    """Apply bounded request handling and safe response metadata at the ASGI edge."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _request_id(Headers(scope=scope).get("x-request-id"))
        started = monotonic()
        status_code = 500
        scope.setdefault("state", {})["request_id"] = request_id
        content_length = Headers(scope=scope).get("content-length")
        if content_length and _too_large(content_length, self.max_body_bytes):
            await _send_too_large(send, request_id, str(scope.get("path", "")))
            log_event(
                logger,
                "http_request_completed",
                request_id=request_id,
                method=str(scope.get("method", ""))[:12],
                path=str(scope.get("path", ""))[:500],
                status=413,
                duration_ms=max(0, int((monotonic() - started) * 1000)),
            )
            return

        received = 0

        async def bounded_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge
            return message

        async def safe_send(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-request-id", request_id.encode("ascii")),
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, bounded_receive, safe_send)
        except RequestBodyTooLarge:
            status_code = 413
            await _send_too_large(send, request_id, str(scope.get("path", "")))
        finally:
            log_event(
                logger,
                "http_request_completed",
                request_id=request_id,
                method=str(scope.get("method", ""))[:12],
                path=str(scope.get("path", ""))[:500],
                status=status_code,
                duration_ms=max(0, int((monotonic() - started) * 1000)),
            )


class RequestBodyTooLarge(Exception):
    pass


def _request_id(value: str | None) -> str:
    if value and 1 <= len(value) <= 64 and all(character.isalnum() or character in "-_." for character in value):
        return value
    return str(uuid4())


def _too_large(value: str, maximum: int) -> bool:
    try:
        return int(value) > maximum
    except ValueError:
        return True


async def _send_too_large(send: Send, request_id: str, path: str) -> None:
    import json

    payload = json.dumps(
        {
            "type": "https://scopeharbor.local/problems/request_body_too_large",
            "title": "Content Too Large",
            "status": 413,
            "detail": "The request body is too large.",
            "instance": path,
            "code": "request_body_too_large",
            "request_id": request_id,
        }
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/problem+json"),
                (b"content-length", str(len(payload)).encode("ascii")),
                (b"x-request-id", request_id.encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})
