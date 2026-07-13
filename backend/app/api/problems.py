from __future__ import annotations

from http import HTTPStatus
from uuid import uuid4

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


SAFE_DEFAULTS = {
    400: "The request could not be processed.",
    401: "Authentication is required.",
    403: "Access is not permitted.",
    404: "The requested resource was not found.",
    409: "The request conflicts with current state.",
    413: "The request body is too large.",
    422: "The request did not pass validation.",
    429: "Too many requests.",
    500: "An internal error occurred.",
    503: "The service is not ready.",
}


def problem_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    detail: str | None = None,
    errors: list[dict[str, object]] | None = None,
) -> JSONResponse:
    title = HTTPStatus(status_code).phrase if status_code in HTTPStatus._value2member_map_ else "Error"
    body: dict[str, object] = {
        "type": f"https://scopeharbor.local/problems/{code}",
        "title": title,
        "status": status_code,
        "detail": detail or SAFE_DEFAULTS.get(status_code, "The request could not be completed."),
        "instance": request.url.path,
        "code": code,
        "request_id": getattr(request.state, "request_id", str(uuid4())),
    }
    if errors:
        body["errors"] = errors
    return JSONResponse(body, status_code=status_code, media_type="application/problem+json")


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else None
    code = getattr(exc, "code", None) or f"http_{exc.status_code}"
    return problem_response(request, status_code=exc.status_code, code=code, detail=detail)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [
        {
            "location": ".".join(str(part) for part in error.get("loc", ())),
            "message": str(error.get("msg", "Invalid value"))[:300],
            "type": str(error.get("type", "validation_error"))[:100],
        }
        for error in exc.errors()[:50]
    ]
    return problem_response(request, status_code=422, code="request_validation_failed", errors=errors)


async def unhandled_exception_handler(request: Request, _exc: Exception) -> JSONResponse:
    return problem_response(request, status_code=500, code="internal_error")
