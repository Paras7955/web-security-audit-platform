from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

_SAME_SITE_VALUES: dict[str, Literal["Lax", "None", "Strict"]] = {
    "lax": "Lax",
    "none": "None",
    "strict": "Strict",
}


@dataclass(frozen=True)
class CookieSecurityAttributes:
    http_only: bool
    secure: bool
    same_site: Literal["Lax", "None", "Strict"] | None


def parse_set_cookie_security(value: str) -> CookieSecurityAttributes:
    """Extract only well-formed security attributes from a Set-Cookie value."""
    http_only = False
    secure = False
    same_site: Literal["Lax", "None", "Strict"] | None = None
    for raw_attribute in value.split(";")[1:]:
        raw_name, separator, raw_value = raw_attribute.strip().partition("=")
        name = raw_name.strip().lower()
        if name == "httponly" and not separator:
            http_only = True
            continue
        if name == "secure" and not separator:
            secure = True
            continue
        if name == "samesite" and separator:
            normalized_value = _SAME_SITE_VALUES.get(raw_value.strip().lower())
            if normalized_value is not None:
                same_site = normalized_value
    return CookieSecurityAttributes(
        http_only=http_only,
        secure=secure,
        same_site=same_site,
    )


def cookie_security_from_mapping(value: object) -> CookieSecurityAttributes:
    if not isinstance(value, dict) or set(value) != {"http_only", "secure", "same_site"}:
        raise ValueError("relay cookie security projection is invalid")
    http_only = value["http_only"]
    secure = value["secure"]
    same_site = value["same_site"]
    if not isinstance(http_only, bool) or not isinstance(secure, bool):
        raise ValueError("relay cookie security projection is invalid")
    if same_site not in {None, "Lax", "None", "Strict"}:
        raise ValueError("relay cookie security projection is invalid")
    return CookieSecurityAttributes(
        http_only=http_only,
        secure=secure,
        same_site=cast(Literal["Lax", "None", "Strict"] | None, same_site),
    )
