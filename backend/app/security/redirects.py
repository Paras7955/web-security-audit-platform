from __future__ import annotations

from urllib.parse import urljoin

from app.security.allowlist import AllowlistTarget
from app.security.ssrf import DestinationValidation, Resolver, validate_destination
from app.security.target_url import NormalizedTargetUrl, TargetUrlError, normalize_target_url


class RedirectValidationError(ValueError):
    pass


def validate_redirect_location(
    current_url: NormalizedTargetUrl,
    location: str,
    allowlist_target: AllowlistTarget,
    resolver: Resolver,
) -> tuple[NormalizedTargetUrl, DestinationValidation]:
    if not location or not location.strip():
        raise RedirectValidationError("redirect location is empty")

    absolute_url = urljoin(current_url.normalized_url, location.strip())
    try:
        next_url = normalize_target_url(absolute_url)
        destination = validate_destination(next_url, allowlist_target, resolver=resolver)
    except (TargetUrlError, ValueError) as exc:
        raise RedirectValidationError("redirect destination is not allowed") from exc

    return next_url, destination


def validate_redirect_chain(
    start_url: NormalizedTargetUrl,
    locations: list[str],
    allowlist_target: AllowlistTarget,
    resolver: Resolver,
) -> list[NormalizedTargetUrl]:
    if len(locations) > allowlist_target.max_redirects:
        raise RedirectValidationError("redirect limit exceeded")

    current_url = start_url
    validated_urls: list[NormalizedTargetUrl] = []
    for location in locations:
        current_url, _destination = validate_redirect_location(current_url, location, allowlist_target, resolver)
        validated_urls.append(current_url)

    return validated_urls

