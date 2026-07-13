from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings, settings
from app.models import AuthProfile


class AuthProfileError(ValueError):
    pass


SUPPORTED_AUTH_PROFILE_TYPES = {"bearer_token", "custom_header"}
ALLOWED_CUSTOM_HEADERS = {
    "api-key",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
}
HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,119}$")
LOCAL_DEV_EXAMPLE_SECRET_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@dataclass(frozen=True)
class ScannerAuthMaterial:
    headers: dict[str, str]


def encrypt_secret(secret: str, config: Settings = settings) -> str:
    secret = secret.strip()
    if not secret:
        raise AuthProfileError("Auth profile secret is required.")
    return _fernet(config).encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(encrypted_secret: str, config: Settings = settings) -> str:
    if not encrypted_secret:
        raise AuthProfileError("Auth profile secret is not configured.")
    try:
        return _fernet(config).decrypt(encrypted_secret.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise AuthProfileError("Auth profile secret could not be decrypted.") from exc


def secret_hint(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 4:
        return "****"
    return f"****{secret[-4:]}"


def validate_profile_input(*, profile_type: str, header_name: str | None, secret: str) -> tuple[str, str | None, str]:
    normalized_type = profile_type.strip().lower()
    if normalized_type not in SUPPORTED_AUTH_PROFILE_TYPES:
        raise AuthProfileError("Unsupported auth profile type.")

    normalized_secret = secret.strip()
    if not normalized_secret:
        raise AuthProfileError("Auth profile secret is required.")

    if normalized_type == "bearer_token":
        return normalized_type, None, normalized_secret

    normalized_header = (header_name or "").strip()
    validate_custom_header_name(normalized_header)
    return normalized_type, normalized_header, normalized_secret


def validate_custom_header_name(header_name: str) -> None:
    if not header_name:
        raise AuthProfileError("Custom header auth profiles require a header name.")
    if not HEADER_NAME_PATTERN.fullmatch(header_name):
        raise AuthProfileError("Custom header name is invalid.")
    if header_name.lower() not in ALLOWED_CUSTOM_HEADERS:
        raise AuthProfileError("Custom header name must be an API key or auth token header.")


def build_scanner_auth_material(profile: AuthProfile, config: Settings = settings) -> ScannerAuthMaterial:
    if profile.revoked_at is not None or not profile.encrypted_secret:
        raise AuthProfileError("Auth profile is revoked.")
    secret = decrypt_secret(profile.encrypted_secret, config)
    if profile.profile_type == "bearer_token":
        return ScannerAuthMaterial(headers={"Authorization": f"Bearer {secret}"})
    if profile.profile_type == "custom_header":
        if profile.header_name is None:
            raise AuthProfileError("Custom header auth profile is missing a header name.")
        validate_custom_header_name(profile.header_name)
        return ScannerAuthMaterial(headers={profile.header_name: secret})
    raise AuthProfileError("Unsupported auth profile type.")


def validate_auth_profile_secret_settings(config: Settings = settings) -> None:
    key = config.auth_profile_secret_key.strip()
    if not key:
        raise AuthProfileError("AUTH_PROFILE_SECRET_KEY is required.")
    _fernet(config)
    if config.app_env.strip().lower() != "local" and key == LOCAL_DEV_EXAMPLE_SECRET_KEY:
        raise AuthProfileError("AUTH_PROFILE_SECRET_KEY must be replaced outside local development.")


def _fernet(config: Settings) -> Fernet:
    try:
        return Fernet(config.auth_profile_secret_key.strip().encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise AuthProfileError("AUTH_PROFILE_SECRET_KEY must be a valid Fernet key.") from exc
