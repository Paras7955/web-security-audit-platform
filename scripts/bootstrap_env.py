#!/usr/bin/env python3
"""Create missing local ScopeHarbor secrets without replacing user-managed values."""

from __future__ import annotations

import argparse
import base64
import os
import secrets
from pathlib import Path
from urllib.parse import quote

GENERATORS = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "DEV_AUTH_TOKEN": lambda: secrets.token_urlsafe(32),
    "AUTH_PROFILE_SECRET_KEY": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
    "ZAP_API_KEY": lambda: secrets.token_hex(32),
    "SCAN_RELAY_SECRET": lambda: secrets.token_urlsafe(48),
}
PLACEHOLDERS = {
    "",
    "changeme",
    "dev-token",
    "example",
    "replace-with-a-generated-fernet-key",
    "replace-with-generated-fernet-key",
}


def _parse_values(lines: list[str]) -> tuple[dict[str, int], dict[str, str]]:
    key_index: dict[str, int] = {}
    values: dict[str, str] = {}
    for index, line in enumerate(lines):
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        key_index[key] = index
        values[key] = value.strip()
    return key_index, values


def _merge_template(lines: list[str], template_lines: list[str]) -> list[str]:
    key_index, _values = _parse_values(lines)
    missing: list[str] = []
    pending_comments: list[str] = []
    for line in template_lines:
        if not line or line.lstrip().startswith("#"):
            pending_comments.append(line)
            continue
        if "=" not in line:
            pending_comments.clear()
            continue
        key = line.split("=", 1)[0].strip()
        if key and key not in key_index:
            if pending_comments:
                missing.extend(pending_comments)
            missing.append(line)
        pending_comments.clear()
    if not missing:
        return lines
    if lines and lines[-1]:
        lines.append("")
    lines.extend(("# Added from the current .env.example by bootstrap.", *missing))
    return lines


def _set_value(lines: list[str], key: str, value: str, key_index: dict[str, int]) -> None:
    if key in key_index:
        lines[key_index[key]] = f"{key}={value}"
    else:
        key_index[key] = len(lines)
        lines.append(f"{key}={value}")


def bootstrap(destination: Path, template: Path) -> tuple[list[str], list[str]]:
    template_lines = template.read_text(encoding="utf-8").splitlines()
    if destination.exists():
        lines = destination.read_text(encoding="utf-8").splitlines()
        lines = _merge_template(lines, template_lines)
    else:
        lines = template_lines

    generated: list[str] = []
    preserved: list[str] = []
    key_index, values = _parse_values(lines)

    for key, generator in GENERATORS.items():
        current = values.get(key, "")
        is_user_managed_fernet = key == "AUTH_PROFILE_SECRET_KEY" and bool(current)
        if is_user_managed_fernet or current.lower() not in PLACEHOLDERS:
            preserved.append(key)
            continue
        replacement = generator()
        _set_value(lines, key, replacement, key_index)
        values[key] = replacement
        generated.append(key)

    if values.get("NEXT_PUBLIC_DEV_AUTH_TOKEN", "").lower() in PLACEHOLDERS:
        key = "NEXT_PUBLIC_DEV_AUTH_TOKEN"
        replacement = values["DEV_AUTH_TOKEN"]
        _set_value(lines, key, replacement, key_index)
        values[key] = replacement
        generated.append(key)

    database_url = values.get("DATABASE_URL", "")
    managed_database_url = not database_url or (
        database_url.startswith("postgresql+psycopg://") and "@postgres:5432/" in database_url
    )
    if managed_database_url:
        username = quote(values.get("POSTGRES_USER", "security_audit"), safe="")
        password = quote(values["POSTGRES_PASSWORD"], safe="")
        database = quote(values.get("POSTGRES_DB", "security_audit"), safe="")
        replacement = f"postgresql+psycopg://{username}:{password}@postgres:5432/{database}"
        _set_value(lines, "DATABASE_URL", replacement, key_index)
        values["DATABASE_URL"] = replacement
        generated.append("DATABASE_URL")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(6)}.tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, destination)
    destination.chmod(0o600)
    return generated, preserved


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    parser.add_argument("--template", type=Path, default=Path(".env.example"))
    args = parser.parse_args()
    generated, preserved = bootstrap(args.output, args.template)
    print(f"ScopeHarbor environment ready at {args.output} (mode 0600).")
    print(f"Generated missing values: {', '.join(generated) if generated else 'none'}.")
    print(f"Preserved existing secrets: {', '.join(preserved) if preserved else 'none'}.")


if __name__ == "__main__":
    main()
