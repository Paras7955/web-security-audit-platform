#!/usr/bin/env python3
"""Create missing local ScopeHarbor secrets without replacing user-managed values."""

from __future__ import annotations

import argparse
import base64
import os
import secrets
from pathlib import Path

GENERATORS = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "DEV_AUTH_TOKEN": lambda: secrets.token_urlsafe(32),
    "AUTH_PROFILE_SECRET_KEY": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
    "ZAP_API_KEY": lambda: secrets.token_hex(32),
}
PLACEHOLDERS = {
    "",
    "changeme",
    "dev-token",
    "example",
    "replace-with-a-generated-fernet-key",
    "replace-with-generated-fernet-key",
}


def bootstrap(destination: Path, template: Path) -> tuple[list[str], list[str]]:
    if destination.exists():
        lines = destination.read_text(encoding="utf-8").splitlines()
    else:
        lines = template.read_text(encoding="utf-8").splitlines()

    generated: list[str] = []
    preserved: list[str] = []
    key_index: dict[str, int] = {}
    values: dict[str, str] = {}
    for index, line in enumerate(lines):
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        key_index[key] = index
        values[key] = value.strip()

    for key, generator in GENERATORS.items():
        current = values.get(key, "")
        if current.lower() not in PLACEHOLDERS:
            preserved.append(key)
            continue
        replacement = generator()
        if key in key_index:
            lines[key_index[key]] = f"{key}={replacement}"
        else:
            lines.append(f"{key}={replacement}")
        values[key] = replacement
        generated.append(key)

    if values.get("NEXT_PUBLIC_DEV_AUTH_TOKEN", "").lower() in PLACEHOLDERS:
        key = "NEXT_PUBLIC_DEV_AUTH_TOKEN"
        replacement = values["DEV_AUTH_TOKEN"]
        if key in key_index:
            lines[key_index[key]] = f"{key}={replacement}"
        else:
            lines.append(f"{key}={replacement}")
        generated.append(key)

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
