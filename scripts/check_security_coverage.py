from __future__ import annotations

import argparse
import json
from pathlib import Path

SECURITY_GROUPS = {
    "authentication": ("backend/app/security/auth.py",),
    "ssrf-and-redirects": (
        "backend/app/security/ssrf.py",
        "backend/app/security/redirects.py",
    ),
    "persistence-redaction": (
        "backend/app/security/sanitization.py",
        "backend/app/findings/redaction.py",
        "backend/app/findings/service.py",
    ),
    "artifact-paths": (
        "backend/app/scans/artifacts.py",
        "backend/app/findings/service.py",
    ),
    "repository-runner": (
        "backend/app/repo_scanner/adapters.py",
        "backend/app/repo_scanner/paths.py",
        "backend/app/repo_scanner/staging.py",
    ),
}


def group_coverage(payload: dict[str, object], paths: tuple[str, ...]) -> float:
    files = payload.get("files")
    if not isinstance(files, dict):
        raise ValueError("Coverage JSON does not contain file measurements.")
    covered = 0
    measured = 0
    for path in paths:
        entry = files.get(path)
        if not isinstance(entry, dict):
            raise ValueError(f"Coverage JSON is missing required boundary file: {path}")
        summary = entry.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"Coverage JSON has no summary for boundary file: {path}")
        covered += int(summary.get("covered_lines", 0)) + int(summary.get("covered_branches", 0))
        measured += int(summary.get("num_statements", 0)) + int(summary.get("num_branches", 0))
    if measured == 0:
        raise ValueError("Security boundary coverage had no measured statements or branches.")
    return covered * 100 / measured


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce ScopeHarbor security-boundary branch coverage.")
    parser.add_argument("coverage_json", type=Path)
    parser.add_argument("--minimum", type=float, default=95.0)
    args = parser.parse_args()

    payload = json.loads(args.coverage_json.read_text(encoding="utf-8"))
    failures: list[str] = []
    for name, paths in SECURITY_GROUPS.items():
        percent = group_coverage(payload, paths)
        print(f"{name}: {percent:.2f}%")
        if percent + 1e-9 < args.minimum:
            failures.append(f"{name} ({percent:.2f}% < {args.minimum:.2f}%)")
    if failures:
        print("Security coverage gate failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
