from __future__ import annotations

import json
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.core.config import Settings, settings
from app.core.contracts import Confidence, Severity
from app.findings.schemas import NormalizedFindingInput
from app.security.sanitization import sanitize_relative_path, sanitize_text

GITLEAKS_VERSION = "8.30.1"
OSV_SCANNER_VERSION = "2.5.0"


class RepoToolError(RuntimeError):
    code = "repo_tool_failed"


class RepoToolUnavailableError(RepoToolError):
    code = "repo_tool_unavailable"


class RepoToolTimeoutError(RepoToolError):
    code = "repo_tool_timeout"


class RepoToolOutputError(RepoToolError):
    code = "repo_tool_output_invalid"


@dataclass(frozen=True)
class ToolReceipt:
    tool_name: str
    tool_version: str | None
    status: str
    warning_code: str | None
    finding_count: int
    started_at: datetime
    completed_at: datetime


@dataclass(frozen=True)
class AdapterResult:
    findings: tuple[NormalizedFindingInput, ...]
    receipt: ToolReceipt


@dataclass(frozen=True)
class RepoScanResult:
    findings: tuple[NormalizedFindingInput, ...]
    receipts: tuple[ToolReceipt, ...]
    warning_codes: tuple[str, ...]


def verify_repo_tools(config: Settings = settings) -> dict[str, str]:
    return {
        "gitleaks": _verify_version(config.gitleaks_binary, GITLEAKS_VERSION),
        "osv-scanner": _verify_version(config.osv_scanner_binary, OSV_SCANNER_VERSION),
    }


def run_repository_scan(
    staged_root: Path,
    config: Settings = settings,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> RepoScanResult:
    gitleaks = run_gitleaks(staged_root, config, checkpoint=checkpoint)
    try:
        osv = run_osv_scanner(staged_root, config, checkpoint=checkpoint)
    except RepoToolError as exc:
        now = datetime.now(UTC)
        osv = AdapterResult(
            findings=(),
            receipt=ToolReceipt(
                tool_name="osv-scanner",
                tool_version=_optional_version(config.osv_scanner_binary, OSV_SCANNER_VERSION),
                status="skipped",
                warning_code=exc.code,
                finding_count=0,
                started_at=now,
                completed_at=now,
            ),
        )
    findings = (gitleaks.findings + osv.findings)[: config.repo_tool_max_findings * 2]
    warnings = tuple(receipt.warning_code for receipt in (gitleaks.receipt, osv.receipt) if receipt.warning_code)
    return RepoScanResult(findings=findings, receipts=(gitleaks.receipt, osv.receipt), warning_codes=warnings)


def run_gitleaks(
    staged_root: Path,
    config: Settings = settings,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> AdapterResult:
    version = _verify_version(config.gitleaks_binary, GITLEAKS_VERSION)
    started = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="gitleaks-output-") as output_dir:
        report_path = Path(output_dir) / "report.json"
        command = [
            config.gitleaks_binary,
            "dir",
            "--no-banner",
            "--no-color",
            "--redact=100",
            "--max-archive-depth=0",
            "--max-decode-depth=0",
            f"--max-target-megabytes={max(1, config.repo_max_file_bytes // (1024 * 1024))}",
            f"--timeout={config.repo_tool_timeout_seconds}",
            "--config",
            config.gitleaks_config_path,
            "--gitleaks-ignore-path",
            str(Path(output_dir) / "no-ignore-file"),
            "--report-format=json",
            "--report-path",
            str(report_path),
            str(staged_root),
        ]
        return_code = _run_tool(command, output_dir=Path(output_dir), config=config, checkpoint=checkpoint)
        if return_code not in {0, 1}:
            raise RepoToolError("Gitleaks did not complete safely.")
        payload = _load_json(report_path, config.repo_tool_output_bytes)
    if not isinstance(payload, list):
        raise RepoToolOutputError("Gitleaks output was not a JSON list.")
    findings = tuple(
        _gitleaks_finding(item, staged_root)
        for item in payload[: config.repo_tool_max_findings]
        if isinstance(item, dict)
    )
    return AdapterResult(
        findings=findings,
        receipt=ToolReceipt("gitleaks", version, "completed", None, len(findings), started, datetime.now(UTC)),
    )


def run_osv_scanner(
    staged_root: Path,
    config: Settings = settings,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> AdapterResult:
    version = _verify_version(config.osv_scanner_binary, OSV_SCANNER_VERSION)
    _validate_osv_database(config)
    started = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="osv-output-") as output_dir:
        report_path = Path(output_dir) / "report.json"
        command = [
            config.osv_scanner_binary,
            "scan",
            "source",
            "--recursive",
            "--offline",
            "--no-resolve",
            "--format=json",
            "--output-file",
            str(report_path),
            "--config",
            config.osv_config_path,
            str(staged_root),
        ]
        environment = {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": config.osv_database_path}
        return_code = _run_tool(
            command,
            output_dir=Path(output_dir),
            config=config,
            extra_environment=environment,
            checkpoint=checkpoint,
        )
        if return_code not in {0, 1, 128}:
            raise RepoToolError("OSV-Scanner did not complete safely.")
        payload = _load_json(report_path, config.repo_tool_output_bytes) if report_path.exists() else {"results": []}
    findings = _osv_findings(payload, staged_root, config.repo_tool_max_findings)
    return AdapterResult(
        findings=findings,
        receipt=ToolReceipt("osv-scanner", version, "completed", None, len(findings), started, datetime.now(UTC)),
    )


def _run_tool(
    command: list[str],
    *,
    output_dir: Path,
    config: Settings,
    extra_environment: dict[str, str] | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> int:
    environment = {
        "HOME": str(output_dir),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": str(output_dir),
    }
    environment.update(extra_environment or {})
    stdout_path = output_dir / "stdout"
    stderr_path = output_dir / "stderr"
    process: subprocess.Popen[bytes] | None = None
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            if checkpoint is not None:
                checkpoint()
            process = subprocess.Popen(  # noqa: S603 - argv-only invocation of startup-validated pinned binaries
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                cwd=output_dir,
                env=environment,
                start_new_session=True,
                umask=0o077,
            )
            _limit_process(
                process.pid,
                config.repo_tool_output_bytes,
                config.repo_tool_timeout_seconds,
            )
            deadline = time.monotonic() + config.repo_tool_timeout_seconds
            while True:
                if checkpoint is not None:
                    checkpoint()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, config.repo_tool_timeout_seconds)
                try:
                    return_code = process.wait(timeout=min(0.25, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
    except FileNotFoundError as exc:
        raise RepoToolUnavailableError("Required repository scanner is unavailable.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepoToolTimeoutError("Repository scanner exceeded its time limit.") from exc
    except OSError as exc:
        raise RepoToolError("Repository scanner could not start safely.") from exc
    finally:
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
    for output_path in (stdout_path, stderr_path):
        if output_path.stat().st_size > config.repo_tool_output_bytes:
            raise RepoToolOutputError("Repository scanner output exceeded its safety limit.")
    return return_code


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        process.kill()
    try:
        process.wait(timeout=1.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        process.kill()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        # The child is already signalled; never expose process details through
        # scanner status or logs.
        pass


def _limit_process(pid: int, max_output_bytes: int, timeout_seconds: int) -> None:
    prlimit = getattr(resource, "prlimit", None)
    if not callable(prlimit):
        raise RepoToolError("Repository scanner resource limits are unavailable.")
    prlimit(pid, resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
    prlimit(pid, resource.RLIMIT_CPU, (timeout_seconds, timeout_seconds + 1))


def _verify_version(binary: str, expected: str) -> str:
    resolved = shutil.which(binary)
    if resolved is None:
        raise RepoToolUnavailableError("Required repository scanner is unavailable.")
    try:
        result = subprocess.run(  # noqa: S603 - resolved executable, no shell, fixed version argument
            [resolved, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepoToolUnavailableError("Repository scanner version could not be verified.") from exc
    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0 or not re.search(rf"(?<!\d){re.escape(expected)}(?!\d)", output):
        raise RepoToolUnavailableError(f"Repository scanner must be pinned to version {expected}.")
    return expected


def _optional_version(binary: str, expected: str) -> str | None:
    try:
        return _verify_version(binary, expected)
    except RepoToolError:
        return None


def _load_json(path: Path, maximum: int) -> object:
    try:
        metadata = path.stat()
        if not path.is_file() or path.is_symlink() or metadata.st_size > maximum:
            raise RepoToolOutputError("Repository scanner output is invalid or oversized.")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RepoToolOutputError("Repository scanner output is not valid bounded JSON.") from exc


def _gitleaks_finding(item: dict[str, Any], staged_root: Path) -> NormalizedFindingInput:
    rule_id = sanitize_text(item.get("RuleID"), maximum=200) or "unknown-secret-rule"
    title = sanitize_text(item.get("Description"), maximum=240) or "Potential hardcoded secret"
    line = _safe_positive_int(item.get("StartLine"))
    return NormalizedFindingInput(
        title=title,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_file=_relative_scanner_path(item.get("File"), staged_root),
        evidence=f"[REDACTED] secret matched rule {rule_id} at line {line or 'unknown'}.",
        source_tool="gitleaks",
        scanner_rule_id=rule_id,
        cwe="CWE-798",
        owasp_category="A02:2021",
        reproduction_steps="Review the referenced source location without copying the secret into tickets or logs.",
        remediation="Revoke the exposed credential, remove it from source, and load a replacement from an approved secret store.",
    )


def _osv_findings(payload: object, staged_root: Path, maximum: int) -> tuple[NormalizedFindingInput, ...]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise RepoToolOutputError("OSV-Scanner output did not contain a results list.")
    findings: list[NormalizedFindingInput] = []
    for result in payload["results"]:
        if not isinstance(result, dict):
            continue
        source_value = result.get("source")
        source: dict[str, Any] = source_value if isinstance(source_value, dict) else {}
        source_path = _relative_scanner_path(source.get("path"), staged_root)
        packages_value = result.get("packages")
        packages: list[object] = packages_value if isinstance(packages_value, list) else []
        for package_result in packages:
            if not isinstance(package_result, dict):
                continue
            package_value = package_result.get("package")
            package: dict[str, Any] = package_value if isinstance(package_value, dict) else {}
            name = sanitize_text(package.get("name"), maximum=200) or "unknown-package"
            version = sanitize_text(package.get("version"), maximum=100) or "unknown"
            ecosystem = sanitize_text(package.get("ecosystem"), maximum=100) or "unknown"
            vulnerabilities_value = package_result.get("vulnerabilities")
            vulnerabilities: list[object] = vulnerabilities_value if isinstance(vulnerabilities_value, list) else []
            seen: set[str] = set()
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                advisory_id = sanitize_text(vulnerability.get("id"), maximum=200)
                if not advisory_id or advisory_id in seen:
                    continue
                seen.add(advisory_id)
                severity = _osv_severity(vulnerability)
                summary = sanitize_text(vulnerability.get("summary"), maximum=220) or "Known dependency vulnerability"
                findings.append(
                    NormalizedFindingInput(
                        title=f"{advisory_id}: {summary}"[:300],
                        severity=severity,
                        confidence=Confidence.HIGH,
                        affected_file=source_path,
                        evidence=f"advisory={advisory_id}; package={name}; version={version}; ecosystem={ecosystem}",
                        source_tool="osv-scanner",
                        scanner_rule_id=advisory_id,
                        cwe="CWE-1104",
                        owasp_category="A06:2021",
                        reproduction_steps="Confirm the package and version in the referenced lockfile against the advisory ID.",
                        remediation=f"Upgrade {name} to a non-affected version identified by {advisory_id}, then regenerate and review the lockfile.",
                    )
                )
                if len(findings) >= maximum:
                    return tuple(findings)
    return tuple(findings)


def _relative_scanner_path(value: object, staged_root: Path) -> str:
    if not isinstance(value, str):
        return "unknown"
    path = Path(value)
    if not path.is_absolute():
        return sanitize_relative_path(str(path)) or "unknown"
    try:
        return sanitize_relative_path(str(path.resolve().relative_to(staged_root.resolve()))) or "unknown"
    except (OSError, ValueError):
        return sanitize_relative_path(path.name) or "unknown"


def _osv_severity(vulnerability: dict[str, Any]) -> Severity:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        label = str(database_specific.get("severity") or "").lower()
        if label in {member.value for member in Severity}:
            return Severity(label)
    severity_items = vulnerability.get("severity")
    if isinstance(severity_items, list):
        for item in severity_items:
            if not isinstance(item, dict):
                continue
            score = str(item.get("score") or "")
            match = re.search(r"(?:^|/)CVSS:[^/]+/.*", score)
            if match and "/C:H" in score:
                return Severity.HIGH
    return Severity.MEDIUM


def _safe_positive_int(value: object) -> int | None:
    if not isinstance(value, str | bytes | int | float):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 < number < 10_000_000 else None


def _validate_osv_database(config: Settings) -> None:
    root = Path(config.osv_database_path) / "osv-scalibr"
    try:
        databases = [path for path in root.glob("*/all.zip") if path.is_file() and not path.is_symlink()]
    except OSError as exc:
        raise RepoToolUnavailableError("OSV offline database is unavailable.") from exc
    if not databases:
        error = RepoToolUnavailableError("OSV offline database is unavailable.")
        error.code = "osv_database_missing"
        raise error
    newest = max(path.stat().st_mtime for path in databases)
    if datetime.fromtimestamp(newest, tz=UTC) < datetime.now(UTC) - timedelta(days=config.osv_database_max_age_days):
        error = RepoToolUnavailableError("OSV offline database is stale.")
        error.code = "osv_database_stale"
        raise error
