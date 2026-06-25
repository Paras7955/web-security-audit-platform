from dataclasses import dataclass
from pathlib import Path

from app.core.contracts import Confidence, Severity
from app.findings.schemas import NormalizedFindingInput


@dataclass(frozen=True)
class RepoScanResult:
    findings: tuple[NormalizedFindingInput, ...]
    errors: tuple[str, ...]


def run_repo_stub_scan(*, repo_path: Path) -> RepoScanResult:
    findings = run_gitleaks_stub(repo_path=repo_path) + run_dependency_stub(repo_path=repo_path)
    return RepoScanResult(findings=findings, errors=())


def run_gitleaks_stub(*, repo_path: Path) -> tuple[NormalizedFindingInput, ...]:
    fixture_file = repo_path / ".env.example"
    affected_file = safe_relative_path(fixture_file if fixture_file.exists() else repo_path, repo_path)
    return (
        NormalizedFindingInput(
            title="Potential hardcoded secret detected by deterministic stub",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            affected_file=affected_file,
            evidence="stub_secret=[REDACTED]",
            source_tool="gitleaks-stub",
            scanner_rule_id="stub-generic-secret",
            cwe="CWE-798",
            owasp_category="A02:2021",
            reproduction_steps="Review the referenced file path using the deterministic repo scanner stub output.",
            remediation="Remove hardcoded secrets and load sensitive values from an approved local secret source.",
            redaction_applied=True,
        ),
    )


def run_dependency_stub(*, repo_path: Path) -> tuple[NormalizedFindingInput, ...]:
    manifest = first_existing(repo_path, ("package-lock.json", "requirements.txt", "pyproject.toml"))
    if manifest is None:
        return (
            NormalizedFindingInput(
                title="Dependency scan skipped by deterministic stub",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                affected_file=safe_relative_path(repo_path, repo_path),
                evidence="No supported dependency manifest or lockfile was found by the deterministic stub.",
                source_tool="dependency-stub",
                scanner_rule_id="stub-no-supported-manifest",
                cwe=None,
                owasp_category=None,
                reproduction_steps="Add a supported manifest or lockfile before running a dependency scan.",
                remediation="Supported examples include package-lock.json and requirements.txt.",
                redaction_applied=True,
            ),
        )
    return (
        NormalizedFindingInput(
            title="Dependency advisory detected by deterministic stub",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_file=safe_relative_path(manifest, repo_path),
            evidence="Stub advisory metadata only; no package installation or repository code execution occurred.",
            source_tool="dependency-stub",
            scanner_rule_id="stub-dependency-advisory",
            cwe="CWE-1104",
            owasp_category="A06:2021",
            reproduction_steps="Review the referenced manifest with the deterministic dependency scanner stub output.",
            remediation="Update affected dependencies after confirming the advisory with a real scanner in a later phase.",
            redaction_applied=True,
        ),
    )


def first_existing(repo_path: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = repo_path / name
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def safe_relative_path(path: Path, repo_path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_path.resolve()))
    except ValueError:
        return "."
