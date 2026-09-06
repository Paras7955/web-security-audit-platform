import os
import stat
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai.service import (
    AiExplanationResult,
    read_ai_explanations,
)
from app.core.contracts import ScanMode, ScanStatus, scan_profile_for_values
from app.models import Finding, ReportArtifact, RepositoryAsset, Scan, ScannerToolRun, Target
from app.scans.artifacts import ArtifactPathError, ensure_scan_artifact_dir, scan_artifact_dir
from app.security.sanitization import sanitize_relative_path, sanitize_text, sanitize_url

REPORT_TYPES = ("markdown", "html")
REPORT_FILENAMES = {
    "markdown": "report.md",
    "html": "report.html",
}
TERMINAL_REPORT_STATUSES = {
    ScanStatus.COMPLETED.value,
    ScanStatus.COMPLETED_WITH_WARNINGS.value,
}
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ReportGenerationError(ValueError):
    pass


@dataclass(frozen=True)
class ReportFinding:
    id: str
    title: str
    severity: str
    confidence: str
    affected_url: str | None
    affected_file: str | None
    evidence: str | None
    source_tool: str
    scanner_rule_id: str | None
    cwe: str | None
    owasp_category: str | None
    reproduction_steps: str | None
    remediation: str | None
    false_positive_notes: str | None
    redaction_applied: bool
    created_at: datetime


@dataclass(frozen=True)
class ReportData:
    scan: Scan
    target: Target | RepositoryAsset
    findings: tuple[ReportFinding, ...]
    tool_runs: tuple["ReportToolRun", ...]
    completed_at: datetime
    guidance: AiExplanationResult


@dataclass(frozen=True)
class ReportToolRun:
    tool_name: str
    tool_version: str | None
    status: str
    warning_code: str | None
    finding_count: int
    started_at: datetime | None
    completed_at: datetime | None


def build_report_data(
    db: Session,
    *,
    scan_id: str,
    workspace_id: str,
) -> ReportData:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    if scan.status not in TERMINAL_REPORT_STATUSES:
        raise ReportGenerationError("Reports can only be generated for completed scans.")
    profile = scan_profile_for_values(scan.scan_profile_id, scan.mode)
    if profile is None or not profile.reports_enabled:
        raise ReportGenerationError(
            "Reports can only be generated for Passive Web, Active Demo, and Repository scans."
        )

    target = (
        db.scalar(
            select(Target).where(
                Target.id == scan.target_id,
                Target.workspace_id == workspace_id,
            )
        )
        if scan.target_id is not None
        else db.scalar(
            select(RepositoryAsset).where(
                RepositoryAsset.id == scan.repository_asset_id,
                RepositoryAsset.workspace_id == workspace_id,
            )
        )
    )
    if target is None:
        raise ReportGenerationError("Scan subject not found.")
    if target.workspace_id != scan.workspace_id:
        raise ReportGenerationError("Scan target workspace does not match scan workspace.")

    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id, Finding.workspace_id == scan.workspace_id)
        .order_by(Finding.severity.asc(), Finding.created_at.asc())
    ).all()
    sorted_findings = tuple(
        safe_report_finding(finding)
        for finding in sorted(findings, key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 99), finding.title.lower()))
    )
    tool_runs = tuple(
        ReportToolRun(
            tool_name=sanitize_text(tool_run.tool_name, maximum=100) or "unknown",
            tool_version=sanitize_text(tool_run.tool_version, maximum=100),
            status=sanitize_text(tool_run.status, maximum=40) or "unknown",
            warning_code=sanitize_text(tool_run.warning_code, maximum=100),
            finding_count=max(0, int(tool_run.finding_count)),
            started_at=tool_run.started_at,
            completed_at=tool_run.completed_at,
        )
        for tool_run in db.scalars(
            select(ScannerToolRun)
            .where(ScannerToolRun.scan_id == scan.id, ScannerToolRun.workspace_id == scan.workspace_id)
            .order_by(ScannerToolRun.created_at.asc(), ScannerToolRun.id.asc())
        ).all()
    )
    # Reports are intentionally local and deterministic. Even when the operator
    # configures an external provider for the interactive endpoint, generating
    # an artifact must not create network work, rate-limit reservations, cache
    # rows, or provider request logs.
    guidance = deduplicate_guidance(
        read_ai_explanations(
            db,
            scan_id=scan.id,
            workspace_id=workspace_id,
            provider_name="template",
            openai_model=None,
            cache_enabled=False,
            cache_context_version="report-v2",
        )
        if profile.ai_enabled
        else disabled_local_guidance(scan.id)
    )
    return ReportData(
        scan=scan,
        target=target,
        findings=sorted_findings,
        tool_runs=tool_runs,
        completed_at=report_timestamp(scan),
        guidance=guidance,
    )


def generate_report_artifacts(
    db: Session,
    *,
    scan_id: str,
    workspace_id: str,
    artifact_root: str | Path,
) -> list[ReportArtifact]:
    data = build_report_data(
        db,
        scan_id=scan_id,
        workspace_id=workspace_id,
    )
    ensure_scan_artifact_dir(artifact_root, scan_id)
    reports_dir = safe_report_dir(artifact_root, scan_id)

    rendered = {
        "markdown": render_markdown_report(data),
        "html": render_html_report(data),
    }

    artifacts: list[ReportArtifact] = []
    for report_type, content in rendered.items():
        path = reports_dir / REPORT_FILENAMES[report_type]
        write_report_file(path, content)
        artifact = get_or_create_report_artifact(db, scan=data.scan, report_type=report_type, path=path)
        artifacts.append(artifact)

    db.commit()
    for artifact in artifacts:
        db.refresh(artifact)
    return artifacts


def get_or_create_report_artifact(db: Session, *, scan: Scan, report_type: str, path: Path) -> ReportArtifact:
    artifact = db.scalar(
        select(ReportArtifact).where(
            ReportArtifact.scan_id == scan.id,
            ReportArtifact.report_type == report_type,
            ReportArtifact.workspace_id == scan.workspace_id,
        )
    )
    if artifact is None:
        artifact = ReportArtifact(
            id=str(uuid4()),
            workspace_id=scan.workspace_id,
            created_by_user_id=scan.created_by_user_id,
            scan_id=scan.id,
            report_type=report_type,
            path=str(path.resolve()),
        )
    else:
        artifact.workspace_id = scan.workspace_id
        artifact.created_by_user_id = scan.created_by_user_id
        artifact.path = str(path.resolve())
    db.add(artifact)
    try:
        with db.begin_nested():
            db.flush()
        return artifact
    except IntegrityError:
        concurrent = db.scalar(
            select(ReportArtifact).where(
                ReportArtifact.workspace_id == scan.workspace_id,
                ReportArtifact.scan_id == scan.id,
                ReportArtifact.report_type == report_type,
            )
        )
        if concurrent is None:
            raise
        return concurrent


def list_report_artifacts(db: Session, *, scan_id: str, workspace_id: str) -> list[ReportArtifact]:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    validate_report_artifact_read_eligibility(scan)
    return list(
        db.scalars(
            select(ReportArtifact)
            .where(
                ReportArtifact.scan_id == scan_id,
                ReportArtifact.workspace_id == scan.workspace_id,
            )
            .order_by(ReportArtifact.report_type.asc(), ReportArtifact.created_at.asc())
        ).all()
    )


def read_report_artifact(
    db: Session,
    artifact: ReportArtifact,
    *,
    artifact_root: str | Path,
    workspace_id: str,
) -> str:
    scan = db.scalar(
        select(Scan).where(
            Scan.id == artifact.scan_id,
            Scan.workspace_id == workspace_id,
        )
    )
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    if artifact.workspace_id != workspace_id:
        raise ReportGenerationError("Scan not found.")
    validate_report_artifact_read_eligibility(scan)
    return read_report_artifact_file(artifact, artifact_root=artifact_root)


def read_report_artifact_file(artifact: ReportArtifact, *, artifact_root: str | Path) -> str:
    path = validate_report_path(artifact.path, artifact_root, scan_id=artifact.scan_id, report_type=artifact.report_type)
    if path.is_symlink():
        raise ReportGenerationError("Report artifact file must not be a symlink.")
    if not path.exists() or not path.is_file():
        raise ReportGenerationError("Report artifact file not found.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 10 * 1024 * 1024:
                raise ReportGenerationError("Report artifact file is invalid.")
            return handle.read()
    except OSError as exc:
        raise ReportGenerationError("Report artifact file could not be read safely.") from exc


def validate_report_path(path: str, artifact_root: str | Path, *, scan_id: str, report_type: str) -> Path:
    expected_filename = REPORT_FILENAMES.get(report_type)
    if expected_filename is None:
        raise ReportGenerationError("Unsupported report artifact type.")

    candidate_path = Path(path)
    if not candidate_path.is_absolute():
        raise ReportGenerationError("Report artifact path must be absolute.")
    expected_path = safe_report_dir(artifact_root, scan_id) / expected_filename
    if candidate_path != expected_path:
        raise ReportGenerationError("Report artifact path does not match the expected report location.")
    return expected_path


def safe_report_dir(artifact_root: str | Path, scan_id: str) -> Path:
    try:
        scan_dir = scan_artifact_dir(artifact_root, scan_id)
    except ArtifactPathError as exc:
        raise ReportGenerationError(str(exc)) from exc

    reports_dir = scan_dir / "reports"
    if reports_dir.is_symlink():
        raise ReportGenerationError("Report artifact directory must not be a symlink.")

    reports_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    reports_dir.chmod(0o700)
    resolved_reports_dir = reports_dir.resolve()
    if scan_dir != resolved_reports_dir and scan_dir not in resolved_reports_dir.parents:
        raise ReportGenerationError("Report artifact directory escaped scan artifact directory.")
    return reports_dir


def write_report_file(path: Path, content: str) -> None:
    if path.is_symlink():
        raise ReportGenerationError("Report artifact file must not be a symlink.")
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ReportGenerationError("Report artifact could not be written safely.") from exc


def validate_report_scan_eligibility(scan: Scan) -> None:
    if scan.status not in TERMINAL_REPORT_STATUSES:
        raise ReportGenerationError("Reports can only be generated for completed scans.")
    if not scan_reports_enabled(scan):
        raise ReportGenerationError(
            "Reports can only be generated for Passive Web, Active Demo, and Repository scans."
        )


def validate_report_artifact_read_eligibility(scan: Scan) -> None:
    if scan.status not in TERMINAL_REPORT_STATUSES:
        raise ReportGenerationError("Reports can only be read for completed scans.")
    if scan.mode == ScanMode.AJAX_SHORT.value:
        return
    if not scan_reports_enabled(scan):
        raise ReportGenerationError("Reports are not available for this scan profile.")


def scan_reports_enabled(scan: Scan) -> bool:
    profile = scan_profile_for_values(scan.scan_profile_id, scan.mode)
    return bool(profile and profile.reports_enabled)


def disabled_local_guidance(scan_id: str) -> AiExplanationResult:
    return AiExplanationResult(
        scan_id=scan_id,
        provider="not_generated",
        fallback_used=False,
        provider_error=None,
        summary="Finding guidance is not generated for repository scans.",
        executive_summary="Finding guidance is not generated for this scan profile.",
        risk_score_explanation="No local risk guidance was generated.",
        scoring_model_version="risk-v1",
        input_fingerprint=None,
        cache_hit=False,
        groups=(),
        explanations=(),
    )


def safe_report_finding(finding: Finding) -> ReportFinding:
    return ReportFinding(
        id=finding.id,
        title=sanitize_text(finding.title, maximum=300) or "Security finding",
        severity=sanitize_text(finding.severity, maximum=40) or "info",
        confidence=sanitize_text(finding.confidence, maximum=40) or "low",
        affected_url=sanitize_url(finding.affected_url),
        affected_file=sanitize_relative_path(finding.affected_file),
        evidence=sanitize_text(finding.evidence, maximum=2048),
        source_tool=sanitize_text(finding.source_tool, maximum=100) or "unknown",
        scanner_rule_id=sanitize_text(finding.scanner_rule_id, maximum=200),
        cwe=sanitize_text(finding.cwe, maximum=100),
        owasp_category=sanitize_text(finding.owasp_category, maximum=100),
        reproduction_steps=sanitize_text(finding.reproduction_steps, maximum=16_384),
        remediation=sanitize_text(finding.remediation, maximum=16_384),
        false_positive_notes=sanitize_text(finding.false_positive_notes, maximum=16_384),
        redaction_applied=True,
        created_at=finding.created_at,
    )


def report_subject_type(data: ReportData) -> str:
    return "web target" if isinstance(data.target, Target) else "repository asset"


def report_subject_policy(data: ReportData) -> str:
    return data.target.allowlist_id if isinstance(data.target, Target) else "repository authorization snapshot"


def report_subject_scope(data: ReportData) -> str:
    if isinstance(data.target, Target):
        return sanitize_text(data.target.base_url, maximum=2048) or "redacted"
    return sanitize_relative_path(data.scan.repo_path_snapshot or data.target.relative_path) or "redacted-relative-path"


def report_authorization_context(data: ReportData) -> str:
    authorized_at = sanitize_text(data.scan.authorization_snapshot.get("authorized_at"), maximum=100)
    if authorized_at:
        return f"Confirmed in the immutable launch snapshot at {authorized_at}"
    if data.scan.authorization_snapshot or data.target.permission_confirmed:
        return "Confirmed before launch and retained in the audit record"
    return "Historical audit record; authorization time was not recorded"


def severity_counts(findings: tuple[ReportFinding, ...]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def severity_summary(findings: tuple[ReportFinding, ...]) -> str:
    counts = severity_counts(findings)
    material = [f"{counts[severity]} {severity}" for severity in ("critical", "high", "medium", "low", "info") if counts[severity]]
    return ", ".join(material) if material else "No normalized findings were recorded."


def render_markdown_report(data: ReportData) -> str:
    counts = severity_counts(data.findings)
    lines = [
        "# ScopeHarbor Security Audit Report",
        "",
        "> Local-first defensive assessment for an explicitly authorized subject.",
        "",
        "## Audit Overview",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Audit completed at | {markdown_inline(format_timestamp(data.completed_at))} |",
        f"| Subject | {markdown_inline(data.target.name)} |",
        f"| Subject type | {markdown_inline(report_subject_type(data))} |",
        f"| Authorized scope | {markdown_inline(report_subject_scope(data))} |",
        f"| Subject policy | {markdown_inline(report_subject_policy(data))} |",
        f"| Scan profile | {markdown_inline(data.scan.scan_profile_id)} |",
        f"| Scan status | {markdown_inline(data.scan.status)} |",
        f"| Scan ID | {markdown_inline(data.scan.id)} |",
        "",
        "## Executive Summary",
        "",
        markdown_inline(data.guidance.executive_summary),
        "",
        f"Severity distribution: {markdown_inline(severity_summary(data.findings))}",
        "",
        "## Severity Distribution",
        "",
        "| Critical | High | Medium | Low | Info | Total |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} | {len(data.findings)} |",
        "",
        "## Scope And Coverage",
        "",
        f"- Custom passive scanner: {tooling_used_unless_repo(data.scan.mode)}.",
        f"- ZAP passive analysis: {zap_passive_tooling(data.scan.mode)}.",
        f"- ZAP active scan: {tooling_used(data.scan.mode, ScanMode.ACTIVE_DEMO.value)}.",
        f"- Modern web crawl: {tooling_used(data.scan.mode, ScanMode.MODERN_WEB_CRAWL.value)}.",
        f"- Finding guidance: {guidance_tooling(data.guidance)}.",
        f"- Repo scanning: {tooling_used(data.scan.mode, ScanMode.REPO.value)}.",
        "- Authenticated workflows: not tested.",
        "- Business logic checks: not tested.",
        "- Arbitrary public scanning: unsupported.",
        "",
        "## Authorization And Data Handling",
        "",
        f"- Authorization context: {markdown_inline(report_authorization_context(data))}.",
        "- Evidence is normalized, independently redacted, and bounded before reporting.",
        "- Full HTTP response bodies, credentials, cookies, queries, and raw scanner output are excluded.",
        "- Finding guidance is deterministic and generated locally from normalized findings.",
        "",
        "## Responsible Use And Limitations",
        "",
        "This report supports local defensive learning and explicitly authorized testing only. It is not a professional penetration test, compliance audit, or guarantee that the subject is secure. Findings are bounded signals for qualified human review and may include false positives or false negatives.",
        "",
        "## Scanner Receipts",
        "",
        render_markdown_tool_runs(data.tool_runs),
        "",
        "## Prioritized Finding Guidance",
        "",
        render_markdown_guidance(data.guidance),
        "",
        "## Detailed Findings",
        "",
    ]

    if not data.findings:
        lines.extend(["No normalized findings were recorded for this scan.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(data.findings, start=1):
        lines.extend(
            [
                f"### {index}. [{markdown_inline(finding.severity.upper())}] {markdown_inline(finding.title)}",
                "",
                "| Attribute | Value |",
                "| --- | --- |",
                f"| Severity | {markdown_inline(finding.severity)} |",
                f"| Confidence | {markdown_inline(finding.confidence)} |",
                f"| Source tool | {markdown_inline(finding.source_tool)} |",
                f"| Scanner rule ID | {markdown_inline(finding.scanner_rule_id or 'not provided')} |",
                f"| CWE | {markdown_inline(finding.cwe or 'not mapped')} |",
                f"| OWASP category | {markdown_inline(finding.owasp_category or 'not mapped')} |",
                f"| Location | {markdown_inline(finding.affected_url or finding.affected_file or 'global')} |",
                f"| Redaction applied | {'yes' if finding.redaction_applied else 'no'} |",
                "",
                "**Evidence**",
                "",
                fenced_block(finding.evidence or "No evidence snippet recorded."),
                "",
                "**Reproduction Steps**",
                "",
                fenced_block(finding.reproduction_steps or "No reproduction steps recorded."),
                "",
                "**Remediation**",
                "",
                fenced_block(finding.remediation or "No remediation guidance recorded."),
                "",
                "**False Positive Notes**",
                "",
                fenced_block(finding.false_positive_notes or "No false-positive notes recorded."),
                "",
            ]
        )
    return "\n".join(lines)


def render_markdown_guidance(guidance: AiExplanationResult) -> str:
    lines = [
        f"- Method: {markdown_inline(guidance_tooling(guidance))}",
        f"- Executive summary: {markdown_inline(guidance.executive_summary)}",
        f"- Risk score context: {markdown_inline(guidance.risk_score_explanation)}",
        f"- Finding summary: {markdown_inline(guidance.summary)}",
        "- Limitation: Guidance uses only normalized, redacted findings and does not add vulnerability claims.",
        "- Occurrences: Equivalent guidance actions are grouped here; every normalized occurrence remains in Detailed Findings.",
    ]
    if guidance.groups:
        lines.extend(["", "### Finding Groups", ""])
        for group in guidance.groups:
            lines.append(f"- {markdown_inline(group.label)}: {group.count}")

    if guidance.explanations:
        lines.extend(["", "### Prioritized Actions", ""])
        for explanation in guidance.explanations:
            lines.extend(
                [
                    f"#### Finding {markdown_inline(explanation.finding_id)}",
                    "",
                    f"- Priority: {explanation.priority}",
                    f"- Summary: {markdown_inline(explanation.summary)}",
                    f"- Why it matters: {markdown_inline(explanation.why_it_matters)}",
                    f"- Recommended action: {markdown_inline(explanation.recommended_action)}",
                    f"- OWASP mapping: {markdown_inline(explanation.owasp_mapping)}",
                    f"- Limitations: {markdown_inline(explanation.limitations)}",
                    "",
                ]
            )
    return "\n".join(lines)


def render_markdown_tool_runs(tool_runs: tuple[ReportToolRun, ...]) -> str:
    if not tool_runs:
        return "No scanner tool receipts were recorded for this scan."
    lines: list[str] = []
    for run in tool_runs:
        lines.extend(
            [
                f"### {markdown_inline(run.tool_name)}",
                "",
                f"- Version: {markdown_inline(run.tool_version or 'not reported')}",
                f"- Status: {markdown_inline(run.status)}",
                f"- Warning code: {markdown_inline(run.warning_code or 'none')}",
                f"- Findings: {run.finding_count}",
                f"- Started at: {format_timestamp(run.started_at) if run.started_at else 'not reported'}",
                f"- Completed at: {format_timestamp(run.completed_at) if run.completed_at else 'not reported'}",
                "",
            ]
        )
    return "\n".join(lines)


def render_html_report(data: ReportData) -> str:
    counts = severity_counts(data.findings)
    finding_sections = "\n".join(render_html_finding(index, finding) for index, finding in enumerate(data.findings, start=1))
    if not finding_sections:
        finding_sections = '<p class="empty">No normalized findings were recorded for this scan.</p>'
    guidance_section = render_html_guidance(data.guidance)
    tool_run_section = render_html_tool_runs(data.tool_runs)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
  <title>ScopeHarbor Security Audit Report</title>
  <style>
    :root {{ color-scheme: light; --ink: #172033; --muted: #526078; --line: #d7dde7; --soft: #f4f6f9; --navy: #13233f; --accent: #b94716; --critical: #8a1c1c; --high: #b83b19; --medium: #8a5a00; --low: #1e5f82; --info: #4d596b; }}
    * {{ box-sizing: border-box; }}
    html {{ background: #eef1f5; }}
    body {{ background: #fff; color: var(--ink); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; font-size: 15px; line-height: 1.58; margin: 0 auto; max-width: 1120px; min-height: 100vh; padding: 48px 56px 64px; }}
    h1, h2, h3, h4 {{ color: var(--navy); line-height: 1.22; margin-top: 0; overflow-wrap: anywhere; }}
    h1 {{ font-size: 2rem; letter-spacing: -.025em; margin-bottom: 8px; }}
    h2 {{ border-bottom: 1px solid var(--line); font-size: 1.25rem; margin: 40px 0 18px; padding-bottom: 9px; }}
    h3 {{ font-size: 1.05rem; margin-bottom: 12px; }}
    h4 {{ font-size: .92rem; margin: 20px 0 7px; }}
    p {{ max-width: 76ch; }}
    code, pre {{ background: var(--soft); border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    code {{ overflow-wrap: anywhere; padding: 2px 4px; }}
    pre {{ border: 1px solid var(--line); margin: 8px 0 16px; overflow-x: auto; padding: 13px 14px; white-space: pre-wrap; word-break: break-word; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border-bottom: 1px solid var(--line); overflow-wrap: anywhere; padding: 10px 12px; text-align: left; vertical-align: top; }}
    th {{ color: #35435b; font-size: .78rem; font-weight: 700; letter-spacing: .02em; }}
    .masthead {{ align-items: flex-start; border-bottom: 3px solid var(--accent); display: flex; gap: 20px; justify-content: space-between; padding-bottom: 22px; }}
    .brand {{ align-items: center; display: flex; gap: 13px; }}
    .brandMark {{ align-items: center; background: var(--navy); border-radius: 10px; color: #fff; display: inline-flex; font-size: .82rem; font-weight: 800; height: 42px; justify-content: center; letter-spacing: .03em; width: 42px; }}
    .kicker {{ color: var(--accent); font-size: .76rem; font-weight: 750; margin: 0 0 4px; }}
    .subtitle {{ color: var(--muted); margin: 0; }}
    .status {{ background: #eef7f0; border-radius: 999px; color: #24633a; font-size: .78rem; font-weight: 700; padding: 6px 10px; }}
    .overview {{ display: grid; gap: 28px; grid-template-columns: minmax(0, 1.15fr) minmax(260px, .85fr); margin-top: 30px; }}
    .overview table th {{ width: 34%; }}
    .executive {{ background: var(--soft); border-radius: 10px; padding: 20px 22px; }}
    .executive h2 {{ border: 0; margin: 0 0 10px; padding: 0; }}
    .severityGrid {{ display: grid; gap: 8px; grid-template-columns: repeat(5, minmax(0, 1fr)); margin: 18px 0; }}
    .severityItem {{ background: var(--soft); border-radius: 8px; padding: 12px; }}
    .severityItem strong {{ display: block; font-size: 1.35rem; }}
    .severityItem span {{ color: var(--muted); font-size: .76rem; }}
    .severity-critical strong {{ color: var(--critical); }} .severity-high strong {{ color: var(--high); }} .severity-medium strong {{ color: var(--medium); }} .severity-low strong {{ color: var(--low); }} .severity-info strong {{ color: var(--info); }}
    .scopeGrid {{ display: grid; gap: 20px; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .scopeBlock {{ border-top: 2px solid var(--navy); padding-top: 12px; }}
    .scopeBlock ul {{ margin: 0; padding-left: 20px; }}
    .tableWrap {{ overflow-x: auto; }}
    .finding {{ break-inside: avoid; border-top: 2px solid var(--navy); margin-top: 30px; padding-top: 18px; }}
    .findingHeader {{ align-items: flex-start; display: flex; gap: 12px; justify-content: space-between; }}
    .severity {{ border-radius: 999px; color: #fff; flex: none; font-size: .7rem; font-weight: 800; padding: 5px 8px; text-transform: uppercase; }}
    .severity.severity-critical {{ background: var(--critical); }} .severity.severity-high {{ background: var(--high); }} .severity.severity-medium {{ background: var(--medium); }} .severity.severity-low {{ background: var(--low); }} .severity.severity-info {{ background: var(--info); }}
    .findingMeta th {{ width: 18%; }}
    .guidanceItem {{ background: var(--soft); border-radius: 8px; break-inside: avoid; margin-top: 12px; padding: 16px 18px; }}
    .guidanceItem h3 {{ margin-bottom: 8px; }}
    .guidanceItem dl {{ display: grid; gap: 7px 14px; grid-template-columns: 150px minmax(0, 1fr); margin: 0; }}
    .guidanceItem dt {{ color: var(--muted); font-weight: 700; }} .guidanceItem dd {{ margin: 0; overflow-wrap: anywhere; }}
    .notice {{ background: #fff7ed; border-radius: 8px; color: #623314; padding: 14px 16px; }}
    .empty {{ color: var(--muted); font-style: italic; }}
    footer {{ border-top: 1px solid var(--line); color: var(--muted); font-size: .8rem; margin-top: 48px; padding-top: 16px; }}
    @media (max-width: 760px) {{ body {{ padding: 28px 20px 44px; }} .masthead, .findingHeader {{ display: block; }} .status {{ display: inline-block; margin-top: 14px; }} .overview, .scopeGrid {{ grid-template-columns: 1fr; }} .severityGrid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} .guidanceItem dl {{ grid-template-columns: 1fr; }} .guidanceItem dd {{ margin-bottom: 8px; }} }}
    @media print {{ @page {{ margin: 14mm; }} html {{ background: #fff; }} body {{ max-width: none; padding: 0; }} .masthead {{ break-after: avoid; }} h2, h3 {{ break-after: avoid; }} .finding, .guidanceItem, table {{ break-inside: avoid; }} a {{ color: inherit; text-decoration: none; }} }}
  </style>
</head>
<body>
  <header class="masthead">
    <div class="brand"><span class="brandMark" aria-hidden="true">SH</span><div><p class="kicker">ScopeHarbor</p><h1>Security Audit Report</h1><p class="subtitle">Authorized, local-first application security review</p></div></div>
    <span class="status">{escape(data.scan.status.replace("_", " "))}</span>
  </header>

  <section class="overview" aria-label="Audit overview">
    <div class="tableWrap"><table>
      <tr><th>Audit completed at</th><td>{escape(format_timestamp(data.completed_at))}</td></tr>
      <tr><th>Subject</th><td>{escape(data.target.name)}</td></tr>
      <tr><th>Subject type</th><td>{escape(report_subject_type(data))}</td></tr>
      <tr><th>Authorized scope</th><td>{escape(report_subject_scope(data))}</td></tr>
      <tr><th>Subject policy</th><td>{escape(report_subject_policy(data))}</td></tr>
      <tr><th>Scan profile</th><td>{escape(data.scan.scan_profile_id)}</td></tr>
      <tr><th>Scan ID</th><td><code>{escape(data.scan.id)}</code></td></tr>
    </table></div>
    <div class="executive"><h2>Executive summary</h2><p>{escape(data.guidance.executive_summary)}</p><p><strong>Severity distribution:</strong> {escape(severity_summary(data.findings))}</p></div>
  </section>

  <h2>Severity distribution</h2>
  <div class="severityGrid" aria-label="Finding counts by severity">
    <div class="severityItem severity-critical"><strong>{counts["critical"]}</strong><span>Critical</span></div>
    <div class="severityItem severity-high"><strong>{counts["high"]}</strong><span>High</span></div>
    <div class="severityItem severity-medium"><strong>{counts["medium"]}</strong><span>Medium</span></div>
    <div class="severityItem severity-low"><strong>{counts["low"]}</strong><span>Low</span></div>
    <div class="severityItem severity-info"><strong>{counts["info"]}</strong><span>Informational</span></div>
  </div>

  <h2>Scope, authorization, and handling</h2>
  <div class="scopeGrid">
    <section class="scopeBlock"><h3>Coverage</h3><ul>
      <li>Custom passive scanner: {escape(tooling_used_unless_repo(data.scan.mode))}.</li>
      <li>ZAP passive analysis: {escape(zap_passive_tooling(data.scan.mode))}.</li>
      <li>ZAP active scan: {escape(tooling_used(data.scan.mode, ScanMode.ACTIVE_DEMO.value))}.</li>
      <li>Modern web crawl: {escape(tooling_used(data.scan.mode, ScanMode.MODERN_WEB_CRAWL.value))}.</li>
      <li>Repository scanning: {escape(tooling_used(data.scan.mode, ScanMode.REPO.value))}.</li>
    </ul></section>
    <section class="scopeBlock"><h3>Authorization and data handling</h3><ul>
      <li>{escape(report_authorization_context(data))}.</li>
      <li>Evidence is normalized, independently redacted, and bounded.</li>
      <li>Full bodies, credentials, cookies, queries, and raw tool output are excluded.</li>
      <li>Finding guidance is deterministic and generated locally.</li>
    </ul></section>
  </div>
  <p class="notice"><strong>Limitations:</strong> Authenticated workflows and business-logic checks were not tested. Arbitrary public scanning is unsupported. This report is not a penetration-test certification or guarantee of security.</p>

  <h2>Scanner receipts</h2>
  {tool_run_section}

  <h2>Prioritized finding guidance</h2>
  {guidance_section}

  <h2>Detailed findings</h2>
  {finding_sections}
  <footer>ScopeHarbor 1.1.0 · Defensive use only · Findings require qualified human review.</footer>
</body>
</html>
"""


def render_html_tool_runs(tool_runs: tuple[ReportToolRun, ...]) -> str:
    if not tool_runs:
        return "<p>No scanner tool receipts were recorded for this scan.</p>"
    rows = "".join(
        "<tr>"
        f"<td>{escape(run.tool_name)}</td>"
        f"<td>{escape(run.tool_version or 'not reported')}</td>"
        f"<td>{escape(run.status)}</td>"
        f"<td>{escape(run.warning_code or 'none')}</td>"
        f"<td>{run.finding_count}</td>"
        f"<td>{escape(format_timestamp(run.started_at) if run.started_at else 'not reported')}</td>"
        f"<td>{escape(format_timestamp(run.completed_at) if run.completed_at else 'not reported')}</td>"
        "</tr>"
        for run in tool_runs
    )
    return (
        "<table><thead><tr><th>Scanner</th><th>Version</th><th>Status</th><th>Warning</th>"
        "<th>Findings</th><th>Started</th><th>Completed</th></tr></thead><tbody>"
        f"{rows}</tbody></table>"
    )


def render_html_guidance(guidance: AiExplanationResult) -> str:
    group_items = "".join(f"<li>{escape(group.label)}: {group.count}</li>" for group in guidance.groups)
    groups = f"<h3>Finding groups</h3><ul>{group_items}</ul>" if group_items else ""
    finding_items = "".join(
        f"""<section class="guidanceItem">
  <h3>Priority {explanation.priority}: {escape(explanation.summary)}</h3>
  <dl>
    <dt>Why it matters</dt><dd>{escape(explanation.why_it_matters)}</dd>
    <dt>Recommended action</dt><dd>{escape(explanation.recommended_action)}</dd>
    <dt>OWASP mapping</dt><dd>{escape(explanation.owasp_mapping)}</dd>
    <dt>Limitations</dt><dd>{escape(explanation.limitations)}</dd>
  </dl>
</section>"""
        for explanation in guidance.explanations
    )
    finding_notes = f"<h3>Prioritized actions</h3>{finding_items}" if finding_items else ""
    return f"""
  <p>{escape(guidance.summary)}</p>
  <p>{escape(guidance.risk_score_explanation)}</p>
  <p><strong>Method:</strong> {escape(guidance_tooling(guidance))}. Guidance uses only normalized, redacted findings and does not add vulnerability claims.</p>
  <p><strong>Occurrences:</strong> Equivalent guidance actions are grouped here; every normalized occurrence remains in Detailed findings.</p>
  {groups}
  {finding_notes}
"""


def deduplicate_guidance(guidance: AiExplanationResult) -> AiExplanationResult:
    seen_signatures: set[tuple[str, ...]] = set()
    kept_finding_ids: set[str] = set()
    explanations = []
    for explanation in guidance.explanations:
        signature = tuple(
            normalize_guidance_text(value)
            for value in (
                explanation.summary,
                explanation.why_it_matters,
                explanation.recommended_action,
                explanation.owasp_mapping,
                explanation.limitations,
            )
        )
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        kept_finding_ids.add(explanation.finding_id)
        explanations.append(explanation)

    groups = tuple(
        replace(
            group,
            count=len(finding_ids),
            finding_ids=finding_ids,
        )
        for group in guidance.groups
        if (finding_ids := tuple(finding_id for finding_id in group.finding_ids if finding_id in kept_finding_ids))
    )
    return replace(guidance, groups=groups, explanations=tuple(explanations))


def normalize_guidance_text(value: str) -> str:
    return " ".join(value.lower().split())


def render_html_finding(index: int, finding: ReportFinding) -> str:
    severity = finding.severity.lower() if finding.severity.lower() in SEVERITY_ORDER else "info"
    return f"""<article class="finding">
  <div class="findingHeader"><h3>{index}. {escape(finding.title)}</h3><span class="severity severity-{severity}">{escape(finding.severity)}</span></div>
  <div class="tableWrap"><table class="findingMeta">
    <tr><th>Severity</th><td>{escape(finding.severity)}</td></tr>
    <tr><th>Confidence</th><td>{escape(finding.confidence)}</td></tr>
    <tr><th>Source tool</th><td>{escape(finding.source_tool)}</td></tr>
    <tr><th>Scanner rule ID</th><td>{escape(finding.scanner_rule_id or "not provided")}</td></tr>
    <tr><th>CWE</th><td>{escape(finding.cwe or "not mapped")}</td></tr>
    <tr><th>OWASP category</th><td>{escape(finding.owasp_category or "not mapped")}</td></tr>
    <tr><th>Location</th><td>{escape(finding.affected_url or finding.affected_file or "global")}</td></tr>
    <tr><th>Redaction applied</th><td>{"yes" if finding.redaction_applied else "no"}</td></tr>
  </table></div>
  <h4>Evidence</h4>
  <pre>{escape(finding.evidence or "No evidence snippet recorded.")}</pre>
  <h4>Reproduction Steps</h4>
  <p>{escape(finding.reproduction_steps or "No reproduction steps recorded.")}</p>
  <h4>Remediation</h4>
  <p>{escape(finding.remediation or "No remediation guidance recorded.")}</p>
  <h4>False Positive Notes</h4>
  <p>{escape(finding.false_positive_notes or "No false-positive notes recorded.")}</p>
</article>"""


def format_scan_mode(mode: str) -> str:
    return {
        "passive": "Passive",
        "active_demo": "Active Demo",
        "modern_web_crawl": "Modern Web Crawl",
        "ajax_short": "Retired AJAX Short (historical)",
        "repo": "Repo",
    }.get(mode, mode)


def tooling_used(scan_mode: str, expected_mode: str) -> str:
    return "used" if scan_mode == expected_mode else "not used"


def tooling_used_unless_repo(scan_mode: str) -> str:
    return "not used" if scan_mode == ScanMode.REPO.value else "used"


def zap_passive_tooling(scan_mode: str) -> str:
    return "not used" if scan_mode == ScanMode.REPO.value else "used for allowlisted URLs"


def guidance_tooling(guidance: AiExplanationResult) -> str:
    if guidance.provider == "not_generated":
        return "not generated for repository scans"
    return "generated locally with deterministic template logic"


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def report_timestamp(scan: Scan) -> datetime:
    timestamp = scan.completed_at or scan.created_at
    if isinstance(timestamp, datetime):
        return timestamp
    return datetime.fromtimestamp(0, UTC)


def markdown_inline(value: object) -> str:
    single_line = " ".join(str(value).splitlines())
    escaped = single_line.translate(
        str.maketrans(
            {
                "\\": "\\\\",
                "`": "\\`",
                "*": "\\*",
                "_": "\\_",
                "{": "\\{",
                "}": "\\}",
                "[": "\\[",
                "]": "\\]",
                "(": "\\(",
                ")": "\\)",
                "#": "\\#",
                "+": "\\+",
                "!": "\\!",
                "|": "\\|",
            }
        )
    )
    return escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fenced_block(value: str) -> str:
    longest_run = 0
    current_run = 0
    for character in value:
        if character == "`":
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0
    fence = "`" * max(3, longest_run + 1)
    return f"{fence}text\n{value}\n{fence}"
