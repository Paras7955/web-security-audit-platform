import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.service import AiExplanationError, AiExplanationResult, AiRateLimitExceeded, generate_ai_explanations
from app.core.contracts import ScanMode, ScanStatus, scan_profile_for_values
from app.models import Finding, ReportArtifact, Scan, ScannerToolRun, Target
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


class ReportGenerationRateLimitError(ReportGenerationError):
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
    target: Target
    findings: tuple[ReportFinding, ...]
    tool_runs: tuple["ReportToolRun", ...]
    generated_at: datetime
    ai_explanations: AiExplanationResult


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
    ai_provider: str,
    workspace_id: str | None = None,
    user_id: str | None = None,
    openai_api_key: str | None = None,
    openai_model: str | None = None,
) -> ReportData:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    if workspace_id is not None and scan.workspace_id != workspace_id:
        raise ReportGenerationError("Scan not found.")
    if scan.status not in TERMINAL_REPORT_STATUSES:
        raise ReportGenerationError("Reports can only be generated for completed scans.")
    profile = scan_profile_for_values(scan.scan_profile_id, scan.mode)
    if profile is None or not profile.reports_enabled:
        raise ReportGenerationError("Reports can only be generated for passive, Active Demo, and Repo scans.")

    target = db.get(Target, scan.target_id)
    if target is None:
        raise ReportGenerationError("Scan target not found.")
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
    try:
        ai_explanations = (
            generate_ai_explanations(
                db,
                scan_id=scan.id,
                workspace_id=workspace_id,
                user_id=user_id,
                action="report_ai_generation",
                provider_name=ai_provider,
                openai_api_key=openai_api_key,
                openai_model=openai_model,
                cache_context_version="report-v1",
            )
            if profile.ai_enabled
            else disabled_ai_explanations(scan.id)
        )
    except AiRateLimitExceeded as exc:
        raise ReportGenerationRateLimitError(str(exc)) from exc
    except AiExplanationError as exc:
        raise ReportGenerationError(str(exc)) from exc
    return ReportData(
        scan=scan,
        target=target,
        findings=sorted_findings,
        tool_runs=tool_runs,
        generated_at=report_timestamp(scan),
        ai_explanations=ai_explanations,
    )


def generate_report_artifacts(
    db: Session,
    *,
    scan_id: str,
    workspace_id: str | None = None,
    user_id: str | None = None,
    artifact_root: str | Path,
    ai_provider: str,
    openai_api_key: str | None = None,
    openai_model: str | None = None,
) -> list[ReportArtifact]:
    data = build_report_data(
        db,
        scan_id=scan_id,
        workspace_id=workspace_id,
        user_id=user_id,
        ai_provider=ai_provider,
        openai_api_key=openai_api_key,
        openai_model=openai_model,
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
    return artifact


def list_report_artifacts(db: Session, *, scan_id: str, workspace_id: str | None = None) -> list[ReportArtifact]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    if workspace_id is not None and scan.workspace_id != workspace_id:
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
    workspace_id: str | None = None,
) -> str:
    scan = db.get(Scan, artifact.scan_id)
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    if workspace_id is not None and (scan.workspace_id != workspace_id or artifact.workspace_id != workspace_id):
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
        raise ReportGenerationError("Reports can only be generated for passive, Active Demo, and Repo scans.")


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


def disabled_ai_explanations(scan_id: str) -> AiExplanationResult:
    return AiExplanationResult(
        scan_id=scan_id,
        provider="not_generated",
        fallback_used=False,
        provider_error=None,
        summary="AI explanations are not generated for repository scans.",
        executive_summary="AI explanations are not generated for this scan profile.",
        risk_score_explanation="No AI risk explanation was generated.",
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


def render_markdown_report(data: ReportData) -> str:
    lines = [
        "# ScopeHarbor Security Audit Report",
        "",
        "## Summary",
        "",
        f"- Generated at: {format_timestamp(data.generated_at)}",
        f"- Target: {data.target.name}",
        f"- Target allowlist ID: {data.target.allowlist_id}",
        f"- Target URL: {data.target.base_url}",
        f"- Scan ID: {data.scan.id}",
        f"- Scan profile: {data.scan.scan_profile_id}",
        f"- Scan status: {data.scan.status}",
        f"- Findings: {len(data.findings)}",
        "",
        "## Scope And Tooling",
        "",
        f"- Custom passive scanner: {tooling_used_unless_repo(data.scan.mode)}.",
        f"- ZAP passive analysis: {zap_passive_tooling(data.scan.mode)}.",
        f"- ZAP active scan: {tooling_used(data.scan.mode, ScanMode.ACTIVE_DEMO.value)}.",
        f"- Modern web crawl: {tooling_used(data.scan.mode, ScanMode.MODERN_WEB_CRAWL.value)}.",
        f"- AI explanations: {ai_tooling(data.ai_explanations)}.",
        f"- Repo scanning: {tooling_used(data.scan.mode, ScanMode.REPO.value)}.",
        "- Authenticated workflows: not tested.",
        "- Business logic checks: not tested.",
        "- Arbitrary public scanning: unsupported.",
        "",
        "## Responsible Use And Limitations",
        "",
        "This report is for local defensive learning and explicitly authorized testing only.",
        "It is not a professional penetration test, compliance audit, or guarantee that the target is secure.",
        "Findings are based on bounded checks against allowlisted targets.",
        "",
        "## Redaction Notice",
        "",
        "Evidence is normalized and redacted before persistence and reporting. Full HTTP response bodies are not stored by default.",
        "",
        "## Scanner Tool Runs",
        "",
        render_markdown_tool_runs(data.tool_runs),
        "",
        "## AI Explanations",
        "",
        render_markdown_ai_explanations(data.ai_explanations),
        "",
        "## Findings",
        "",
    ]

    if not data.findings:
        lines.extend(["No normalized findings were recorded for this scan.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(data.findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence}",
                f"- Source tool: {finding.source_tool}",
                f"- Scanner rule ID: {finding.scanner_rule_id or 'not provided'}",
                f"- CWE: {finding.cwe or 'not mapped'}",
                f"- OWASP category: {finding.owasp_category or 'not mapped'}",
                f"- Location: {finding.affected_url or finding.affected_file or 'global'}",
                f"- Redaction applied: {'yes' if finding.redaction_applied else 'no'}",
                "",
                "**Evidence**",
                "",
                fenced_block(finding.evidence or "No evidence snippet recorded."),
                "",
                "**Reproduction Steps**",
                "",
                finding.reproduction_steps or "No reproduction steps recorded.",
                "",
                "**Remediation**",
                "",
                finding.remediation or "No remediation guidance recorded.",
                "",
                "**False Positive Notes**",
                "",
                finding.false_positive_notes or "No false-positive notes recorded.",
                "",
            ]
        )
    return "\n".join(lines)


def render_markdown_ai_explanations(explanations: AiExplanationResult) -> str:
    lines = [
        f"- Provider used: {explanations.provider}",
        f"- Fallback used: {'yes' if explanations.fallback_used else 'no'}",
        f"- Executive summary: {explanations.executive_summary}",
        f"- Risk score explanation: {explanations.risk_score_explanation}",
        f"- Summary: {explanations.summary}",
        "- Limitation: AI explanations are based only on normalized, redacted findings and do not add new vulnerability claims.",
    ]
    if explanations.provider_error:
        lines.append(f"- Provider error: {explanations.provider_error}")

    if explanations.groups:
        lines.extend(["", "### AI Finding Groups", ""])
        for group in explanations.groups:
            lines.append(f"- {group.label}: {group.count}")

    if explanations.explanations:
        lines.extend(["", "### AI Finding Notes", ""])
        for explanation in explanations.explanations:
            lines.extend(
                [
                    f"#### Finding {explanation.finding_id}",
                    "",
                    f"- Priority: {explanation.priority}",
                    f"- Summary: {explanation.summary}",
                    f"- Why it matters: {explanation.why_it_matters}",
                    f"- Recommended action: {explanation.recommended_action}",
                    f"- OWASP mapping: {explanation.owasp_mapping}",
                    f"- Limitations: {explanation.limitations}",
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
                f"### {run.tool_name}",
                "",
                f"- Version: {run.tool_version or 'not reported'}",
                f"- Status: {run.status}",
                f"- Warning code: {run.warning_code or 'none'}",
                f"- Findings: {run.finding_count}",
                f"- Started at: {format_timestamp(run.started_at) if run.started_at else 'not reported'}",
                f"- Completed at: {format_timestamp(run.completed_at) if run.completed_at else 'not reported'}",
                "",
            ]
        )
    return "\n".join(lines)


def render_html_report(data: ReportData) -> str:
    finding_sections = "\n".join(render_html_finding(index, finding) for index, finding in enumerate(data.findings, start=1))
    if not finding_sections:
        finding_sections = "<p>No normalized findings were recorded for this scan.</p>"
    ai_section = render_html_ai_explanations(data.ai_explanations)
    tool_run_section = render_html_tool_runs(data.tool_runs)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
  <title>ScopeHarbor Security Audit Report</title>
  <style>
    body {{ color: #17202a; font-family: Arial, sans-serif; line-height: 1.5; margin: 32px; }}
    h1, h2, h3 {{ line-height: 1.2; }}
    code, pre {{ background: #f1f3f6; border-radius: 6px; }}
    pre {{ overflow-x: auto; padding: 12px; }}
    table {{ border-collapse: collapse; margin: 12px 0; width: 100%; }}
    td, th {{ border: 1px solid #d8dde5; padding: 8px; text-align: left; vertical-align: top; }}
    .finding {{ border-top: 1px solid #d8dde5; margin-top: 24px; padding-top: 16px; }}
  </style>
</head>
<body>
  <h1>ScopeHarbor Security Audit Report</h1>
  <h2>Summary</h2>
  <table>
    <tr><th>Generated at</th><td>{escape(format_timestamp(data.generated_at))}</td></tr>
    <tr><th>Target</th><td>{escape(data.target.name)}</td></tr>
    <tr><th>Target allowlist ID</th><td>{escape(data.target.allowlist_id)}</td></tr>
    <tr><th>Target URL</th><td>{escape(data.target.base_url)}</td></tr>
    <tr><th>Scan ID</th><td>{escape(data.scan.id)}</td></tr>
    <tr><th>Scan profile</th><td>{escape(data.scan.scan_profile_id)}</td></tr>
    <tr><th>Scan status</th><td>{escape(data.scan.status)}</td></tr>
    <tr><th>Findings</th><td>{len(data.findings)}</td></tr>
  </table>

  <h2>Scope And Tooling</h2>
  <ul>
    <li>Custom passive scanner: {escape(tooling_used_unless_repo(data.scan.mode))}.</li>
    <li>ZAP passive analysis: {escape(zap_passive_tooling(data.scan.mode))}.</li>
    <li>ZAP active scan: {escape(tooling_used(data.scan.mode, ScanMode.ACTIVE_DEMO.value))}.</li>
    <li>Modern web crawl: {escape(tooling_used(data.scan.mode, ScanMode.MODERN_WEB_CRAWL.value))}.</li>
    <li>AI explanations: {escape(ai_tooling(data.ai_explanations))}.</li>
    <li>Repo scanning: {escape(tooling_used(data.scan.mode, ScanMode.REPO.value))}.</li>
    <li>Authenticated workflows: not tested.</li>
    <li>Business logic checks: not tested.</li>
    <li>Arbitrary public scanning: unsupported.</li>
  </ul>

  <h2>Responsible Use And Limitations</h2>
  <p>This report is for local defensive learning and explicitly authorized testing only.</p>
  <p>It is not a professional penetration test, compliance audit, or guarantee that the target is secure.</p>
  <p>Findings are based on bounded checks against allowlisted targets.</p>

  <h2>Redaction Notice</h2>
  <p>Evidence is normalized and redacted before persistence and reporting. Full HTTP response bodies are not stored by default.</p>

  <h2>AI Explanations</h2>
  {ai_section}

  <h2>Scanner Tool Runs</h2>
  {tool_run_section}

  <h2>Findings</h2>
  {finding_sections}
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


def render_html_ai_explanations(explanations: AiExplanationResult) -> str:
    group_items = "".join(
        f"<li>{escape(group.label)}: {group.count}</li>"
        for group in explanations.groups
    )
    groups = f"<h3>AI Finding Groups</h3><ul>{group_items}</ul>" if group_items else ""
    finding_items = "".join(
        f"""<section class="finding">
  <h3>Finding {escape(explanation.finding_id)}</h3>
  <table>
    <tr><th>Priority</th><td>{explanation.priority}</td></tr>
    <tr><th>Summary</th><td>{escape(explanation.summary)}</td></tr>
    <tr><th>Why it matters</th><td>{escape(explanation.why_it_matters)}</td></tr>
    <tr><th>Recommended action</th><td>{escape(explanation.recommended_action)}</td></tr>
    <tr><th>OWASP mapping</th><td>{escape(explanation.owasp_mapping)}</td></tr>
    <tr><th>Limitations</th><td>{escape(explanation.limitations)}</td></tr>
  </table>
</section>"""
        for explanation in explanations.explanations
    )
    finding_notes = f"<h3>AI Finding Notes</h3>{finding_items}" if finding_items else ""
    provider_error = ""
    if explanations.provider_error:
        provider_error = f"<p><strong>Provider error:</strong> {escape(explanations.provider_error)}</p>"
    return f"""
  <table>
    <tr><th>Provider used</th><td>{escape(explanations.provider)}</td></tr>
    <tr><th>Fallback used</th><td>{"yes" if explanations.fallback_used else "no"}</td></tr>
    <tr><th>Executive summary</th><td>{escape(explanations.executive_summary)}</td></tr>
    <tr><th>Risk score explanation</th><td>{escape(explanations.risk_score_explanation)}</td></tr>
    <tr><th>Summary</th><td>{escape(explanations.summary)}</td></tr>
  </table>
  <p>AI explanations are based only on normalized, redacted findings and do not add new vulnerability claims.</p>
  {provider_error}
  {groups}
  {finding_notes}
"""


def render_html_finding(index: int, finding: Finding) -> str:
    return f"""<section class="finding">
  <h3>{index}. {escape(finding.title)}</h3>
  <table>
    <tr><th>Severity</th><td>{escape(finding.severity)}</td></tr>
    <tr><th>Confidence</th><td>{escape(finding.confidence)}</td></tr>
    <tr><th>Source tool</th><td>{escape(finding.source_tool)}</td></tr>
    <tr><th>Scanner rule ID</th><td>{escape(finding.scanner_rule_id or "not provided")}</td></tr>
    <tr><th>CWE</th><td>{escape(finding.cwe or "not mapped")}</td></tr>
    <tr><th>OWASP category</th><td>{escape(finding.owasp_category or "not mapped")}</td></tr>
    <tr><th>Location</th><td>{escape(finding.affected_url or finding.affected_file or "global")}</td></tr>
    <tr><th>Redaction applied</th><td>{"yes" if finding.redaction_applied else "no"}</td></tr>
  </table>
  <h4>Evidence</h4>
  <pre>{escape(finding.evidence or "No evidence snippet recorded.")}</pre>
  <h4>Reproduction Steps</h4>
  <p>{escape(finding.reproduction_steps or "No reproduction steps recorded.")}</p>
  <h4>Remediation</h4>
  <p>{escape(finding.remediation or "No remediation guidance recorded.")}</p>
  <h4>False Positive Notes</h4>
  <p>{escape(finding.false_positive_notes or "No false-positive notes recorded.")}</p>
</section>"""


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


def ai_tooling(explanations: AiExplanationResult) -> str:
    if explanations.provider == "not_generated":
        return "not generated for repo scans"
    return f"generated with {explanations.provider} provider"


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def report_timestamp(scan: Scan) -> datetime:
    timestamp = scan.completed_at or scan.created_at
    if isinstance(timestamp, datetime):
        return timestamp
    return datetime.fromtimestamp(0, UTC)


def fenced_block(value: str) -> str:
    fence = "```"
    if fence in value:
        return f"````text\n{value}\n````"
    return f"```text\n{value}\n```"
