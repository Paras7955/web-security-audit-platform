from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.contracts import ScanMode, ScanStatus
from app.models import Finding, ReportArtifact, Scan, Target
from app.scans.artifacts import ensure_scan_artifact_dir


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
class ReportData:
    scan: Scan
    target: Target
    findings: tuple[Finding, ...]
    generated_at: datetime
    ai_provider: str


def build_report_data(db: Session, *, scan_id: str, ai_provider: str) -> ReportData:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ReportGenerationError("Scan not found.")
    if scan.status not in TERMINAL_REPORT_STATUSES:
        raise ReportGenerationError("Reports can only be generated for completed scans.")
    if scan.mode != ScanMode.PASSIVE.value:
        raise ReportGenerationError("Reports can only be generated for passive scans in Phase 7.")

    target = db.get(Target, scan.target_id)
    if target is None:
        raise ReportGenerationError("Scan target not found.")

    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.severity.asc(), Finding.created_at.asc())
    ).all()
    sorted_findings = tuple(sorted(findings, key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 99), finding.title.lower())))
    return ReportData(scan=scan, target=target, findings=sorted_findings, generated_at=report_timestamp(scan), ai_provider=ai_provider)


def generate_report_artifacts(
    db: Session,
    *,
    scan_id: str,
    artifact_root: str | Path,
    ai_provider: str,
) -> list[ReportArtifact]:
    data = build_report_data(db, scan_id=scan_id, ai_provider=ai_provider)
    reports_dir = ensure_scan_artifact_dir(artifact_root, scan_id) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    rendered = {
        "markdown": render_markdown_report(data),
        "html": render_html_report(data),
    }

    artifacts: list[ReportArtifact] = []
    for report_type, content in rendered.items():
        path = reports_dir / REPORT_FILENAMES[report_type]
        path.write_text(content, encoding="utf-8")
        artifact = get_or_create_report_artifact(db, scan_id=scan_id, report_type=report_type, path=path)
        artifacts.append(artifact)

    db.commit()
    for artifact in artifacts:
        db.refresh(artifact)
    return artifacts


def get_or_create_report_artifact(db: Session, *, scan_id: str, report_type: str, path: Path) -> ReportArtifact:
    artifact = db.scalar(
        select(ReportArtifact).where(
            ReportArtifact.scan_id == scan_id,
            ReportArtifact.report_type == report_type,
        )
    )
    if artifact is None:
        artifact = ReportArtifact(id=str(uuid4()), scan_id=scan_id, report_type=report_type, path=str(path.resolve()))
    else:
        artifact.path = str(path.resolve())
    db.add(artifact)
    return artifact


def list_report_artifacts(db: Session, *, scan_id: str) -> list[ReportArtifact]:
    if db.get(Scan, scan_id) is None:
        raise ReportGenerationError("Scan not found.")
    return list(
        db.scalars(
            select(ReportArtifact)
            .where(ReportArtifact.scan_id == scan_id)
            .order_by(ReportArtifact.report_type.asc(), ReportArtifact.created_at.asc())
        ).all()
    )


def read_report_artifact(artifact: ReportArtifact, *, artifact_root: str | Path) -> str:
    path = validate_report_path(artifact.path, artifact_root, scan_id=artifact.scan_id, report_type=artifact.report_type)
    if not path.exists() or not path.is_file():
        raise ReportGenerationError("Report artifact file not found.")
    return path.read_text(encoding="utf-8")


def validate_report_path(path: str, artifact_root: str | Path, *, scan_id: str, report_type: str) -> Path:
    expected_filename = REPORT_FILENAMES.get(report_type)
    if expected_filename is None:
        raise ReportGenerationError("Unsupported report artifact type.")

    artifact_root_path = Path(artifact_root).resolve()
    candidate_path = Path(path)
    if not candidate_path.is_absolute():
        raise ReportGenerationError("Report artifact path must be absolute.")
    candidate = candidate_path.resolve()
    expected_path = (artifact_root_path / "scans" / scan_id / "reports" / expected_filename).resolve()
    if candidate != expected_path:
        raise ReportGenerationError("Report artifact path does not match the expected report location.")
    return candidate


def render_markdown_report(data: ReportData) -> str:
    lines = [
        "# Defensive Web App Security Audit Report",
        "",
        "## Summary",
        "",
        f"- Generated at: {format_timestamp(data.generated_at)}",
        f"- Target: {data.target.name}",
        f"- Target allowlist ID: {data.target.allowlist_id}",
        f"- Target URL: {data.target.base_url}",
        f"- Scan ID: {data.scan.id}",
        f"- Scan mode: {format_scan_mode(data.scan.mode)}",
        f"- Scan status: {data.scan.status}",
        f"- Findings: {len(data.findings)}",
        "",
        "## Scope And Tooling",
        "",
        "- Custom passive scanner: used.",
        "- ZAP active scan: not used.",
        "- AJAX crawl: not used.",
        f"- AI explanations: not generated in Phase 7; configured provider: {data.ai_provider}.",
        "- Repo scanning: not included.",
        "- Authenticated workflows: not tested.",
        "- Business logic checks: not tested.",
        "- Arbitrary public scanning: unsupported.",
        "",
        "## Responsible Use And Limitations",
        "",
        "This report is for local defensive learning and explicitly authorized testing only.",
        "It is not a professional penetration test, compliance audit, or guarantee that the target is secure.",
        "Findings are based on bounded passive checks against allowlisted targets.",
        "",
        "## Redaction Notice",
        "",
        "Evidence is normalized and redacted before persistence and reporting. Full HTTP response bodies are not stored by default.",
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


def render_html_report(data: ReportData) -> str:
    finding_sections = "\n".join(render_html_finding(index, finding) for index, finding in enumerate(data.findings, start=1))
    if not finding_sections:
        finding_sections = "<p>No normalized findings were recorded for this scan.</p>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Defensive Web App Security Audit Report</title>
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
  <h1>Defensive Web App Security Audit Report</h1>
  <h2>Summary</h2>
  <table>
    <tr><th>Generated at</th><td>{escape(format_timestamp(data.generated_at))}</td></tr>
    <tr><th>Target</th><td>{escape(data.target.name)}</td></tr>
    <tr><th>Target allowlist ID</th><td>{escape(data.target.allowlist_id)}</td></tr>
    <tr><th>Target URL</th><td>{escape(data.target.base_url)}</td></tr>
    <tr><th>Scan ID</th><td>{escape(data.scan.id)}</td></tr>
    <tr><th>Scan mode</th><td>{escape(format_scan_mode(data.scan.mode))}</td></tr>
    <tr><th>Scan status</th><td>{escape(data.scan.status)}</td></tr>
    <tr><th>Findings</th><td>{len(data.findings)}</td></tr>
  </table>

  <h2>Scope And Tooling</h2>
  <ul>
    <li>Custom passive scanner: used.</li>
    <li>ZAP active scan: not used.</li>
    <li>AJAX crawl: not used.</li>
    <li>AI explanations: not generated in Phase 7; configured provider: {escape(data.ai_provider)}.</li>
    <li>Repo scanning: not included.</li>
    <li>Authenticated workflows: not tested.</li>
    <li>Business logic checks: not tested.</li>
    <li>Arbitrary public scanning: unsupported.</li>
  </ul>

  <h2>Responsible Use And Limitations</h2>
  <p>This report is for local defensive learning and explicitly authorized testing only.</p>
  <p>It is not a professional penetration test, compliance audit, or guarantee that the target is secure.</p>
  <p>Findings are based on bounded passive checks against allowlisted targets.</p>

  <h2>Redaction Notice</h2>
  <p>Evidence is normalized and redacted before persistence and reporting. Full HTTP response bodies are not stored by default.</p>

  <h2>Findings</h2>
  {finding_sections}
</body>
</html>
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
        "ajax_short": "AJAX Short",
    }.get(mode, mode)


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
