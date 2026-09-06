import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.db.session import SessionLocal
from app.main import app
from app.models import AiExplanationCache, AiRequestLog, Finding, ReportArtifact, Scan, ScannerToolRun, Target, Workspace
from app.reports.service import (
    ReportGenerationError,
    fenced_block,
    generate_report_artifacts,
    markdown_inline,
    read_report_artifact_file,
)
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class ReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.finding_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(
                Target(
                    id=self.target_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    allowlist_id="juice-shop",
                    name="OWASP Juice Shop",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            db.add(
                Scan(
                    id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    target_id=self.target_id,
                    mode="passive",
                    status="completed",
                    current_step="normalizing_findings",
                    status_message="Completed.",
                    progress_percent=100,
                    completed_at=datetime(2026, 6, 17, 18, 0, 0, tzinfo=UTC),
                )
            )
            db.commit()
            db.add(
                Finding(
                    id=self.finding_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    title="<script>alert('xss')</script>",
                    severity="high",
                    confidence="high",
                    affected_url="http://juice-shop:3000/",
                    evidence="<b>Missing header</b>\napi_key=[REDACTED]",
                    source_tool="custom-passive",
                    scanner_rule_id="header:content-security-policy",
                    dedupe_key="custom-passive|http://juice-shop:3000/|missing content security policy|cwe-693",
                    cwe="CWE-693",
                    owasp_category="A05:2021",
                    reproduction_steps="Visit the page and inspect response headers.",
                    remediation="Set a Content-Security-Policy header.",
                    redaction_applied=True,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(AiRequestLog).where(AiRequestLog.workspace_id == DEV_WORKSPACE_ID))
            db.execute(delete(AiExplanationCache).where(AiExplanationCache.workspace_id == DEV_WORKSPACE_ID))
            db.execute(delete(ReportArtifact).where(ReportArtifact.scan_id == self.scan_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_generate_report_artifacts_writes_markdown_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )

                self.assertEqual({artifact.report_type for artifact in artifacts}, {"markdown", "html"})
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                html = next(artifact for artifact in artifacts if artifact.report_type == "html")
                markdown_content = read_report_artifact_file(markdown, artifact_root=temp_dir)
                html_content = read_report_artifact_file(html, artifact_root=temp_dir)

            self.assertIn("| Subject policy | juice-shop |", markdown_content)
            self.assertNotIn("+00:00Z", markdown_content)
            self.assertIn("ZAP passive analysis: used for allowlisted URLs.", markdown_content)
            self.assertIn("ZAP active scan: not used.", markdown_content)
            self.assertIn("Finding guidance: generated locally with deterministic template logic.", markdown_content)
            self.assertIn("## Prioritized Finding Guidance", markdown_content)
            self.assertIn("## Severity Distribution", markdown_content)
            self.assertIn("| 0 | 1 | 0 | 0 | 0 | 1 |", markdown_content)
            self.assertIn(f"Finding {self.finding_id}", markdown_content)
            self.assertIn("| Redaction applied | yes |", markdown_content)
            self.assertIn("Audit completed at", markdown_content)
            self.assertNotIn("Generated at", markdown_content)
            self.assertIn("&lt;script&gt;", markdown_content)
            self.assertNotIn("<script>alert('xss')</script>", markdown_content)
            self.assertNotIn("+00:00Z", html_content)
            self.assertIn("<h2>Prioritized finding guidance</h2>", html_content)
            self.assertIn("<h2>Severity distribution</h2>", html_content)
            self.assertIn("Audit completed at", html_content)
            self.assertIn("ZAP passive analysis: used for allowlisted URLs.", html_content)
            self.assertIn("generated locally with deterministic template logic", html_content)
            self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_content)
            self.assertNotIn("<script>alert('xss')</script>", html_content)
            self.assertNotIn("<script", html_content.lower())
            self.assertNotIn("http://", html_content.split("<style>", 1)[1].split("</style>", 1)[0])

    def test_markdown_dynamic_values_cannot_inject_structure(self) -> None:
        rendered = markdown_inline("safe\n## injected *emphasis* <script>")

        self.assertNotIn("\n", rendered)
        self.assertIn("\\#\\# injected", rendered)
        self.assertIn("\\*emphasis\\*", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_markdown_fence_is_longer_than_any_embedded_backtick_run(self) -> None:
        value = "before `````` after"
        rendered = fenced_block(value)
        lines = rendered.splitlines()

        self.assertEqual(lines[0], "```````text")
        self.assertEqual(lines[-1], "```````")
        self.assertIn(value, rendered)

    def test_reports_include_safe_scanner_tool_receipts_without_raw_output(self) -> None:
        tool_run_id = str(uuid4())
        with tempfile.TemporaryDirectory() as temp_dir, SessionLocal() as db:
            db.add(
                ScannerToolRun(
                    id=tool_run_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    tool_name="gitleaks",
                    tool_version="8.30.1",
                    status="completed",
                    warning_code=None,
                    finding_count=2,
                    started_at=datetime(2026, 6, 17, 17, 59, tzinfo=UTC),
                    completed_at=datetime(2026, 6, 17, 18, 0, tzinfo=UTC),
                )
            )
            db.commit()
            artifacts = generate_report_artifacts(
                db,
                scan_id=self.scan_id,
                workspace_id=DEV_WORKSPACE_ID,
                artifact_root=temp_dir,
            )
            markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
            content = read_report_artifact_file(markdown, artifact_root=temp_dir)

        self.assertIn("## Scanner Receipts", content)
        self.assertIn("### gitleaks", content)
        self.assertIn("Version: 8.30.1", content)
        self.assertIn("Findings: 2", content)
        self.assertNotIn("raw output", content.lower())

    def test_generate_reports_api_lists_and_serves_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.api.reports.settings.artifact_root", temp_dir):
                generate_response = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)
                self.assertEqual(generate_response.status_code, 201)
                generated = generate_response.json()["items"]
                self.assertEqual(len(generated), 2)

                list_response = self.client.get(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)
                self.assertEqual(list_response.status_code, 200)
                self.assertEqual(len(list_response.json()["items"]), 2)

                markdown = next(report for report in generated if report["report_type"] == "markdown")
                view_response = self.client.get(markdown["view_url"], headers=DEV_AUTH_HEADERS)
                self.assertEqual(view_response.status_code, 200)
                self.assertIn("ScopeHarbor Security Audit Report", view_response.text)

                download_response = self.client.get(markdown["download_url"], headers=DEV_AUTH_HEADERS)
                self.assertEqual(download_response.status_code, 200)
                self.assertIn("attachment;", download_response.headers["content-disposition"])

                html = next(report for report in generated if report["report_type"] == "html")
                html_response = self.client.get(html["view_url"], headers=DEV_AUTH_HEADERS)
                self.assertEqual(
                    html_response.headers["content-security-policy"],
                    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
                    "form-action 'none'; frame-ancestors 'none'",
                )
                self.assertNotIn("<script", html_response.text.lower())
                self.assertNotIn("<link", html_response.text.lower())
                self.assertNotIn(" src=", html_response.text.lower())

    def test_report_generation_never_calls_or_persists_external_ai(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("app.api.reports.settings.artifact_root", temp_dir),
                patch("app.api.reports.settings.ai_provider", "openai"),
                patch("app.ai.service.OpenAiProvider.explain") as external_provider,
            ):
                first = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)
                second = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        external_provider.assert_not_called()
        with SessionLocal() as db:
            self.assertEqual(db.query(AiRequestLog).filter(AiRequestLog.workspace_id == DEV_WORKSPACE_ID).count(), 0)
            self.assertEqual(db.query(AiExplanationCache).filter(AiExplanationCache.scan_id == self.scan_id).count(), 0)

    def test_reports_require_completed_scan(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.status = "running"
            db.add(scan)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("completed scans", response.json()["detail"])

    def test_report_generation_is_independent_of_ai_rate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.api.reports.settings.artifact_root", temp_dir), patch("app.ai.service.settings.ai_rate_limit_max_requests", 0):
                response = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 201)

    def test_report_generation_rejects_scan_target_workspace_mismatch(self) -> None:
        mismatch_workspace_id = f"report-mismatch-{uuid4()}"
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                target = db.get(Target, self.target_id)
                self.assertIsNotNone(target)
                db.add(Workspace(id=mismatch_workspace_id, owner_user_id=DEV_USER_ID, name="Report Mismatch"))
                db.flush()
                target.workspace_id = mismatch_workspace_id
                db.add(target)
                db.commit()

            try:
                with SessionLocal() as db:
                    with self.assertRaises(ReportGenerationError):
                        generate_report_artifacts(
                            db,
                            scan_id=self.scan_id,
                            workspace_id=DEV_WORKSPACE_ID,
                            artifact_root=temp_dir,
                        )
            finally:
                with SessionLocal() as db:
                    target = db.get(Target, self.target_id)
                    if target is not None:
                        target.workspace_id = DEV_WORKSPACE_ID
                        db.add(target)
                        db.flush()
                    db.execute(delete(Workspace).where(Workspace.id == mismatch_workspace_id))
                    db.commit()

    def test_reports_support_active_demo_scan(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "active_demo"
            scan.scan_profile_id = "active-demo"
            finding = db.get(Finding, self.finding_id)
            self.assertIsNotNone(finding)
            finding.source_tool = "zap-active"
            finding.evidence = "ZAP active alert metadata with api_key=[REDACTED]"
            db.add(scan)
            db.add(finding)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(response.json()["items"]), 2)

        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                markdown_content = read_report_artifact_file(markdown, artifact_root=temp_dir)

        self.assertIn("| Scan profile | active-demo |", markdown_content)
        self.assertIn("ZAP active scan: used.", markdown_content)
        self.assertIn("| Source tool | zap-active |", markdown_content)

    def test_reports_reject_ajax_short_scan(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "ajax_short"
            scan.scan_profile_id = "ajax-short"
            db.add(scan)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Passive Web, Active Demo, and Repository scans", response.json()["detail"])

    def test_reports_reject_inconsistent_scan_profile(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "ajax_short"
            scan.scan_profile_id = "passive-web"
            db.add(scan)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Passive Web, Active Demo, and Repository scans", response.json()["detail"])

    def test_reports_support_repo_scan_without_ai_provider_payload(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "repo"
            scan.scan_profile_id = "repository"
            finding = db.get(Finding, self.finding_id)
            self.assertIsNotNone(finding)
            finding.source_tool = "gitleaks"
            finding.affected_url = None
            finding.affected_file = ".env.example"
            finding.evidence = "stub_secret=[REDACTED]"
            db.add(scan)
            db.add(finding)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.ai.service.OpenAiProvider.explain") as ai_provider:
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                markdown_content = read_report_artifact_file(markdown, artifact_root=temp_dir)

        ai_provider.assert_not_called()
        self.assertIn("| Scan profile | repository |", markdown_content)
        self.assertIn("Repo scanning: used.", markdown_content)
        self.assertIn("Finding guidance: not generated for repository scans.", markdown_content)
        self.assertIn("| Source tool | gitleaks |", markdown_content)

    def test_reports_omit_unredacted_finding_text(self) -> None:
        unsafe_secret = "raw-secret-token"
        with SessionLocal() as db:
            finding = db.get(Finding, self.finding_id)
            self.assertIsNotNone(finding)
            finding.affected_url = f"http://user:pass@juice-shop:3000/callback?token={unsafe_secret}#secret"
            finding.evidence = f"authorization: bearer {unsafe_secret}"
            finding.reproduction_steps = f"Visit /callback?token={unsafe_secret}"
            finding.remediation = f"Remove {unsafe_secret}."
            finding.false_positive_notes = f"Validate {unsafe_secret} manually."
            finding.redaction_applied = False
            db.add(finding)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                html = next(artifact for artifact in artifacts if artifact.report_type == "html")
                markdown_content = read_report_artifact_file(markdown, artifact_root=temp_dir)
                html_content = read_report_artifact_file(html, artifact_root=temp_dir)

        self.assertNotIn(unsafe_secret, markdown_content)
        self.assertNotIn(unsafe_secret, html_content)
        self.assertNotIn("user:pass", markdown_content)
        self.assertNotIn("user:pass", html_content)
        self.assertIn("http://juice-shop:3000/callback", markdown_content)
        self.assertIn("authorization: bearer [REDACTED]", markdown_content)
        self.assertIn("Visit /callback", markdown_content)

    def test_report_reader_rejects_paths_outside_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            outside_path = Path(outside_dir) / "report.md"
            outside_path.write_text("outside", encoding="utf-8")
            artifact = ReportArtifact(
                id=str(uuid4()),
                scan_id=self.scan_id,
                report_type="markdown",
                path=str(outside_path),
            )

            with self.assertRaises(ValueError):
                read_report_artifact_file(artifact, artifact_root=temp_dir)

    def test_completed_historical_ajax_report_artifacts_remain_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                artifact_id = markdown.id
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "ajax_short"
                scan.scan_profile_id = "ajax-short"
                db.add(scan)
                db.commit()

            list_response = self.client.get(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)
            view_response = self.client.get(f"/api/v1/reports/{artifact_id}", headers=DEV_AUTH_HEADERS)
            download_response = self.client.get(f"/api/v1/reports/{artifact_id}/download", headers=DEV_AUTH_HEADERS)

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(view_response.status_code, 200)
        self.assertEqual(download_response.status_code, 200)

    def test_report_artifact_api_rejects_non_completed_scans(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                artifact_id = markdown.id
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.status = "running"
                db.add(scan)
                db.commit()

            list_response = self.client.get(f"/api/v1/scans/{self.scan_id}/reports", headers=DEV_AUTH_HEADERS)
            view_response = self.client.get(f"/api/v1/reports/{artifact_id}", headers=DEV_AUTH_HEADERS)
            download_response = self.client.get(f"/api/v1/reports/{artifact_id}/download", headers=DEV_AUTH_HEADERS)

        self.assertEqual(list_response.status_code, 400)
        self.assertEqual(view_response.status_code, 400)
        self.assertEqual(download_response.status_code, 400)
        self.assertIn("completed scans", list_response.json()["detail"])

    def test_report_reader_rejects_unexpected_paths_inside_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            unexpected_path = Path(temp_dir) / "scans" / self.scan_id / "crawl-summary.json"
            unexpected_path.parent.mkdir(parents=True, exist_ok=True)
            unexpected_path.write_text("not a report", encoding="utf-8")
            artifact = ReportArtifact(
                id=str(uuid4()),
                scan_id=self.scan_id,
                report_type="markdown",
                path=str(unexpected_path),
            )

            with self.assertRaises(ValueError):
                read_report_artifact_file(artifact, artifact_root=temp_dir)

    def test_report_generation_rejects_symlinked_report_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_link = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_link.parent.mkdir(parents=True, exist_ok=True)
            reports_link.symlink_to(outside_dir, target_is_directory=True)

            with SessionLocal() as db, self.assertRaises(ValueError):
                generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )

            self.assertFalse((Path(outside_dir) / "report.md").exists())

    def test_report_reader_rejects_symlinked_report_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_link = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_link.parent.mkdir(parents=True, exist_ok=True)
            reports_link.symlink_to(outside_dir, target_is_directory=True)
            escaped_report = Path(outside_dir) / "report.md"
            escaped_report.write_text("outside", encoding="utf-8")
            artifact = ReportArtifact(
                id=str(uuid4()),
                scan_id=self.scan_id,
                report_type="markdown",
                path=str(escaped_report),
            )

            with self.assertRaises(ValueError):
                read_report_artifact_file(artifact, artifact_root=temp_dir)

    def test_report_generation_rejects_symlinked_report_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_dir = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            outside_report = Path(outside_dir) / "report.md"
            outside_report.write_text("outside", encoding="utf-8")
            (reports_dir / "report.md").symlink_to(outside_report)

            with SessionLocal() as db, self.assertRaises(ValueError):
                generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )

            self.assertEqual(outside_report.read_text(encoding="utf-8"), "outside")

    def test_report_reader_rejects_symlinked_report_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_dir = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            outside_report = Path(outside_dir) / "report.md"
            outside_report.write_text("outside", encoding="utf-8")
            report_link = reports_dir / "report.md"
            report_link.symlink_to(outside_report)
            artifact = ReportArtifact(
                id=str(uuid4()),
                scan_id=self.scan_id,
                report_type="markdown",
                path=str(report_link),
            )

            with self.assertRaises(ValueError):
                read_report_artifact_file(artifact, artifact_root=temp_dir)

    def test_report_reader_rejects_symlinked_html_report_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_dir = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            outside_report = Path(outside_dir) / "report.html"
            outside_report.write_text("outside", encoding="utf-8")
            report_link = reports_dir / "report.html"
            report_link.symlink_to(outside_report)
            artifact = ReportArtifact(
                id=str(uuid4()),
                scan_id=self.scan_id,
                report_type="html",
                path=str(report_link),
            )

            with self.assertRaises(ValueError):
                read_report_artifact_file(artifact, artifact_root=temp_dir)

    def test_report_generation_rejects_symlinked_scan_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sibling_scan_dir = Path(temp_dir) / "scans" / "other-scan"
            sibling_scan_dir.mkdir(parents=True, exist_ok=True)
            scan_link = Path(temp_dir) / "scans" / self.scan_id
            scan_link.symlink_to(sibling_scan_dir, target_is_directory=True)

            with SessionLocal() as db, self.assertRaises(ValueError):
                generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )

            self.assertFalse((sibling_scan_dir / "reports" / "report.md").exists())

    def test_report_reader_rejects_symlinked_scan_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sibling_scan_dir = Path(temp_dir) / "scans" / "other-scan"
            reports_dir = sibling_scan_dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            escaped_report = reports_dir / "report.md"
            escaped_report.write_text("outside", encoding="utf-8")
            scan_link = Path(temp_dir) / "scans" / self.scan_id
            scan_link.symlink_to(sibling_scan_dir, target_is_directory=True)
            artifact = ReportArtifact(
                id=str(uuid4()),
                scan_id=self.scan_id,
                report_type="markdown",
                path=str(escaped_report),
            )

            with self.assertRaises(ValueError):
                read_report_artifact_file(artifact, artifact_root=temp_dir)

    def test_regeneration_reuses_rows_and_keeps_report_content_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                first_artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                first_markdown = next(artifact for artifact in first_artifacts if artifact.report_type == "markdown")
                first_content = read_report_artifact_file(first_markdown, artifact_root=temp_dir)

                second_artifacts = generate_report_artifacts(
                    db,
                    scan_id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    artifact_root=temp_dir,
                )
                second_markdown = next(artifact for artifact in second_artifacts if artifact.report_type == "markdown")
                second_content = read_report_artifact_file(second_markdown, artifact_root=temp_dir)
                artifacts = db.scalars(select(ReportArtifact).where(ReportArtifact.scan_id == self.scan_id)).all()

            self.assertEqual(len(artifacts), 2)
            self.assertEqual(first_content, second_content)
            self.assertIn("Audit completed at | 2026-06-17T18:00:00Z", first_content)


if __name__ == "__main__":
    unittest.main()
