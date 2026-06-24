import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.db.session import SessionLocal
from app.main import app
from app.models import Finding, ReportArtifact, Scan, Target
from app.reports.service import generate_report_artifacts, read_report_artifact


class ReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.finding_id = str(uuid4())
        with SessionLocal() as db:
            db.add(
                Target(
                    id=self.target_id,
                    allowlist_id="juice-shop",
                    name="OWASP Juice Shop",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            db.add(
                Scan(
                    id=self.scan_id,
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
            db.execute(delete(ReportArtifact).where(ReportArtifact.scan_id == self.scan_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_generate_report_artifacts_writes_markdown_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")

                self.assertEqual({artifact.report_type for artifact in artifacts}, {"markdown", "html"})
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                html = next(artifact for artifact in artifacts if artifact.report_type == "html")
                markdown_content = read_report_artifact(markdown, artifact_root=temp_dir)
                html_content = read_report_artifact(html, artifact_root=temp_dir)

            self.assertIn("Target allowlist ID: juice-shop", markdown_content)
            self.assertNotIn("+00:00Z", markdown_content)
            self.assertIn("ZAP passive analysis: used for allowlisted URLs.", markdown_content)
            self.assertIn("ZAP active scan: not used.", markdown_content)
            self.assertIn("AI explanations: generated with template provider.", markdown_content)
            self.assertIn("## AI Explanations", markdown_content)
            self.assertIn("Provider used: template", markdown_content)
            self.assertIn(f"Finding {self.finding_id}", markdown_content)
            self.assertIn("Redaction applied: yes", markdown_content)
            self.assertNotIn("+00:00Z", html_content)
            self.assertIn("<h2>AI Explanations</h2>", html_content)
            self.assertIn("ZAP passive analysis: used for allowlisted URLs.", html_content)
            self.assertIn("generated with template provider", html_content)
            self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_content)
            self.assertNotIn("<script>alert('xss')</script>", html_content)

    def test_generate_reports_api_lists_and_serves_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.api.reports.settings.artifact_root", temp_dir):
                generate_response = self.client.post(f"/scans/{self.scan_id}/reports")
                self.assertEqual(generate_response.status_code, 201)
                generated = generate_response.json()
                self.assertEqual(len(generated), 2)

                list_response = self.client.get(f"/scans/{self.scan_id}/reports")
                self.assertEqual(list_response.status_code, 200)
                self.assertEqual(len(list_response.json()), 2)

                markdown = next(report for report in generated if report["report_type"] == "markdown")
                view_response = self.client.get(markdown["view_url"])
                self.assertEqual(view_response.status_code, 200)
                self.assertIn("Defensive Web App Security Audit Report", view_response.text)

                download_response = self.client.get(markdown["download_url"])
                self.assertEqual(download_response.status_code, 200)
                self.assertIn("attachment;", download_response.headers["content-disposition"])

    def test_reports_require_completed_scan(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.status = "running"
            db.add(scan)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/scans/{self.scan_id}/reports")

        self.assertEqual(response.status_code, 400)
        self.assertIn("completed scans", response.json()["detail"])

    def test_reports_support_active_demo_scan(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "active_demo"
            finding = db.get(Finding, self.finding_id)
            self.assertIsNotNone(finding)
            finding.source_tool = "zap-active"
            finding.evidence = "ZAP active alert metadata with api_key=[REDACTED]"
            db.add(scan)
            db.add(finding)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/scans/{self.scan_id}/reports")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(response.json()), 2)

        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                artifacts = generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")
                markdown = next(artifact for artifact in artifacts if artifact.report_type == "markdown")
                markdown_content = read_report_artifact(markdown, artifact_root=temp_dir)

        self.assertIn("Scan mode: Active Demo", markdown_content)
        self.assertIn("ZAP active scan: used.", markdown_content)
        self.assertIn("Source tool: zap-active", markdown_content)

    def test_reports_reject_ajax_short_scan(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "ajax_short"
            db.add(scan)
            db.commit()

        with tempfile.TemporaryDirectory() as temp_dir, patch("app.api.reports.settings.artifact_root", temp_dir):
            response = self.client.post(f"/scans/{self.scan_id}/reports")

        self.assertEqual(response.status_code, 400)
        self.assertIn("passive and Active Demo scans", response.json()["detail"])

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
                read_report_artifact(artifact, artifact_root=temp_dir)

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
                read_report_artifact(artifact, artifact_root=temp_dir)

    def test_report_generation_rejects_symlinked_report_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_link = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_link.parent.mkdir(parents=True, exist_ok=True)
            reports_link.symlink_to(outside_dir, target_is_directory=True)

            with SessionLocal() as db, self.assertRaises(ValueError):
                generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")

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
                read_report_artifact(artifact, artifact_root=temp_dir)

    def test_report_generation_rejects_symlinked_report_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            reports_dir = Path(temp_dir) / "scans" / self.scan_id / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            outside_report = Path(outside_dir) / "report.md"
            outside_report.write_text("outside", encoding="utf-8")
            (reports_dir / "report.md").symlink_to(outside_report)

            with SessionLocal() as db, self.assertRaises(ValueError):
                generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")

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
                read_report_artifact(artifact, artifact_root=temp_dir)

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
                read_report_artifact(artifact, artifact_root=temp_dir)

    def test_report_generation_rejects_symlinked_scan_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sibling_scan_dir = Path(temp_dir) / "scans" / "other-scan"
            sibling_scan_dir.mkdir(parents=True, exist_ok=True)
            scan_link = Path(temp_dir) / "scans" / self.scan_id
            scan_link.symlink_to(sibling_scan_dir, target_is_directory=True)

            with SessionLocal() as db, self.assertRaises(ValueError):
                generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")

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
                read_report_artifact(artifact, artifact_root=temp_dir)

    def test_regeneration_reuses_rows_and_keeps_report_content_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                first_artifacts = generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")
                first_markdown = next(artifact for artifact in first_artifacts if artifact.report_type == "markdown")
                first_content = read_report_artifact(first_markdown, artifact_root=temp_dir)

                second_artifacts = generate_report_artifacts(db, scan_id=self.scan_id, artifact_root=temp_dir, ai_provider="template")
                second_markdown = next(artifact for artifact in second_artifacts if artifact.report_type == "markdown")
                second_content = read_report_artifact(second_markdown, artifact_root=temp_dir)
                artifacts = db.scalars(select(ReportArtifact).where(ReportArtifact.scan_id == self.scan_id)).all()

            self.assertEqual(len(artifacts), 2)
            self.assertEqual(first_content, second_content)
            self.assertIn("Generated at: 2026-06-17T18:00:00Z", first_content)


if __name__ == "__main__":
    unittest.main()
