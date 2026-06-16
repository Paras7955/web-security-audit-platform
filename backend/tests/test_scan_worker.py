import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import delete, select

from app.core.contracts import Confidence, ScanStatus, ScanStep, Severity
from app.db.session import SessionLocal
from app.findings.schemas import NormalizedFindingInput
from app.models import Finding, Scan, Target
from app.scans.artifacts import ArtifactPathError, ensure_scan_artifact_dir, scan_artifact_dir
from app.scans.lifecycle import claim_next_queued_scan, run_internal_lifecycle_job, run_passive_scan_job
from app.scanner.passive import PassiveScanResult
from app.security.allowlist import ScanAllowlist


class ScanWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
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
                    status=ScanStatus.QUEUED.value,
                    current_step=ScanStep.TARGET_VALIDATION.value,
                    status_message="Queued for test.",
                    progress_percent=0,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_worker_claims_queued_scan(self) -> None:
        with SessionLocal() as db:
            scan = claim_next_queued_scan(db)

            self.assertIsNotNone(scan)
            self.assertEqual(scan.id, self.scan_id)
            self.assertEqual(scan.status, "validating")
            self.assertEqual(scan.current_step, "target_validation")
            self.assertEqual(scan.progress_percent, 5)
            self.assertIsNotNone(scan.started_at)

    def test_internal_lifecycle_job_completes_scan_and_writes_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)

                run_internal_lifecycle_job(db, scan, temp_dir)

                self.assertEqual(scan.status, "completed")
                self.assertEqual(scan.current_step, "target_validation")
                self.assertEqual(scan.progress_percent, 100)
                self.assertIsNotNone(scan.completed_at)
                self.assertIn("internal lifecycle job completed", scan.status_message)

            artifact_file = Path(temp_dir) / "scans" / self.scan_id / "internal_lifecycle.txt"
            self.assertTrue(artifact_file.exists())

    def test_artifact_path_must_stay_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ArtifactPathError):
                scan_artifact_dir(temp_dir, "../escape")

            artifact_dir = ensure_scan_artifact_dir(temp_dir, self.scan_id)
            self.assertTrue(artifact_dir.exists())
            self.assertIn(Path(temp_dir).resolve(), artifact_dir.parents)

    def test_artifact_root_must_not_escape_through_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as external_dir:
            scans_link = Path(temp_dir) / "scans"
            scans_link.symlink_to(external_dir, target_is_directory=True)

            with self.assertRaises(ArtifactPathError):
                scan_artifact_dir(temp_dir, self.scan_id)

    def test_worker_fails_non_passive_queued_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "active_demo"
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_internal_lifecycle_job(db, scan, temp_dir)

                self.assertEqual(scan.status, "failed")
                self.assertEqual(scan.error_code, "scan_worker_failed")
                self.assertIn("only supports passive", scan.error_detail)

    def test_worker_fails_unconfirmed_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                target = db.get(Target, self.target_id)
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(target)
                self.assertIsNotNone(scan)
                target.permission_confirmed = False
                db.add(target)
                db.commit()
                db.refresh(scan)

                run_internal_lifecycle_job(db, scan, temp_dir)

                self.assertEqual(scan.status, "failed")
                self.assertEqual(scan.error_code, "scan_worker_failed")
                self.assertIn("authorization is not confirmed", scan.error_detail)

    def test_passive_scan_job_persists_findings(self) -> None:
        allowlist = ScanAllowlist.model_validate(
            {
                "targets": [
                    {
                        "id": "juice-shop",
                        "name": "OWASP Juice Shop",
                        "base_url": "http://juice-shop:3000",
                        "schemes": ["http"],
                        "hosts": ["juice-shop"],
                        "ports": [3000],
                        "allowed_modes": ["passive"],
                        "max_redirects": 5,
                        "local_demo": True,
                    }
                ]
            }
        )
        finding = NormalizedFindingInput(
            title="Missing Content Security Policy",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            affected_url="http://juice-shop:3000/",
            evidence="Content-Security-Policy header was not present.",
            source_tool="custom-passive",
            scanner_rule_id="header:content-security-policy",
            cwe="CWE-693",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_result = PassiveScanResult(
                pages=(),
                findings=(finding,),
                errors=(),
                artifact_dir=Path(temp_dir) / "scans" / self.scan_id,
            )
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result):
                    run_passive_scan_job(db, scan, temp_dir, allowlist)

                self.assertEqual(scan.status, "completed")
                self.assertEqual(scan.current_step, "normalizing_findings")
                self.assertEqual(scan.progress_percent, 100)
                persisted = db.scalars(select(Finding).where(Finding.scan_id == self.scan_id)).all()
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].source_tool, "custom-passive")
                self.assertEqual(persisted[0].scanner_rule_id, "header:content-security-policy")


if __name__ == "__main__":
    unittest.main()
