import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete

from app.core.contracts import ScanStatus, ScanStep
from app.db.session import SessionLocal
from app.models import Scan, Target
from app.scans.artifacts import ArtifactPathError, ensure_scan_artifact_dir, scan_artifact_dir
from app.scans.lifecycle import claim_next_queued_scan, run_internal_lifecycle_job


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
                self.assertEqual(scan.current_step, "normalizing_findings")
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


if __name__ == "__main__":
    unittest.main()
