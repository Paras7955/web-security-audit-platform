import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from cryptography.fernet import Fernet
from sqlalchemy import delete

from app.db.session import SessionLocal
from app.maintenance import (
    backfill_legacy_risk_scores,
    cleanup_orphan_artifacts,
    prune_operational_data,
    reencrypt_auth_profiles,
)
from app.models import ApiRateLimitLog, AuditLog, AuthProfile, RiskScore, Scan, Target
from tests.helpers import DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class MaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.operational_log_id = str(uuid4())
        self.audit_log_id = str(uuid4())
        self.auth_profile_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(
                Target(
                    id=self.target_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    allowlist_id="juice-shop",
                    name="Maintenance target",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                    authorization_confirmed_at=datetime.now(UTC),
                )
            )
            db.flush()
            db.add(
                Scan(
                    id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    target_id=self.target_id,
                    mode="passive",
                    scan_profile_id="passive-web",
                    status="completed",
                    current_step="normalizing_findings",
                    status_message="Completed.",
                    progress_percent=100,
                    completed_at=datetime.now(UTC),
                    attempt_count=0,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(RiskScore).where(RiskScore.scan_id == self.scan_id))
            db.execute(delete(ApiRateLimitLog).where(ApiRateLimitLog.id == self.operational_log_id))
            db.execute(delete(AuditLog).where(AuditLog.id == self.audit_log_id))
            db.execute(delete(AuthProfile).where(AuthProfile.id == self.auth_profile_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_orphan_cleanup_is_dry_run_first_and_never_removes_known_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scans_root = Path(temp_dir) / "scans"
            known = scans_root / self.scan_id
            orphan = scans_root / str(uuid4())
            known.mkdir(parents=True)
            orphan.mkdir()
            (orphan / "safe.txt").write_text("fixture", encoding="utf-8")
            with SessionLocal() as db:
                dry_run = cleanup_orphan_artifacts(db, artifact_root=temp_dir, apply=False)
                self.assertEqual(dry_run.candidates, 1)
                self.assertEqual(dry_run.changed, 0)
                self.assertTrue(orphan.exists())
                applied = cleanup_orphan_artifacts(db, artifact_root=temp_dir, apply=True)
            self.assertEqual(applied.changed, 1)
            self.assertFalse(orphan.exists())
            self.assertTrue(known.exists())

    def test_risk_backfill_requires_apply(self) -> None:
        with SessionLocal() as db:
            dry_run = backfill_legacy_risk_scores(db, apply=False)
            self.assertGreaterEqual(dry_run.candidates, 1)
            self.assertIsNone(db.query(RiskScore).filter(RiskScore.scan_id == self.scan_id).one_or_none())
            applied = backfill_legacy_risk_scores(db, apply=True)
            self.assertGreaterEqual(applied.changed, 1)
            self.assertIsNotNone(db.query(RiskScore).filter(RiskScore.scan_id == self.scan_id).one_or_none())

    def test_operational_pruning_never_prunes_audit_logs(self) -> None:
        old = datetime.now(UTC) - timedelta(days=90)
        with SessionLocal() as db:
            db.add(
                ApiRateLimitLog(
                    id=self.operational_log_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    user_id=DEV_USER_ID,
                    action="maintenance-test",
                    allowed=True,
                    created_at=old,
                )
            )
            db.add(
                AuditLog(
                    id=self.audit_log_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    user_id=DEV_USER_ID,
                    event_type="maintenance.test",
                    metadata_json={},
                    created_at=old,
                )
            )
            db.commit()
            dry_run = prune_operational_data(db, older_than_days=30, apply=False)
            self.assertGreaterEqual(dry_run.candidates, 1)
            self.assertIsNotNone(db.get(ApiRateLimitLog, self.operational_log_id))
            prune_operational_data(db, older_than_days=30, apply=True)
            self.assertIsNone(db.get(ApiRateLimitLog, self.operational_log_id))
            self.assertIsNotNone(db.get(AuditLog, self.audit_log_id))

    def test_fernet_reencryption_requires_apply_and_never_changes_revoked_profiles(self) -> None:
        previous_key = Fernet.generate_key().decode("ascii")
        current_key = Fernet.generate_key().decode("ascii")
        ciphertext = Fernet(previous_key.encode("ascii")).encrypt(b"canary-secret").decode("ascii")
        with SessionLocal() as db:
            db.add(
                AuthProfile(
                    id=self.auth_profile_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    label="Re-encryption fixture",
                    profile_type="bearer_token",
                    encrypted_secret=ciphertext,
                    secret_hint="****cret",
                )
            )
            db.commit()
            with (
                patch("app.maintenance.settings.auth_profile_previous_secret_key", previous_key),
                patch("app.maintenance.settings.auth_profile_secret_key", current_key),
            ):
                dry_run = reencrypt_auth_profiles(db, apply=False)
                self.assertGreaterEqual(dry_run.candidates, 1)
                self.assertEqual(db.get(AuthProfile, self.auth_profile_id).encrypted_secret, ciphertext)
                reencrypt_auth_profiles(db, apply=True)
            updated = db.get(AuthProfile, self.auth_profile_id)
            self.assertEqual(
                Fernet(current_key.encode("ascii")).decrypt(updated.encrypted_secret.encode("ascii")),
                b"canary-secret",
            )


if __name__ == "__main__":
    unittest.main()
