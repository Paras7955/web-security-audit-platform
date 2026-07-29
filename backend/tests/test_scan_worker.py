import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.auth_profiles import AuthProfileError, encrypt_secret
from app.core.contracts import Confidence, ScanStatus, ScanStep, Severity
from app.db.session import SessionLocal
from app.findings.schemas import NormalizedFindingInput
from app.models import (
    LEGACY_USER_ID,
    LEGACY_WORKSPACE_ID,
    AuthProfile,
    Finding,
    FindingOccurrenceState,
    FindingState,
    RepositoryAsset,
    RiskScore,
    Scan,
    ScannerToolRun,
    Target,
    WorkerHeartbeat,
    Workspace,
)
from app.repo_scanner.adapters import RepoScanResult, ToolReceipt
from app.scanner.passive import PassiveScanResult
from app.scans.artifacts import ArtifactPathError, ensure_scan_artifact_dir, scan_artifact_dir
from app.scans.lifecycle import (
    ScanLeaseLostError,
    claim_next_queued_scan,
    recover_stale_scan_leases,
    renew_scan_lease,
    run_passive_scan_job,
    run_repo_scan_job,
    update_scan_progress,
)
from app.security.allowlist import ScanAllowlist
from app.zap.active import ZapActiveDemoResult
from app.zap.client_spider import ZapClientSpiderResult
from app.zap.passive import ZapPassiveResult
from sqlalchemy import delete, select
from worker.main import ScanExecutionMonitor, validate_worker_startup


class ScanWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.repository_asset_id = str(uuid4())
        policy = build_test_allowlist().get_target("juice-shop")
        if policy is None:
            raise AssertionError("test allowlist policy missing")
        with SessionLocal() as db:
            db.add(
                Target(
                    id=self.target_id,
                    allowlist_id="juice-shop",
                    name="OWASP Juice Shop",
                    base_url="http://juice-shop:3000/",
                    policy_fingerprint=policy.policy_fingerprint,
                    policy_scope_base_url=policy.base_url,
                    permission_confirmed=True,
                )
            )
            db.add(
                Scan(
                    id=self.scan_id,
                    target_id=self.target_id,
                    target_policy_fingerprint=policy.policy_fingerprint,
                    acknowledgements_snapshot=["authorized_target"],
                    authorization_snapshot=web_authorization_snapshot(
                        target_id=self.target_id,
                        policy=policy,
                    ),
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
            finding_ids = [row[0] for row in db.query(Finding.id).filter(Finding.scan_id == self.scan_id).all()]
            if finding_ids:
                db.execute(delete(FindingOccurrenceState).where(FindingOccurrenceState.finding_id.in_(finding_ids)))
            db.execute(delete(FindingState).where(FindingState.target_id == self.target_id))
            db.execute(delete(FindingState).where(FindingState.repository_asset_id == self.repository_asset_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(RiskScore).where(RiskScore.scan_id == self.scan_id))
            db.execute(delete(ScannerToolRun).where(ScannerToolRun.scan_id == self.scan_id))
            db.execute(delete(WorkerHeartbeat).where(WorkerHeartbeat.worker_id == "test-execution-worker"))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(RepositoryAsset).where(RepositoryAsset.id == self.repository_asset_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.execute(delete(AuthProfile).where(AuthProfile.id == "auth-profile-1"))
            db.execute(delete(Workspace).where(Workspace.id == "different-workspace"))
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
            self.assertIsNotNone(scan.lease_owner)
            self.assertIsNotNone(scan.lease_expires_at)
            self.assertEqual(scan.attempt_count, 1)

    def test_stale_worker_lease_fails_without_retry_or_raw_detail(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = datetime.now(UTC) - timedelta(minutes=5)
            scan.lease_owner = "crashed-worker"
            scan.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            scan.attempt_count = 1
            db.add(scan)
            db.commit()

            self.assertGreaterEqual(recover_stale_scan_leases(db), 1)
            db.refresh(scan)
            self.assertEqual(scan.status, ScanStatus.FAILED.value)
            self.assertEqual(scan.error_code, "worker_interrupted")
            self.assertIsNone(scan.error_detail)
            self.assertEqual(scan.attempt_count, 1)
            self.assertIsNone(scan.lease_owner)

    def test_execution_monitor_renews_lease_and_worker_heartbeat_in_separate_session(self) -> None:
        with SessionLocal() as db:
            scan = claim_next_queued_scan(db, worker_id="test-execution-worker")
            self.assertIsNotNone(scan)
            original_expiry = scan.lease_expires_at

            monitor = ScanExecutionMonitor(
                scan_id=scan.id,
                worker_id="test-execution-worker",
                interval_seconds=60,
            )
            self.assertTrue(monitor.renew_now())

            db.refresh(scan)
            heartbeat = db.scalar(
                select(WorkerHeartbeat).where(WorkerHeartbeat.worker_id == "test-execution-worker")
            )
            self.assertIsNotNone(heartbeat)
            self.assertEqual(heartbeat.status, "processing")
            self.assertEqual(heartbeat.current_scan_id, scan.id)
            self.assertGreater(scan.lease_expires_at, original_expiry)

    def test_execution_monitor_periodically_reports_lease_loss(self) -> None:
        monitor = ScanExecutionMonitor(
            scan_id=self.scan_id,
            worker_id="test-execution-worker",
            interval_seconds=0.001,
        )
        with patch.object(monitor, "renew_now", return_value=False) as renew:
            with monitor:
                deadline = time.monotonic() + 0.5
                while renew.call_count == 0 and time.monotonic() < deadline:
                    time.sleep(0.005)
                with self.assertRaises(ScanLeaseLostError):
                    monitor.checkpoint()
        renew.assert_called_once_with()

    def test_owned_progress_write_is_rejected_after_lease_owner_changes(self) -> None:
        with SessionLocal() as db:
            scan = claim_next_queued_scan(db, worker_id="first-worker")
            self.assertIsNotNone(scan)

            with SessionLocal() as competing_db:
                competing_scan = competing_db.get(Scan, scan.id)
                self.assertIsNotNone(competing_scan)
                competing_scan.lease_owner = "second-worker"
                competing_scan.lease_heartbeat_at = datetime.now(UTC)
                competing_scan.lease_expires_at = datetime.now(UTC) + timedelta(seconds=45)
                competing_db.add(competing_scan)
                competing_db.commit()

            with self.assertRaises(ScanLeaseLostError):
                update_scan_progress(
                    db,
                    scan,
                    status=ScanStatus.RUNNING,
                    current_step=ScanStep.CUSTOM_CRAWL,
                    status_message="Stale worker must not persist this.",
                    progress_percent=30,
                    expected_lease_owner="first-worker",
                )
            db.rollback()
            db.refresh(scan)
            self.assertEqual(scan.lease_owner, "second-worker")
            self.assertEqual(scan.progress_percent, 5)

    def test_expired_lease_cannot_be_resurrected(self) -> None:
        with SessionLocal() as db:
            scan = claim_next_queued_scan(db, worker_id="test-execution-worker")
            self.assertIsNotNone(scan)
            scan.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            db.add(scan)
            db.commit()

        with SessionLocal() as renewal_db:
            self.assertFalse(
                renew_scan_lease(
                    renewal_db,
                    scan_id=self.scan_id,
                    worker_id="test-execution-worker",
                )
            )

    def test_historical_ajax_job_fails_as_retired(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "ajax_short"
            scan.scan_profile_id = "ajax-short"
            db.add(scan)
            db.commit()
            run_passive_scan_job(db, scan, temp_dir, build_test_allowlist())
            self.assertEqual(scan.status, ScanStatus.FAILED.value)
            self.assertEqual(scan.error_code, "retired_profile")
            self.assertIsNone(scan.error_detail)

    def test_worker_startup_fails_on_invalid_auth_profile_secret_key(self) -> None:
        with patch("worker.main.settings.auth_profile_secret_key", "not-a-fernet-key"):
            with self.assertRaises(AuthProfileError):
                validate_worker_startup()

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

    def test_scan_artifact_path_must_not_be_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as external_dir:
            scan_link = Path(temp_dir) / "scans" / self.scan_id
            scan_link.parent.mkdir(parents=True, exist_ok=True)
            scan_link.symlink_to(external_dir, target_is_directory=True)

            with self.assertRaises(ArtifactPathError):
                scan_artifact_dir(temp_dir, self.scan_id)

    def test_worker_fails_unsupported_queued_scan_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "future_mode"
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_passive_scan_job(db, scan, temp_dir, build_test_allowlist())

                self.assertEqual(scan.status, "failed")
                self.assertEqual(scan.error_code, "scan_worker_failed")
                self.assertIsNone(scan.error_detail)

    def test_worker_uses_queued_authority_after_target_authorization_changes(self) -> None:
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

                fake_result = PassiveScanResult(
                    pages=(),
                    findings=(),
                    errors=(),
                    artifact_dir=Path(temp_dir) / "scans" / self.scan_id,
                )
                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result):
                    run_passive_scan_job(db, scan, temp_dir, build_test_allowlist())

                self.assertEqual(scan.status, "completed")
                self.assertIsNone(scan.error_detail)

    def test_worker_fails_workspace_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                if db.get(Workspace, "different-workspace") is None:
                    db.add(Workspace(id="different-workspace", owner_user_id=LEGACY_USER_ID, name="Different Workspace"))
                    db.flush()
                scan.workspace_id = "different-workspace"
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_passive_scan_job(db, scan, temp_dir, build_test_allowlist())

                self.assertEqual(scan.status, "failed")
                self.assertEqual(scan.error_code, "scan_worker_failed")
                self.assertIsNone(scan.error_detail)

    def test_passive_scan_job_persists_findings(self) -> None:
        allowlist = build_test_allowlist()
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
                authorize_web_scan(scan, allowlist)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result):
                    run_passive_scan_job(db, scan, temp_dir, allowlist)

                self.assertEqual(scan.status, "completed")
                self.assertEqual(scan.current_step, "normalizing_findings")
                self.assertEqual(scan.progress_percent, 100)
                persisted = db.scalars(select(Finding).where(Finding.scan_id == self.scan_id)).all()
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].source_tool, "custom-passive")
                self.assertEqual(persisted[0].scanner_rule_id, "header:content-security-policy")

    def test_passive_scan_job_passes_decrypted_auth_headers_to_custom_scanner(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive",))
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_result = PassiveScanResult(pages=(), findings=(), errors=(), artifact_dir=Path(temp_dir) / "scans" / self.scan_id)
            with SessionLocal() as db:
                db.add(
                    AuthProfile(
                        id="auth-profile-1",
                        workspace_id=LEGACY_WORKSPACE_ID,
                        created_by_user_id=LEGACY_USER_ID,
                        label="Bearer",
                        profile_type="bearer_token",
                        encrypted_secret=encrypt_secret("worker-token"),
                        secret_hint="****oken",
                    )
                )
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.auth_profile_id = "auth-profile-1"
                authorize_web_scan(scan, allowlist, auth_profile_id="auth-profile-1")
                db.add(scan)
                db.commit()
                db.refresh(scan)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result) as passive_scan:
                    run_passive_scan_job(db, scan, temp_dir, allowlist)

                passive_scan.assert_called_once()
                self.assertEqual(passive_scan.call_args.kwargs["auth_headers"], {"Authorization": "Bearer worker-token"})

    def test_non_passive_scan_job_fails_when_auth_profile_is_attached(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive", "active_demo"))
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                db.add(
                    AuthProfile(
                        id="auth-profile-1",
                        workspace_id=LEGACY_WORKSPACE_ID,
                        created_by_user_id=LEGACY_USER_ID,
                        label="Bearer",
                        profile_type="bearer_token",
                        encrypted_secret=encrypt_secret("worker-token"),
                        secret_hint="****oken",
                    )
                )
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "active_demo"
                scan.scan_profile_id = "active-demo"
                scan.auth_profile_id = "auth-profile-1"
                authorize_web_scan(scan, allowlist, auth_profile_id="auth-profile-1")
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url="http://zap:8080")

                self.assertEqual(scan.status, "failed")
                self.assertEqual(scan.error_code, "scan_worker_failed")
                self.assertIsNone(scan.error_detail)

    def test_passive_scan_job_persists_zap_passive_findings(self) -> None:
        allowlist = build_test_allowlist(passive_zap=True)
        custom_finding = NormalizedFindingInput(
            title="Missing Content Security Policy",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            affected_url="http://juice-shop:3000/",
            evidence="Content-Security-Policy header was not present.",
            source_tool="custom-passive",
            scanner_rule_id="header:content-security-policy",
            cwe="CWE-693",
        )
        zap_finding = NormalizedFindingInput(
            title="ZAP CSP Alert",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_url="http://juice-shop:3000/",
            evidence="ZAP passive alert metadata.",
            source_tool="zap-passive",
            scanner_rule_id="10038",
            cwe="CWE-693",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_result = PassiveScanResult(
                pages=(),
                findings=(custom_finding,),
                errors=(),
                artifact_dir=Path(temp_dir) / "scans" / self.scan_id,
            )
            fake_zap_result = ZapPassiveResult(
                findings=(zap_finding,),
                errors=(),
                submitted_urls=("http://juice-shop:3000/",),
            )
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result), patch(
                    "app.scans.lifecycle.run_zap_passive_scan", return_value=fake_zap_result
                ) as zap:
                    run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url="http://zap:8080")

                zap.assert_called_once()
                self.assertEqual(scan.status, "completed")
                persisted = db.scalars(select(Finding).where(Finding.scan_id == self.scan_id).order_by(Finding.source_tool.asc())).all()
                self.assertEqual(len(persisted), 2)
                self.assertEqual({finding.source_tool for finding in persisted}, {"custom-passive", "zap-passive"})
                receipts = db.scalars(select(ScannerToolRun).where(ScannerToolRun.scan_id == self.scan_id)).all()
                self.assertEqual({receipt.tool_name for receipt in receipts}, {"scopeharbor-passive", "zap-passive"})
                self.assertTrue(all(receipt.status == "completed" for receipt in receipts))
                self.assertEqual({receipt.tool_name: receipt.finding_count for receipt in receipts}, {"scopeharbor-passive": 1, "zap-passive": 1})

    def test_passive_scan_job_completes_with_warning_when_zap_warns(self) -> None:
        allowlist = build_test_allowlist(passive_zap=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_result = PassiveScanResult(
                pages=(),
                findings=(),
                errors=(),
                artifact_dir=Path(temp_dir) / "scans" / self.scan_id,
            )
            fake_zap_result = ZapPassiveResult(
                findings=(),
                errors=("ZAP passive scanner did not finish within the poll limit.",),
                submitted_urls=(),
            )
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result), patch(
                    "app.scans.lifecycle.run_zap_passive_scan", return_value=fake_zap_result
                ):
                    run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url="http://zap:8080")

                self.assertEqual(scan.status, "completed_with_warnings")
                self.assertEqual(scan.current_step, "normalizing_findings")
                self.assertIn("warning", scan.status_message)
                receipt = db.scalar(
                    select(ScannerToolRun).where(
                        ScannerToolRun.scan_id == self.scan_id,
                        ScannerToolRun.tool_name == "zap-passive",
                    )
                )
                self.assertIsNotNone(receipt)
                self.assertEqual(receipt.status, "completed_with_warnings")
                self.assertEqual(receipt.warning_code, "zap_passive_warning")
                self.assertNotIn("poll limit", receipt.warning_code)

    def test_active_demo_scan_job_persists_zap_active_findings(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive", "active_demo"))
        active_finding = NormalizedFindingInput(
            title="ZAP Active Demo Alert",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_url="http://juice-shop:3000/",
            evidence="ZAP active alert metadata.",
            source_tool="zap-active",
            scanner_rule_id="40012",
            cwe="CWE-79",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_result = PassiveScanResult(
                pages=(),
                findings=(),
                errors=(),
                artifact_dir=Path(temp_dir) / "scans" / self.scan_id,
            )
            fake_zap_passive = ZapPassiveResult(findings=(), errors=(), submitted_urls=("http://juice-shop:3000/",))
            fake_zap_active = ZapActiveDemoResult(
                findings=(active_finding,),
                errors=(),
                submitted_url="http://juice-shop:3000/",
            )
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "active_demo"
                scan.scan_profile_id = "active-demo"
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result), patch(
                    "app.scans.lifecycle.run_zap_passive_scan", return_value=fake_zap_passive
                ), patch("app.scans.lifecycle.run_zap_active_demo_scan", return_value=fake_zap_active) as active:
                    run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url="http://zap:8080")

                active.assert_called_once()
                self.assertEqual(scan.status, "completed")
                self.assertEqual(scan.current_step, "normalizing_findings")
                persisted = db.scalars(select(Finding).where(Finding.scan_id == self.scan_id)).all()
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].source_tool, "zap-active")
                receipts = db.scalars(select(ScannerToolRun).where(ScannerToolRun.scan_id == self.scan_id)).all()
                self.assertEqual(
                    {receipt.tool_name for receipt in receipts},
                    {"scopeharbor-passive", "zap-passive", "zap-active"},
                )

    def test_active_demo_scan_job_fails_when_mode_removed_from_allowlist(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive",))

        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "active_demo"
                scan.scan_profile_id = "active-demo"
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url="http://zap:8080")

                self.assertEqual(scan.status, "failed")
                self.assertIsNone(scan.error_detail)

    def test_active_demo_scan_job_fails_without_zap_base_url(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive", "active_demo"))

        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "active_demo"
                scan.scan_profile_id = "active-demo"
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url=None)

                self.assertEqual(scan.status, "failed")
                self.assertIsNone(scan.error_detail)

    def test_modern_web_crawl_job_persists_client_spider_findings(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive", "modern_web_crawl"))
        client_finding = NormalizedFindingInput(
            title="ZAP Client Spider Alert",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            affected_url="http://juice-shop:3000/search",
            evidence="ZAP Client Spider alert metadata.",
            source_tool="zap-client-spider",
            scanner_rule_id="10038",
            cwe="CWE-693",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_result = PassiveScanResult(
                pages=(),
                findings=(),
                errors=(),
                artifact_dir=Path(temp_dir) / "scans" / self.scan_id,
            )
            fake_zap_passive = ZapPassiveResult(findings=(), errors=(), submitted_urls=("http://juice-shop:3000/",))
            fake_client_spider = ZapClientSpiderResult(
                findings=(client_finding,),
                errors=(),
                submitted_url="http://juice-shop:3000/",
            )
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "modern_web_crawl"
                scan.scan_profile_id = "modern-web-crawl"
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                with patch("app.scans.lifecycle.run_passive_scan", return_value=fake_result), patch(
                    "app.scans.lifecycle.run_zap_passive_scan", return_value=fake_zap_passive
                ), patch("app.scans.lifecycle.run_zap_client_spider_scan", return_value=fake_client_spider) as spider:
                    run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url="http://zap:8080")

                spider.assert_called_once()
                self.assertEqual(scan.status, "completed")
                self.assertEqual(scan.current_step, "normalizing_findings")
                persisted = db.scalars(select(Finding).where(Finding.scan_id == self.scan_id)).all()
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].source_tool, "zap-client-spider")
                receipts = db.scalars(select(ScannerToolRun).where(ScannerToolRun.scan_id == self.scan_id)).all()
                self.assertEqual(
                    {receipt.tool_name for receipt in receipts},
                    {"scopeharbor-passive", "zap-passive", "zap-client-spider"},
                )

    def test_modern_web_crawl_job_fails_without_zap_base_url(self) -> None:
        allowlist = build_test_allowlist(allowed_modes=("passive", "modern_web_crawl"))

        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "modern_web_crawl"
                scan.scan_profile_id = "modern-web-crawl"
                authorize_web_scan(scan, allowlist)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_passive_scan_job(db, scan, temp_dir, allowlist, zap_base_url=None)

                self.assertEqual(scan.status, "failed")
                self.assertIsNone(scan.error_detail)

    def test_repo_scan_job_persists_real_tool_findings_and_receipts(self) -> None:
        repo_finding = NormalizedFindingInput(
            title="Potential hardcoded secret",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            affected_file=".env.example",
            evidence="[REDACTED] secret matched rule generic-secret.",
            source_tool="gitleaks",
            scanner_rule_id="generic-secret",
            cwe="CWE-798",
            redaction_applied=True,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "security-project"
            repo_path.mkdir()
            with SessionLocal() as db:
                target = db.get(Target, self.target_id)
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(target)
                self.assertIsNotNone(scan)
                db.add(
                    RepositoryAsset(
                        id=self.repository_asset_id,
                        workspace_id=LEGACY_WORKSPACE_ID,
                        created_by_user_id=LEGACY_USER_ID,
                        name="Security Project",
                        relative_path=repo_path.name,
                        permission_confirmed=True,
                    )
                )
                scan.mode = "repo"
                scan.scan_profile_id = "repository"
                scan.target_id = None
                scan.repository_asset_id = self.repository_asset_id
                scan.repo_path_snapshot = repo_path.name
                scan.authorization_snapshot = repository_authorization_snapshot(
                    repository_asset_id=self.repository_asset_id,
                    relative_path=repo_path.name,
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)

                now = datetime.now(UTC)
                receipt = ToolReceipt("gitleaks", "8.30.1", "completed", None, 1, now, now)
                fake_result = RepoScanResult(findings=(repo_finding,), receipts=(receipt,), warning_codes=())
                with patch("app.scans.lifecycle.run_repository_scan", return_value=fake_result) as repo_scan:
                    run_repo_scan_job(db, scan, temp_dir, temp_dir)

                repo_scan.assert_called_once()
                self.assertTrue(callable(repo_scan.call_args.kwargs["checkpoint"]))
                self.assertEqual(scan.status, "completed")
                self.assertEqual(scan.current_step, "normalizing_findings")
                persisted = db.scalars(select(Finding).where(Finding.scan_id == self.scan_id)).all()
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].source_tool, "gitleaks")
                self.assertTrue(persisted[0].redaction_applied)
                tool_run = db.scalar(select(ScannerToolRun).where(ScannerToolRun.scan_id == self.scan_id))
                self.assertIsNotNone(tool_run)
                self.assertEqual(tool_run.tool_version, "8.30.1")

    def test_repo_scan_job_fails_without_valid_repo_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                scan.mode = "repo"
                db.add(scan)
                db.commit()
                db.refresh(scan)

                run_repo_scan_job(db, scan, temp_dir, temp_dir)

                self.assertEqual(scan.status, "failed")
                self.assertIsNone(scan.error_detail)

    def test_repo_scan_job_uses_queued_path_snapshot_after_asset_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "security-project"
            repo_path.mkdir()
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                asset = RepositoryAsset(
                    id=self.repository_asset_id,
                    workspace_id=LEGACY_WORKSPACE_ID,
                    created_by_user_id=LEGACY_USER_ID,
                    name="Security Project",
                    relative_path="changed-after-queue",
                    permission_confirmed=True,
                )
                db.add(asset)
                scan.mode = "repo"
                scan.scan_profile_id = "repository"
                scan.target_id = None
                scan.repository_asset_id = self.repository_asset_id
                scan.repo_path_snapshot = repo_path.name
                scan.authorization_snapshot = repository_authorization_snapshot(
                    repository_asset_id=self.repository_asset_id,
                    relative_path=repo_path.name,
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)

                fake_result = RepoScanResult(findings=(), receipts=(), warning_codes=())
                with patch("app.scans.lifecycle.run_repository_scan", return_value=fake_result) as repo_scan:
                    run_repo_scan_job(db, scan, temp_dir, temp_dir)

                self.assertEqual(scan.status, "completed")
                staged_path = repo_scan.call_args.args[0]
                self.assertNotEqual(staged_path, repo_path)
                self.assertTrue(staged_path.name.startswith("scan-"))

    def test_repo_scan_job_uses_queued_authority_after_asset_authorization_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "security-project"
            repo_path.mkdir()
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                self.assertIsNotNone(scan)
                db.add(
                    RepositoryAsset(
                        id=self.repository_asset_id,
                        workspace_id=LEGACY_WORKSPACE_ID,
                        created_by_user_id=LEGACY_USER_ID,
                        name="Security Project",
                        relative_path=repo_path.name,
                        permission_confirmed=False,
                    )
                )
                scan.mode = "repo"
                scan.scan_profile_id = "repository"
                scan.target_id = None
                scan.repository_asset_id = self.repository_asset_id
                scan.repo_path_snapshot = repo_path.name
                scan.authorization_snapshot = repository_authorization_snapshot(
                    repository_asset_id=self.repository_asset_id,
                    relative_path=repo_path.name,
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)

                fake_result = RepoScanResult(findings=(), receipts=(), warning_codes=())
                with patch("app.scans.lifecycle.run_repository_scan", return_value=fake_result):
                    run_repo_scan_job(db, scan, temp_dir, temp_dir)

                self.assertEqual(scan.status, "completed")
                self.assertIsNone(scan.error_detail)


def build_test_allowlist(
    allowed_modes: tuple[str, ...] = ("passive",),
    *,
    passive_zap: bool = False,
) -> ScanAllowlist:
    profile_engines: dict[str, list[str]] = {}
    if "passive" in allowed_modes:
        profile_engines["passive-web"] = ["scopeharbor-passive"]
        if passive_zap:
            profile_engines["passive-web"].append("zap-passive")
    if "active_demo" in allowed_modes:
        profile_engines["active-demo"] = [
            "scopeharbor-passive",
            "zap-passive",
            "zap-active",
        ]
    if "modern_web_crawl" in allowed_modes:
        profile_engines["modern-web-crawl"] = [
            "scopeharbor-passive",
            "zap-passive",
            "zap-client-spider",
        ]
    return ScanAllowlist.model_validate(
        {
            "version": 2,
            "targets": [
                {
                    "id": "juice-shop",
                    "name": "OWASP Juice Shop",
                    "base_url": "http://juice-shop:3000/",
                    "connection": {
                        "kind": "compose_service",
                        "host": "juice-shop",
                        "port": 3000,
                    },
                    "profile_engines": profile_engines,
                    "disposable_demo": True,
                    "tls": {"trust": "system"},
                    "max_redirects": 5,
                }
            ]
        }
    )


def web_authorization_snapshot(
    *,
    target_id: str,
    policy,
    auth_profile_id: str | None = None,
) -> dict[str, object]:
    return {
        "subject_type": "web_target",
        "subject_id": target_id,
        "target_url": "http://juice-shop:3000/",
        "allowlist_id": policy.id,
        "policy_fingerprint": policy.policy_fingerprint,
        "auth_profile_id": auth_profile_id,
    }


def authorize_web_scan(
    scan: Scan,
    allowlist: ScanAllowlist,
    *,
    auth_profile_id: str | None = None,
) -> None:
    policy = allowlist.get_target("juice-shop")
    if policy is None:
        raise AssertionError("test allowlist policy missing")
    scan.target_policy_fingerprint = policy.policy_fingerprint
    scan.authorization_snapshot = web_authorization_snapshot(
        target_id=scan.target_id or "",
        policy=policy,
        auth_profile_id=auth_profile_id,
    )


def repository_authorization_snapshot(
    *,
    repository_asset_id: str,
    relative_path: str,
) -> dict[str, object]:
    return {
        "subject_type": "repository_asset",
        "subject_id": repository_asset_id,
        "relative_path": relative_path,
    }


if __name__ == "__main__":
    unittest.main()
