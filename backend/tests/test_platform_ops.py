import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.core.contracts import ScanStatus, ScanStep
from app.db.session import SessionLocal
from app.main import app
from app.models import ApiRateLimitLog, AuditLog, Scan, Target, WorkerHeartbeat
from app.ops.heartbeat import record_worker_heartbeat
from app.ops.rate_limits import lock_rate_limit_scope
from app.scans.lifecycle import check_scan_cancelled
from app.security.auth import AuthenticatedPrincipal
from app.security.auth import ensure_user_workspace_identity
from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class PlatformOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.scan_destination_guard = patch("app.api.scans.validate_destination")
        self.scan_destination_guard.start()
        self.addCleanup(self.scan_destination_guard.stop)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
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
                    scan_profile_id="passive-web",
                    status=ScanStatus.QUEUED.value,
                    current_step=ScanStep.TARGET_VALIDATION.value,
                    status_message="Queued.",
                    progress_percent=0,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(AuditLog).where(AuditLog.workspace_id == DEV_WORKSPACE_ID))
            db.execute(delete(ApiRateLimitLog).where(ApiRateLimitLog.workspace_id == DEV_WORKSPACE_ID))
            db.execute(delete(WorkerHeartbeat).where(WorkerHeartbeat.worker_id.like("test-worker%")))
            db.execute(delete(Scan).where(Scan.target_id == self.target_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_scan_create_rate_limit_denies_and_records_log(self) -> None:
        with patch("app.api.scans.settings.scan_create_rate_limit_max_requests", 0):
            response = self.client.post(
                "/api/v1/scans",
                headers=DEV_AUTH_HEADERS,
                json={"target_id": self.target_id, "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            )

        self.assertEqual(response.status_code, 429)
        with SessionLocal() as db:
            log = db.query(ApiRateLimitLog).filter(ApiRateLimitLog.action == "scan_create").one()
        self.assertFalse(log.allowed)

    def test_scan_create_records_audit_event(self) -> None:
        response = self.client.post(
            "/api/v1/scans",
            headers=DEV_AUTH_HEADERS,
            json={"target_id": self.target_id, "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
        )

        self.assertEqual(response.status_code, 201)
        scan_id = response.json()["id"]
        with SessionLocal() as db:
            audit = db.query(AuditLog).filter(AuditLog.event_type == "scan.created", AuditLog.resource_id == scan_id).one()
        self.assertEqual(audit.resource_type, "scan")
        self.assertEqual(audit.metadata_json["target_id"], self.target_id)

    def test_cancel_queued_scan_marks_cancelled_and_audits(self) -> None:
        response = self.client.post(f"/api/v1/scans/{self.scan_id}/cancel", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "cancelled")
        self.assertIsNotNone(body["completed_at"])
        self.assertIsNotNone(body["cancellation_requested_at"])
        with SessionLocal() as db:
            audit = db.query(AuditLog).filter(AuditLog.event_type == "scan.cancel_requested", AuditLog.resource_id == self.scan_id).one()
        self.assertEqual(audit.metadata_json["previous_status"], "queued")

    def test_cancel_running_scan_records_request_until_worker_checkpoint(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.status = ScanStatus.RUNNING.value
            scan.progress_percent = 40
            db.add(scan)
            db.commit()

        response = self.client.post(f"/api/v1/scans/{self.scan_id}/cancel", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")
        self.assertIsNotNone(response.json()["cancellation_requested_at"])

        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            with self.assertRaises(Exception):
                check_scan_cancelled(db, scan)
            db.refresh(scan)
            self.assertEqual(scan.status, "cancelled")

    def test_cancel_running_scan_is_idempotent_after_request(self) -> None:
        first_user_id = "first-cancel-user"
        requested_at = datetime.now(UTC)
        with SessionLocal() as db:
            ensure_user_workspace_identity(
                db,
                user_id=first_user_id,
                workspace_id=DEV_WORKSPACE_ID,
                provider="dev",
                provider_subject=first_user_id,
                display_name="First Cancel User",
                workspace_name="Dev Workspace",
            )
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.status = ScanStatus.RUNNING.value
            scan.progress_percent = 40
            scan.cancellation_requested_at = requested_at
            scan.cancellation_requested_by_user_id = first_user_id
            db.add(scan)
            db.commit()

        response = self.client.post(f"/api/v1/scans/{self.scan_id}/cancel", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            self.assertEqual(scan.cancellation_requested_by_user_id, first_user_id)
            audit_count = db.query(AuditLog).filter(AuditLog.event_type == "scan.cancel_requested", AuditLog.resource_id == self.scan_id).count()
        self.assertEqual(audit_count, 0)

    def test_audit_logs_are_workspace_scoped(self) -> None:
        self.client.post(f"/api/v1/scans/{self.scan_id}/cancel", headers=DEV_AUTH_HEADERS)

        response = self.client.get("/api/v1/audit-logs", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(item["event_type"] == "scan.cancel_requested" for item in response.json()["items"]))

    def test_platform_health_reports_components(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with SessionLocal() as db:
                record_worker_heartbeat(db, worker_id="test-worker-health", status="polling")

            with patch("app.api.ops.settings.artifact_root", temp_dir), patch("app.api.ops.httpx.get") as get:
                get.return_value.raise_for_status.return_value = None
                response = self.client.get("/api/v1/ops/health", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["database"]["status"], "ok")
        self.assertEqual(body["worker"]["status"], "ok")
        self.assertEqual(body["zap"]["status"], "ok")
        self.assertEqual(body["artifact_root"]["status"], "ok")
        self.assertEqual(body["artifact_root"]["detail"], "artifact root writable")
        self.assertNotIn(temp_dir, body["artifact_root"]["detail"])
        self.assertGreaterEqual(body["queue_depth"], 0)

    def test_rate_limit_scope_uses_transaction_advisory_lock_on_postgres(self) -> None:
        class FakeDialect:
            name = "postgresql"

        class FakeBind:
            dialect = FakeDialect()

        class FakeSession:
            def __init__(self) -> None:
                self.statements: list[str] = []
                self.params: list[dict[str, int]] = []

            def get_bind(self) -> FakeBind:
                return FakeBind()

            def execute(self, statement, params):  # type: ignore[no-untyped-def]
                self.statements.append(str(statement))
                self.params.append(params)

        fake_session = FakeSession()
        principal = AuthenticatedPrincipal(
            user_id=DEV_USER_ID,
            workspace_id=DEV_WORKSPACE_ID,
            provider="dev",
            provider_subject="dev-user",
        )

        lock_rate_limit_scope(fake_session, principal, "scan_create")  # type: ignore[arg-type]

        self.assertEqual(fake_session.statements, ["SELECT pg_advisory_xact_lock(:lock_key)"])
        self.assertIsInstance(fake_session.params[0]["lock_key"], int)


if __name__ == "__main__":
    unittest.main()
