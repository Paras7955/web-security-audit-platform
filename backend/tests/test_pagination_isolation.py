import unittest
from datetime import UTC, datetime
from urllib.parse import urlencode
from uuid import uuid4

from app.db.session import SessionLocal
from app.main import app
from app.models import (
    AuditLog,
    AuthIdentity,
    AuthProfile,
    Finding,
    PlatformUser,
    ReportArtifact,
    Scan,
    SuppressionRule,
    Tag,
    Target,
    Workspace,
)
from app.security.auth import ensure_user_workspace_identity
from fastapi.testclient import TestClient
from sqlalchemy import delete

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class CursorPaginationIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        suffix = uuid4().hex
        self.other_user_id = f"page-user-{suffix}"
        self.other_workspace_id = f"page-workspace-{suffix}"
        self.dev_target_ids = [f"page-target-a-{suffix}", f"page-target-b-{suffix}"]
        self.other_target_id = f"page-target-other-{suffix}"
        self.dev_scan_ids = [f"page-scan-a-{suffix}", f"page-scan-b-{suffix}"]
        self.other_scan_id = f"page-scan-other-{suffix}"
        self.dev_finding_ids = [f"page-finding-a-{suffix}", f"page-finding-b-{suffix}"]
        self.other_finding_id = f"page-finding-other-{suffix}"
        self.dev_profile_ids = [f"page-profile-a-{suffix}", f"page-profile-b-{suffix}"]
        self.other_profile_id = f"page-profile-other-{suffix}"
        self.dev_suppression_ids = [f"page-suppression-a-{suffix}", f"page-suppression-b-{suffix}"]
        self.other_suppression_id = f"page-suppression-other-{suffix}"
        self.dev_tag_ids = [f"page-tag-a-{suffix}", f"page-tag-b-{suffix}"]
        self.other_tag_id = f"page-tag-other-{suffix}"
        self.dev_audit_ids = [f"page-audit-a-{suffix}", f"page-audit-b-{suffix}"]
        self.other_audit_id = f"page-audit-other-{suffix}"
        self.dev_report_ids = [f"page-report-a-{suffix}", f"page-report-b-{suffix}"]
        self.other_report_id = f"page-report-other-{suffix}"
        now = datetime.now(UTC)
        with SessionLocal() as db:
            ensure_dev_principal(db)
            ensure_user_workspace_identity(
                db,
                user_id=self.other_user_id,
                workspace_id=self.other_workspace_id,
                provider="pagination-test",
                provider_subject=self.other_user_id,
                display_name="Pagination Other User",
                workspace_name="Pagination Other Workspace",
            )
            for target_id, workspace_id, user_id in (
                *[(item, DEV_WORKSPACE_ID, DEV_USER_ID) for item in self.dev_target_ids],
                (self.other_target_id, self.other_workspace_id, self.other_user_id),
            ):
                db.add(
                    Target(
                        id=target_id,
                        workspace_id=workspace_id,
                        created_by_user_id=user_id,
                        allowlist_id="juice-shop",
                        name="Pagination target",
                        base_url="http://juice-shop:3000/",
                        permission_confirmed=True,
                        authorization_confirmed_at=now,
                        created_at=now,
                    )
                )
            db.flush()
            for scan_id, target_id, workspace_id, user_id in (
                *[
                    (scan_id, target_id, DEV_WORKSPACE_ID, DEV_USER_ID)
                    for scan_id, target_id in zip(self.dev_scan_ids, self.dev_target_ids, strict=True)
                ],
                (self.other_scan_id, self.other_target_id, self.other_workspace_id, self.other_user_id),
            ):
                db.add(
                    Scan(
                        id=scan_id,
                        workspace_id=workspace_id,
                        created_by_user_id=user_id,
                        target_id=target_id,
                        mode="passive",
                        scan_profile_id="passive-web",
                        status="completed",
                        current_step="normalizing_findings",
                        status_message="Completed.",
                        progress_percent=100,
                        completed_at=now,
                        attempt_count=0,
                        created_at=now,
                    )
                )
            db.flush()
            for finding_id, scan_id, workspace_id in (
                *[
                    (finding_id, scan_id, DEV_WORKSPACE_ID)
                    for finding_id, scan_id in zip(self.dev_finding_ids, self.dev_scan_ids, strict=True)
                ],
                (self.other_finding_id, self.other_scan_id, self.other_workspace_id),
            ):
                db.add(
                    Finding(
                        id=finding_id,
                        workspace_id=workspace_id,
                        scan_id=scan_id,
                        title="Pagination finding",
                        severity="low",
                        confidence="high",
                        affected_url="http://juice-shop:3000/",
                        source_tool="custom-passive",
                        dedupe_key=finding_id,
                        redaction_applied=True,
                        created_at=now,
                    )
                )
            for profile_id, workspace_id, user_id in (
                *[(item, DEV_WORKSPACE_ID, DEV_USER_ID) for item in self.dev_profile_ids],
                (self.other_profile_id, self.other_workspace_id, self.other_user_id),
            ):
                db.add(
                    AuthProfile(
                        id=profile_id,
                        workspace_id=workspace_id,
                        created_by_user_id=user_id,
                        label="Pagination profile",
                        profile_type="bearer_token",
                        encrypted_secret="ciphertext",
                        secret_hint="****text",
                        rotation_count=0,
                        created_at=now,
                    )
                )
            for rule_id, target_id, workspace_id, user_id in (
                *[
                    (rule_id, target_id, DEV_WORKSPACE_ID, DEV_USER_ID)
                    for rule_id, target_id in zip(self.dev_suppression_ids, self.dev_target_ids, strict=True)
                ],
                (self.other_suppression_id, self.other_target_id, self.other_workspace_id, self.other_user_id),
            ):
                db.add(
                    SuppressionRule(
                        id=rule_id,
                        workspace_id=workspace_id,
                        target_id=target_id,
                        reason="Pagination fixture",
                        created_by_user_id=user_id,
                        created_at=now,
                    )
                )
            for tag_id, workspace_id, user_id in (
                *[(item, DEV_WORKSPACE_ID, DEV_USER_ID) for item in self.dev_tag_ids],
                (self.other_tag_id, self.other_workspace_id, self.other_user_id),
            ):
                db.add(
                    Tag(
                        id=tag_id,
                        workspace_id=workspace_id,
                        label=tag_id,
                        created_by_user_id=user_id,
                        created_at=now,
                    )
                )
            for audit_id, workspace_id, user_id in (
                *[(item, DEV_WORKSPACE_ID, DEV_USER_ID) for item in self.dev_audit_ids],
                (self.other_audit_id, self.other_workspace_id, self.other_user_id),
            ):
                db.add(
                    AuditLog(
                        id=audit_id,
                        workspace_id=workspace_id,
                        user_id=user_id,
                        event_type="pagination.fixture",
                        metadata_json={},
                        created_at=now,
                    )
                )
            for report_id, scan_id, workspace_id, user_id, report_type in (
                (self.dev_report_ids[0], self.dev_scan_ids[0], DEV_WORKSPACE_ID, DEV_USER_ID, "markdown"),
                (self.dev_report_ids[1], self.dev_scan_ids[0], DEV_WORKSPACE_ID, DEV_USER_ID, "html"),
                (self.other_report_id, self.other_scan_id, self.other_workspace_id, self.other_user_id, "markdown"),
            ):
                db.add(
                    ReportArtifact(
                        id=report_id,
                        workspace_id=workspace_id,
                        created_by_user_id=user_id,
                        scan_id=scan_id,
                        report_type=report_type,
                        path=f"/tmp/{report_id}.md",
                        created_at=now,
                    )
                )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(ReportArtifact).where(ReportArtifact.id.in_(self.dev_report_ids + [self.other_report_id])))
            db.execute(delete(Finding).where(Finding.id.in_(self.dev_finding_ids + [self.other_finding_id])))
            db.execute(delete(SuppressionRule).where(SuppressionRule.id.in_(self.dev_suppression_ids + [self.other_suppression_id])))
            db.execute(delete(Tag).where(Tag.id.in_(self.dev_tag_ids + [self.other_tag_id])))
            db.execute(delete(AuditLog).where(AuditLog.id.in_(self.dev_audit_ids + [self.other_audit_id])))
            db.execute(delete(AuthProfile).where(AuthProfile.id.in_(self.dev_profile_ids + [self.other_profile_id])))
            db.execute(delete(Scan).where(Scan.id.in_(self.dev_scan_ids + [self.other_scan_id])))
            db.execute(delete(Target).where(Target.id.in_(self.dev_target_ids + [self.other_target_id])))
            db.execute(delete(AuthIdentity).where(AuthIdentity.user_id == self.other_user_id))
            db.execute(delete(Workspace).where(Workspace.id == self.other_workspace_id))
            db.execute(delete(PlatformUser).where(PlatformUser.id == self.other_user_id))
            db.commit()

    def test_every_public_collection_has_stable_cursor_pagination_and_workspace_isolation(self) -> None:
        cases = (
            ("/api/v1/targets", set(self.dev_target_ids), self.other_target_id),
            ("/api/v1/scans", set(self.dev_scan_ids), self.other_scan_id),
            ("/api/v1/findings", set(self.dev_finding_ids), self.other_finding_id),
            ("/api/v1/auth-profiles", set(self.dev_profile_ids), self.other_profile_id),
            ("/api/v1/suppressions", set(self.dev_suppression_ids), self.other_suppression_id),
            ("/api/v1/tags", set(self.dev_tag_ids), self.other_tag_id),
            ("/api/v1/audit-logs", set(self.dev_audit_ids), self.other_audit_id),
            (f"/api/v1/scans/{self.dev_scan_ids[0]}/reports", set(self.dev_report_ids), self.other_report_id),
        )
        for path, expected_ids, hidden_id in cases:
            first = self.client.get(f"{path}?limit=1", headers=DEV_AUTH_HEADERS)
            self.assertEqual(first.status_code, 200, path)
            first_body = first.json()
            self.assertEqual(len(first_body["items"]), 1, path)
            self.assertIsNotNone(first_body["next_cursor"], path)
            second = self.client.get(
                f"{path}?{urlencode({'limit': 1, 'cursor': first_body['next_cursor']})}",
                headers=DEV_AUTH_HEADERS,
            )
            self.assertEqual(second.status_code, 200, path)
            observed = {first_body["items"][0]["id"], second.json()["items"][0]["id"]}
            self.assertEqual(observed, expected_ids, path)
            self.assertNotIn(hidden_id, observed, path)

    def test_cursor_and_limit_validation_fail_closed(self) -> None:
        invalid_cursor = self.client.get("/api/v1/targets?cursor=not-a-cursor", headers=DEV_AUTH_HEADERS)
        excessive_limit = self.client.get("/api/v1/targets?limit=201", headers=DEV_AUTH_HEADERS)
        self.assertEqual(invalid_cursor.status_code, 400)
        self.assertEqual(excessive_limit.status_code, 422)


if __name__ == "__main__":
    unittest.main()
