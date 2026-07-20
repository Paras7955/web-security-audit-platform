import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.db.session import SessionLocal
from app.main import app
from app.models import AuthIdentity, Finding, PlatformUser, RiskScore, Scan, Target, Workspace
from app.risk import SCORING_MODEL_VERSION, calculate_scan_risk_score, persist_scan_risk_score
from app.security.auth import ensure_user_workspace_identity
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class RiskDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_ids: list[str] = []
        self.scan_ids: list[str] = []
        self.finding_ids: list[str] = []
        self.extra_workspace_ids: list[str] = []
        self.extra_user_ids: list[str] = []

    def tearDown(self) -> None:
        with SessionLocal() as db:
            if self.scan_ids:
                db.execute(delete(RiskScore).where(RiskScore.scan_id.in_(self.scan_ids)))
            if self.finding_ids:
                db.execute(delete(Finding).where(Finding.id.in_(self.finding_ids)))
            if self.scan_ids:
                db.execute(delete(Scan).where(Scan.id.in_(self.scan_ids)))
            if self.target_ids:
                db.execute(delete(Target).where(Target.id.in_(self.target_ids)))
            if self.extra_user_ids:
                db.execute(delete(AuthIdentity).where(AuthIdentity.user_id.in_(self.extra_user_ids)))
            if self.extra_workspace_ids:
                db.execute(delete(Workspace).where(Workspace.id.in_(self.extra_workspace_ids)))
            if self.extra_user_ids:
                db.execute(delete(PlatformUser).where(PlatformUser.id.in_(self.extra_user_ids)))
            db.commit()

    def test_risk_v1_snapshot_is_deterministic(self) -> None:
        scan = self.make_scan_object()
        findings = [
            self.make_finding_object(scan.id, "critical-confirmed", severity="critical", confidence="confirmed"),
            self.make_finding_object(scan.id, "medium-high", severity="medium", confidence="high"),
            self.make_finding_object(scan.id, "info-low", severity="info", confidence="low"),
        ]

        score = calculate_scan_risk_score(scan, findings)

        self.assertEqual(score.scoring_model_version, "risk-v1")
        self.assertEqual(score.score, 100)
        self.assertEqual(score.label, "Critical")
        self.assertEqual(score.input_summary["severity_counts"], {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 1})
        self.assertEqual(score.input_summary["confidence_counts"], {"confirmed": 1, "high": 1, "medium": 0, "low": 1})
        self.assertEqual(score.input_summary["weighted_total"], 134.0)
        self.assertEqual(score.input_summary["scan_profile_id"], "passive-web")
        self.assertEqual(score.input_summary["lifecycle_adjustments"], [])

    def test_scan_risk_score_calculates_missing_legacy_score_without_get_write(self) -> None:
        target_id = self.create_target()
        scan_id = self.create_scan(target_id)
        self.create_finding(scan_id, "medium-high", severity="medium", confidence="high")

        response = self.client.get(f"/api/v1/scans/{scan_id}/risk-score", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["scoring_model_version"], SCORING_MODEL_VERSION)
        self.assertEqual(body["score"], 32)
        self.assertEqual(body["label"], "Moderate")
        with SessionLocal() as db:
            self.assertEqual(db.query(RiskScore).filter(RiskScore.scan_id == scan_id).count(), 0)

    def test_dashboard_endpoints_are_workspace_scoped(self) -> None:
        baseline_overview = self.client.get("/api/v1/dashboard/overview", headers=DEV_AUTH_HEADERS)
        self.assertEqual(baseline_overview.status_code, 200)
        baseline_body = baseline_overview.json()
        target_id = self.create_target()
        scan_id = self.create_scan(target_id)
        self.create_finding(scan_id, "dev-finding", severity="low", confidence="high")
        other_workspace_id = f"risk-test-workspace-{uuid4()}"
        other_user_id = f"risk-test-user-{uuid4()}"
        other_target_id = self.create_target(workspace_id=other_workspace_id, user_id=other_user_id)
        other_scan_id = self.create_scan(other_target_id, workspace_id=other_workspace_id, user_id=other_user_id)
        self.create_finding(other_scan_id, "other-finding", workspace_id=other_workspace_id, severity="critical", confidence="confirmed")

        overview = self.client.get("/api/v1/dashboard/overview", headers=DEV_AUTH_HEADERS)
        target_dashboard = self.client.get(f"/api/v1/targets/{target_id}/dashboard", headers=DEV_AUTH_HEADERS)
        hidden_target_dashboard = self.client.get(f"/api/v1/targets/{other_target_id}/dashboard", headers=DEV_AUTH_HEADERS)
        hidden_score = self.client.get(f"/api/v1/scans/{other_scan_id}/risk-score", headers=DEV_AUTH_HEADERS)

        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["targets_count"], baseline_body["targets_count"] + 1)
        self.assertEqual(overview.json()["findings_count"], baseline_body["findings_count"] + 1)
        self.assertEqual(overview.json()["severity_counts"]["critical"], baseline_body["severity_counts"]["critical"])
        self.assertEqual(target_dashboard.status_code, 200)
        self.assertEqual(target_dashboard.json()["target_id"], target_id)
        self.assertEqual(hidden_target_dashboard.status_code, 404)
        self.assertEqual(hidden_score.status_code, 404)

    def test_workspace_overview_dedupes_by_target_and_key(self) -> None:
        first_target_id = self.create_target(name="First target")
        second_target_id = self.create_target(name="Second target")
        first_scan_id = self.create_scan(first_target_id)
        second_scan_id = self.create_scan(second_target_id)
        self.create_finding(first_scan_id, "shared-key", severity="medium", confidence="high")
        self.create_finding(second_scan_id, "shared-key", severity="medium", confidence="high")

        overview = self.client.get("/api/v1/dashboard/overview", headers=DEV_AUTH_HEADERS)

        self.assertEqual(overview.status_code, 200)
        self.assertGreaterEqual(overview.json()["severity_counts"]["medium"], 2)

    def test_duplicate_dedupe_keys_use_deterministic_highest_risk_finding(self) -> None:
        scan = self.make_scan_object()
        older_low = self.make_finding_object(scan.id, "duplicate-key", severity="low", confidence="low")
        newer_high = self.make_finding_object(scan.id, "duplicate-key", severity="high", confidence="confirmed")

        score = calculate_scan_risk_score(scan, [older_low, newer_high])
        reversed_score = calculate_scan_risk_score(scan, [newer_high, older_low])

        self.assertEqual(score.score, 70)
        self.assertEqual(reversed_score.score, score.score)
        self.assertEqual(score.input_summary["weighted_findings"][0]["severity"], "high")

    def test_scan_comparison_classifies_changes(self) -> None:
        target_id = self.create_target()
        baseline_scan_id = self.create_scan(target_id, created_offset=0)
        comparison_scan_id = self.create_scan(target_id, created_offset=1)
        self.create_finding(baseline_scan_id, "unchanged", severity="info", confidence="low")
        self.create_finding(comparison_scan_id, "unchanged", severity="info", confidence="low")
        self.create_finding(baseline_scan_id, "changed", severity="high", confidence="high")
        self.create_finding(comparison_scan_id, "changed", severity="medium", confidence="high")
        self.create_finding(baseline_scan_id, "resolved", severity="medium", confidence="high")
        self.create_finding(comparison_scan_id, "new", severity="low", confidence="medium")

        response = self.client.get(
            f"/api/v1/scans/{comparison_scan_id}/comparison?baseline_scan_id={baseline_scan_id}",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual([item["dedupe_key"] for item in body["new_findings"]], ["new"])
        self.assertEqual([item["dedupe_key"] for item in body["resolved_findings"]], ["resolved"])
        self.assertEqual([item["dedupe_key"] for item in body["unchanged_findings"]], ["unchanged"])
        self.assertEqual([item["dedupe_key"] for item in body["severity_changed_findings"]], ["changed"])
        self.assertEqual(body["scoring_model_version"], SCORING_MODEL_VERSION)
        self.assertLess(body["score_delta"], 0)

    def test_comparison_rejects_incompatible_or_incomplete_scans(self) -> None:
        first_target_id = self.create_target()
        second_target_id = self.create_target(name="Second target")
        first_scan_id = self.create_scan(first_target_id)
        second_scan_id = self.create_scan(second_target_id)
        queued_scan_id = self.create_scan(first_target_id, status="queued")

        cross_target = self.client.get(f"/api/v1/scans/{second_scan_id}/comparison?baseline_scan_id={first_scan_id}", headers=DEV_AUTH_HEADERS)
        incomplete = self.client.get(f"/api/v1/scans/{first_scan_id}/comparison?baseline_scan_id={queued_scan_id}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(cross_target.status_code, 400)
        self.assertIn("same target", cross_target.json()["detail"])
        self.assertEqual(incomplete.status_code, 400)
        self.assertIn("completed scan", incomplete.json()["detail"])

    def test_comparison_rejects_scans_from_different_audit_profiles(self) -> None:
        target_id = self.create_target()
        passive_scan_id = self.create_scan(target_id, scan_profile_id="passive-web")
        active_scan_id = self.create_scan(target_id, mode="active_demo", scan_profile_id="active-demo")

        response = self.client.get(
            f"/api/v1/scans/{active_scan_id}/comparison?baseline_scan_id={passive_scan_id}",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Scans must use the same audit profile.")

    def test_comparison_hides_scans_from_other_workspaces(self) -> None:
        target_id = self.create_target()
        comparison_scan_id = self.create_scan(target_id)
        other_workspace_id = f"risk-comparison-workspace-{uuid4()}"
        other_user_id = f"risk-comparison-user-{uuid4()}"
        other_target_id = self.create_target(workspace_id=other_workspace_id, user_id=other_user_id)
        other_scan_id = self.create_scan(other_target_id, workspace_id=other_workspace_id, user_id=other_user_id)

        response = self.client.get(
            f"/api/v1/scans/{comparison_scan_id}/comparison?baseline_scan_id={other_scan_id}",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Scan not found.")

    def test_completed_with_warnings_is_accepted_for_scores_and_comparison(self) -> None:
        target_id = self.create_target()
        baseline_scan_id = self.create_scan(target_id, status="completed_with_warnings", created_offset=0)
        comparison_scan_id = self.create_scan(target_id, status="completed_with_warnings", created_offset=1)
        self.create_finding(baseline_scan_id, "baseline", severity="low", confidence="high")
        self.create_finding(comparison_scan_id, "comparison", severity="medium", confidence="high")

        score = self.client.get(f"/api/v1/scans/{baseline_scan_id}/risk-score", headers=DEV_AUTH_HEADERS)
        comparison = self.client.get(
            f"/api/v1/scans/{comparison_scan_id}/comparison?baseline_scan_id={baseline_scan_id}",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(score.status_code, 200)
        self.assertEqual(comparison.status_code, 200)
        self.assertEqual(comparison.json()["baseline_scan_id"], baseline_scan_id)

    def test_existing_risk_score_row_is_returned_without_duplicate_insert(self) -> None:
        target_id = self.create_target()
        scan_id = self.create_scan(target_id)
        self.create_finding(scan_id, "medium-high", severity="medium", confidence="high")
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all())
            persist_scan_risk_score(db, scan, findings)
        first = self.client.get(f"/api/v1/scans/{scan_id}/risk-score", headers=DEV_AUTH_HEADERS)
        second = self.client.get(f"/api/v1/scans/{scan_id}/risk-score", headers=DEV_AUTH_HEADERS)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["id"], second.json()["id"])
        with SessionLocal() as db:
            rows = db.query(RiskScore).filter(RiskScore.scan_id == scan_id, RiskScore.scoring_model_version == SCORING_MODEL_VERSION).all()
            self.assertEqual(len(rows), 1)

    def test_latest_target_comparison_uses_two_newest_completed_scans(self) -> None:
        target_id = self.create_target()
        oldest_scan_id = self.create_scan(target_id, created_offset=0)
        newest_scan_id = self.create_scan(target_id, created_offset=1)
        self.create_finding(oldest_scan_id, "old", severity="low", confidence="high")
        self.create_finding(newest_scan_id, "new", severity="medium", confidence="high")

        response = self.client.get(f"/api/v1/targets/{target_id}/latest-comparison", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["baseline_scan_id"], oldest_scan_id)
        self.assertEqual(body["comparison_scan_id"], newest_scan_id)
        self.assertEqual([item["dedupe_key"] for item in body["new_findings"]], ["new"])

    def test_latest_comparison_uses_completion_order_not_creation_order(self) -> None:
        target_id = self.create_target()
        created_later_completed_earlier = self.create_scan(target_id, created_offset=2, completed_offset=3)
        created_earlier_completed_later = self.create_scan(target_id, created_offset=1, completed_offset=4)
        self.create_finding(created_later_completed_earlier, "baseline", severity="low", confidence="high")
        self.create_finding(created_earlier_completed_later, "latest", severity="medium", confidence="high")

        response = self.client.get(f"/api/v1/targets/{target_id}/latest-comparison", headers=DEV_AUTH_HEADERS)
        target_dashboard = self.client.get(f"/api/v1/targets/{target_id}/dashboard", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["baseline_scan_id"], created_later_completed_earlier)
        self.assertEqual(response.json()["comparison_scan_id"], created_earlier_completed_later)
        self.assertEqual(target_dashboard.status_code, 200)
        self.assertEqual(target_dashboard.json()["latest_risk_score"]["scan_id"], created_earlier_completed_later)

    def test_latest_comparison_uses_prior_scan_from_latest_scan_profile(self) -> None:
        target_id = self.create_target()
        passive_baseline_id = self.create_scan(target_id, scan_profile_id="passive-web", completed_offset=1)
        self.create_scan(target_id, mode="active_demo", scan_profile_id="active-demo", completed_offset=2)
        passive_latest_id = self.create_scan(target_id, scan_profile_id="passive-web", completed_offset=3)

        response = self.client.get(f"/api/v1/targets/{target_id}/latest-comparison", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["baseline_scan_id"], passive_baseline_id)
        self.assertEqual(response.json()["comparison_scan_id"], passive_latest_id)

    def test_latest_comparison_requires_prior_scan_from_latest_scan_profile(self) -> None:
        target_id = self.create_target()
        self.create_scan(target_id, scan_profile_id="passive-web", completed_offset=1)
        self.create_scan(target_id, mode="active_demo", scan_profile_id="active-demo", completed_offset=2)

        response = self.client.get(f"/api/v1/targets/{target_id}/latest-comparison", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 404)
        self.assertIn("same audit profile", response.json()["detail"])

    def test_workspace_overview_latest_risk_uses_completion_order(self) -> None:
        target_id = self.create_target()
        created_later_completed_earlier = self.create_scan(target_id, created_offset=2, completed_offset=3)
        created_earlier_completed_later = self.create_scan(target_id, created_offset=1, completed_offset=4)
        self.create_finding(created_later_completed_earlier, "earlier", severity="low", confidence="high")
        self.create_finding(created_earlier_completed_later, "later", severity="medium", confidence="high")

        response = self.client.get("/api/v1/dashboard/overview", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["latest_risk_score"]["scan_id"], created_earlier_completed_later)

    def test_latest_selection_has_stable_id_tie_breaker(self) -> None:
        target_id = self.create_target()
        lower_scan_id = self.create_scan(
            target_id,
            scan_id="00000000-0000-0000-0000-000000000001",
            created_offset=9999,
            completed_offset=10000,
        )
        higher_scan_id = self.create_scan(
            target_id,
            scan_id="00000000-0000-0000-0000-000000000002",
            created_offset=9999,
            completed_offset=10000,
        )
        self.create_finding(lower_scan_id, "lower", severity="low", confidence="high")
        self.create_finding(higher_scan_id, "higher", severity="medium", confidence="high")

        latest = self.client.get(f"/api/v1/targets/{target_id}/latest-comparison", headers=DEV_AUTH_HEADERS)
        overview = self.client.get("/api/v1/dashboard/overview", headers=DEV_AUTH_HEADERS)

        self.assertEqual(latest.status_code, 200)
        self.assertEqual(latest.json()["comparison_scan_id"], higher_scan_id)
        self.assertEqual(latest.json()["baseline_scan_id"], lower_scan_id)
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["latest_risk_score"]["scan_id"], higher_scan_id)

    def create_target(self, *, workspace_id: str = DEV_WORKSPACE_ID, user_id: str = DEV_USER_ID, name: str = "Juice Shop") -> str:
        target_id = str(uuid4())
        with SessionLocal() as db:
            ensure_identity(db, workspace_id=workspace_id, user_id=user_id)
            target = Target(
                id=target_id,
                workspace_id=workspace_id,
                created_by_user_id=user_id,
                allowlist_id="juice-shop",
                name=name,
                base_url="http://juice-shop:3000",
                permission_confirmed=True,
            )
            db.add(target)
            db.commit()
        self.target_ids.append(target_id)
        if workspace_id != DEV_WORKSPACE_ID and workspace_id not in self.extra_workspace_ids:
            self.extra_workspace_ids.append(workspace_id)
        if user_id != DEV_USER_ID and user_id not in self.extra_user_ids:
            self.extra_user_ids.append(user_id)
        return target_id

    def create_scan(
        self,
        target_id: str,
        *,
        workspace_id: str = DEV_WORKSPACE_ID,
        user_id: str = DEV_USER_ID,
        status: str = "completed",
        mode: str = "passive",
        scan_profile_id: str = "passive-web",
        created_offset: int = 0,
        completed_offset: int | None = None,
        scan_id: str | None = None,
    ) -> str:
        scan_id = scan_id or str(uuid4())
        created_at = datetime(2026, 7, 7, tzinfo=UTC) + timedelta(minutes=created_offset)
        is_completed = status in {"completed", "completed_with_warnings"}
        completed_at = datetime(2026, 7, 7, tzinfo=UTC) + timedelta(minutes=completed_offset if completed_offset is not None else created_offset + 1)
        with SessionLocal() as db:
            scan = Scan(
                id=scan_id,
                workspace_id=workspace_id,
                created_by_user_id=user_id,
                target_id=target_id,
                mode=mode,
                scan_profile_id=scan_profile_id,
                status=status,
                current_step="normalizing_findings" if is_completed else "target_validation",
                status_message="Completed." if is_completed else "Queued.",
                progress_percent=100 if is_completed else 0,
                started_at=created_at,
                completed_at=completed_at if is_completed else None,
                created_at=created_at,
            )
            db.add(scan)
            db.commit()
        self.scan_ids.append(scan_id)
        return scan_id

    def create_finding(
        self,
        scan_id: str,
        dedupe_key: str,
        *,
        workspace_id: str = DEV_WORKSPACE_ID,
        severity: str,
        confidence: str,
    ) -> str:
        finding_id = str(uuid4())
        with SessionLocal() as db:
            finding = self.make_finding_object(scan_id, dedupe_key, severity=severity, confidence=confidence)
            finding.id = finding_id
            finding.workspace_id = workspace_id
            db.add(finding)
            db.commit()
        self.finding_ids.append(finding_id)
        return finding_id

    def make_scan_object(self) -> Scan:
        return Scan(
            id=str(uuid4()),
            workspace_id=DEV_WORKSPACE_ID,
            created_by_user_id=DEV_USER_ID,
            target_id=str(uuid4()),
            mode="passive",
            scan_profile_id="passive-web",
            status="completed",
            current_step="normalizing_findings",
            progress_percent=100,
        )

    def make_finding_object(self, scan_id: str, dedupe_key: str, *, severity: str, confidence: str) -> Finding:
        return Finding(
            id=str(uuid4()),
            workspace_id=DEV_WORKSPACE_ID,
            scan_id=scan_id,
            title=f"Finding {dedupe_key}",
            severity=severity,
            confidence=confidence,
            affected_url=f"http://juice-shop:3000/{dedupe_key}",
            evidence="redacted evidence",
            source_tool="test",
            scanner_rule_id=dedupe_key,
            dedupe_key=dedupe_key,
            redaction_applied=True,
        )


def ensure_identity(db, *, workspace_id: str, user_id: str) -> None:
    if workspace_id == DEV_WORKSPACE_ID and user_id == DEV_USER_ID:
        ensure_dev_principal(db)
        return
    ensure_user_workspace_identity(
        db,
        user_id=user_id,
        workspace_id=workspace_id,
        provider="dev",
        provider_subject=user_id,
        display_name=user_id,
        workspace_name=workspace_id,
    )


if __name__ == "__main__":
    unittest.main()
