import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import delete, select

from app import demo_seed
from app.demo_seed import (
    BASELINE_SCAN_ID,
    FINDING_SEEDS,
    JUICE_TARGET_ID,
    LATEST_SCAN_ID,
    REPO_SCAN_ID,
    REPO_TARGET_ID,
    seed_demo_data,
)
from app.models import (
    AuthIdentity,
    Finding,
    FindingOccurrenceState,
    FindingState,
    ReportArtifact,
    RiskScore,
    Scan,
    SuppressionRule,
    Tag,
    TagAssignment,
    Target,
    Workspace,
)
from app.reports.service import read_report_artifact_file
from app.risk import SCORING_MODEL_VERSION
from tests.helpers import DEV_USER_ID, DEV_WORKSPACE_ID


class DemoSeedTests(unittest.TestCase):
    def tearDown(self) -> None:
        cleanup_demo_seed()

    def test_seed_demo_data_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_root = Path(temp_dir) / "artifacts"
            repo_root = Path(temp_dir) / "repositories"
            first = run_seed(artifact_root, repo_root)
            second = run_seed(artifact_root, repo_root)

            self.assertEqual(first, second)
            self.assertEqual(second.targets, 2)
            self.assertEqual(second.scans, 3)
            self.assertEqual(second.findings, len(FINDING_SEEDS))
            self.assertEqual(second.reports, 4)
            self.assertEqual(second.risk_scores, 3)

            with session() as db:
                self.assertEqual(db.query(Target).filter(Target.id.in_([JUICE_TARGET_ID, REPO_TARGET_ID])).count(), 2)
                self.assertEqual(db.query(Scan).filter(Scan.id.in_([BASELINE_SCAN_ID, LATEST_SCAN_ID, REPO_SCAN_ID])).count(), 3)
                self.assertEqual(db.query(Finding).filter(Finding.id.in_([seed.id for seed in FINDING_SEEDS])).count(), len(FINDING_SEEDS))
                self.assertEqual(db.query(ReportArtifact).filter(ReportArtifact.id.like("demo-report-%")).count(), 4)

    def test_demo_seed_command_requires_explicit_enablement(self) -> None:
        with patch("app.demo_seed.settings.demo_seed_enabled", False), self.assertRaises(SystemExit) as exc:
            demo_seed.main()

        self.assertIn("DEMO_SEED_ENABLED=true", str(exc.exception))

    def test_demo_seed_command_requires_dev_auth_mode(self) -> None:
        with (
            patch("app.demo_seed.settings.demo_seed_enabled", True),
            patch("app.demo_seed.settings.auth_mode", "required"),
            patch("app.demo_seed.settings.auth_provider", "auth0"),
            self.assertRaises(SystemExit) as exc,
        ):
            demo_seed.main()

        self.assertIn("AUTH_MODE=dev", str(exc.exception))

    def test_seed_demo_data_stays_workspace_scoped_and_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_root = Path(temp_dir) / "artifacts"
            repo_root = Path(temp_dir) / "repositories"
            run_seed(artifact_root, repo_root)

            with session() as db:
                targets = db.scalars(select(Target).where(Target.id.in_([JUICE_TARGET_ID, REPO_TARGET_ID]))).all()
                scans = db.scalars(select(Scan).where(Scan.id.in_([BASELINE_SCAN_ID, LATEST_SCAN_ID, REPO_SCAN_ID]))).all()
                findings = db.scalars(select(Finding).where(Finding.id.in_([seed.id for seed in FINDING_SEEDS]))).all()

                self.assertTrue(all(target.workspace_id == DEV_WORKSPACE_ID for target in targets))
                self.assertTrue(all(target.allowlist_id == "juice-shop" for target in targets))
                self.assertTrue(all(target.base_url == "http://juice-shop:3000" for target in targets))
                self.assertTrue(all(scan.workspace_id == DEV_WORKSPACE_ID for scan in scans))
                self.assertTrue(all(finding.workspace_id == DEV_WORKSPACE_ID for finding in findings))
                self.assertTrue(all(finding.redaction_applied for finding in findings))
                self.assertFalse(any("super-secret" in (finding.evidence or "") for finding in findings))

                repo_target = db.get(Target, REPO_TARGET_ID)
                self.assertIsNotNone(repo_target)
                self.assertFalse(Path(repo_target.repo_path).is_absolute())
                self.assertTrue((repo_root / repo_target.repo_path).resolve().is_relative_to(repo_root.resolve()))

                other_workspace = Workspace(id="demo-seed-other-workspace", owner_user_id=DEV_USER_ID, name="Other")
                db.add(other_workspace)
                db.commit()
                other_count = db.query(Target).filter(Target.workspace_id == "demo-seed-other-workspace").count()
                self.assertEqual(other_count, 0)

    def test_seed_demo_data_persists_versioned_scores_management_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_root = Path(temp_dir) / "artifacts"
            repo_root = Path(temp_dir) / "repositories"
            run_seed(artifact_root, repo_root)

            with session() as db:
                scores = db.scalars(select(RiskScore).where(RiskScore.id.like("demo-risk-%"))).all()
                self.assertEqual(len(scores), 3)
                self.assertTrue(all(score.scoring_model_version == SCORING_MODEL_VERSION for score in scores))
                self.assertTrue(all(score.input_summary["scan_profile_id"] in {"passive-web", "repository"} for score in scores))

                csp_state = db.get(FindingState, "demo-state-csp")
                api_key_occurrence = db.scalar(select(FindingOccurrenceState).where(FindingOccurrenceState.finding_id == "demo-finding-repo-api-key"))
                suppression = db.get(SuppressionRule, "demo-suppression-repo-api-key")
                self.assertEqual(csp_state.lifecycle_status, "in_progress")
                self.assertIsNotNone(suppression)
                self.assertTrue(api_key_occurrence.suppressed)
                self.assertEqual(api_key_occurrence.suppression_rule_id, suppression.id)

                tag_count = db.query(Tag).filter(Tag.id.like("demo-tag-%")).count()
                assignment_count = db.query(TagAssignment).filter(TagAssignment.id.like("demo-tag-%")).count()
                self.assertEqual(tag_count, 3)
                self.assertEqual(assignment_count, 3)

                reports = db.scalars(select(ReportArtifact).where(ReportArtifact.id.like("demo-report-%"))).all()
                self.assertEqual(len(reports), 4)
                for report in reports:
                    report_path = Path(report.path)
                    self.assertTrue(report_path.exists())
                    self.assertTrue(report_path.resolve().is_relative_to(artifact_root.resolve()))
                    content = read_report_artifact_file(report, artifact_root=artifact_root)
                    self.assertNotIn("super-secret", content)


def run_seed(artifact_root: Path, repo_root: Path):
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        return seed_demo_data(db, artifact_root=artifact_root, repo_scan_root=repo_root)


def cleanup_demo_seed() -> None:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        db.execute(delete(TagAssignment).where(TagAssignment.id.like("demo-tag-%")))
        db.execute(delete(Tag).where(Tag.id.like("demo-tag-%")))
        db.execute(delete(ReportArtifact).where(ReportArtifact.id.like("demo-report-%")))
        db.execute(delete(RiskScore).where(RiskScore.id.like("demo-risk-%")))
        db.execute(delete(FindingOccurrenceState).where(FindingOccurrenceState.finding_id.in_([seed.id for seed in FINDING_SEEDS])))
        db.execute(delete(FindingState).where(FindingState.target_id.in_([JUICE_TARGET_ID, REPO_TARGET_ID])))
        db.execute(delete(SuppressionRule).where(SuppressionRule.id.like("demo-suppression-%")))
        db.execute(delete(Finding).where(Finding.id.in_([seed.id for seed in FINDING_SEEDS])))
        db.execute(delete(Scan).where(Scan.id.in_([BASELINE_SCAN_ID, LATEST_SCAN_ID, REPO_SCAN_ID])))
        db.execute(delete(Target).where(Target.id.in_([JUICE_TARGET_ID, REPO_TARGET_ID])))
        db.execute(delete(AuthIdentity).where(AuthIdentity.id == "demo-auth-identity"))
        db.execute(delete(Workspace).where(Workspace.id == "demo-seed-other-workspace"))
        db.commit()


def session():
    from app.db.session import SessionLocal

    return SessionLocal()


if __name__ == "__main__":
    unittest.main()
