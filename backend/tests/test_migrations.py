import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote
from uuid import uuid4

from alembic import command
from alembic.config import Config
from app.core.config import settings
from app.db.session import check_database_ready, engine
from sqlalchemy import create_engine, inspect, text


class MigrationTests(unittest.TestCase):
    def test_runtime_readiness_matches_migration_head(self) -> None:
        self.assertTrue(check_database_ready())

    def test_clean_upgrade_from_zero_reaches_head(self) -> None:
        with isolated_schema() as (database_url, migration_config):
            with patch("app.core.config.settings.database_url", database_url):
                command.upgrade(migration_config, "head")
            isolated_engine = create_engine(database_url)
            try:
                with isolated_engine.connect() as connection:
                    self.assertEqual(connection.scalar(text("SELECT version_num FROM alembic_version")), "0014_worker_scanner_readiness")
                    tables = set(inspect(connection).get_table_names())
                    self.assertIn("scanner_tool_runs", tables)
                    self.assertIn("auth_profiles", tables)
                    self.assertIn("repository_assets", tables)
                    self.assertIn("artifact_cleanup_tasks", tables)
                    self.assertNotIn("evidence_artifacts", tables)
                    scan_constraints = {
                        constraint["name"]
                        for constraint in inspect(connection).get_check_constraints("scans")
                    }
                    self.assertIn("ck_scans_exactly_one_subject", scan_constraints)
                    target_columns = {column["name"] for column in inspect(connection).get_columns("targets")}
                    self.assertIn("archived_at", target_columns)
                    self.assertIn("archived_by_user_id", target_columns)
                    heartbeat_columns = {column["name"] for column in inspect(connection).get_columns("worker_heartbeats")}
                    self.assertIn("zap_status", heartbeat_columns)
                    self.assertIn("zap_detail", heartbeat_columns)
            finally:
                isolated_engine.dispose()

    def test_upgrade_from_0008_cleans_legacy_data_without_relabelling_completed_ajax_history(self) -> None:
        with isolated_schema() as (database_url, migration_config):
            with patch("app.core.config.settings.database_url", database_url):
                command.upgrade(migration_config, "0008_platform_ops")
            isolated_engine = create_engine(database_url)
            try:
                with isolated_engine.begin() as connection:
                    seed_0008_fixture(connection)
                with patch("app.core.config.settings.database_url", database_url):
                    command.upgrade(migration_config, "head")
                with isolated_engine.connect() as connection:
                    unsafe = connection.execute(
                        text("SELECT affected_url, evidence, remediation, redaction_applied FROM findings WHERE id='migration-unsafe-finding'")
                    ).mappings().one()
                    self.assertEqual(unsafe["affected_url"], "http://juice-shop:3000/callback")
                    self.assertNotIn("raw-secret-token", str(dict(unsafe)))
                    self.assertTrue(unsafe["redaction_applied"])
                    self.assertEqual(
                        connection.scalar(text("SELECT count(*) FROM findings WHERE id='migration-stub-finding'")),
                        0,
                    )
                    self.assertEqual(
                        connection.scalar(text("SELECT count(*) FROM report_artifacts WHERE scan_id='migration-repo-scan'")),
                        0,
                    )
                    self.assertEqual(
                        connection.scalar(text("SELECT count(*) FROM risk_scores WHERE scan_id='migration-repo-scan'")),
                        0,
                    )
                    repo = connection.execute(
                        text("SELECT status, error_code, error_detail FROM scans WHERE id='migration-repo-scan'")
                    ).mappings().one()
                    self.assertEqual(repo["status"], "completed_with_warnings")
                    self.assertEqual(repo["error_code"], "legacy_repo_results_removed")
                    self.assertIsNone(repo["error_detail"])
                    self.assertEqual(
                        connection.scalar(text("SELECT status FROM scans WHERE id='migration-ajax-completed'")),
                        "completed",
                    )
                    retired = connection.execute(
                        text("SELECT status, error_code, error_detail FROM scans WHERE id='migration-ajax-queued'")
                    ).mappings().one()
                    self.assertEqual(retired["status"], "failed")
                    self.assertEqual(retired["error_code"], "retired_profile")
                    self.assertIsNone(retired["error_detail"])
                    self.assertIsNotNone(
                        connection.scalar(
                            text("SELECT authorization_confirmed_at FROM targets WHERE id='migration-target'")
                        )
                    )
                    self.assertIsNone(
                        connection.scalar(text("SELECT repo_path FROM targets WHERE id='migration-target'"))
                    )
                    profile = connection.execute(
                        text(
                            "SELECT encrypted_secret, rotation_count, revoked_at FROM auth_profiles "
                            "WHERE id='migration-auth-profile'"
                        )
                    ).mappings().one()
                    self.assertEqual(profile["encrypted_secret"], "legacy-ciphertext")
                    self.assertEqual(profile["rotation_count"], 0)
                    self.assertIsNone(profile["revoked_at"])
            finally:
                isolated_engine.dispose()

    def test_upgrade_from_0012_repairs_dual_subject_scans_before_constraint(self) -> None:
        with isolated_schema() as (database_url, migration_config):
            with patch("app.core.config.settings.database_url", database_url):
                command.upgrade(migration_config, "0012_portfolio_readiness")
            isolated_engine = create_engine(database_url)
            try:
                with isolated_engine.begin() as connection:
                    connection.execute(
                        text(
                            "INSERT INTO targets "
                            "(id, workspace_id, created_by_user_id, allowlist_id, name, base_url, permission_confirmed) "
                            "VALUES ('dual-target','legacy-dev-workspace','legacy-dev-user','juice-shop',"
                            "'Dual target','http://juice-shop:3000/',true)"
                        )
                    )
                    connection.execute(
                        text(
                            "INSERT INTO repository_assets "
                            "(id, workspace_id, created_by_user_id, name, relative_path, permission_confirmed) "
                            "VALUES ('dual-repository','legacy-dev-workspace','legacy-dev-user',"
                            "'Dual repository','security-project',true)"
                        )
                    )
                    connection.execute(
                        text(
                            "INSERT INTO scans "
                            "(id, workspace_id, created_by_user_id, target_id, repository_asset_id, "
                            "repo_path_snapshot, acknowledgements_snapshot, authorization_snapshot, "
                            "mode, scan_profile_id, status, progress_percent) "
                            "VALUES ('dual-scan','legacy-dev-workspace','legacy-dev-user','dual-target',"
                            "'dual-repository','security-project',CAST('[]' AS JSON),CAST('{}' AS JSON),"
                            "'repo','repository','queued',0)"
                        )
                    )

                with patch("app.core.config.settings.database_url", database_url):
                    command.upgrade(migration_config, "head")

                with isolated_engine.connect() as connection:
                    subject = connection.execute(
                        text(
                            "SELECT target_id, repository_asset_id FROM scans "
                            "WHERE id='dual-scan'"
                        )
                    ).mappings().one()
                    self.assertIsNone(subject["target_id"])
                    self.assertEqual(subject["repository_asset_id"], "dual-repository")
            finally:
                isolated_engine.dispose()

    def test_schema_head_has_no_model_drift(self) -> None:
        with isolated_schema() as (database_url, migration_config):
            with patch("app.core.config.settings.database_url", database_url):
                command.upgrade(migration_config, "head")
                command.check(migration_config)


@contextmanager
def isolated_schema():
    schema = f"migration_{uuid4().hex}"
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    separator = "&" if "?" in settings.database_url else "?"
    database_url = f"{settings.database_url}{separator}options={quote(f'-csearch_path={schema}', safe='')}"
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "alembic"))
    try:
        yield database_url, config
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))


def seed_0008_fixture(connection) -> None:  # type: ignore[no-untyped-def]
    connection.execute(
        text(
            "INSERT INTO auth_profiles (id, workspace_id, created_by_user_id, label, profile_type, header_name, "
            "encrypted_secret, secret_hint) VALUES "
            "('migration-auth-profile','legacy-dev-workspace','legacy-dev-user','Legacy profile','bearer_token',NULL,"
            "'legacy-ciphertext','****text')"
        )
    )
    connection.execute(
        text(
            "INSERT INTO targets (id, workspace_id, created_by_user_id, allowlist_id, name, base_url, permission_confirmed, auth_profile_id, repo_path) "
            "VALUES ('migration-target','legacy-dev-workspace','legacy-dev-user','juice-shop','Migration target',"
            "'http://juice-shop:3000/',true,'migration-auth-profile','/tmp/legacy-repository')"
        )
    )
    scans = (
        ("migration-passive-scan", "passive", "passive-web", "completed"),
        ("migration-repo-scan", "repo", "repository", "completed"),
        ("migration-ajax-completed", "ajax_short", "ajax-short", "completed"),
        ("migration-ajax-queued", "ajax_short", "ajax-short", "queued"),
    )
    for scan_id, mode, profile, status in scans:
        connection.execute(
            text(
                "INSERT INTO scans (id, workspace_id, created_by_user_id, target_id, mode, scan_profile_id, status, "
                "current_step, status_message, progress_percent, error_code, error_detail) "
                "VALUES (:id,'legacy-dev-workspace','legacy-dev-user','migration-target',:mode,:profile,:status,"
                "'target_validation','Legacy status',0,'legacy_error','raw-secret-token')"
            ),
            {"id": scan_id, "mode": mode, "profile": profile, "status": status},
        )
    connection.execute(
        text(
            "INSERT INTO findings (id, workspace_id, scan_id, title, severity, confidence, affected_url, evidence, "
            "source_tool, dedupe_key, remediation, redaction_applied) VALUES "
            "('migration-unsafe-finding','legacy-dev-workspace','migration-passive-scan','Unsafe raw-secret-token','high','high',"
            "'http://user:raw-secret-token@juice-shop:3000/callback?token=raw-secret-token#fragment',"
            "'authorization: bearer raw-secret-token','custom-passive','migration-unsafe','Remove raw-secret-token',false),"
            "('migration-stub-finding','legacy-dev-workspace','migration-repo-scan','Stub result','medium','medium',NULL,"
            "'stub_secret=raw-secret-token','gitleaks-stub','migration-stub','Remove stub',true)"
        )
    )
    connection.execute(
        text(
            "INSERT INTO report_artifacts (id, workspace_id, created_by_user_id, scan_id, report_type, path) "
            "VALUES ('migration-stub-report','legacy-dev-workspace','legacy-dev-user','migration-repo-scan','markdown','/tmp/report.md')"
        )
    )
    connection.execute(
        text(
            "INSERT INTO risk_scores (id, workspace_id, target_id, scan_id, scoring_model_version, score, label, input_summary) "
            "VALUES ('migration-stub-risk','legacy-dev-workspace','migration-target','migration-repo-scan','risk-v1',10,'Low',CAST('{}' AS JSON))"
        )
    )


if __name__ == "__main__":
    unittest.main()
