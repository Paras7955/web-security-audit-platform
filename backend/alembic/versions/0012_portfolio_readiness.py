"""Add portfolio-readiness subjects, integrity constraints, and cleanup ledger.

Revision ID: 0012_portfolio_readiness
Revises: 0011_target_archiving
Create Date: 2026-07-29
"""
from __future__ import annotations

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op

revision: str = "0012_portfolio_readiness"
down_revision: str | None = "0011_target_archiving"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("policy_fingerprint", sa.String(length=64), nullable=True))
    op.add_column("targets", sa.Column("policy_scope_base_url", sa.String(length=2048), nullable=True))

    op.create_table(
        "repository_assets",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("relative_path", sa.String(length=2048), nullable=False),
        sa.Column("permission_confirmed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archived_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=True),
        sa.UniqueConstraint("workspace_id", "relative_path", name="uq_repository_assets_workspace_path"),
    )
    op.create_index(
        "ix_repository_assets_workspace_created_id",
        "repository_assets",
        ["workspace_id", "created_at", "id"],
    )
    op.create_index(
        "ix_repository_assets_workspace_active",
        "repository_assets",
        ["workspace_id", "archived_at"],
    )

    op.alter_column("scans", "target_id", existing_type=sa.String(length=64), nullable=True)
    op.add_column("scans", sa.Column("repository_asset_id", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("repo_path_snapshot", sa.String(length=2048), nullable=True))
    op.add_column("scans", sa.Column("target_policy_fingerprint", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("acknowledgements_snapshot", sa.JSON(), server_default="[]", nullable=False))
    op.add_column("scans", sa.Column("authorization_snapshot", sa.JSON(), server_default="{}", nullable=False))
    op.create_foreign_key(
        "fk_scans_repository_asset_id",
        "scans",
        "repository_assets",
        ["repository_asset_id"],
        ["id"],
    )
    op.create_index("ix_scans_repository_asset_id", "scans", ["repository_asset_id"])

    _add_repository_subject_columns()
    _add_management_lifecycle()
    _remove_unsafe_evidence_channel()
    _reconcile_duplicate_reports()
    op.create_unique_constraint(
        "uq_report_artifacts_scan_type",
        "report_artifacts",
        ["workspace_id", "scan_id", "report_type"],
    )

    op.create_table(
        "artifact_cleanup_tasks",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("scan_id", "action", name="uq_artifact_cleanup_tasks_scan_action"),
    )
    op.create_index(
        "ix_artifact_cleanup_tasks_pending",
        "artifact_cleanup_tasks",
        ["completed_at", "created_at"],
    )

    if not context.is_offline_mode():
        _invalidate_unreceipted_repository_scans(op.get_bind())


def _add_repository_subject_columns() -> None:
    op.alter_column("finding_states", "target_id", existing_type=sa.String(length=64), nullable=True)
    op.add_column("finding_states", sa.Column("repository_asset_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_finding_states_repository_asset_id",
        "finding_states",
        "repository_assets",
        ["repository_asset_id"],
        ["id"],
    )
    op.create_unique_constraint(
        "uq_finding_states_repository_identity",
        "finding_states",
        ["workspace_id", "repository_asset_id", "dedupe_key"],
    )
    op.create_check_constraint(
        "ck_finding_states_exactly_one_subject",
        "finding_states",
        "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
    )
    op.create_index(
        "ix_finding_states_workspace_repository_status",
        "finding_states",
        ["workspace_id", "repository_asset_id", "lifecycle_status"],
    )

    op.alter_column("suppression_rules", "target_id", existing_type=sa.String(length=64), nullable=True)
    op.add_column("suppression_rules", sa.Column("repository_asset_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_suppression_rules_repository_asset_id",
        "suppression_rules",
        "repository_assets",
        ["repository_asset_id"],
        ["id"],
    )
    op.create_check_constraint(
        "ck_suppression_rules_exactly_one_subject",
        "suppression_rules",
        "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
    )
    op.create_index(
        "ix_suppression_rules_workspace_repository",
        "suppression_rules",
        ["workspace_id", "repository_asset_id"],
    )

    op.alter_column("risk_scores", "target_id", existing_type=sa.String(length=64), nullable=True)
    op.add_column("risk_scores", sa.Column("repository_asset_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_risk_scores_repository_asset_id",
        "risk_scores",
        "repository_assets",
        ["repository_asset_id"],
        ["id"],
    )
    op.create_unique_constraint(
        "uq_risk_scores_repository_scan_model",
        "risk_scores",
        ["workspace_id", "repository_asset_id", "scan_id", "scoring_model_version"],
    )
    op.create_check_constraint(
        "ck_risk_scores_exactly_one_subject",
        "risk_scores",
        "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
    )
    op.create_index(
        "ix_risk_scores_workspace_repository",
        "risk_scores",
        ["workspace_id", "repository_asset_id"],
    )


def _add_management_lifecycle() -> None:
    op.add_column("suppression_rules", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("suppression_rules", sa.Column("revoked_by_user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_suppression_rules_revoked_by_user_id",
        "suppression_rules",
        "platform_users",
        ["revoked_by_user_id"],
        ["id"],
    )
    op.add_column("tags", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tags", sa.Column("archived_by_user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_tags_archived_by_user_id",
        "tags",
        "platform_users",
        ["archived_by_user_id"],
        ["id"],
    )


def _remove_unsafe_evidence_channel() -> None:
    op.drop_constraint("findings_raw_artifact_ref_fkey", "findings", type_="foreignkey")
    op.drop_column("findings", "raw_artifact_ref")
    op.drop_table("evidence_artifacts")


def _reconcile_duplicate_reports() -> None:
    if context.is_offline_mode():
        return
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            DELETE FROM tag_assignments
            WHERE resource_type = 'report'
              AND resource_id IN (
                SELECT id FROM (
                  SELECT id, row_number() OVER (
                    PARTITION BY workspace_id, scan_id, report_type
                    ORDER BY created_at DESC, id DESC
                  ) AS duplicate_number
                  FROM report_artifacts
                ) ranked
                WHERE duplicate_number > 1
              )
            """
        )
    )
    connection.execute(
        sa.text(
            """
            DELETE FROM report_artifacts
            WHERE id IN (
              SELECT id FROM (
                SELECT id, row_number() OVER (
                  PARTITION BY workspace_id, scan_id, report_type
                  ORDER BY created_at DESC, id DESC
                ) AS duplicate_number
                FROM report_artifacts
              ) ranked
              WHERE duplicate_number > 1
            )
            """
        )
    )


def _invalidate_unreceipted_repository_scans(connection: sa.Connection) -> None:
    scans = sa.table(
        "scans",
        sa.column("id"),
        sa.column("status"),
        sa.column("status_message"),
        sa.column("error_code"),
        sa.column("error_detail"),
        sa.column("completed_at"),
        sa.column("lease_owner"),
        sa.column("lease_expires_at"),
        sa.column("lease_heartbeat_at"),
    )
    findings = sa.table("findings", sa.column("id"), sa.column("scan_id"))
    occurrence_states = sa.table("finding_occurrence_states", sa.column("finding_id"))
    risk_scores = sa.table("risk_scores", sa.column("scan_id"))
    ai_cache = sa.table("ai_explanation_cache", sa.column("scan_id"))
    reports = sa.table("report_artifacts", sa.column("id"), sa.column("scan_id"))
    tag_assignments = sa.table(
        "tag_assignments",
        sa.column("resource_type"),
        sa.column("resource_id"),
    )
    scan_ids = [
        row[0]
        for row in connection.execute(
            sa.text(
                """
                SELECT scans.id
                FROM scans
                WHERE scans.mode = 'repo'
                  AND NOT EXISTS (
                    SELECT 1 FROM scanner_tool_runs
                    WHERE scanner_tool_runs.scan_id = scans.id
                      AND scanner_tool_runs.tool_name IN ('gitleaks', 'osv-scanner')
                  )
                """
            )
        )
    ]
    if not scan_ids:
        _queue_passive_summary_cleanup(connection)
        return

    connection.execute(
        sa.delete(occurrence_states).where(
            occurrence_states.c.finding_id.in_(
                sa.select(findings.c.id).where(findings.c.scan_id.in_(scan_ids))
            )
        )
    )
    connection.execute(sa.delete(findings).where(findings.c.scan_id.in_(scan_ids)))
    connection.execute(sa.delete(risk_scores).where(risk_scores.c.scan_id.in_(scan_ids)))
    connection.execute(sa.delete(ai_cache).where(ai_cache.c.scan_id.in_(scan_ids)))
    report_ids = [
        row[0]
        for row in connection.execute(sa.select(reports.c.id).where(reports.c.scan_id.in_(scan_ids)))
    ]
    if report_ids:
        connection.execute(
            sa.delete(tag_assignments).where(
                tag_assignments.c.resource_type == "report",
                tag_assignments.c.resource_id.in_(report_ids),
            )
        )
    connection.execute(sa.delete(reports).where(reports.c.scan_id.in_(scan_ids)))
    connection.execute(
        sa.update(scans)
        .where(scans.c.id.in_(scan_ids))
        .values(
            status=sa.case(
                (
                    scans.c.status.in_(("completed", "completed_with_warnings")),
                    "completed_with_warnings",
                ),
                else_="failed",
            ),
            status_message=(
                "Legacy repository results lacked verified tool receipts and were removed; "
                "rerun the scan."
            ),
            error_code="legacy_repo_results_removed",
            error_detail=None,
            completed_at=sa.func.coalesce(scans.c.completed_at, sa.func.current_timestamp()),
            lease_owner=None,
            lease_expires_at=None,
            lease_heartbeat_at=None,
        )
    )
    for scan_id in scan_ids:
        connection.execute(
            sa.text(
                """
                INSERT INTO artifact_cleanup_tasks (id, scan_id, action, reason)
                VALUES (:id, :scan_id, 'remove_invalidated_scan_artifacts', 'receiptless_repository_results')
                ON CONFLICT (scan_id, action) DO NOTHING
                """
            ),
            {"id": str(uuid4()), "scan_id": scan_id},
        )
    _queue_passive_summary_cleanup(connection)


def _queue_passive_summary_cleanup(connection: sa.Connection) -> None:
    for scan_id in connection.scalars(sa.text("SELECT id FROM scans WHERE mode = 'passive'")):
        connection.execute(
            sa.text(
                """
                INSERT INTO artifact_cleanup_tasks (id, scan_id, action, reason)
                VALUES (:id, :scan_id, 'remove_passive_summary', 'retired_passive_summary')
                ON CONFLICT (scan_id, action) DO NOTHING
                """
            ),
            {"id": str(uuid4()), "scan_id": scan_id},
        )


def downgrade() -> None:
    op.drop_index("ix_artifact_cleanup_tasks_pending", table_name="artifact_cleanup_tasks")
    op.drop_table("artifact_cleanup_tasks")

    op.drop_constraint("uq_report_artifacts_scan_type", "report_artifacts", type_="unique")
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("artifact_type", sa.String(length=80), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("redaction_applied", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_evidence_artifacts_workspace_id", "evidence_artifacts", ["workspace_id"])
    op.add_column("findings", sa.Column("raw_artifact_ref", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "findings_raw_artifact_ref_fkey",
        "findings",
        "evidence_artifacts",
        ["raw_artifact_ref"],
        ["id"],
    )

    op.drop_constraint("fk_tags_archived_by_user_id", "tags", type_="foreignkey")
    op.drop_column("tags", "archived_by_user_id")
    op.drop_column("tags", "archived_at")
    op.drop_constraint("fk_suppression_rules_revoked_by_user_id", "suppression_rules", type_="foreignkey")
    op.drop_column("suppression_rules", "revoked_by_user_id")
    op.drop_column("suppression_rules", "revoked_at")

    op.drop_index("ix_risk_scores_workspace_repository", table_name="risk_scores")
    op.drop_constraint("ck_risk_scores_exactly_one_subject", "risk_scores", type_="check")
    op.drop_constraint("uq_risk_scores_repository_scan_model", "risk_scores", type_="unique")
    op.drop_constraint("fk_risk_scores_repository_asset_id", "risk_scores", type_="foreignkey")
    op.drop_column("risk_scores", "repository_asset_id")
    op.alter_column("risk_scores", "target_id", existing_type=sa.String(length=64), nullable=False)

    op.drop_index("ix_suppression_rules_workspace_repository", table_name="suppression_rules")
    op.drop_constraint("ck_suppression_rules_exactly_one_subject", "suppression_rules", type_="check")
    op.drop_constraint("fk_suppression_rules_repository_asset_id", "suppression_rules", type_="foreignkey")
    op.drop_column("suppression_rules", "repository_asset_id")
    op.alter_column("suppression_rules", "target_id", existing_type=sa.String(length=64), nullable=False)

    op.drop_index("ix_finding_states_workspace_repository_status", table_name="finding_states")
    op.drop_constraint("ck_finding_states_exactly_one_subject", "finding_states", type_="check")
    op.drop_constraint("uq_finding_states_repository_identity", "finding_states", type_="unique")
    op.drop_constraint("fk_finding_states_repository_asset_id", "finding_states", type_="foreignkey")
    op.drop_column("finding_states", "repository_asset_id")
    op.alter_column("finding_states", "target_id", existing_type=sa.String(length=64), nullable=False)

    op.drop_index("ix_scans_repository_asset_id", table_name="scans")
    op.drop_constraint("fk_scans_repository_asset_id", "scans", type_="foreignkey")
    op.drop_column("scans", "authorization_snapshot")
    op.drop_column("scans", "acknowledgements_snapshot")
    op.drop_column("scans", "target_policy_fingerprint")
    op.drop_column("scans", "repo_path_snapshot")
    op.drop_column("scans", "repository_asset_id")
    op.alter_column("scans", "target_id", existing_type=sa.String(length=64), nullable=False)

    op.drop_index("ix_repository_assets_workspace_active", table_name="repository_assets")
    op.drop_index("ix_repository_assets_workspace_created_id", table_name="repository_assets")
    op.drop_table("repository_assets")
    op.drop_column("targets", "policy_scope_base_url")
    op.drop_column("targets", "policy_fingerprint")
