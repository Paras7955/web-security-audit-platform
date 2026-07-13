"""Add public cursor indexes and counter constraints.

Revision ID: 0010_public_indexes
Revises: 0009_public_readiness
Create Date: 2026-07-13
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "0010_public_indexes"
down_revision: Union[str, None] = "0009_public_readiness"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_check_constraint("ck_auth_profiles_rotation_count", "auth_profiles", "rotation_count >= 0")
    op.create_check_constraint("ck_scans_attempt_count", "scans", "attempt_count >= 0")
    op.create_index("ix_auth_profiles_workspace_created_id", "auth_profiles", ["workspace_id", "created_at", "id"])
    op.create_index("ix_targets_workspace_created_id", "targets", ["workspace_id", "created_at", "id"])
    op.create_index("ix_findings_workspace_created_id", "findings", ["workspace_id", "created_at", "id"])
    op.create_index(
        "ix_suppression_rules_workspace_created_id", "suppression_rules", ["workspace_id", "created_at", "id"]
    )
    op.create_index("ix_tags_workspace_created_id", "tags", ["workspace_id", "created_at", "id"])
    op.create_index(
        "ix_report_artifacts_workspace_created_id", "report_artifacts", ["workspace_id", "created_at", "id"]
    )
    op.create_index(
        "ix_report_artifacts_workspace_scan_created_id",
        "report_artifacts",
        ["workspace_id", "scan_id", "created_at", "id"],
    )
    op.create_index(
        "ix_tag_assignments_workspace_created_id", "tag_assignments", ["workspace_id", "created_at", "id"]
    )
    op.create_index(
        "ix_scanner_tool_runs_workspace_scan_created_id",
        "scanner_tool_runs",
        ["workspace_id", "scan_id", "created_at", "id"],
    )
    op.create_index("ix_audit_logs_workspace_created_id", "audit_logs", ["workspace_id", "created_at", "id"])


def downgrade() -> None:
    op.drop_index("ix_scanner_tool_runs_workspace_scan_created_id", table_name="scanner_tool_runs")
    op.drop_index("ix_tag_assignments_workspace_created_id", table_name="tag_assignments")
    op.drop_index("ix_report_artifacts_workspace_scan_created_id", table_name="report_artifacts")
    op.drop_index("ix_audit_logs_workspace_created_id", table_name="audit_logs")
    op.drop_index("ix_report_artifacts_workspace_created_id", table_name="report_artifacts")
    op.drop_index("ix_tags_workspace_created_id", table_name="tags")
    op.drop_index("ix_suppression_rules_workspace_created_id", table_name="suppression_rules")
    op.drop_index("ix_findings_workspace_created_id", table_name="findings")
    op.drop_index("ix_targets_workspace_created_id", table_name="targets")
    op.drop_index("ix_auth_profiles_workspace_created_id", table_name="auth_profiles")
    op.drop_constraint("ck_scans_attempt_count", "scans", type_="check")
    op.drop_constraint("ck_auth_profiles_rotation_count", "auth_profiles", type_="check")
