"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-06-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "auth_profiles",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=True),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "targets",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=True),
        sa.Column("allowlist_id", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("permission_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("repo_path", sa.String(length=2048), nullable=True),
        sa.Column("auth_profile_id", sa.String(length=64), sa.ForeignKey("auth_profiles.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("target_id", sa.String(length=64), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("mode", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("current_step", sa.String(length=80), nullable=True),
        sa.Column("status_message", sa.String(length=500), nullable=True),
        sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("artifact_type", sa.String(length=80), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("redaction_applied", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("severity", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.String(length=40), nullable=False),
        sa.Column("affected_url", sa.String(length=2048), nullable=True),
        sa.Column("affected_file", sa.String(length=2048), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column("scanner_rule_id", sa.String(length=200), nullable=True),
        sa.Column("dedupe_key", sa.String(length=500), nullable=False),
        sa.Column("owasp_category", sa.String(length=100), nullable=True),
        sa.Column("cwe", sa.String(length=100), nullable=True),
        sa.Column("reproduction_steps", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("false_positive_notes", sa.Text(), nullable=True),
        sa.Column("redaction_applied", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("raw_artifact_ref", sa.String(length=64), sa.ForeignKey("evidence_artifacts.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_dedupe_key", "findings", ["dedupe_key"])
    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("report_type", sa.String(length=40), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("report_artifacts")
    op.drop_index("ix_findings_dedupe_key", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("evidence_artifacts")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_table("auth_profiles")
    op.drop_table("workspaces")

