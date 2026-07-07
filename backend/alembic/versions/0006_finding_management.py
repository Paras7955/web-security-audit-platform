"""finding management

Revision ID: 0006_finding_management
Revises: 0005_risk_scores
Create Date: 2026-07-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0006_finding_management"
down_revision: Union[str, None] = "0005_risk_scores"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_states",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("target_id", sa.String(length=64), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("dedupe_key", sa.String(length=500), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=40), server_default="open", nullable=False),
        sa.Column("updated_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("workspace_id", "target_id", "dedupe_key", name="uq_finding_states_identity"),
    )
    op.create_index("ix_finding_states_workspace_target_status", "finding_states", ["workspace_id", "target_id", "lifecycle_status"])

    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("target_id", sa.String(length=64), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("dedupe_key", sa.String(length=500), nullable=True),
        sa.Column("severity", sa.String(length=40), nullable=True),
        sa.Column("source_tool", sa.String(length=100), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_suppression_rules_workspace_target", "suppression_rules", ["workspace_id", "target_id"])
    op.create_index("ix_suppression_rules_expires_at", "suppression_rules", ["expires_at"])

    op.create_table(
        "finding_occurrence_states",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("finding_id", sa.String(length=64), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=40), server_default="open", nullable=False),
        sa.Column("suppressed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("suppression_rule_id", sa.String(length=64), sa.ForeignKey("suppression_rules.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("finding_id", name="uq_finding_occurrence_states_finding"),
    )
    op.create_index("ix_finding_occurrence_states_workspace", "finding_occurrence_states", ["workspace_id"])
    op.create_index("ix_finding_occurrence_states_suppression", "finding_occurrence_states", ["suppression_rule_id"])

    op.create_table(
        "tags",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("label", sa.String(length=80), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("workspace_id", "label", name="uq_tags_workspace_label"),
    )

    op.create_table(
        "tag_assignments",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("tag_id", sa.String(length=64), sa.ForeignKey("tags.id"), nullable=False),
        sa.Column("resource_type", sa.String(length=40), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("workspace_id", "tag_id", "resource_type", "resource_id", name="uq_tag_assignments_resource"),
    )
    op.create_index("ix_tag_assignments_workspace_resource", "tag_assignments", ["workspace_id", "resource_type", "resource_id"])


def downgrade() -> None:
    op.drop_index("ix_tag_assignments_workspace_resource", table_name="tag_assignments")
    op.drop_table("tag_assignments")
    op.drop_table("tags")
    op.drop_index("ix_finding_occurrence_states_suppression", table_name="finding_occurrence_states")
    op.drop_index("ix_finding_occurrence_states_workspace", table_name="finding_occurrence_states")
    op.drop_table("finding_occurrence_states")
    op.drop_index("ix_suppression_rules_expires_at", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_workspace_target", table_name="suppression_rules")
    op.drop_table("suppression_rules")
    op.drop_index("ix_finding_states_workspace_target_status", table_name="finding_states")
    op.drop_table("finding_states")
