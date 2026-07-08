"""ai cache rate limits

Revision ID: 0007_ai_cache_rate_limits
Revises: 0006_finding_management
Create Date: 2026-07-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_ai_cache_rate_limits"
down_revision: Union[str, None] = "0006_finding_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_request_logs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=True),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("input_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("cache_hit", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("allowed", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ai_request_logs_workspace_action_created", "ai_request_logs", ["workspace_id", "action", "created_at"])
    op.create_index("ix_ai_request_logs_user_action_created", "ai_request_logs", ["user_id", "action", "created_at"])

    op.create_table(
        "ai_explanation_cache",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("input_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "workspace_id",
            "scan_id",
            "action",
            "provider",
            "model",
            "config_hash",
            "input_fingerprint",
            name="uq_ai_explanation_cache_input",
        ),
    )
    op.create_index("ix_ai_explanation_cache_scan", "ai_explanation_cache", ["workspace_id", "scan_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_ai_explanation_cache_scan", table_name="ai_explanation_cache")
    op.drop_table("ai_explanation_cache")
    op.drop_index("ix_ai_request_logs_user_action_created", table_name="ai_request_logs")
    op.drop_index("ix_ai_request_logs_workspace_action_created", table_name="ai_request_logs")
    op.drop_table("ai_request_logs")
