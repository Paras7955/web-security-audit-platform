"""platform ops

Revision ID: 0008_platform_ops
Revises: 0007_ai_cache_rate_limits
Create Date: 2026-07-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_platform_ops"
down_revision: Union[str, None] = "0007_ai_cache_rate_limits"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("cancellation_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("cancellation_requested_by_user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_scans_cancellation_requested_by_user_id",
        "scans",
        "platform_users",
        ["cancellation_requested_by_user_id"],
        ["id"],
    )

    op.create_table(
        "api_rate_limit_logs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("allowed", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_api_rate_limit_logs_window", "api_rate_limit_logs", ["workspace_id", "user_id", "action", "created_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=True),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=80), nullable=True),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_workspace_created", "audit_logs", ["workspace_id", "created_at"])
    op.create_index("ix_audit_logs_workspace_event", "audit_logs", ["workspace_id", "event_type", "created_at"])
    op.create_index("ix_audit_logs_workspace_resource", "audit_logs", ["workspace_id", "resource_type", "resource_id"])

    op.create_table(
        "worker_heartbeats",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("worker_id", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=80), nullable=False),
        sa.Column("current_scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("queue_depth", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("worker_id", name="uq_worker_heartbeats_worker_id"),
    )
    op.create_index("ix_worker_heartbeats_last_seen", "worker_heartbeats", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("ix_worker_heartbeats_last_seen", table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")
    op.drop_index("ix_audit_logs_workspace_resource", table_name="audit_logs")
    op.drop_index("ix_audit_logs_workspace_event", table_name="audit_logs")
    op.drop_index("ix_audit_logs_workspace_created", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_api_rate_limit_logs_window", table_name="api_rate_limit_logs")
    op.drop_table("api_rate_limit_logs")
    op.drop_constraint("fk_scans_cancellation_requested_by_user_id", "scans", type_="foreignkey")
    op.drop_column("scans", "cancellation_requested_by_user_id")
    op.drop_column("scans", "cancellation_requested_at")
