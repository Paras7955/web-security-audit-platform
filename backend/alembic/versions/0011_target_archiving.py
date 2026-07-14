"""Add safe target archiving.

Revision ID: 0011_target_archiving
Revises: 0010_public_indexes
Create Date: 2026-07-14
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_target_archiving"
down_revision: str | None = "0010_public_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("targets", sa.Column("archived_by_user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_targets_archived_by_user_id_platform_users",
        "targets",
        "platform_users",
        ["archived_by_user_id"],
        ["id"],
    )
    op.create_index(
        "ix_targets_workspace_active_created_id",
        "targets",
        ["workspace_id", "archived_at", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_targets_workspace_active_created_id", table_name="targets")
    op.drop_constraint("fk_targets_archived_by_user_id_platform_users", "targets", type_="foreignkey")
    op.drop_column("targets", "archived_by_user_id")
    op.drop_column("targets", "archived_at")
