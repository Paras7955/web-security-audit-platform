"""Record worker-mediated scanner readiness.

Revision ID: 0014_worker_scanner_readiness
Revises: 0013_scan_subject_integrity
Create Date: 2026-08-25
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_worker_scanner_readiness"
down_revision: str | None = "0013_scan_subject_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("worker_heartbeats", sa.Column("zap_status", sa.String(length=20), nullable=True))
    op.add_column("worker_heartbeats", sa.Column("zap_detail", sa.String(length=160), nullable=True))


def downgrade() -> None:
    op.drop_column("worker_heartbeats", "zap_detail")
    op.drop_column("worker_heartbeats", "zap_status")
