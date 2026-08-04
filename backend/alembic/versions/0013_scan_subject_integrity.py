"""Enforce exactly one authorized subject for every scan.

Revision ID: 0013_scan_subject_integrity
Revises: 0012_portfolio_readiness
Create Date: 2026-08-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_scan_subject_integrity"
down_revision: str | None = "0012_portfolio_readiness"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE scans SET target_id = NULL "
            "WHERE target_id IS NOT NULL AND repository_asset_id IS NOT NULL"
        )
    )
    op.create_check_constraint(
        "ck_scans_exactly_one_subject",
        "scans",
        "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_scans_exactly_one_subject",
        "scans",
        type_="check",
    )
