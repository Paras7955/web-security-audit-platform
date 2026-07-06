"""scan profiles

Revision ID: 0003_scan_profiles
Revises: 0002_auth_workspaces
Create Date: 2026-07-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_scan_profiles"
down_revision: Union[str, None] = "0002_auth_workspaces"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PROFILE_BY_MODE = {
    "passive": "passive-web",
    "active_demo": "active-demo",
    "ajax_short": "ajax-short",
    "repo": "repository",
}


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("scan_profile_id", sa.String(length=80), nullable=False, server_default="passive-web"),
    )
    for mode, profile_id in PROFILE_BY_MODE.items():
        op.execute(
            sa.text("UPDATE scans SET scan_profile_id = :profile_id WHERE mode = :mode").bindparams(
                profile_id=profile_id,
                mode=mode,
            )
        )
    op.create_index("ix_scans_scan_profile_id", "scans", ["scan_profile_id"])


def downgrade() -> None:
    op.drop_index("ix_scans_scan_profile_id", table_name="scans")
    op.drop_column("scans", "scan_profile_id")
