"""auth profile secrets

Revision ID: 0004_auth_profile_secrets
Revises: 0003_scan_profiles
Create Date: 2026-07-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004_auth_profile_secrets"
down_revision: Union[str, None] = "0003_scan_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("auth_profiles", sa.Column("profile_type", sa.String(length=40), nullable=False, server_default="bearer_token"))
    op.add_column("auth_profiles", sa.Column("header_name", sa.String(length=120), nullable=True))
    op.add_column("auth_profiles", sa.Column("encrypted_secret", sa.Text(), nullable=False, server_default=""))
    op.add_column("auth_profiles", sa.Column("secret_hint", sa.String(length=80), nullable=False, server_default=""))
    op.add_column("scans", sa.Column("auth_profile_id", sa.String(length=64), sa.ForeignKey("auth_profiles.id"), nullable=True))
    op.create_index("ix_scans_auth_profile_id", "scans", ["auth_profile_id"])


def downgrade() -> None:
    op.drop_index("ix_scans_auth_profile_id", table_name="scans")
    op.drop_column("scans", "auth_profile_id")
    op.drop_column("auth_profiles", "secret_hint")
    op.drop_column("auth_profiles", "encrypted_secret")
    op.drop_column("auth_profiles", "header_name")
    op.drop_column("auth_profiles", "profile_type")
