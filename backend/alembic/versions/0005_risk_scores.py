"""risk scores

Revision ID: 0005_risk_scores
Revises: 0004_auth_profile_secrets
Create Date: 2026-07-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0005_risk_scores"
down_revision: Union[str, None] = "0004_auth_profile_secrets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("target_id", sa.String(length=64), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("scoring_model_version", sa.String(length=40), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=40), nullable=False),
        sa.Column("input_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("workspace_id", "target_id", "scan_id", "scoring_model_version", name="uq_risk_scores_scan_model"),
    )
    op.create_index("ix_risk_scores_workspace_target", "risk_scores", ["workspace_id", "target_id"])
    op.create_index("ix_risk_scores_scan_id", "risk_scores", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_risk_scores_scan_id", table_name="risk_scores")
    op.drop_index("ix_risk_scores_workspace_target", table_name="risk_scores")
    op.drop_table("risk_scores")
