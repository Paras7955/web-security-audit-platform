"""auth workspace ownership

Revision ID: 0002_auth_workspaces
Revises: 0001_initial_schema
Create Date: 2026-06-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_auth_workspaces"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


LEGACY_USER_ID = "legacy-dev-user"
LEGACY_WORKSPACE_ID = "legacy-dev-workspace"
LEGACY_IDENTITY_ID = "legacy-dev-identity"


def upgrade() -> None:
    op.create_table(
        "platform_users",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "auth_identities",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=64), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("provider_subject", sa.String(length=300), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("provider", "provider_subject", name="uq_auth_identities_provider_subject"),
    )

    op.execute(
        sa.text(
            "INSERT INTO platform_users (id, display_name) VALUES (:id, :display_name) "
            "ON CONFLICT (id) DO NOTHING"
        ).bindparams(id=LEGACY_USER_ID, display_name="Legacy Dev User")
    )
    op.execute(
        sa.text(
            "INSERT INTO auth_identities (id, user_id, provider, provider_subject) "
            "VALUES (:id, :user_id, :provider, :provider_subject) "
            "ON CONFLICT (provider, provider_subject) DO NOTHING"
        ).bindparams(
            id=LEGACY_IDENTITY_ID,
            user_id=LEGACY_USER_ID,
            provider="dev",
            provider_subject=LEGACY_USER_ID,
        )
    )
    op.execute(
        sa.text(
            "INSERT INTO workspaces (id, name) VALUES (:id, :name) "
            "ON CONFLICT (id) DO NOTHING"
        ).bindparams(id=LEGACY_WORKSPACE_ID, name="Legacy Dev Workspace")
    )

    op.add_column(
        "workspaces",
        sa.Column(
            "owner_user_id",
            sa.String(length=64),
            nullable=False,
            server_default=LEGACY_USER_ID,
        ),
    )
    op.create_foreign_key("fk_workspaces_owner_user_id_platform_users", "workspaces", "platform_users", ["owner_user_id"], ["id"])

    op.add_column(
        "auth_profiles",
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default=LEGACY_USER_ID),
    )
    op.execute(sa.text("UPDATE auth_profiles SET workspace_id = :workspace_id WHERE workspace_id IS NULL").bindparams(workspace_id=LEGACY_WORKSPACE_ID))
    op.alter_column("auth_profiles", "workspace_id", existing_type=sa.String(length=64), nullable=False, server_default=LEGACY_WORKSPACE_ID)
    op.create_foreign_key("fk_auth_profiles_created_by_user_id_platform_users", "auth_profiles", "platform_users", ["created_by_user_id"], ["id"])
    op.create_index("ix_auth_profiles_workspace_id", "auth_profiles", ["workspace_id"])

    op.add_column(
        "targets",
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default=LEGACY_USER_ID),
    )
    op.execute(sa.text("UPDATE targets SET workspace_id = :workspace_id WHERE workspace_id IS NULL").bindparams(workspace_id=LEGACY_WORKSPACE_ID))
    op.alter_column("targets", "workspace_id", existing_type=sa.String(length=64), nullable=False, server_default=LEGACY_WORKSPACE_ID)
    op.create_foreign_key("fk_targets_created_by_user_id_platform_users", "targets", "platform_users", ["created_by_user_id"], ["id"])
    op.create_index("ix_targets_workspace_id", "targets", ["workspace_id"])

    op.add_column("scans", sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default=LEGACY_WORKSPACE_ID))
    op.add_column("scans", sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default=LEGACY_USER_ID))
    op.execute(
        sa.text(
            "UPDATE scans SET workspace_id = targets.workspace_id "
            "FROM targets WHERE scans.target_id = targets.id"
        )
    )
    op.create_foreign_key("fk_scans_workspace_id_workspaces", "scans", "workspaces", ["workspace_id"], ["id"])
    op.create_foreign_key("fk_scans_created_by_user_id_platform_users", "scans", "platform_users", ["created_by_user_id"], ["id"])
    op.create_index("ix_scans_workspace_id", "scans", ["workspace_id"])

    op.add_column("evidence_artifacts", sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default=LEGACY_WORKSPACE_ID))
    op.add_column("evidence_artifacts", sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default=LEGACY_USER_ID))
    op.execute(
        sa.text(
            "UPDATE evidence_artifacts SET workspace_id = scans.workspace_id, created_by_user_id = scans.created_by_user_id "
            "FROM scans WHERE evidence_artifacts.scan_id = scans.id"
        )
    )
    op.create_foreign_key("fk_evidence_artifacts_workspace_id_workspaces", "evidence_artifacts", "workspaces", ["workspace_id"], ["id"])
    op.create_foreign_key("fk_evidence_artifacts_created_by_user_id_platform_users", "evidence_artifacts", "platform_users", ["created_by_user_id"], ["id"])
    op.create_index("ix_evidence_artifacts_workspace_id", "evidence_artifacts", ["workspace_id"])

    op.add_column("findings", sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default=LEGACY_WORKSPACE_ID))
    op.execute(
        sa.text(
            "UPDATE findings SET workspace_id = scans.workspace_id "
            "FROM scans WHERE findings.scan_id = scans.id"
        )
    )
    op.create_foreign_key("fk_findings_workspace_id_workspaces", "findings", "workspaces", ["workspace_id"], ["id"])
    op.create_index("ix_findings_workspace_id", "findings", ["workspace_id"])

    op.add_column("report_artifacts", sa.Column("workspace_id", sa.String(length=64), nullable=False, server_default=LEGACY_WORKSPACE_ID))
    op.add_column("report_artifacts", sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default=LEGACY_USER_ID))
    op.execute(
        sa.text(
            "UPDATE report_artifacts SET workspace_id = scans.workspace_id, created_by_user_id = scans.created_by_user_id "
            "FROM scans WHERE report_artifacts.scan_id = scans.id"
        )
    )
    op.create_foreign_key("fk_report_artifacts_workspace_id_workspaces", "report_artifacts", "workspaces", ["workspace_id"], ["id"])
    op.create_foreign_key("fk_report_artifacts_created_by_user_id_platform_users", "report_artifacts", "platform_users", ["created_by_user_id"], ["id"])
    op.create_index("ix_report_artifacts_workspace_id", "report_artifacts", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_report_artifacts_workspace_id", table_name="report_artifacts")
    op.drop_constraint("fk_report_artifacts_created_by_user_id_platform_users", "report_artifacts", type_="foreignkey")
    op.drop_constraint("fk_report_artifacts_workspace_id_workspaces", "report_artifacts", type_="foreignkey")
    op.drop_column("report_artifacts", "created_by_user_id")
    op.drop_column("report_artifacts", "workspace_id")

    op.drop_index("ix_findings_workspace_id", table_name="findings")
    op.drop_constraint("fk_findings_workspace_id_workspaces", "findings", type_="foreignkey")
    op.drop_column("findings", "workspace_id")

    op.drop_index("ix_evidence_artifacts_workspace_id", table_name="evidence_artifacts")
    op.drop_constraint("fk_evidence_artifacts_created_by_user_id_platform_users", "evidence_artifacts", type_="foreignkey")
    op.drop_constraint("fk_evidence_artifacts_workspace_id_workspaces", "evidence_artifacts", type_="foreignkey")
    op.drop_column("evidence_artifacts", "created_by_user_id")
    op.drop_column("evidence_artifacts", "workspace_id")

    op.drop_index("ix_scans_workspace_id", table_name="scans")
    op.drop_constraint("fk_scans_created_by_user_id_platform_users", "scans", type_="foreignkey")
    op.drop_constraint("fk_scans_workspace_id_workspaces", "scans", type_="foreignkey")
    op.drop_column("scans", "created_by_user_id")
    op.drop_column("scans", "workspace_id")

    op.drop_index("ix_targets_workspace_id", table_name="targets")
    op.drop_constraint("fk_targets_created_by_user_id_platform_users", "targets", type_="foreignkey")
    op.drop_column("targets", "created_by_user_id")
    op.alter_column("targets", "workspace_id", existing_type=sa.String(length=64), nullable=True, server_default=None)

    op.drop_index("ix_auth_profiles_workspace_id", table_name="auth_profiles")
    op.drop_constraint("fk_auth_profiles_created_by_user_id_platform_users", "auth_profiles", type_="foreignkey")
    op.drop_column("auth_profiles", "created_by_user_id")
    op.alter_column("auth_profiles", "workspace_id", existing_type=sa.String(length=64), nullable=True, server_default=None)

    op.drop_constraint("fk_workspaces_owner_user_id_platform_users", "workspaces", type_="foreignkey")
    op.drop_column("workspaces", "owner_user_id")
    op.drop_table("auth_identities")
    op.drop_table("platform_users")
