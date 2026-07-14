"""ScopeHarbor public-readiness schema and legacy cleanup.

Revision ID: 0009_public_readiness
Revises: 0008_platform_ops
Create Date: 2026-07-13
"""
from __future__ import annotations

import re
from typing import Sequence, Union
from urllib.parse import urlsplit, urlunsplit

from alembic import context, op
import sqlalchemy as sa


revision: str = "0009_public_readiness"
down_revision: Union[str, None] = "0008_platform_ops"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"(?i)(cookie|set-cookie|api[-_]?key|access[-_]?token|password|secret)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\b(?:raw|live|prod|production|demo|test)[-_](?:secret|token|api[-_]?key)(?:[-_][a-z0-9]{3,})*\b"),
)


def upgrade() -> None:
    op.alter_column("auth_profiles", "encrypted_secret", existing_type=sa.Text(), nullable=True)
    op.add_column("auth_profiles", sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("auth_profiles", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("auth_profiles", sa.Column("revoked_by_user_id", sa.String(length=64), nullable=True))
    op.add_column("auth_profiles", sa.Column("rotation_count", sa.Integer(), server_default="0", nullable=False))
    op.create_foreign_key(
        "fk_auth_profiles_revoked_by_user_id", "auth_profiles", "platform_users", ["revoked_by_user_id"], ["id"]
    )

    op.add_column("targets", sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("targets", sa.Column("auth_profile_attached_at", sa.DateTime(timezone=True), nullable=True))

    op.add_column("scans", sa.Column("lease_owner", sa.String(length=120), nullable=True))
    op.add_column("scans", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("lease_heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False))
    op.create_check_constraint("ck_scans_progress_percent", "scans", "progress_percent >= 0 AND progress_percent <= 100")
    op.create_index("ix_scans_workspace_created_id", "scans", ["workspace_id", "created_at", "id"])
    op.create_index("ix_scans_status_lease", "scans", ["status", "lease_expires_at"])

    op.create_table(
        "scanner_tool_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("workspace_id", sa.String(length=64), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column("tool_version", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("warning_code", sa.String(length=100), nullable=True),
        sa.Column("finding_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("finding_count >= 0", name="ck_scanner_tool_runs_finding_count"),
        sa.UniqueConstraint("scan_id", "tool_name", name="uq_scanner_tool_runs_scan_tool"),
    )
    op.create_index("ix_scanner_tool_runs_workspace_scan", "scanner_tool_runs", ["workspace_id", "scan_id"])

    if not context.is_offline_mode():
        connection = op.get_bind()
        connection.execute(sa.text("UPDATE scans SET error_detail = NULL WHERE error_detail IS NOT NULL"))
        connection.execute(
            sa.text("UPDATE targets SET authorization_confirmed_at = created_at WHERE permission_confirmed = true AND authorization_confirmed_at IS NULL")
        )
        connection.execute(
            sa.text("UPDATE targets SET auth_profile_attached_at = created_at WHERE auth_profile_id IS NOT NULL AND auth_profile_attached_at IS NULL")
        )
        connection.execute(
            sa.text(
                "UPDATE targets SET repo_path = NULL WHERE repo_path LIKE '/%' "
                "OR repo_path ~ '(^|/)\\.\\.(/|$)' OR position(E'\\\\' in repo_path) > 0"
            )
        )
        _sanitize_existing_findings(connection)
        _remove_stub_results(connection)
        connection.execute(
            sa.text(
                "UPDATE scans SET status = 'failed', error_code = 'retired_profile', error_detail = NULL, "
                "status_message = 'This historical AJAX profile was retired; create a modern-web-crawl scan.', "
                "completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP) "
                "WHERE mode = 'ajax_short' AND status NOT IN ('completed','completed_with_warnings','failed','cancelled')"
            )
        )


def _sanitize_existing_findings(connection: sa.Connection) -> None:
    rows = connection.execute(
        sa.text(
            "SELECT id, affected_url, title, evidence, reproduction_steps, remediation, false_positive_notes FROM findings"
        )
    ).mappings()
    for row in rows:
        values = {field: _safe_text(row[field], 16_384) for field in ("title", "evidence", "reproduction_steps", "remediation", "false_positive_notes")}
        values["affected_url"] = _safe_url(row["affected_url"])
        values["id"] = row["id"]
        connection.execute(
            sa.text(
                "UPDATE findings SET affected_url=:affected_url, title=:title, evidence=:evidence, "
                "reproduction_steps=:reproduction_steps, remediation=:remediation, "
                "false_positive_notes=:false_positive_notes, redaction_applied=true WHERE id=:id"
            ),
            values,
        )


def _remove_stub_results(connection: sa.Connection) -> None:
    affected = [
        row[0]
        for row in connection.execute(
            sa.text("SELECT DISTINCT scan_id FROM findings WHERE source_tool IN ('gitleaks-stub','dependency-stub','repo-stub')")
        )
    ]
    if not affected:
        return
    params = {f"id_{index}": scan_id for index, scan_id in enumerate(affected)}
    placeholders = ",".join(f":id_{index}" for index in range(len(affected)))
    connection.execute(
        sa.text(f"DELETE FROM finding_occurrence_states WHERE finding_id IN (SELECT id FROM findings WHERE scan_id IN ({placeholders}))"), params
    )
    connection.execute(sa.text(f"DELETE FROM findings WHERE scan_id IN ({placeholders})"), params)
    connection.execute(sa.text(f"DELETE FROM report_artifacts WHERE scan_id IN ({placeholders})"), params)
    connection.execute(sa.text(f"DELETE FROM risk_scores WHERE scan_id IN ({placeholders})"), params)
    connection.execute(
        sa.text(
            f"UPDATE scans SET status='completed_with_warnings', status_message='Legacy deterministic results were removed; rerun with real repository tools.', "
            f"error_code='legacy_repo_results_removed', error_detail=NULL WHERE id IN ({placeholders})"
        ),
        params,
    )


def _safe_url(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if not parsed.scheme or not host:
        return _safe_text(value.split("?", 1)[0].split("#", 1)[0], 2048)
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme.lower(), f"{host.lower()}{port}", parsed.path or "/", "", ""))[:2048]


def _safe_text(value: object, maximum: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]", text)
    return text.replace("\x00", "")[:maximum]


def downgrade() -> None:
    op.drop_index("ix_scanner_tool_runs_workspace_scan", table_name="scanner_tool_runs")
    op.drop_table("scanner_tool_runs")
    op.drop_index("ix_scans_status_lease", table_name="scans")
    op.drop_index("ix_scans_workspace_created_id", table_name="scans")
    op.drop_constraint("ck_scans_progress_percent", "scans", type_="check")
    op.drop_column("scans", "attempt_count")
    op.drop_column("scans", "lease_heartbeat_at")
    op.drop_column("scans", "lease_expires_at")
    op.drop_column("scans", "lease_owner")
    op.drop_column("targets", "auth_profile_attached_at")
    op.drop_column("targets", "authorization_confirmed_at")
    op.drop_constraint("fk_auth_profiles_revoked_by_user_id", "auth_profiles", type_="foreignkey")
    op.drop_column("auth_profiles", "rotation_count")
    op.drop_column("auth_profiles", "revoked_by_user_id")
    op.drop_column("auth_profiles", "revoked_at")
    op.drop_column("auth_profiles", "rotated_at")
    op.alter_column("auth_profiles", "encrypted_secret", existing_type=sa.Text(), nullable=False)
