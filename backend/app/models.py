from datetime import datetime

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

LEGACY_USER_ID = "legacy-dev-user"
LEGACY_WORKSPACE_ID = "legacy-dev-workspace"


class PlatformUser(Base):
    __tablename__ = "platform_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthIdentity(Base):
    __tablename__ = "auth_identities"
    __table_args__ = (UniqueConstraint("provider", "provider_subject", name="uq_auth_identities_provider_subject"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    provider_subject: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("platform_users.id"),
        nullable=False,
        default=LEGACY_USER_ID,
        server_default=LEGACY_USER_ID,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthProfile(Base):
    __tablename__ = "auth_profiles"
    __table_args__ = (
        CheckConstraint("rotation_count >= 0", name="ck_auth_profiles_rotation_count"),
        Index("ix_auth_profiles_workspace_id", "workspace_id"),
        Index("ix_auth_profiles_workspace_created_id", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id"),
        nullable=False,
        default=LEGACY_WORKSPACE_ID,
        server_default=LEGACY_WORKSPACE_ID,
    )
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    profile_type: Mapped[str] = mapped_column(String(40), nullable=False, default="bearer_token", server_default="bearer_token")
    header_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True, default="")
    secret_hint: Mapped[str] = mapped_column(String(80), nullable=False, default="", server_default="")
    created_by_user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("platform_users.id"),
        nullable=False,
        default=LEGACY_USER_ID,
        server_default=LEGACY_USER_ID,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    rotation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        Index("ix_targets_workspace_id", "workspace_id"),
        Index("ix_targets_workspace_created_id", "workspace_id", "created_at", "id"),
        Index("ix_targets_workspace_active_created_id", "workspace_id", "archived_at", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id"),
        nullable=False,
        default=LEGACY_WORKSPACE_ID,
        server_default=LEGACY_WORKSPACE_ID,
    )
    allowlist_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    policy_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_scope_base_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    permission_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    repo_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    auth_profile_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("auth_profiles.id"), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("platform_users.id"),
        nullable=False,
        default=LEGACY_USER_ID,
        server_default=LEGACY_USER_ID,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    auth_profile_attached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target")


class RepositoryAsset(Base):
    __tablename__ = "repository_assets"
    __table_args__ = (
        UniqueConstraint("workspace_id", "relative_path", name="uq_repository_assets_workspace_path"),
        Index("ix_repository_assets_workspace_created_id", "workspace_id", "created_at", "id"),
        Index("ix_repository_assets_workspace_active", "workspace_id", "archived_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    permission_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)

    scans: Mapped[list["Scan"]] = relationship(back_populates="repository_asset")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("progress_percent >= 0 AND progress_percent <= 100", name="ck_scans_progress_percent"),
        CheckConstraint("attempt_count >= 0", name="ck_scans_attempt_count"),
        CheckConstraint(
            "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
            name="ck_scans_exactly_one_subject",
        ),
        Index("ix_scans_workspace_id", "workspace_id"),
        Index("ix_scans_scan_profile_id", "scan_profile_id"),
        Index("ix_scans_auth_profile_id", "auth_profile_id"),
        Index("ix_scans_repository_asset_id", "repository_asset_id"),
        Index("ix_scans_workspace_created_id", "workspace_id", "created_at", "id"),
        Index("ix_scans_status_lease", "status", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id"),
        nullable=False,
        default=LEGACY_WORKSPACE_ID,
        server_default=LEGACY_WORKSPACE_ID,
    )
    created_by_user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("platform_users.id"),
        nullable=False,
        default=LEGACY_USER_ID,
        server_default=LEGACY_USER_ID,
    )
    target_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("targets.id"), nullable=True)
    repository_asset_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("repository_assets.id"), nullable=True)
    repo_path_snapshot: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    target_policy_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acknowledgements_snapshot: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list, server_default="[]")
    authorization_snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict, server_default="{}")
    auth_profile_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("auth_profiles.id"), nullable=True)
    mode: Mapped[str] = mapped_column(String(40), nullable=False)
    scan_profile_id: Mapped[str] = mapped_column(String(80), nullable=False, default="passive-web", server_default="passive-web")
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    current_step: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancellation_requested_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    target: Mapped[Target | None] = relationship(back_populates="scans")
    repository_asset: Mapped[RepositoryAsset | None] = relationship(back_populates="scans")


class ScannerToolRun(Base):
    __tablename__ = "scanner_tool_runs"
    __table_args__ = (
        CheckConstraint("finding_count >= 0", name="ck_scanner_tool_runs_finding_count"),
        UniqueConstraint("scan_id", "tool_name", name="uq_scanner_tool_runs_scan_tool"),
        Index("ix_scanner_tool_runs_workspace_scan", "workspace_id", "scan_id"),
        Index("ix_scanner_tool_runs_workspace_scan_created_id", "workspace_id", "scan_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    warning_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_workspace_id", "workspace_id"),
        Index("ix_findings_workspace_created_id", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id"),
        nullable=False,
        default=LEGACY_WORKSPACE_ID,
        server_default=LEGACY_WORKSPACE_ID,
    )
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    affected_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    affected_file: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reproduction_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    redaction_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FindingState(Base):
    __tablename__ = "finding_states"
    __table_args__ = (
        UniqueConstraint("workspace_id", "target_id", "dedupe_key", name="uq_finding_states_identity"),
        UniqueConstraint(
            "workspace_id",
            "repository_asset_id",
            "dedupe_key",
            name="uq_finding_states_repository_identity",
        ),
        CheckConstraint(
            "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
            name="ck_finding_states_exactly_one_subject",
        ),
        Index("ix_finding_states_workspace_target_status", "workspace_id", "target_id", "lifecycle_status"),
        Index(
            "ix_finding_states_workspace_repository_status",
            "workspace_id",
            "repository_asset_id",
            "lifecycle_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("targets.id"), nullable=True)
    repository_asset_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("repository_assets.id"), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(500), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(40), nullable=False, default="open", server_default="open")
    updated_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"
    __table_args__ = (
        Index("ix_suppression_rules_workspace_target", "workspace_id", "target_id"),
        Index("ix_suppression_rules_workspace_repository", "workspace_id", "repository_asset_id"),
        Index("ix_suppression_rules_expires_at", "expires_at"),
        Index("ix_suppression_rules_workspace_created_id", "workspace_id", "created_at", "id"),
        CheckConstraint(
            "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
            name="ck_suppression_rules_exactly_one_subject",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("targets.id"), nullable=True)
    repository_asset_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("repository_assets.id"), nullable=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FindingOccurrenceState(Base):
    __tablename__ = "finding_occurrence_states"
    __table_args__ = (
        UniqueConstraint("finding_id", name="uq_finding_occurrence_states_finding"),
        Index("ix_finding_occurrence_states_workspace", "workspace_id"),
        Index("ix_finding_occurrence_states_suppression", "suppression_rule_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id"), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(40), nullable=False, default="open", server_default="open")
    suppressed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    suppression_rule_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("suppression_rules.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("workspace_id", "label", name="uq_tags_workspace_label"),
        Index("ix_tags_workspace_created_id", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(80), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)


class TagAssignment(Base):
    __tablename__ = "tag_assignments"
    __table_args__ = (
        UniqueConstraint("workspace_id", "tag_id", "resource_type", "resource_id", name="uq_tag_assignments_resource"),
        Index("ix_tag_assignments_workspace_resource", "workspace_id", "resource_type", "resource_id"),
        Index("ix_tag_assignments_workspace_created_id", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    tag_id: Mapped[str] = mapped_column(String(64), ForeignKey("tags.id"), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "scan_id", "report_type", name="uq_report_artifacts_scan_type"),
        Index("ix_report_artifacts_workspace_id", "workspace_id"),
        Index("ix_report_artifacts_workspace_created_id", "workspace_id", "created_at", "id"),
        Index("ix_report_artifacts_workspace_scan_created_id", "workspace_id", "scan_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("workspaces.id"),
        nullable=False,
        default=LEGACY_WORKSPACE_ID,
        server_default=LEGACY_WORKSPACE_ID,
    )
    created_by_user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("platform_users.id"),
        nullable=False,
        default=LEGACY_USER_ID,
        server_default=LEGACY_USER_ID,
    )
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AiRequestLog(Base):
    __tablename__ = "ai_request_logs"
    __table_args__ = (
        Index("ix_ai_request_logs_workspace_action_created", "workspace_id", "action", "created_at"),
        Index("ix_ai_request_logs_user_action_created", "user_id", "action", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AiExplanationCache(Base):
    __tablename__ = "ai_explanation_cache"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "scan_id",
            "action",
            "provider",
            "model",
            "config_hash",
            "input_fingerprint",
            name="uq_ai_explanation_cache_input",
        ),
        Index("ix_ai_explanation_cache_scan", "workspace_id", "scan_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ApiRateLimitLog(Base):
    __tablename__ = "api_rate_limit_logs"
    __table_args__ = (Index("ix_api_rate_limit_logs_window", "workspace_id", "user_id", "action", "created_at"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_workspace_created", "workspace_id", "created_at"),
        Index("ix_audit_logs_workspace_event", "workspace_id", "event_type", "created_at"),
        Index("ix_audit_logs_workspace_resource", "workspace_id", "resource_type", "resource_id"),
        Index("ix_audit_logs_workspace_created_id", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"
    __table_args__ = (
        UniqueConstraint("worker_id", name="uq_worker_heartbeats_worker_id"),
        Index("ix_worker_heartbeats_last_seen", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    worker_id: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(80), nullable=False)
    current_scan_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("scans.id"), nullable=True)
    queue_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    zap_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    zap_detail: Mapped[str | None] = mapped_column(String(160), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        UniqueConstraint("workspace_id", "target_id", "scan_id", "scoring_model_version", name="uq_risk_scores_scan_model"),
        UniqueConstraint(
            "workspace_id",
            "repository_asset_id",
            "scan_id",
            "scoring_model_version",
            name="uq_risk_scores_repository_scan_model",
        ),
        CheckConstraint(
            "(target_id IS NOT NULL) <> (repository_asset_id IS NOT NULL)",
            name="ck_risk_scores_exactly_one_subject",
        ),
        Index("ix_risk_scores_workspace_target", "workspace_id", "target_id"),
        Index("ix_risk_scores_workspace_repository", "workspace_id", "repository_asset_id"),
        Index("ix_risk_scores_scan_id", "scan_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("targets.id"), nullable=True)
    repository_asset_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("repository_assets.id"), nullable=True)
    scan_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("scans.id"), nullable=True)
    scoring_model_version: Mapped[str] = mapped_column(String(40), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String(40), nullable=False)
    input_summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ArtifactCleanupTask(Base):
    __tablename__ = "artifact_cleanup_tasks"
    __table_args__ = (
        UniqueConstraint("scan_id", "action", name="uq_artifact_cleanup_tasks_scan_action"),
        Index("ix_artifact_cleanup_tasks_pending", "completed_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
