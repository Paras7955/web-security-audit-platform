from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


LEGACY_USER_ID = "legacy-dev-user"
LEGACY_WORKSPACE_ID = "legacy-dev-workspace"


class PlatformUser(Base):
    __tablename__ = "platform_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthIdentity(Base):
    __tablename__ = "auth_identities"
    __table_args__ = (UniqueConstraint("provider", "provider_subject", name="uq_auth_identities_provider_subject"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    provider_subject: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


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
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthProfile(Base):
    __tablename__ = "auth_profiles"

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
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    secret_hint: Mapped[str] = mapped_column(String(80), nullable=False, default="", server_default="")
    created_by_user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("platform_users.id"),
        nullable=False,
        default=LEGACY_USER_ID,
        server_default=LEGACY_USER_ID,
    )
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Target(Base):
    __tablename__ = "targets"

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
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

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
    target_id: Mapped[str] = mapped_column(String(64), ForeignKey("targets.id"), nullable=False)
    auth_profile_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("auth_profiles.id"), nullable=True)
    mode: Mapped[str] = mapped_column(String(40), nullable=False)
    scan_profile_id: Mapped[str] = mapped_column(String(80), nullable=False, default="passive-web", server_default="passive-web")
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    current_step: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    target: Mapped[Target] = relationship(back_populates="scans")


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

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
    artifact_type: Mapped[str] = mapped_column(String(80), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    redaction_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Finding(Base):
    __tablename__ = "findings"

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
    raw_artifact_ref: Mapped[str | None] = mapped_column(String(64), ForeignKey("evidence_artifacts.id"), nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FindingState(Base):
    __tablename__ = "finding_states"
    __table_args__ = (UniqueConstraint("workspace_id", "target_id", "dedupe_key", name="uq_finding_states_identity"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), ForeignKey("targets.id"), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(500), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(40), nullable=False, default="open", server_default="open")
    updated_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), ForeignKey("targets.id"), nullable=False)
    dedupe_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FindingOccurrenceState(Base):
    __tablename__ = "finding_occurrence_states"
    __table_args__ = (UniqueConstraint("finding_id", name="uq_finding_occurrence_states_finding"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id"), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(40), nullable=False, default="open", server_default="open")
    suppressed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    suppression_rule_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("suppression_rules.id"), nullable=True)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("workspace_id", "label", name="uq_tags_workspace_label"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(80), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TagAssignment(Base):
    __tablename__ = "tag_assignments"
    __table_args__ = (UniqueConstraint("workspace_id", "tag_id", "resource_type", "resource_id", name="uq_tag_assignments_resource"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    tag_id: Mapped[str] = mapped_column(String(64), ForeignKey("tags.id"), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"

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
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AiRequestLog(Base):
    __tablename__ = "ai_request_logs"

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
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


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
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("platform_users.id"), nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (UniqueConstraint("workspace_id", "target_id", "scan_id", "scoring_model_version", name="uq_risk_scores_scan_model"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), ForeignKey("workspaces.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), ForeignKey("targets.id"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("scans.id"), nullable=True)
    scoring_model_version: Mapped[str] = mapped_column(String(40), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String(40), nullable=False)
    input_summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
