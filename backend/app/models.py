from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
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
    mode: Mapped[str] = mapped_column(String(40), nullable=False)
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
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
