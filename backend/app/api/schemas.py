from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    target_id: str = Field(min_length=1, max_length=64)
    scan_profile_id: str = Field(min_length=1, max_length=80)
    acknowledgements: set[str] = Field(default_factory=set, max_length=20)


class ScanFailureRead(BaseModel):
    code: str
    message: str


class ScanRead(BaseModel):
    id: str
    target_id: str
    scan_profile_id: str
    status: str
    current_step: str | None
    status_message: str | None
    progress_percent: int
    started_at: datetime | None
    completed_at: datetime | None
    cancellation_requested_at: datetime | None
    failure: ScanFailureRead | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingRead(BaseModel):
    id: str
    scan_id: str
    target_id: str | None = None
    title: str
    severity: str
    confidence: str
    affected_url: str | None
    affected_file: str | None
    evidence: str | None
    source_tool: str
    scanner_rule_id: str | None
    dedupe_key: str
    owasp_category: str | None
    cwe: str | None
    reproduction_steps: str | None
    remediation: str | None
    false_positive_notes: str | None
    lifecycle_status: str = "open"
    suppressed: bool = False
    suppression_rule_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingLifecycleUpdate(BaseModel):
    lifecycle_status: str = Field(min_length=1, max_length=40)


class SuppressionRuleCreate(BaseModel):
    target_id: str = Field(min_length=1, max_length=64)
    dedupe_key: str | None = Field(default=None, max_length=500)
    severity: str | None = Field(default=None, max_length=40)
    source_tool: str | None = Field(default=None, max_length=100)
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime | None = None


class SuppressionRuleRead(BaseModel):
    id: str
    target_id: str
    dedupe_key: str | None
    severity: str | None
    source_tool: str | None
    reason: str
    created_by_user_id: str
    expires_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TagCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class TagRead(BaseModel):
    id: str
    label: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TagAssignmentCreate(BaseModel):
    tag_id: str = Field(min_length=1, max_length=64)
    resource_type: str = Field(min_length=1, max_length=40)
    resource_id: str = Field(min_length=1, max_length=64)


class TagAssignmentRead(BaseModel):
    id: str
    tag_id: str
    resource_type: str
    resource_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportArtifactRead(BaseModel):
    id: str
    scan_id: str
    report_type: str
    view_url: str
    download_url: str
    created_at: datetime


class AiExplanationGroupRead(BaseModel):
    label: str
    count: int
    finding_ids: list[str]


class FindingExplanationRead(BaseModel):
    finding_id: str
    priority: int
    summary: str
    why_it_matters: str
    recommended_action: str
    owasp_mapping: str
    limitations: str


class AiExplanationRead(BaseModel):
    scan_id: str
    provider: str
    fallback_used: bool
    provider_error_code: str | None
    summary: str
    executive_summary: str
    risk_score_explanation: str
    scoring_model_version: str
    input_fingerprint: str | None
    cache_hit: bool
    groups: list[AiExplanationGroupRead]
    explanations: list[FindingExplanationRead]


class AuditLogRead(BaseModel):
    id: str
    event_type: str
    resource_type: str | None
    resource_id: str | None
    metadata_json: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HealthComponentRead(BaseModel):
    status: str
    detail: str | None = None


class PlatformHealthRead(BaseModel):
    status: str
    database: HealthComponentRead
    worker: HealthComponentRead
    queue_depth: int
    zap: HealthComponentRead
    artifact_root: HealthComponentRead


class TargetCreate(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    permission_confirmed: bool
    repo_path: str | None = Field(default=None, max_length=2048)
    auth_profile_id: str | None = Field(default=None, max_length=64)


class TargetRepoPathUpdate(BaseModel):
    repo_path: str | None = Field(default=None, max_length=2048)


class TargetAuthProfileUpdate(BaseModel):
    auth_profile_id: str | None = Field(default=None, max_length=64)


class TargetRead(BaseModel):
    id: str
    allowlist_id: str
    name: str
    base_url: str
    permission_confirmed: bool
    has_repo_path: bool
    auth_profile_id: str | None
    allowed_modes: list[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetValidationRead(BaseModel):
    allowlist_id: str
    name: str
    base_url: str
    allowed_modes: list[str]
    max_redirects: int
    local_demo: bool


class AuthProfileCreate(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    profile_type: str = Field(min_length=1, max_length=40)
    header_name: str | None = Field(default=None, max_length=120)
    secret: str = Field(min_length=1, max_length=4096)


class AuthProfileRead(BaseModel):
    id: str
    label: str
    profile_type: str
    header_name: str | None
    secret_hint: str
    status: str
    rotated_at: datetime | None
    revoked_at: datetime | None
    rotation_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthProfileRotate(BaseModel):
    secret: str = Field(min_length=1, max_length=4096)


class ScannerToolRunRead(BaseModel):
    id: str
    scan_id: str
    tool_name: str
    tool_version: str | None
    status: str
    warning_code: str | None
    finding_count: int
    started_at: datetime | None
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


PageItem = TypeVar("PageItem")


class CursorPage(BaseModel, Generic[PageItem]):
    items: list[PageItem]
    next_cursor: str | None


class RiskScoreRead(BaseModel):
    id: str
    target_id: str
    scan_id: str | None
    scoring_model_version: str
    score: int
    label: str
    input_summary: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DashboardScanSummaryRead(BaseModel):
    id: str
    target_id: str
    target_name: str
    scan_profile_id: str
    mode: str
    status: str
    created_at: datetime
    completed_at: datetime | None
    risk_score: RiskScoreRead | None


class DashboardOverviewRead(BaseModel):
    targets_count: int
    scans_count: int
    completed_scans_count: int
    findings_count: int
    severity_counts: dict[str, int]
    latest_risk_score: RiskScoreRead | None
    recent_scans: list[DashboardScanSummaryRead]


class TargetDashboardRead(BaseModel):
    target_id: str
    target_name: str
    base_url: str
    scan_count: int
    completed_scan_count: int
    findings_count: int
    severity_counts: dict[str, int]
    latest_risk_score: RiskScoreRead | None
    recent_scans: list[DashboardScanSummaryRead]


class FindingChangeRead(BaseModel):
    dedupe_key: str
    title: str
    source_tool: str
    location: str | None
    previous_severity: str | None = None
    current_severity: str | None = None


class ScanComparisonRead(BaseModel):
    target_id: str
    baseline_scan_id: str
    comparison_scan_id: str
    scoring_model_version: str
    baseline_score: RiskScoreRead
    comparison_score: RiskScoreRead
    score_delta: int
    new_findings: list[FindingChangeRead]
    resolved_findings: list[FindingChangeRead]
    unchanged_findings: list[FindingChangeRead]
    severity_changed_findings: list[FindingChangeRead]
