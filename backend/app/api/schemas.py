from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.contracts import CONTRACTS
from app.security.sanitization import sanitize_metadata


def _known_acknowledgements() -> set[str]:
    raw_codes = CONTRACTS.get("acknowledgement_codes")
    if not isinstance(raw_codes, dict):
        raise RuntimeError("Shared acknowledgement codes must be an object.")
    known: set[str] = set()
    for codes in raw_codes.values():
        if not isinstance(codes, list):
            raise RuntimeError("Shared acknowledgement code groups must be arrays.")
        known.update(str(code) for code in codes)
    return known


KNOWN_ACKNOWLEDGEMENTS = _known_acknowledgements()


class ScanCreate(BaseModel):
    target_id: str | None = Field(default=None, min_length=1, max_length=64)
    repository_asset_id: str | None = Field(default=None, min_length=1, max_length=64)
    scan_profile_id: str = Field(min_length=1, max_length=80)
    acknowledgements: set[str] = Field(max_length=20)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_subject(self) -> "ScanCreate":
        if (self.target_id is None) == (self.repository_asset_id is None):
            raise ValueError("Provide exactly one of target_id or repository_asset_id.")
        return self

    @field_validator("acknowledgements")
    @classmethod
    def validate_acknowledgements(cls, values: set[str]) -> set[str]:
        normalized = {value.strip() for value in values}
        if any(not value or len(value) > 80 for value in normalized):
            raise ValueError("Acknowledgement codes must be non-empty and at most 80 characters.")
        unknown = sorted(normalized - KNOWN_ACKNOWLEDGEMENTS)
        if unknown:
            raise ValueError("Unknown acknowledgement code.")
        return normalized


class ScanFailureRead(BaseModel):
    code: str
    message: str


class ScanRead(BaseModel):
    id: str
    target_id: str | None
    repository_asset_id: str | None = None
    subject_type: str = "web_target"
    subject_id: str
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
    repository_asset_id: str | None = None
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
    target_id: str | None = Field(default=None, min_length=1, max_length=64)
    repository_asset_id: str | None = Field(default=None, min_length=1, max_length=64)
    dedupe_key: str | None = Field(default=None, max_length=500)
    severity: str | None = Field(default=None, max_length=40)
    source_tool: str | None = Field(default=None, max_length=100)
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_subject(self) -> "SuppressionRuleCreate":
        if (self.target_id is None) == (self.repository_asset_id is None):
            raise ValueError("Provide exactly one of target_id or repository_asset_id.")
        return self


class SuppressionRuleRead(BaseModel):
    id: str
    target_id: str | None
    repository_asset_id: str | None = None
    dedupe_key: str | None
    severity: str | None
    source_tool: str | None
    reason: str
    created_by_user_id: str
    expires_at: datetime | None
    revoked_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TagCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class TagRead(BaseModel):
    id: str
    label: str
    created_at: datetime
    archived_at: datetime | None = None

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

    @field_validator("metadata_json", mode="before")
    @classmethod
    def safe_metadata(cls, value: object) -> dict[str, Any]:
        sanitized = sanitize_metadata(value)
        if not isinstance(sanitized, dict):
            return {}
        forbidden = {
            "mode",
            "cancelled_by_user_id",
            "cancellation_requested_by_user_id",
            "error_detail",
            "failure_detail",
            "raw_error",
            "repo_path",
            "artifact_path",
            "traceback",
        }
        return {str(key): item for key, item in sanitized.items() if str(key).lower() not in forbidden}


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


class TargetValidationCreate(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)


class TargetReauthorize(BaseModel):
    permission_confirmed: bool


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
    available_scan_profile_ids: list[str]
    zap_required_scan_profile_ids: list[str]
    connection_class: str
    scope_path: str
    tls_trust: str
    policy_status: str
    policy_fingerprint: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetValidationRead(BaseModel):
    allowlist_id: str
    name: str
    base_url: str
    available_scan_profile_ids: list[str]
    zap_required_scan_profile_ids: list[str]
    max_redirects: int
    local_demo: bool
    connection_class: str
    scope_path: str
    tls_trust: str
    policy_fingerprint: str


class TargetPolicyRead(BaseModel):
    allowlist_id: str
    name: str
    base_url: str
    connection_class: str
    scope_path: str
    tls_trust: str
    available_scan_profile_ids: list[str]
    zap_required_scan_profile_ids: list[str]
    max_redirects: int
    disposable_demo: bool
    policy_fingerprint: str


class RepositoryAssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    repo_path: str = Field(min_length=1, max_length=2048)
    permission_confirmed: bool


class RepositoryAssetRead(BaseModel):
    id: str
    name: str
    relative_path: str
    permission_confirmed: bool
    authorization_confirmed_at: datetime | None
    archived_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


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


class CursorPage[PageItem](BaseModel):
    items: list[PageItem]
    next_cursor: str | None


class RiskScoreRead(BaseModel):
    id: str
    target_id: str | None
    repository_asset_id: str | None = None
    scan_id: str | None
    scoring_model_version: str
    score: int
    label: str
    input_summary: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("input_summary", mode="before")
    @classmethod
    def safe_input_summary(cls, value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        allowed = {
            "finding_count",
            "severity_counts",
            "confidence_counts",
            "weighted_total",
            "scan_profile_id",
        }
        return {str(key): item for key, item in value.items() if key in allowed}


class DashboardScanSummaryRead(BaseModel):
    id: str
    target_id: str | None
    repository_asset_id: str | None = None
    subject_type: str = "web_target"
    subject_id: str
    target_name: str
    scan_profile_id: str
    status: str
    created_at: datetime
    completed_at: datetime | None
    risk_score: RiskScoreRead | None


class DashboardOverviewRead(BaseModel):
    targets_count: int
    repository_assets_count: int = 0
    scans_count: int
    completed_scans_count: int
    findings_count: int
    severity_counts: dict[str, int]
    latest_risk_score: RiskScoreRead | None
    recent_scans: list[DashboardScanSummaryRead]
    posture_basis: str = "latest completed scan per subject and profile"
    current_posture_score: RiskScoreRead | None = None
    historical_findings_count: int = 0
    historical_severity_counts: dict[str, int] = Field(default_factory=dict)


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
    posture_basis: str = "latest completed scan per subject and profile"
    current_posture_score: RiskScoreRead | None = None
    historical_findings_count: int = 0
    historical_severity_counts: dict[str, int] = Field(default_factory=dict)


class RepositoryDashboardRead(BaseModel):
    repository_asset_id: str
    repository_asset_name: str
    relative_path: str
    scan_count: int
    completed_scan_count: int
    findings_count: int
    severity_counts: dict[str, int]
    latest_risk_score: RiskScoreRead | None
    recent_scans: list[DashboardScanSummaryRead]
    posture_basis: str = "latest completed scan per subject and profile"
    current_posture_score: RiskScoreRead | None = None
    historical_findings_count: int = 0
    historical_severity_counts: dict[str, int] = Field(default_factory=dict)


class FindingChangeRead(BaseModel):
    dedupe_key: str
    title: str
    source_tool: str
    location: str | None
    previous_severity: str | None = None
    current_severity: str | None = None


class ScanComparisonRead(BaseModel):
    target_id: str | None
    repository_asset_id: str | None = None
    subject_type: str = "web_target"
    subject_id: str
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
