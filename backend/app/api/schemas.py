from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    target_id: str = Field(min_length=1, max_length=64)
    scan_profile_id: str | None = Field(default=None, max_length=80)
    mode: str | None = Field(default=None, max_length=40)
    active_demo_acknowledged: bool = False
    ajax_short_acknowledged: bool = False


class ScanRead(BaseModel):
    id: str
    target_id: str
    auth_profile_id: str | None
    mode: str
    scan_profile_id: str
    status: str
    current_step: str | None
    status_message: str | None
    progress_percent: int
    started_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    error_detail: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingRead(BaseModel):
    id: str
    scan_id: str
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
    redaction_applied: bool
    raw_artifact_ref: str | None
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
    provider_error: str | None
    summary: str
    groups: list[AiExplanationGroupRead]
    explanations: list[FindingExplanationRead]


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
    repo_path: str | None
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
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
