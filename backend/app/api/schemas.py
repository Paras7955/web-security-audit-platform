from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    target_id: str = Field(min_length=1, max_length=64)
    mode: str = Field(default="passive", max_length=40)


class ScanRead(BaseModel):
    id: str
    target_id: str
    mode: str
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


class TargetCreate(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    permission_confirmed: bool
    repo_path: str | None = Field(default=None, max_length=2048)
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
