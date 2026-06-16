from pydantic import BaseModel, Field, field_validator

from app.core.contracts import Confidence, Severity


class EvidenceArtifactInput(BaseModel):
    artifact_type: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=2048)
    redaction_applied: bool = True


class NormalizedFindingInput(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    confidence: Confidence
    affected_url: str | None = Field(default=None, max_length=2048)
    affected_file: str | None = Field(default=None, max_length=2048)
    evidence: str | None = None
    source_tool: str = Field(min_length=1, max_length=100)
    scanner_rule_id: str | None = Field(default=None, max_length=200)
    dedupe_key: str | None = Field(default=None, max_length=500)
    owasp_category: str | None = Field(default=None, max_length=100)
    cwe: str | None = Field(default=None, max_length=100)
    reproduction_steps: str | None = None
    remediation: str | None = None
    false_positive_notes: str | None = None
    redaction_applied: bool | None = None
    raw_artifact: EvidenceArtifactInput | None = None

    @field_validator("title", "source_tool")
    @classmethod
    def strip_required_fields(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

