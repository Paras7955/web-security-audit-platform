from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


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

