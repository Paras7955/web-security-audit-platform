from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def default_allowlist_path() -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "config" / "scan-allowlist.yml"
        if candidate.exists():
            return str(candidate)
    return "config/scan-allowlist.yml"


class Settings(BaseSettings):
    app_env: str = "local"
    database_url: str = "postgresql+psycopg://security_audit:security_audit@postgres:5432/security_audit"
    allowlist_path: str = default_allowlist_path()
    artifact_root: str = "/app/artifacts"
    repo_scan_root: str = "/app/repositories"
    auth_mode: str = "dev"
    auth_provider: str = "dev"
    auth_oidc_issuer: str | None = None
    auth_oidc_audience: str | None = None
    auth_oidc_jwks_url: str | None = None
    dev_auth_token: str = "dev-token"
    dev_auth_user_id: str = "dev-user"
    dev_auth_workspace_id: str = "dev-workspace"
    dev_auth_subject: str = "dev-user"
    auth_profile_secret_key: str = ""
    ai_provider: str = "template"
    ai_rate_limit_window_seconds: int = 3600
    ai_rate_limit_max_requests: int = 20
    ai_cache_enabled: bool = True
    api_rate_limit_window_seconds: int = 3600
    scan_create_rate_limit_max_requests: int = 1000
    report_generation_rate_limit_max_requests: int = 200
    health_zap_timeout_seconds: float = 1.5
    worker_id: str = "default-worker"
    worker_stale_after_seconds: int = 30
    openai_model: str | None = None
    openai_api_key: str | None = None
    zap_base_url: str = "http://zap:8080"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
