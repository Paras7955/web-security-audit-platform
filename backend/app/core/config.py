from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://security_audit:security_audit@postgres:5432/security_audit"
    allowlist_path: str = str(REPO_ROOT / "config" / "scan-allowlist.yml")
    artifact_root: str = "/app/artifacts"
    ai_provider: str = "template"
    openai_model: str | None = None
    openai_api_key: str | None = None
    zap_base_url: str = "http://zap:8080"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
