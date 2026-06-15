from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://security_audit:security_audit@postgres:5432/security_audit"
    allowlist_path: str = "/app/config/scan-allowlist.yml"
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

