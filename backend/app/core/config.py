from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import field_validator
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
    dev_auth_token: str = "dev-token"  # noqa: S105 - known sentinel rejected outside explicit local mode
    dev_auth_user_id: str = "dev-user"
    dev_auth_workspace_id: str = "dev-workspace"
    dev_auth_subject: str = "dev-user"
    auth_profile_secret_key: str = ""
    auth_profile_previous_secret_key: str | None = None
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
    demo_seed_enabled: bool = False
    openai_model: str | None = None
    openai_api_key: str | None = None
    zap_base_url: str = "http://zap:8080"
    zap_api_key: str = ""
    cors_origins: list[str] = ["http://localhost:3001"]
    trusted_hosts: list[str] = ["localhost", "127.0.0.1", "testserver", "backend"]
    trusted_proxy_ips: list[str] = []
    max_request_body_bytes: int = 1_048_576
    page_default_limit: int = 50
    page_max_limit: int = 200
    ai_max_findings: int = 100
    ai_max_payload_bytes: int = 131_072
    repo_max_files: int = 20_000
    repo_max_file_bytes: int = 20 * 1024 * 1024
    repo_max_total_bytes: int = 512 * 1024 * 1024
    repo_tool_timeout_seconds: int = 120
    repo_tool_output_bytes: int = 10 * 1024 * 1024
    repo_tool_max_findings: int = 1_000
    repo_staging_root: str = "/tmp/scopeharbor-repo-staging"  # noqa: S108 - 0700 bounded tmpfs in the worker
    gitleaks_binary: str = "gitleaks"
    gitleaks_config_path: str = "/app/config/gitleaks.toml"
    osv_scanner_binary: str = "osv-scanner"
    osv_config_path: str = "/app/config/osv-scanner.toml"
    osv_database_path: str = "/var/lib/osv-scanner"
    osv_database_max_age_days: int = 7
    worker_lease_seconds: int = 45
    scan_relay_url: str | None = None
    scan_relay_secret: str = ""
    scan_relay_request_timeout_seconds: int = 10
    scan_relay_body_bytes: int = 65_536

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
                raise ValueError("CORS_ORIGINS must contain exact HTTP(S) origins without paths")
            if "*" in origin or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("CORS_ORIGINS cannot contain wildcards, credentials, queries, or fragments")
        return origins

    @field_validator("trusted_hosts")
    @classmethod
    def validate_trusted_hosts(cls, hosts: list[str]) -> list[str]:
        if not hosts or any(not host or "*" in host or "/" in host for host in hosts):
            raise ValueError("TRUSTED_HOSTS must contain exact host names")
        return hosts

    @field_validator("trusted_proxy_ips")
    @classmethod
    def validate_trusted_proxy_ips(cls, proxies: list[str]) -> list[str]:
        normalized: list[str] = []
        for proxy in proxies:
            try:
                normalized.append(ip_address(proxy.strip()).compressed)
            except ValueError as exc:
                raise ValueError("TRUSTED_PROXY_IPS must contain exact IP addresses") from exc
        if len(normalized) != len(set(normalized)):
            raise ValueError("TRUSTED_PROXY_IPS cannot contain duplicates")
        return normalized


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
