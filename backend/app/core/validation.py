from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import Settings, settings
from app.security.allowlist import load_allowlist


class RuntimeConfigurationError(ValueError):
    pass


def validate_runtime_settings(config: Settings = settings) -> None:
    if len(config.zap_api_key) < 32 or config.zap_api_key.lower() in {"changeme", "dev-token", "example"}:
        raise RuntimeConfigurationError("ZAP_API_KEY must be a generated secret with at least 32 characters.")
    zap_url = urlsplit(config.zap_base_url)
    if (
        zap_url.scheme != "http"
        or not zap_url.hostname
        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", zap_url.hostname)
        or zap_url.username
        or zap_url.password
        or zap_url.path not in {"", "/"}
        or zap_url.query
        or zap_url.fragment
    ):
        raise RuntimeConfigurationError("ZAP_BASE_URL must be an exact internal HTTP service URL without credentials.")
    positive_limits = {
        "MAX_REQUEST_BODY_BYTES": config.max_request_body_bytes,
        "PAGE_DEFAULT_LIMIT": config.page_default_limit,
        "PAGE_MAX_LIMIT": config.page_max_limit,
        "AI_MAX_FINDINGS": config.ai_max_findings,
        "AI_MAX_PAYLOAD_BYTES": config.ai_max_payload_bytes,
        "REPO_MAX_FILES": config.repo_max_files,
        "REPO_MAX_FILE_BYTES": config.repo_max_file_bytes,
        "REPO_MAX_TOTAL_BYTES": config.repo_max_total_bytes,
        "REPO_TOOL_TIMEOUT_SECONDS": config.repo_tool_timeout_seconds,
        "REPO_TOOL_OUTPUT_BYTES": config.repo_tool_output_bytes,
        "REPO_TOOL_MAX_FINDINGS": config.repo_tool_max_findings,
        "WORKER_LEASE_SECONDS": config.worker_lease_seconds,
        "WORKER_STALE_AFTER_SECONDS": config.worker_stale_after_seconds,
        "AI_RATE_LIMIT_WINDOW_SECONDS": config.ai_rate_limit_window_seconds,
        "AI_RATE_LIMIT_MAX_REQUESTS": config.ai_rate_limit_max_requests,
        "API_RATE_LIMIT_WINDOW_SECONDS": config.api_rate_limit_window_seconds,
        "SCAN_CREATE_RATE_LIMIT_MAX_REQUESTS": config.scan_create_rate_limit_max_requests,
        "REPORT_GENERATION_RATE_LIMIT_MAX_REQUESTS": config.report_generation_rate_limit_max_requests,
        "OSV_DATABASE_MAX_AGE_DAYS": config.osv_database_max_age_days,
        "SCAN_RELAY_REQUEST_TIMEOUT_SECONDS": config.scan_relay_request_timeout_seconds,
        "SCAN_RELAY_BODY_BYTES": config.scan_relay_body_bytes,
    }
    if any(value < 1 for value in positive_limits.values()):
        invalid = sorted(name for name, value in positive_limits.items() if value < 1)
        raise RuntimeConfigurationError(f"Runtime limits must be positive: {invalid}.")
    if config.page_default_limit > config.page_max_limit or config.page_max_limit > 200:
        raise RuntimeConfigurationError("Pagination limits are invalid.")
    if config.repo_max_file_bytes > config.repo_max_total_bytes:
        raise RuntimeConfigurationError("REPO_MAX_FILE_BYTES cannot exceed REPO_MAX_TOTAL_BYTES.")
    if config.ai_max_payload_bytes > config.max_request_body_bytes:
        raise RuntimeConfigurationError("AI_MAX_PAYLOAD_BYTES cannot exceed MAX_REQUEST_BODY_BYTES.")
    if config.worker_lease_seconds < max(15, config.worker_stale_after_seconds):
        raise RuntimeConfigurationError(
            "WORKER_LEASE_SECONDS must be at least 15 and not shorter than WORKER_STALE_AFTER_SECONDS."
        )
    if not 0 < config.health_zap_timeout_seconds <= 10:
        raise RuntimeConfigurationError("HEALTH_ZAP_TIMEOUT_SECONDS must be greater than zero and at most 10.")
    ai_provider = config.ai_provider.strip().lower()
    if ai_provider not in {"template", "openai"}:
        raise RuntimeConfigurationError("AI_PROVIDER must be template or openai.")
    if ai_provider == "openai" and (
        not (config.openai_model or "").strip()
        or not (config.openai_api_key or "").strip()
        or (config.openai_api_key or "").strip().lower() in {"changeme", "example", "dev-token"}
    ):
        raise RuntimeConfigurationError("AI_PROVIDER=openai requires a real OPENAI_MODEL and OPENAI_API_KEY.")
    if bool(config.scan_relay_url) != bool(config.scan_relay_secret):
        raise RuntimeConfigurationError("SCAN_RELAY_URL and SCAN_RELAY_SECRET must be configured together.")
    if config.scan_relay_url:
        relay_url = urlsplit(config.scan_relay_url)
        if (
            relay_url.scheme != "http"
            or not relay_url.hostname
            or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", relay_url.hostname)
            or relay_url.username
            or relay_url.password
            or relay_url.path not in {"", "/"}
            or relay_url.query
            or relay_url.fragment
            or len(config.scan_relay_secret.encode()) < 32
        ):
            raise RuntimeConfigurationError(
                "SCAN_RELAY_URL must be an exact internal HTTP service URL and its secret must contain at least 32 bytes."
            )
    load_allowlist(config.allowlist_path)
    for raw_path in (config.artifact_root, config.repo_scan_root, config.repo_staging_root):
        path = Path(raw_path)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.is_dir() or path.is_symlink():
            raise RuntimeConfigurationError("Runtime storage paths must be real directories.")
    for raw_path in (config.gitleaks_config_path, config.osv_config_path):
        path = Path(raw_path)
        if not path.is_file() or path.is_symlink():
            raise RuntimeConfigurationError("Trusted scanner configuration files must exist as regular files.")
    osv_database = Path(config.osv_database_path)
    osv_database.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not osv_database.is_dir() or osv_database.is_symlink():
        raise RuntimeConfigurationError("OSV database path must be a real directory.")
