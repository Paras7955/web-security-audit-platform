from __future__ import annotations

from pathlib import Path
import re
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
    }
    if any(value < 1 for value in positive_limits.values()):
        invalid = sorted(name for name, value in positive_limits.items() if value < 1)
        raise RuntimeConfigurationError(f"Runtime limits must be positive: {invalid}.")
    if config.page_default_limit > config.page_max_limit or config.page_max_limit > 200:
        raise RuntimeConfigurationError("Pagination limits are invalid.")
    if config.repo_max_file_bytes > config.repo_max_total_bytes:
        raise RuntimeConfigurationError("REPO_MAX_FILE_BYTES cannot exceed REPO_MAX_TOTAL_BYTES.")
    if config.worker_lease_seconds < 15:
        raise RuntimeConfigurationError("WORKER_LEASE_SECONDS must be at least 15.")
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
