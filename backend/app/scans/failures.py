from __future__ import annotations

from app.api.schemas import ScanFailureRead

SAFE_FAILURE_MESSAGES: dict[str, str] = {
    "auth_profile_invalid": "The configured target authorization profile could not be used.",
    "cancelled": "The scan was cancelled.",
    "client_spider_failed": "The modern web crawl could not be completed.",
    "dependency_scan_skipped": "Dependency analysis was skipped because its local advisory data was unavailable.",
    "legacy_repo_results_removed": "Legacy sample results were removed. Rerun this repository scan.",
    "repo_limit_exceeded": "The repository exceeds a configured safety limit.",
    "repo_tool_failed": "A required repository scanner could not complete safely.",
    "retired_profile": "This historical scan profile is retired. Create a modern web crawl instead.",
    "scan_deadline_exceeded": "The scan exceeded its configured time limit.",
    "target_validation_failed": "The target no longer passes ScopeHarbor safety validation.",
    "worker_interrupted": "The scanner worker stopped before the scan could complete.",
}


def safe_scan_failure(error_code: str | None, status: str) -> ScanFailureRead | None:
    if not error_code and status not in {"failed", "completed_with_warnings"}:
        return None
    code = error_code or "scan_failed"
    return ScanFailureRead(code=code, message=SAFE_FAILURE_MESSAGES.get(code, "The scan could not be completed safely."))
