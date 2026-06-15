import json
from enum import StrEnum
from pathlib import Path


def _load_contracts() -> dict[str, object]:
    for parent in Path(__file__).resolve().parents:
        contract_path = parent / "shared" / "contracts.json"
        if contract_path.exists():
            break
    else:
        raise FileNotFoundError("Could not locate shared/contracts.json")

    with contract_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


CONTRACTS = _load_contracts()


class ScanMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE_DEMO = "active_demo"
    AJAX_SHORT = "ajax_short"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    NORMALIZING = "normalizing"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStep(StrEnum):
    TARGET_VALIDATION = "target_validation"
    CUSTOM_CRAWL = "custom_crawl"
    CUSTOM_CHECKS = "custom_checks"
    ZAP_SPIDER = "zap_spider"
    ZAP_PASSIVE = "zap_passive"
    ZAP_ACTIVE = "zap_active"
    ZAP_AJAX = "zap_ajax"
    REPO_SECRETS_SCAN = "repo_secrets_scan"
    REPO_DEPENDENCY_SCAN = "repo_dependency_scan"
    NORMALIZING_FINDINGS = "normalizing_findings"
    GENERATING_REPORTS = "generating_reports"
    GENERATING_AI_EXPLANATIONS = "generating_ai_explanations"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


DEFAULT_LIMITS = CONTRACTS["default_limits"]
