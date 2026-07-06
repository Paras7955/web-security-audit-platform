import json
from dataclasses import dataclass
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
    REPO = "repo"


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


@dataclass(frozen=True)
class ScanProfile:
    id: str
    label: str
    mode: ScanMode
    description: str
    requires_active_demo_acknowledgement: bool
    requires_ajax_short_acknowledgement: bool
    requires_repo_path: bool
    local_demo_only: bool
    reports_enabled: bool
    ai_enabled: bool


def _load_scan_profiles() -> tuple[ScanProfile, ...]:
    profiles: list[ScanProfile] = []
    for raw_profile in CONTRACTS["scan_profiles"]:
        profile = ScanProfile(
            id=str(raw_profile["id"]),
            label=str(raw_profile["label"]),
            mode=ScanMode(str(raw_profile["mode"])),
            description=str(raw_profile["description"]),
            requires_active_demo_acknowledgement=bool(raw_profile["requires_active_demo_acknowledgement"]),
            requires_ajax_short_acknowledgement=bool(raw_profile["requires_ajax_short_acknowledgement"]),
            requires_repo_path=bool(raw_profile["requires_repo_path"]),
            local_demo_only=bool(raw_profile["local_demo_only"]),
            reports_enabled=bool(raw_profile["reports_enabled"]),
            ai_enabled=bool(raw_profile["ai_enabled"]),
        )
        profiles.append(profile)
    return tuple(profiles)


SCAN_PROFILES = _load_scan_profiles()
SCAN_PROFILE_BY_ID = {profile.id: profile for profile in SCAN_PROFILES}
DEFAULT_SCAN_PROFILE_BY_MODE = {profile.mode.value: profile for profile in SCAN_PROFILES}


def scan_profile_for_id(profile_id: str) -> ScanProfile | None:
    return SCAN_PROFILE_BY_ID.get(profile_id)


def default_scan_profile_for_mode(mode: str) -> ScanProfile | None:
    return DEFAULT_SCAN_PROFILE_BY_MODE.get(mode)
