from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.core.contracts import Confidence, DEFAULT_LIMITS, Severity
from app.findings.schemas import NormalizedFindingInput
from app.security.allowlist import AllowlistTarget
from app.security.ssrf import Resolver, validate_destination
from app.security.target_url import NormalizedTargetUrl, normalize_target_url


ZAP_PASSIVE_URL_CAP = int(DEFAULT_LIMITS["page_cap"])
ZAP_ALERT_CAP = 500
ZAP_POLL_LIMIT = 20


class ZapPassiveError(ValueError):
    pass


@dataclass(frozen=True)
class ZapPassiveResult:
    findings: tuple[NormalizedFindingInput, ...]
    errors: tuple[str, ...]
    submitted_urls: tuple[str, ...]


class ZapApiClient:
    def __init__(self, *, base_url: str, timeout_seconds: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def new_session(self, *, name: str) -> None:
        self._zap_get("/JSON/core/action/newSession/", {"name": name, "overwrite": "true"})

    def new_context(self, *, name: str) -> str:
        payload = self._zap_get("/JSON/context/action/newContext/", {"contextName": name})
        context_id = payload.get("contextId")
        if not isinstance(context_id, str):
            raise ZapPassiveError("ZAP did not return a context id.")
        return context_id

    def include_in_context(self, *, context_name: str, regex: str) -> None:
        self._zap_get("/JSON/context/action/includeInContext/", {"contextName": context_name, "regex": regex})

    def set_context_in_scope(self, *, context_name: str, enabled: bool) -> None:
        self._zap_get(
            "/JSON/context/action/setContextInScope/",
            {"contextName": context_name, "booleanInScope": str(enabled).lower()},
        )

    def enable_passive_scanner(self) -> None:
        self._zap_get("/JSON/pscan/action/setEnabled/", {"enabled": "true"})

    def delete_all_alerts(self) -> None:
        self._zap_get("/JSON/core/action/deleteAllAlerts/", {})

    def access_url(self, *, url: str) -> None:
        self._zap_get("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "false"})

    def records_to_scan(self) -> int:
        payload = self._zap_get("/JSON/pscan/view/recordsToScan/", {})
        raw_count = payload.get("recordsToScan")
        if not isinstance(raw_count, str):
            raise ZapPassiveError("ZAP did not return passive records count.")
        try:
            return int(raw_count)
        except ValueError as exc:
            raise ZapPassiveError("ZAP returned an invalid passive records count.") from exc

    def alerts(self, *, base_url: str) -> list[dict[str, object]]:
        payload = self._zap_get(
            "/JSON/core/view/alerts/",
            {"baseurl": base_url, "start": "0", "count": str(ZAP_ALERT_CAP)},
        )
        alerts = payload.get("alerts")
        if not isinstance(alerts, list):
            raise ZapPassiveError("ZAP did not return an alerts list.")
        return [alert for alert in alerts if isinstance(alert, dict)]

    def _zap_get(self, path: str, params: dict[str, str]) -> dict[str, object]:
        try:
            response = httpx.get(f"{self.base_url}{path}", params=params, timeout=self.timeout_seconds)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ZapPassiveError(f"ZAP API request failed: {path}") from exc
        if not isinstance(payload, dict):
            raise ZapPassiveError(f"ZAP API response was not an object: {path}")
        return payload


def run_zap_passive_scan(
    *,
    scan_id: str,
    target_url: str,
    allowlist_target: AllowlistTarget,
    zap_base_url: str,
    observed_urls: tuple[str, ...],
    client: ZapApiClient | None = None,
    resolver: Resolver | None = None,
) -> ZapPassiveResult:
    try:
        target = validate_zap_scope_url(target_url, allowlist_target, resolver=resolver)
        scoped_urls = scope_observed_urls(
            target=target,
            allowlist_target=allowlist_target,
            urls=observed_urls,
            resolver=resolver,
        )
        zap_client = client or ZapApiClient(base_url=zap_base_url)
        context_name = f"scan-{scan_id}"
        zap_client.new_session(name=context_name)
        zap_client.new_context(name=context_name)
        zap_client.include_in_context(context_name=context_name, regex=context_regex(target.normalized_url))
        zap_client.set_context_in_scope(context_name=context_name, enabled=True)
        zap_client.enable_passive_scanner()
        zap_client.delete_all_alerts()

        for url in scoped_urls:
            zap_client.access_url(url=url)

        wait_for_passive_records(zap_client)
        findings = tuple(normalize_zap_alert(alert) for alert in zap_client.alerts(base_url=target.normalized_url))
        return ZapPassiveResult(findings=findings, errors=(), submitted_urls=scoped_urls)
    except Exception as exc:
        return ZapPassiveResult(findings=(), errors=(str(exc),), submitted_urls=())


def scope_observed_urls(
    *,
    target: NormalizedTargetUrl,
    allowlist_target: AllowlistTarget,
    urls: tuple[str, ...],
    resolver: Resolver | None,
) -> tuple[str, ...]:
    scoped: list[str] = [target.normalized_url]
    seen: set[str] = {target.normalized_url}
    for raw_url in urls:
        try:
            normalized = validate_zap_scope_url(raw_url, allowlist_target, resolver=resolver)
        except Exception:
            continue
        if (
            normalized.scheme != target.scheme
            or normalized.host != target.host
            or normalized.port != target.port
            or normalized.normalized_url in seen
        ):
            continue
        scoped.append(normalized.normalized_url)
        seen.add(normalized.normalized_url)
        if len(scoped) >= ZAP_PASSIVE_URL_CAP:
            break
    return tuple(scoped)


def validate_zap_scope_url(
    raw_url: str,
    allowlist_target: AllowlistTarget,
    resolver: Resolver | None,
) -> NormalizedTargetUrl:
    normalized = normalize_target_url(raw_url)
    if resolver is None:
        validate_destination(normalized, allowlist_target)
    else:
        validate_destination(normalized, allowlist_target, resolver=resolver)
    return normalized


def context_regex(target_url: str) -> str:
    parsed = urlsplit(target_url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return f"{re.escape(origin)}/.*"


def wait_for_passive_records(client: ZapApiClient) -> None:
    for _attempt in range(ZAP_POLL_LIMIT):
        if client.records_to_scan() <= 0:
            return
    raise ZapPassiveError("ZAP passive scanner did not finish within the poll limit.")


def normalize_zap_alert(alert: dict[str, object]) -> NormalizedFindingInput:
    name = string_field(alert, "alert") or string_field(alert, "name") or "ZAP passive alert"
    plugin_id = string_field(alert, "pluginId") or string_field(alert, "alertRef")
    cwe = normalize_cwe(string_field(alert, "cweid"))
    return NormalizedFindingInput(
        title=name,
        severity=map_zap_risk(string_field(alert, "risk")),
        confidence=map_zap_confidence(string_field(alert, "confidence")),
        affected_url=sanitize_alert_url(string_field(alert, "url")),
        evidence=build_alert_evidence(alert),
        source_tool="zap-passive",
        scanner_rule_id=plugin_id,
        cwe=cwe,
        owasp_category=map_owasp_category(cwe),
        reproduction_steps="Review the affected URL and confirm the ZAP passive alert against the response metadata.",
        remediation=string_field(alert, "solution") or None,
        false_positive_notes="ZAP passive alerts require human validation before remediation is prioritized.",
    )


def build_alert_evidence(alert: dict[str, object]) -> str:
    parts = []
    for key, label in (("evidence", "Evidence"), ("param", "Parameter"), ("description", "Description")):
        value = string_field(alert, key)
        if value:
            parts.append(f"{label}: {value}")
    return "\n".join(parts) or "ZAP passive alert metadata was recorded without a response body."


def string_field(alert: dict[str, object], key: str) -> str | None:
    value = alert.get(key)
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def sanitize_alert_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def normalize_cwe(value: str | None) -> str | None:
    if value is None or value in {"0", "-1"}:
        return None
    return f"CWE-{value}" if value.isdigit() else value


def map_zap_risk(value: str | None) -> Severity:
    normalized = (value or "").lower()
    if normalized == "critical":
        return Severity.CRITICAL
    if normalized == "high":
        return Severity.HIGH
    if normalized == "medium":
        return Severity.MEDIUM
    if normalized == "low":
        return Severity.LOW
    return Severity.INFO


def map_zap_confidence(value: str | None) -> Confidence:
    normalized = (value or "").lower()
    if normalized in {"confirmed", "high"}:
        return Confidence.HIGH
    if normalized == "medium":
        return Confidence.MEDIUM
    return Confidence.LOW


def map_owasp_category(cwe: str | None) -> str | None:
    if cwe in {"CWE-16", "CWE-693", "CWE-1021"}:
        return "A05:2021"
    if cwe in {"CWE-79", "CWE-89"}:
        return "A03:2021"
    if cwe in {"CWE-200", "CWE-209"}:
        return "A01:2021"
    return None
