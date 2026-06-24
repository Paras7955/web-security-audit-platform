from __future__ import annotations

import time
from dataclasses import dataclass

from app.findings.schemas import NormalizedFindingInput
from app.security.allowlist import AllowlistTarget
from app.security.ssrf import Resolver, SsrfGuardError
from app.security.target_url import TargetUrlError
from app.zap.passive import (
    ZapApiClient,
    ZapPassiveError,
    alert_url_map_key,
    context_regex,
    normalize_zap_alert,
    rewrite_alert_url,
    validate_zap_scope_url,
)


ZAP_ACTIVE_POLL_LIMIT = 180
ZAP_ACTIVE_POLL_INTERVAL_SECONDS = 0.5


@dataclass(frozen=True)
class ZapActiveDemoResult:
    findings: tuple[NormalizedFindingInput, ...]
    errors: tuple[str, ...]
    submitted_url: str | None


def run_zap_active_demo_scan(
    *,
    scan_id: str,
    target_url: str,
    allowlist_target: AllowlistTarget,
    zap_base_url: str,
    client: ZapApiClient | None = None,
    resolver: Resolver | None = None,
) -> ZapActiveDemoResult:
    try:
        if not allowlist_target.local_demo:
            raise ZapPassiveError("ZAP Active Demo scans are restricted to local/demo allowlist targets.")
        target = validate_zap_scope_url(target_url, allowlist_target, resolver=resolver)
        zap_client = client or ZapApiClient(base_url=zap_base_url)
        context_name = f"active-demo-{scan_id}"
        zap_client.new_session(name=context_name)
        context_id = zap_client.new_context(name=context_name)
        zap_client.include_in_context(context_name=context_name, regex=context_regex(target.pinned_url))
        zap_client.set_context_in_scope(context_name=context_name, enabled=True)
        zap_client.enable_passive_scanner()
        zap_client.delete_all_alerts()
        zap_client.access_url(url=target.pinned_url)
        scan_id_from_zap = zap_client.active_scan(url=target.pinned_url, context_id=context_id)
        wait_for_active_scan(zap_client, scan_id=scan_id_from_zap)
        alert_page = zap_client.alerts(base_url=target.pinned_url)
        url_map = {alert_url_map_key(target.pinned_url): target.original_url}
        findings = tuple(normalize_zap_alert(rewrite_alert_url(alert, url_map), source_tool="zap-active") for alert in alert_page.alerts)
        errors = ("ZAP alert results were truncated at the configured cap.",) if alert_page.truncated else ()
        return ZapActiveDemoResult(findings=findings, errors=errors, submitted_url=target.original_url)
    except (ZapPassiveError, TargetUrlError, SsrfGuardError) as exc:
        return ZapActiveDemoResult(findings=(), errors=(str(exc),), submitted_url=None)


def wait_for_active_scan(client: ZapApiClient, *, scan_id: str) -> None:
    for _attempt in range(ZAP_ACTIVE_POLL_LIMIT):
        if client.active_scan_status(scan_id=scan_id) >= 100:
            return
        time.sleep(ZAP_ACTIVE_POLL_INTERVAL_SECONDS)
    raise ZapPassiveError("ZAP active scan did not finish within the poll limit.")
