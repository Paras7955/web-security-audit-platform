from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.findings.schemas import NormalizedFindingInput
from app.security.allowlist import AllowlistTarget
from app.security.ssrf import Resolver, SsrfGuardError
from app.security.target_url import TargetUrlError
from app.zap.passive import (
    ZapApiClient,
    ZapPassiveError,
    context_regex,
    normalize_zap_alert,
    wait_for_passive_records,
    validate_zap_scope_url,
)


ZAP_AJAX_MAX_DURATION_MINUTES = 1
ZAP_AJAX_MAX_CRAWL_DEPTH = 2
ZAP_AJAX_POLL_LIMIT = 150
ZAP_AJAX_POLL_INTERVAL_SECONDS = 0.5


@dataclass(frozen=True)
class ZapAjaxShortResult:
    findings: tuple[NormalizedFindingInput, ...]
    errors: tuple[str, ...]
    submitted_url: str | None


def run_zap_ajax_short_scan(
    *,
    scan_id: str,
    target_url: str,
    allowlist_target: AllowlistTarget,
    zap_base_url: str,
    client: ZapApiClient | None = None,
    resolver: Resolver | None = None,
) -> ZapAjaxShortResult:
    try:
        if not allowlist_target.local_demo:
            raise ZapPassiveError("ZAP AJAX Short scans are restricted to local/demo allowlist targets.")
        target = validate_zap_scope_url(target_url, allowlist_target, resolver=resolver)
        zap_client = client or ZapApiClient(base_url=zap_base_url)
        context_name = f"ajax-short-{scan_id}"
        zap_client.new_session(name=context_name)
        zap_client.new_context(name=context_name)
        zap_client.include_in_context(context_name=context_name, regex=context_regex(target.pinned_url))
        zap_client.set_context_in_scope(context_name=context_name, enabled=True)
        zap_client.enable_passive_scanner()
        zap_client.delete_all_alerts()
        zap_client.set_ajax_max_duration(minutes=ZAP_AJAX_MAX_DURATION_MINUTES)
        zap_client.set_ajax_max_crawl_depth(depth=ZAP_AJAX_MAX_CRAWL_DEPTH)
        zap_client.ajax_scan(url=target.pinned_url, context_name=context_name)
        wait_for_ajax_scan(zap_client)
        wait_for_passive_records(zap_client)
        alert_page = zap_client.alerts(base_url=target.pinned_url)
        findings = tuple(
            normalize_zap_alert(rewrite_alert_origin(alert, target.pinned_url, target.original_url), source_tool="zap-ajax")
            for alert in alert_page.alerts
        )
        errors = ("ZAP alert results were truncated at the configured cap.",) if alert_page.truncated else ()
        return ZapAjaxShortResult(findings=findings, errors=errors, submitted_url=target.original_url)
    except (ZapPassiveError, TargetUrlError, SsrfGuardError) as exc:
        return ZapAjaxShortResult(findings=(), errors=(str(exc),), submitted_url=None)


def wait_for_ajax_scan(client: ZapApiClient) -> None:
    try:
        for _attempt in range(ZAP_AJAX_POLL_LIMIT):
            if client.ajax_status().lower() == "stopped":
                return
            time.sleep(ZAP_AJAX_POLL_INTERVAL_SECONDS)
        raise ZapPassiveError("ZAP AJAX Short scan did not finish within the poll limit.")
    finally:
        if client.ajax_status().lower() != "stopped":
            client.stop_ajax()


def rewrite_alert_origin(alert: dict[str, object], pinned_url: str, original_url: str) -> dict[str, object]:
    alert_url = alert.get("url")
    if not isinstance(alert_url, str):
        return alert
    parsed_alert = urlsplit(alert_url)
    parsed_pinned = urlsplit(pinned_url)
    if parsed_alert.scheme != parsed_pinned.scheme or parsed_alert.netloc != parsed_pinned.netloc:
        return alert
    parsed_original = urlsplit(original_url)
    rewritten = dict(alert)
    rewritten["url"] = urlunsplit(
        (
            parsed_original.scheme,
            parsed_original.netloc,
            parsed_alert.path or "/",
            parsed_alert.query,
            "",
        )
    )
    return rewritten
