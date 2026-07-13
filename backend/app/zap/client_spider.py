from __future__ import annotations

import time
from collections.abc import Callable
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
    validate_zap_scope_url,
    wait_for_passive_records,
)


CLIENT_SPIDER_TIMEOUT_SECONDS = 120
CLIENT_SPIDER_POLL_INTERVAL_SECONDS = 0.5
CLIENT_SPIDER_MAX_CRAWL_DEPTH = 2
CLIENT_SPIDER_PAGE_LOAD_SECONDS = 10
CLIENT_SPIDER_BROWSERS = 1


class ZapClientSpiderCancelled(Exception):
    pass


@dataclass(frozen=True)
class ZapClientSpiderResult:
    findings: tuple[NormalizedFindingInput, ...]
    errors: tuple[str, ...]
    submitted_url: str | None


def run_zap_client_spider_scan(
    *,
    scan_id: str,
    target_url: str,
    allowlist_target: AllowlistTarget,
    zap_base_url: str,
    client: ZapApiClient | None = None,
    resolver: Resolver | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> ZapClientSpiderResult:
    try:
        if not allowlist_target.local_demo:
            raise ZapPassiveError("Modern web crawls are restricted to local/demo allowlist targets.")
        target = validate_zap_scope_url(target_url, allowlist_target, resolver=resolver)
        zap_client = client or ZapApiClient(base_url=zap_base_url)
        context_name = f"client-spider-{scan_id}"
        zap_client.new_session(name=context_name)
        zap_client.new_context(name=context_name)
        zap_client.include_in_context(context_name=context_name, regex=context_regex(target.pinned_url))
        zap_client.set_context_in_scope(context_name=context_name, enabled=True)
        zap_client.enable_passive_scanner()
        zap_client.delete_all_alerts()
        spider_id = zap_client.client_spider_scan(
            url=target.pinned_url,
            context_name=context_name,
            max_crawl_depth=CLIENT_SPIDER_MAX_CRAWL_DEPTH,
            page_load_seconds=CLIENT_SPIDER_PAGE_LOAD_SECONDS,
            number_of_browsers=CLIENT_SPIDER_BROWSERS,
        )
        wait_for_client_spider(zap_client, spider_id, should_cancel=should_cancel)
        wait_for_passive_records(zap_client)
        alert_page = zap_client.alerts(base_url=target.pinned_url)
        findings = tuple(
            normalize_zap_alert(
                _rewrite_alert_origin(alert, target.pinned_url, target.original_url),
                source_tool="zap-client-spider",
            )
            for alert in alert_page.alerts
        )
        errors = ("zap_alert_cap_reached",) if alert_page.truncated else ()
        return ZapClientSpiderResult(findings=findings, errors=errors, submitted_url=target.original_url)
    except ZapClientSpiderCancelled:
        raise
    except (ZapPassiveError, TargetUrlError, SsrfGuardError):
        return ZapClientSpiderResult(findings=(), errors=("client_spider_failed",), submitted_url=None)


def wait_for_client_spider(
    client: ZapApiClient,
    scan_id: str,
    *,
    should_cancel: Callable[[], bool] | None = None,
) -> None:
    deadline = time.monotonic() + CLIENT_SPIDER_TIMEOUT_SECONDS
    completed = False
    try:
        while time.monotonic() < deadline:
            if should_cancel and should_cancel():
                raise ZapClientSpiderCancelled
            if client.client_spider_status(scan_id=scan_id) >= 100:
                completed = True
                return
            time.sleep(CLIENT_SPIDER_POLL_INTERVAL_SECONDS)
        raise ZapPassiveError("ZAP Client Spider exceeded its time limit.")
    finally:
        if not completed:
            client.stop_client_spider(scan_id=scan_id)


def _rewrite_alert_origin(alert: dict[str, object], pinned_url: str, original_url: str) -> dict[str, object]:
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
        (parsed_original.scheme, parsed_original.netloc, parsed_alert.path or "/", "", "")
    )
    return rewritten
