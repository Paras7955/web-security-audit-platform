from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.core.contracts import DEFAULT_LIMITS
from app.findings.schemas import NormalizedFindingInput
from app.scanner.checks import run_passive_checks
from app.scanner.crawler import CrawledPage, crawl_site
from app.scanner.http_client import GuardedHttpClient
from app.scans.artifacts import ensure_scan_artifact_dir
from app.security.allowlist import AllowlistTarget


@dataclass(frozen=True)
class PassiveScanResult:
    pages: tuple[CrawledPage, ...]
    findings: tuple[NormalizedFindingInput, ...]
    errors: tuple[str, ...]
    artifact_dir: Path


def run_passive_scan(
    *,
    scan_id: str,
    target_url: str,
    allowlist_target: AllowlistTarget,
    artifact_root: str | Path,
    auth_headers: dict[str, str] | None = None,
    client: GuardedHttpClient | None = None,
    execution_checkpoint: Callable[[], None] | None = None,
) -> PassiveScanResult:
    scanner_client = client or GuardedHttpClient(
        allowlist_target=allowlist_target,
        timeout_seconds=int(DEFAULT_LIMITS["request_timeout_seconds"]),
        default_headers=auth_headers,
        execution_checkpoint=execution_checkpoint,
    )
    crawl_result = crawl_site(
        start_url=target_url,
        client=scanner_client,
        max_depth=int(DEFAULT_LIMITS["crawl_depth"]),
        page_cap=int(DEFAULT_LIMITS["page_cap"]),
        execution_checkpoint=execution_checkpoint,
    )
    findings = run_passive_checks(crawl_result.pages, scanner_client, target_url)
    artifact_dir = ensure_scan_artifact_dir(artifact_root, scan_id)
    return PassiveScanResult(
        pages=crawl_result.pages,
        findings=tuple(findings),
        errors=crawl_result.errors,
        artifact_dir=artifact_dir,
    )
