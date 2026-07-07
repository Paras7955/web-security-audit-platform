from __future__ import annotations

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
) -> PassiveScanResult:
    scanner_client = client or GuardedHttpClient(
        allowlist_target=allowlist_target,
        timeout_seconds=int(DEFAULT_LIMITS["request_timeout_seconds"]),
        default_headers=auth_headers,
    )
    crawl_result = crawl_site(
        start_url=target_url,
        client=scanner_client,
        max_depth=int(DEFAULT_LIMITS["crawl_depth"]),
        page_cap=int(DEFAULT_LIMITS["page_cap"]),
    )
    findings = run_passive_checks(crawl_result.pages, scanner_client, target_url)
    artifact_dir = ensure_scan_artifact_dir(artifact_root, scan_id)
    write_crawl_summary(artifact_dir, crawl_result.pages, crawl_result.errors, findings)
    return PassiveScanResult(
        pages=crawl_result.pages,
        findings=tuple(findings),
        errors=crawl_result.errors,
        artifact_dir=artifact_dir,
    )


def write_crawl_summary(
    artifact_dir: Path,
    pages: tuple[CrawledPage, ...],
    errors: tuple[str, ...],
    findings: list[NormalizedFindingInput],
) -> None:
    lines = [
        "Passive scan crawl summary",
        f"pages={len(pages)}",
        f"errors={len(errors)}",
        f"findings={len(findings)}",
        "",
    ]
    lines.extend(f"{page.status_code} {page.url}" for page in pages)
    if errors:
        lines.append("")
        lines.append("Errors:")
        lines.extend(errors)
    (artifact_dir / "passive_scan_summary.txt").write_text("\n".join(lines), encoding="utf-8")
