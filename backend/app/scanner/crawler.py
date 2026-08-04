from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

from app.scanner.html_parser import FormMetadata, extract_html_metadata
from app.scanner.http_client import GuardedHttpClient, ScannerHttpError
from app.security.target_url import TargetUrlError, normalize_target_url


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    links: tuple[str, ...]
    forms: tuple[FormMetadata, ...]
    inputs: tuple[str, ...]
    redirect_chain: tuple[str, ...]
    set_cookie_headers: tuple[str, ...] = ()


@dataclass(frozen=True)
class CrawlResult:
    pages: tuple[CrawledPage, ...]
    errors: tuple[str, ...]


def crawl_site(
    *,
    start_url: str,
    client: GuardedHttpClient,
    max_depth: int,
    page_cap: int,
    execution_checkpoint: Callable[[], None] | None = None,
) -> CrawlResult:
    start = normalize_target_url(start_url)
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    seen: set[str] = set()
    pages: list[CrawledPage] = []
    errors: list[str] = []

    while queue and len(pages) < page_cap:
        if execution_checkpoint is not None:
            execution_checkpoint()
        raw_url, depth = queue.popleft()
        try:
            normalized = normalize_target_url(raw_url).normalized_url
        except TargetUrlError as exc:
            errors.append(str(exc))
            continue

        if normalized in seen:
            continue
        seen.add(normalized)

        try:
            response = client.get(normalized)
        except (ScannerHttpError, TargetUrlError, ValueError) as exc:
            errors.append(str(exc))
            continue

        metadata = extract_html_metadata(response.body)
        page = CrawledPage(
            url=response.url.normalized_url,
            status_code=response.status_code,
            headers=response.headers,
            body=response.body,
            links=tuple(metadata.links),
            forms=tuple(metadata.forms),
            inputs=tuple(metadata.inputs),
            redirect_chain=response.redirect_chain,
            set_cookie_headers=response.set_cookie_headers,
        )
        pages.append(page)

        if depth >= max_depth:
            continue
        for link in metadata.links:
            absolute_url = urljoin(response.url.normalized_url, link)
            try:
                normalized_link_url = normalize_target_url(absolute_url)
            except TargetUrlError:
                continue
            if (
                normalized_link_url.scheme != start.scheme
                or normalized_link_url.host != start.host
                or normalized_link_url.port != start.port
            ):
                continue
            normalized_link = normalized_link_url.normalized_url
            if normalized_link not in seen:
                queue.append((normalized_link, depth + 1))

    return CrawlResult(pages=tuple(pages), errors=tuple(errors))
