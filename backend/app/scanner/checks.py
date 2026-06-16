from __future__ import annotations

from urllib.parse import urljoin

from app.core.contracts import Confidence, Severity
from app.findings.schemas import NormalizedFindingInput
from app.scanner.crawler import CrawledPage
from app.scanner.http_client import GuardedHttpClient, ScannerHttpError


SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content Security Policy", "CWE-693"),
    "x-frame-options": ("Missing X-Frame-Options", "CWE-1021"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "CWE-693"),
    "referrer-policy": ("Missing Referrer-Policy", "CWE-200"),
}

EXPOSED_FILE_PROBES = (
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/config.php",
)

ROUTE_HINTS = (
    "/login",
    "/admin",
)


def run_passive_checks(pages: tuple[CrawledPage, ...], client: GuardedHttpClient, base_url: str) -> list[NormalizedFindingInput]:
    findings: list[NormalizedFindingInput] = []
    for page in pages:
        findings.extend(check_security_headers(page))
        findings.extend(check_cookies(page))
        findings.extend(check_forms(page))

    findings.extend(probe_exposed_files(client, base_url))
    findings.extend(probe_route_hints(client, base_url))
    return findings


def check_security_headers(page: CrawledPage) -> list[NormalizedFindingInput]:
    findings: list[NormalizedFindingInput] = []
    for header, (title, cwe) in SECURITY_HEADERS.items():
        if header not in page.headers:
            findings.append(
                NormalizedFindingInput(
                    title=title,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    affected_url=page.url,
                    evidence=f"Header '{header}' was not present in the HTTP response.",
                    source_tool="custom-passive",
                    scanner_rule_id=f"header:{header}",
                    cwe=cwe,
                    owasp_category="A05:2021",
                    remediation=f"Set a suitable {header} header for this response.",
                )
            )
    return findings


def check_cookies(page: CrawledPage) -> list[NormalizedFindingInput]:
    set_cookie_headers = page.set_cookie_headers or tuple([page.headers["set-cookie"]] if "set-cookie" in page.headers else [])
    if not set_cookie_headers:
        return []

    findings: list[NormalizedFindingInput] = []
    attributes = {
        "httponly": "Cookie Missing HttpOnly Attribute",
        "secure": "Cookie Missing Secure Attribute",
        "samesite": "Cookie Missing SameSite Attribute",
    }
    for set_cookie in set_cookie_headers:
        lower_cookie = set_cookie.lower()
        for attribute, title in attributes.items():
            if attribute not in lower_cookie:
                findings.append(
                    NormalizedFindingInput(
                        title=title,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        affected_url=page.url,
                        evidence=f"A Set-Cookie header is missing the {attribute} attribute.",
                        source_tool="custom-passive",
                        scanner_rule_id=f"cookie:{attribute}",
                        cwe="CWE-614",
                        owasp_category="A05:2021",
                        remediation=f"Set the {attribute} attribute on sensitive cookies where appropriate.",
                    )
                )
    return findings


def check_forms(page: CrawledPage) -> list[NormalizedFindingInput]:
    findings: list[NormalizedFindingInput] = []
    for form in page.forms:
        if "password" in form.inputs and form.method == "get":
            findings.append(
                NormalizedFindingInput(
                    title="Password Form Uses GET",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    affected_url=page.url,
                    evidence=f"Form action={form.action or '<current>'} method=get contains a password input.",
                    source_tool="custom-passive",
                    scanner_rule_id="form:password-get",
                    cwe="CWE-598",
                    owasp_category="A02:2021",
                    remediation="Submit password forms with POST over HTTPS and avoid placing secrets in URLs.",
                )
            )
    return findings


def probe_exposed_files(client: GuardedHttpClient, base_url: str) -> list[NormalizedFindingInput]:
    findings: list[NormalizedFindingInput] = []
    for path in EXPOSED_FILE_PROBES:
        url = urljoin(base_url, path)
        try:
            response = client.get(url)
        except ScannerHttpError:
            continue
        if response.status_code == 200 and response.body.strip():
            findings.append(
                NormalizedFindingInput(
                    title="Potentially Exposed Sensitive File",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    affected_url=response.url.normalized_url,
                    evidence=f"Probe returned HTTP 200 for {path}.",
                    source_tool="custom-passive",
                    scanner_rule_id=f"probe:{path}",
                    cwe="CWE-200",
                    owasp_category="A01:2021",
                    remediation="Remove sensitive files from the web root or block direct access.",
                )
            )
    return findings


def probe_route_hints(client: GuardedHttpClient, base_url: str) -> list[NormalizedFindingInput]:
    findings: list[NormalizedFindingInput] = []
    for path in ROUTE_HINTS:
        url = urljoin(base_url, path)
        try:
            response = client.get(url)
        except ScannerHttpError:
            continue
        if response.status_code in {200, 401, 403}:
            findings.append(
                NormalizedFindingInput(
                    title="Authentication Route Hint",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    affected_url=response.url.normalized_url,
                    evidence=f"Route hint {path} returned HTTP {response.status_code}.",
                    source_tool="custom-passive",
                    scanner_rule_id=f"route-hint:{path}",
                    cwe=None,
                    owasp_category=None,
                    remediation="Review discovered authentication or administration routes during manual validation.",
                )
            )
    return findings
