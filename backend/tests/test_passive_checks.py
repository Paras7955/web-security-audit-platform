import unittest

from app.scanner.checks import check_cookies, check_forms, check_security_headers, probe_exposed_files, probe_route_hints
from app.scanner.cookies import parse_set_cookie_security
from app.scanner.crawler import CrawledPage
from app.scanner.html_parser import FormMetadata
from app.scanner.http_client import ScannerHttpResponse
from app.security.target_url import normalize_target_url


class FakeClient:
    def get(self, raw_url: str) -> ScannerHttpResponse:
        url = normalize_target_url(raw_url)
        status_code = 200 if url.path in {"/.env", "/login"} else 404
        body = "secret=value" if url.path == "/.env" else "ok"
        return ScannerHttpResponse(
            url=url,
            status_code=status_code,
            headers={},
            body=body,
            redirect_chain=(),
        )


def page(**overrides) -> CrawledPage:
    values = {
        "url": "http://juice-shop:3000/",
        "status_code": 200,
        "headers": {},
        "body": "",
        "links": (),
        "forms": (),
        "inputs": (),
        "redirect_chain": (),
    }
    values.update(overrides)
    return CrawledPage(**values)


class PassiveChecksTests(unittest.TestCase):
    def test_missing_security_headers_emit_findings(self) -> None:
        findings = check_security_headers(page())

        self.assertTrue(any(finding.scanner_rule_id == "header:content-security-policy" for finding in findings))
        self.assertTrue(all(finding.source_tool == "custom-passive" for finding in findings))

    def test_cookie_attribute_findings_redact_cookie_evidence_later(self) -> None:
        findings = check_cookies(page(headers={"set-cookie": "session=abc123"}))

        self.assertEqual({finding.scanner_rule_id for finding in findings}, {"cookie:httponly", "cookie:secure", "cookie:samesite"})

    def test_cookie_attribute_findings_check_each_cookie(self) -> None:
        findings = check_cookies(
            page(
                cookie_security=(
                    parse_set_cookie_security("session=abc123; HttpOnly; Secure; SameSite=Lax"),
                    parse_set_cookie_security("theme=light"),
                )
            )
        )

        self.assertEqual({finding.scanner_rule_id for finding in findings}, {"cookie:httponly", "cookie:secure", "cookie:samesite"})
        self.assertTrue(all("theme=light" not in (finding.evidence or "") for finding in findings))

    def test_cookie_attribute_names_are_parsed_instead_of_substring_matched(self) -> None:
        findings = check_cookies(
            page(
                cookie_security=(
                    parse_set_cookie_security(
                        "session=secure-httponly-samesite; Path=/secure/httponly/samesite"
                    ),
                )
            )
        )

        self.assertEqual(
            {finding.scanner_rule_id for finding in findings},
            {"cookie:httponly", "cookie:secure", "cookie:samesite"},
        )

    def test_malformed_cookie_security_attributes_are_not_treated_as_present(self) -> None:
        findings = check_cookies(
            page(
                cookie_security=(
                    parse_set_cookie_security(
                        "session=secret; Secure=canary; HttpOnly=canary; SameSite=canary"
                    ),
                )
            )
        )

        self.assertEqual(
            {finding.scanner_rule_id for finding in findings},
            {"cookie:httponly", "cookie:secure", "cookie:samesite"},
        )

    def test_password_get_form_emits_medium_finding(self) -> None:
        findings = check_forms(page(forms=(FormMetadata(action="/login", method="get", inputs=["password"]),)))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].scanner_rule_id, "form:password-get")

    def test_exposed_file_probe_emits_only_on_http_200_with_body(self) -> None:
        findings = probe_exposed_files(FakeClient(), "http://juice-shop:3000/")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scanner_rule_id, "probe:/.env")

    def test_route_hint_probe_emits_info_finding(self) -> None:
        findings = probe_route_hints(FakeClient(), "http://juice-shop:3000/")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "info")
        self.assertEqual(findings[0].scanner_rule_id, "route-hint:/login")


if __name__ == "__main__":
    unittest.main()
