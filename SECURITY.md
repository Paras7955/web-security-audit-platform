# Security Policy And Responsible Use

This project is a defensive web application security learning and portfolio tool. It is not an unauthorized hacking tool and does not replace a professional penetration test, code review, compliance audit, or legal authorization process.

## Authorized Use Only

Use this platform only against applications that you own, run locally, or are explicitly authorized to test.

V1 active scans are local/demo allowlist only. Arbitrary public targets must be blocked by code, not only by warnings.

Do not use this platform for:

- Credential attacks.
- Password spraying or brute force.
- Destructive testing.
- Stealth scanning.
- Mass scanning.
- Scanning systems you do not own or lack permission to test.
- Testing the project itself outside authorized environments.

## Scan Safety Rules

- Scanner targets must match `config/scan-allowlist.yml`.
- Docker service names are canonical scanner targets inside containers.
- HTTP clients must disable automatic redirects and manually revalidate redirect destinations.
- Every outbound scanner request must pass SSRF and allowlist validation.
- ZAP must be scoped to the exact allowlisted target/context.
- ZAP passive URL submission must use only validated allowlisted URLs, pin submission URLs to the SSRF-validated destination IP, serialize shared daemon access, and disable automatic redirect following.
- Active Demo scans require explicit user acknowledgement, must be limited to configured local/demo targets, and must use the same scoped ZAP context and destination-IP pinning controls.
- AJAX Short scans require explicit user acknowledgement, must be limited to configured local/demo targets, and must use the same scoped ZAP context, destination-IP pinning controls, and shared daemon serialization.
- Repo scans require a saved allowlisted target with a configured local repo path.
- Repo paths must be absolute, existing directories under the configured `REPO_SCAN_ROOT`, and must not be symlinks.
- Repo scans must not clone remote code, install dependencies, fetch remote repositories, run package scripts, run builds, or execute repository code.
- Cloud demos must use sample data only and must not allow arbitrary active scans.

## Evidence And Secret Handling

- Do not store full HTTP response bodies by default.
- Store minimal evidence snippets only.
- Redact sensitive values before database writes, reports, or AI processing.
- Generate reports only from normalized persisted findings and redacted evidence snippets.
- Reports are available for completed passive, Active Demo, and Repo scans after normalization and redaction.
- AI is available for completed passive and Active Demo scans only; repo findings must not be sent to AI providers in Phase 10.
- Secret scan results must be redacted.
- Never send raw response bodies, raw ZAP output, raw secret scanner output, or unredacted evidence to AI providers.

## AI Provider Safety

- Use `AI_PROVIDER=template` by default for local deterministic explanations.
- Optional OpenAI explanations must receive only normalized finding fields and redacted evidence snippets.
- Omit finding text fields from AI provider payloads when redaction has not been confirmed.
- Strip query strings and fragments from URLs before including locations in AI provider payloads.
- Do not send raw artifacts, raw HTTP bodies, raw ZAP output, secret scanner output, authorization material, cookies, or unredacted evidence to any AI provider.
- Do not send repo-scan findings to AI providers in Phase 10.
- AI explanations must describe only existing findings and must not invent vulnerabilities, affected assets, evidence, or scan coverage.
- If an optional provider fails or is misconfigured, fall back to template explanations and disclose the fallback.

## Vulnerability Reporting For This Project

Do not open public issues with exploitable details.

Preferred reporting path before public release: GitHub private vulnerability reporting/security advisory.

Before publishing this project, replace this placeholder with a maintainer contact:

```text
security-contact@example.com
```

When reporting a vulnerability, include:

- Affected version or commit.
- Clear reproduction steps.
- Expected and actual behavior.
- Impact.
- Any relevant logs or screenshots with secrets removed.

## Disclosure Boundary

This project is for local defensive learning and authorized testing. Report vulnerabilities found in third-party software only through that software owner's approved disclosure process.
