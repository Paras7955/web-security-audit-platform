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
- Platform APIs that create or read targets, scans, findings, reports, and AI explanations must require authenticated workspace context.
- Workspace isolation must be enforced in backend queries, including direct finding and report artifact lookups by ID.
- Background scan jobs and generated artifacts must carry persisted workspace and user context.
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
- Target-application auth profiles are supported only for guarded passive-web scanner requests in Phase 14.
- Active Demo, AJAX Short, browser/ZAP authenticated behavior, repo scans, login automation, password-form workflows, and business-logic auth testing must not use auth profiles in Phase 14.
- Cloud demos must use sample data only and must not allow arbitrary active scans.

## Evidence And Secret Handling

- Do not store full HTTP response bodies by default.
- Store minimal evidence snippets only.
- Redact sensitive values before database writes, reports, or AI processing.
- Generate reports only from normalized persisted findings and redacted evidence snippets.
- Reports are available for completed passive, Active Demo, and Repo scans after normalization and redaction.
- AI is available for completed passive and Active Demo scans only; repo findings must not be sent to AI providers in Phase 10.
- Secret scan results must be redacted.
- Auth profile secrets must be encrypted with a deployment-specific `AUTH_PROFILE_SECRET_KEY`.
- `AUTH_PROFILE_SECRET_KEY` must be present and valid at startup/readiness; production-like environments must not use the local development example key.
- Auth profile API reads must never return secret material.
- Auth profile secrets must not appear in findings, reports, AI payloads, artifacts, logs, scan status messages, or audit-style records.
- Never send raw response bodies, raw ZAP output, raw secret scanner output, or unredacted evidence to AI providers.

## Risk Scoring And Dashboards

- Risk scores must be deterministic and versioned with `scoring_model_version`.
- Risk scoring must use normalized/redacted persisted finding fields only.
- Dashboard, risk-score, and scan-comparison APIs must enforce authenticated workspace scope.
- Scan comparison must compare only compatible completed scans from the same workspace and target.
- Stable comparison identity must come from normalized target plus finding `dedupe_key`, not raw scanner output.
- AI providers may explain deterministic score inputs in later phases, but must not compute risk scores.

## Finding Management

- Finding lifecycle state must be workspace-owned and keyed by normalized target plus finding `dedupe_key`.
- Lifecycle and suppression state must not rewrite immutable scan finding occurrences or scanner evidence.
- Suppression rules must use normalized persisted finding fields only, never raw scanner output or raw artifacts.
- Suppression must not prevent scanners from detecting or storing future matching findings.
- Suppression expiration must be reflected when findings are read.
- Tags and tag assignments must be scoped to the authenticated workspace.
- Finding filters and direct finding lookups must enforce authenticated workspace scope.

## Platform Operations Safety

- API rate limits must be enforced server-side and scoped by authenticated workspace/user/action.
- Audit records are append-only operational records; corrections must create new events rather than rewriting old ones.
- Audit metadata must not include secrets, auth profile material, raw artifacts, raw HTTP bodies, cookies, credentials, or unredacted evidence.
- Scan cancellation is cooperative. Queued scans may become `cancelled` immediately; running scans must stop only at safe worker checkpoints.
- Cancellation must not broaden scanner scope, skip SSRF checks, or leave ZAP contexts outside the existing target scope.
- Health endpoints may report operational status but must not expose secrets or sensitive local filesystem contents.

## Demo Seed Safety

- Demo seed behavior must be an explicit command gated by `DEMO_SEED_ENABLED=true`; it must not run automatically at startup and must not be exposed as a public API endpoint.
- Seeded targets must use existing allowlist entries and must not allow arbitrary public URLs.
- Seeded repo paths must stay under `REPO_SCAN_ROOT`.
- Seeded findings, reports, lifecycle state, suppression rules, tags, and risk scores must remain workspace-scoped sample data.
- Seeded data must not include real credentials, auth profile secrets, raw HTTP bodies, raw scanner artifacts, cookies, or unredacted evidence.
- The seed command must not clone repositories, fetch remote code, install dependencies, run package scripts, build, or execute repository code.

## AI Provider Safety

- Use `AI_PROVIDER=template` by default for local deterministic explanations.
- Optional OpenAI explanations must receive only normalized finding fields and redacted evidence snippets.
- Omit finding text fields from AI provider payloads when redaction has not been confirmed.
- Strip query strings and fragments from URLs before including locations in AI provider payloads.
- Cache AI explanations only from normalized/redacted inputs and safe generated output; never cache raw artifacts, raw scanner output, secrets, credentials, cookies, or unredacted evidence.
- Treat lifecycle state, suppression state and expiration, report context, provider/model/config, and deterministic risk-score model inputs as cache invalidation inputs.
- Rate-limit uncached interactive and report-triggered AI generation by workspace/user/action/provider/model/config window.
- Do not send raw artifacts, raw HTTP bodies, raw ZAP output, secret scanner output, authorization material, cookies, or unredacted evidence to any AI provider.
- Do not send repo-scan findings to AI providers in Phase 10.
- AI explanations must describe only existing findings and must not invent vulnerabilities, affected assets, evidence, or scan coverage.
- AI may explain deterministic risk score inputs, but must not compute or override risk scores.
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
