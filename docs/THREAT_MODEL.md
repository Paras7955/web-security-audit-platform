# ScopeHarbor Threat Model

## Scope

This model covers ScopeHarbor 1.0 running locally through the supplied Docker
Compose configuration. It focuses on malicious or malformed scan targets,
repositories, scanner output, identities, provider output, and local
misconfiguration. Host compromise, malicious Docker/OS kernels, and a fully
compromised operator account are outside the application boundary.

## Assets

- Platform identities and workspace-owned records.
- Target auth-profile secrets and local environment secrets.
- Authorized target applications and their availability.
- Local repository contents and filesystem paths.
- Findings, reports, risk scores, audit history, and operator trust in results.
- Scanner scope, destination integrity, and worker availability.

## Trust boundaries

1. Browser to loopback frontend/API.
2. Bearer token to authenticated workspace principal.
3. API to PostgreSQL and report storage.
4. API/worker configuration to allowlist and filesystem roots.
5. Worker to target network and ZAP.
6. Worker to untrusted repository contents and scanner processes.
7. Normalized findings to reports, caches, logs, audits, and optional AI.
8. One-shot OSV updater to the external advisory source.

## Threats and controls

| Threat | Primary controls | Residual concern |
| --- | --- | --- |
| Unauthorized or public scanning | exact static allowlist, authorization confirmation, profile acknowledgements, local-demo flags | operator can deliberately edit local config |
| SSRF/DNS rebinding | URL normalization, HTTP-only support, IP policy, destination pinning, per-hop validation, no automatic redirects | Docker/network configuration remains trusted |
| ZAP scope escape | internal-only daemon, API key, exact context, destination pinning, local-demo restriction, advisory lock, time/alert caps | third-party scanner defects |
| Cross-workspace IDOR | bearer principal, workspace predicates on direct/list reads, persisted worker context | future routes must preserve the pattern |
| Credential disclosure | Fernet encryption, secret-free API schemas, constant-time dev auth, redaction, safe logs/errors/audits | host/env access can reveal local secrets |
| Malicious repository | root confinement, regular-file-only staging, excluded trees, trusted config, no code/build/hooks, tmpfs and resource caps | content parsers/tool defects |
| Symlink/path traversal | resolved root checks, relative persisted path, no-follow artifact/report handling, symlink exclusion | privileged host mutation outside container boundary |
| Scanner-output injection | bounded output, JSON/schema checks, independent sanitization, HTML escaping, report CSP | novel secret patterns may require redactor updates |
| Raw data sent to AI | safe projection, finding/payload caps, profile restrictions, structured-output validation, template default | external provider is still a separate processor |
| Provider error leakage | stable fallback codes and generic messages; raw errors not persisted/returned | local process diagnostics must stay structured |
| Queue duplication/stale jobs | row locking, worker leases, heartbeat, attempt counters, interruption failure, no active/browser retry | hard termination can leave external work briefly running |
| Resource exhaustion | request, page, crawl, staging, file, output, finding, timeout, rate, and tmpfs caps | operator can raise local limits unsafely |
| Unsafe upgrade data | migration cleanup of errors/URLs/text/stubs, report/risk invalidation, retired AJAX handling | backups retain historical raw data under operator control |
| Report script/content injection | HTML escaping, no-follow atomic writes, restrictive modes, strict response CSP | downloaded HTML opened outside ScopeHarbor loses response headers |
| Audit/history deletion | maintenance excludes audit, finding, report, and scan history | direct database administration remains trusted |

## Abuse cases that must remain denied

- Starting a scan for a URL that is not an exact allowlist match.
- Adding an HTTPS target before pinned TLS has correct SNI/certificate checks.
- Following a redirect to a different service, host, port, or prohibited IP.
- Attaching another workspace's target, scan, report, finding, or auth profile.
- Sending an auth-profile secret through ZAP, Client Spider, reports, AI, or logs.
- Scanning a repository outside `REPO_SCAN_ROOT` or through a symlink.
- Honoring repository `.gitleaks*`, OSV config, ignore, package-manager, or build
  instructions.
- Falling back to online dependency resolution during an ordinary scan.
- Persisting raw scanner output, response bodies, query strings, tracebacks, or
  provider errors.
- Automatically retrying a browser or active scan after worker interruption.

## Security invariants for review

Changes affecting outbound requests, URLs, persistence, reports, AI, auth,
artifacts, repositories, migrations, or worker recovery require tests at both
the success and denial boundary. Use synthetic canary values and verify their
absence from database rows, files, API responses, captured logs, audit metadata,
AI request/cache entries, and reports.

A new feature that needs broader network access, executes repository code, uses
authenticated browser sessions, or permits public targets is not an incremental
implementation detail; it changes this threat model and requires explicit scope
approval.

## Accepted limitations

- A trusted local operator controls `.env`, Compose, allowlist, filesystem
  mounts, and Docker; deliberate unsafe reconfiguration is not preventable.
- ScopeHarbor does not isolate mutually hostile operators on one deployment.
- Static redaction cannot prove that every possible secret format is detected.
- Third-party scanners may produce false positives, false negatives, or defects.
- A downloaded HTML report is protected by escaping but not by the API response
  CSP after it leaves ScopeHarbor.
- No scan result is a security guarantee.
