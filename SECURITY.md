# ScopeHarbor Security Policy

ScopeHarbor is a defensive, local-first application security audit platform.
Use it only against applications, services, and repositories you own or have
explicit permission to assess. You are responsible for confirming the target,
scope, timing, data-handling rules, and authorization before every scan.

ScopeHarbor is an MIT-licensed portfolio project, not a hosted scanning service.
No response-time, remediation-time, warranty, or support commitment is offered.

## Report a vulnerability

Use GitHub Private Vulnerability Reporting from the repository's **Security**
tab. Include the affected version/commit, a concise impact statement, minimal
reproduction steps using a target you control, the crossed boundary, and a
suggested mitigation if known.

Never include real credentials, cookies, raw production traffic, personal data,
third-party secrets, or an exploit against a system you do not own. Use
synthetic canaries. The repository owner must enable Private Vulnerability
Reporting before this channel exists; until then, do not publish sensitive
details in a public issue.

Security fixes target current `main` and the latest published source version.
Historical phase branches are development records, not supported release lines.

## Defensive-use boundaries

ScopeHarbor enforces the following in backend, relay, worker, database, and
Compose configuration:

- Every launchable web target must exactly match trusted allowlist schema v2.
  Arbitrary public, cloud, metadata-service, private-LAN, loopback, link-local,
  multicast, and unspecified destinations are denied.
- A policy fixes exact origin/base path, `compose_service` or `host_gateway`
  connection identity, HTTP/HTTPS trust, redirect cap, eligible engines, and
  whether the target is a disposable demo.
- Target roots cannot contain userinfo, queries, or fragments. Paths reject
  encoded separators, backslashes, repeated separators, and dot traversal.
  Prefixes match on segment boundaries.
- Launch-authority changes invalidate the policy fingerprint and require
  reauthorization. Origin or base-path changes require a new target.
- Users must confirm authorization and submit profile-specific acknowledgement
  codes before launch.
- General local applications receive bounded ScopeHarbor passive scanning only.
  ZAP Passive, Active Demo, and Client Spider require an explicitly compatible,
  disposable HTTP demo policy.
- Historical AJAX scans remain readable, but AJAX execution is retired.

Do not weaken these controls for examples, tests, demos, or UI convenience.
Editing the allowlist changes scanner authority and requires security review.

## Guarded relay and network isolation

The worker has no direct host/public route. It sends a signed, expiring,
single-use capability to a minimal non-root relay. The relay independently
reloads and validates the allowlist, capability, destination policy, method,
headers, body limit, and destination IP.

The relay:

- permits only `GET`;
- strips hop-by-hop and routing headers;
- caps request/response headers and response bodies;
- disables automatic redirects and manually validates every hop;
- dials the validated IP while preserving configured `Host` and TLS SNI;
- returns that validated IP as a bounded internal projection so the isolated
  worker can pin eligible ZAP work without independently resolving the target;
- supports system trust or one confined operator CA bundle;
- has no insecure TLS mode;
- receives no database, artifact, ZAP, AI, repository, or platform-auth access;
- emits no URL, credential, body, or target-derived logs.

Redirects are handled manually inside the relay and must stay on the same
origin and inside the configured base path. Every hop receives allowlist, path,
SSRF, and IP revalidation before the relay follows it. Credentials are never
forwarded across an origin or policy boundary.

Compose separates data, scanner-control, scan-target, host-access,
operator-access, and updater networks. Only the relay receives host-gateway
access. Do not add a public/host route to the worker.

The worker accepts the relay's destination projection only after parsing it as
an IP address and reapplying the target's address-class or exact host-gateway
policy. ZAP combines only those already validated addresses with the policy's
exact connection port; it never receives target credentials. Both policy
loading and worker execution reject every ZAP engine unless the target is an
explicitly compatible disposable demo.

## Repository isolation

Repository scans use workspace-scoped `RepositoryAsset` records. The stored
identity is a relative path below `REPO_SCAN_ROOT`; launch snapshots that path,
authorization time, creator, policy fingerprint, and acknowledgements. Workers
execute only the immutable snapshot and recheck workspace ownership.

The worker stages regular files into a per-scan `0700` ephemeral directory and
excludes symlinks, special files, `.git`, dependencies, caches, and build output.
It uses pinned Gitleaks and OSV-Scanner with ScopeHarbor-owned configuration. It
never:

- clones, fetches, or accesses repository remotes during a scan;
- installs packages, resolves dependencies, builds, runs hooks/scripts, or
  executes repository code;
- trusts repository-supplied scanner/ignore configuration;
- falls back to network access when the offline OSV database is absent or stale.

Raw scanner output is bounded, parsed from ephemeral storage, and discarded.
Gitleaks output is fully redacted. Only normalized safe findings and tool
receipts are persisted.

## Authentication and workspace isolation

Local development auth is accepted only with explicit
`APP_ENV=local`/dev-mode settings and constant-time bearer comparison.
Production-like use requires strict OIDC issuer, audience, RS256 signature,
`sub`, `exp`, and `iat` validation.

Every protected service/API lookup includes authenticated workspace context.
Direct IDs are never authorization. Worker jobs persist and revalidate workspace
context before execution.

Target auth profiles are not platform identities. Supported secrets are
Fernet-encrypted, write-only, and injected only into ScopeHarbor passive
requests through the relay. They never enter ZAP, browser scans, repository
scans, findings, reports, finding guidance, external AI, receipts, status,
artifacts, logs, or audits.

Plaintext auth-profile create/rotate requests are accepted only when
`APP_ENV=local`. Non-local requests require direct HTTPS or an exact trusted
proxy IP asserting HTTPS. Rotation, revocation, attachment, target updates, and
scan launch follow one profile→target→scan transaction-lock order and revalidate
state after locking.

Keep `.env`, `AUTH_PROFILE_SECRET_KEY`, previous Fernet keys, development/OIDC
tokens, relay/ZAP/database secrets, and AI keys out of Git.

## Execution safety

A worker owns a scan through a bounded lease renewed by a separate database
session. Every execution-state write is fenced by `lease_owner`. Lease loss,
cancellation, or deadline expiry aborts execution.

Passive requests, ZAP polling, and repository processes check cancellation,
deadline, and lease ownership. Scanner subprocesses use isolated process groups
and terminate descendants on abort. ZAP clients ignore inherited proxy
environment, disable redirects, request explicit stop operations, and keep the
advisory lock until external work is confirmed stopped.

The ZAP container stays non-root, capability-free, network-confined, and
read-only apart from bounded tmpfs mounts. Its ephemeral `.ZAP` mount permits
execution solely so the bundled WebDriver can support Client Spider and
browser-backed active rules; browser profiles and caches remain ephemeral, and
startup readiness verifies the driver is executable.

Active/browser work is not automatically replayed after interruption.

## Data minimization

Every boundary independently sanitizes and caps input; source-provided redaction
flags are never trusted. These values must not cross database, artifact, API,
report, finding-guidance, external-provider, cache, audit, or log boundaries:

- raw HTTP request/response bodies or passive crawl summaries;
- cookies, authorization values, API keys, passwords, or session material;
- raw ZAP/Gitleaks/OSV output;
- raw provider errors, exceptions, or tracebacks;
- absolute repository paths;
- URL userinfo, queries, or fragments;
- unredacted evidence or target-controlled markup.

Reports use normalized projections, idempotent uniqueness, Markdown-structure
escaping, safe dynamic fences, HTML escaping, atomic no-follow writes,
restrictive permissions, and report CSP. Report generation always derives
guidance through deterministic local template logic; it never contacts an
external provider or consumes AI cache, request-log, or rate-limit capacity.
Optional interactive AI receives a bounded safe projection only for eligible
web profiles, streams under a hard response cap, and must return incrementally
valid structured output. GET never initiates external paid/network work.

If a canary appears in any persisted or returned surface, stop the affected
workflow and treat it as a security defect.

## Operational expectations

- Run the platform setup script after every upgrade; its isolated bootstrap
  merges new settings and preserves a non-empty user-managed Fernet key.
- Review every allowlist/CA change and reauthorize affected targets.
- Keep container digests and hash locks reviewed and current.
- Update OSV deliberately before repository dependency scans.
- Review maintenance dry-runs before adding `--apply`.
- Never automatically prune audit logs, findings, reports, or scan history.
- Use a clean temporary database for release and migration verification.
- Keep CORS, trusted hosts, and trusted proxy IPs exact.
- Treat `/health` as liveness only; use `/ready`, protected platform health, and
  safe structured diagnostics for readiness.

## Explicit non-goals

ScopeHarbor 1.1 does not provide arbitrary public/cloud scanning, hosted
scanning, mutually hostile multi-user isolation, RBAC/team administration,
authenticated browser sessions, login automation, business-logic/IDOR testing,
remote repository cloning, dependency installation, Nuclei, Semgrep/full SAST,
PDF export, or a guarantee that a target is secure.

Findings are signals for qualified human review and can contain false positives
or false negatives.
