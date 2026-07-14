# ScopeHarbor Security Policy

ScopeHarbor is a defensive, local-first application security audit platform.
Use it only against applications, services, and repositories you own or have
explicit permission to assess. You are responsible for confirming the target,
scope, timing, data-handling rules, and authorization before every scan.

This repository is source-visible and currently unlicensed. It is not a hosted
service and does not provide a public scanning service.

## Report a vulnerability in ScopeHarbor

Use GitHub Private Vulnerability Reporting from this repository's **Security**
tab and select **Report a vulnerability**. Include:

- the affected version or commit;
- a concise impact statement;
- minimal reproduction steps using a target you control;
- the security boundary that was crossed;
- a suggested mitigation, if known.

Do not include real credentials, cookies, raw production traffic, personal data,
or third-party secrets. Use a synthetic canary when evidence is necessary.

The repository owner must enable GitHub Private Vulnerability Reporting before
this channel is available. Until it is enabled, do not publish an exploit or
sensitive report in a public issue. General, non-sensitive defects may still be
reported through ordinary repository channels when those channels are open.

No response-time or remediation-time commitment is currently offered.

## Supported version

Security fixes target the current `main` branch and the latest published source
version. Historical phase branches are development records and are not supported
release lines.

## Defensive-use boundaries

ScopeHarbor enforces these boundaries in backend and worker code:

- Every launchable web target must exactly match
  `config/scan-allowlist.yml`; arbitrary URLs are denied.
- Users must confirm authorization when creating a target and submit the
  profile-specific acknowledgement codes when starting a scan.
- ZAP active and Client Spider profiles are limited to allowlist entries marked
  as local demos.
- The guarded web scanner accepts exact HTTP Docker-service targets only. HTTPS
  is rejected until destination-pinned TLS can verify certificate and SNI
  correctly.
- Scanner requests disable automatic redirects. Each redirect is normalized,
  rematched to the allowlist, revalidated for SSRF, and connected to the
  validated destination IP.
- ZAP uses a generated API key and exact target/context scope. It is not
  published to the host network.
- Cancelling a scan stops it at a safe checkpoint. Active demo and browser scans
  are never automatically retried after worker interruption.
- A worker owns a scan through a bounded lease. Stale work fails with the safe
  `worker_interrupted` code rather than being silently adopted.

Do not weaken these controls for convenience, examples, tests, or UI behavior.
Adding an allowlist entry is a security decision, not general application data.

## Repository-scanner isolation

Repository scans accept only absolute existing directories below the configured
`REPO_SCAN_ROOT`. ScopeHarbor stages regular files into a per-scan `0700`
ephemeral workspace and excludes symlinks, special files, `.git`, dependency
directories, caches, and build output.

The worker uses trusted ScopeHarbor configurations with pinned Gitleaks and
OSV-Scanner binaries. It does not honor repository-supplied ignore/config files,
clone code, access remotes during a scan, resolve dependencies, run package
managers, build projects, execute hooks, or execute repository code. Gitleaks
uses full redaction. OSV runs only against a deliberately updated offline
database. Raw scanner output is bounded, parsed from ephemeral storage, and
discarded.

The explicit OSV database update command is the only repository-scanner network
operation. A missing or stale OSV database results in a safe warning and skipped
dependency adapter, not an online fallback.

## Authentication and workspace isolation

Local development auth is accepted only under explicit local/dev configuration,
uses constant-time token comparison, and must not use example credentials.
Production-like authentication requires an OIDC bearer token with strict
issuer, audience, RS256 signature, `sub`, `exp`, and `iat` validation.

Every protected API lookup is scoped by the authenticated workspace. Direct IDs
must never be treated as authorization. Worker jobs persist their workspace and
user context and reject mismatches.

Target auth profiles are not platform identities. Supported profile secrets are
Fernet-encrypted at rest, never returned by the API, and injected only into the
guarded passive HTTP client. Browser/ZAP authentication, login automation, and
password-form workflows are not supported. Rotation and revocation are blocked
while a nonterminal scan references a profile; revocation destroys encrypted
material and leaves only a history-safe tombstone.

Keep `AUTH_PROFILE_SECRET_KEY`, its temporary previous key, development tokens,
OIDC settings, ZAP keys, database passwords, and AI provider keys in local
environment configuration. Never commit them.

## Data minimization and redaction

All persistence boundaries must independently sanitize their input. Scanner
claims such as `redaction_applied` are not trusted. Before any database or
artifact write, ScopeHarbor removes URL userinfo, queries, and fragments; caps
free text; redacts credential-like material; and converts failures into stable
operator-safe codes and messages.

The following must not cross database, artifact, API, report, audit, cache, log,
or external-AI boundaries:

- raw HTTP request or response bodies;
- cookies, authorization values, API keys, passwords, or session material;
- raw ZAP/Gitleaks/OSV output;
- raw provider errors, tracebacks, or internal exception details;
- absolute repository paths;
- URLs containing userinfo, queries, or fragments;
- unredacted finding evidence.

Reports use normalized safe projections, atomic no-follow writes, restrictive
file permissions, HTML escaping, and a strict report content security policy.
The optional external AI provider receives only a bounded safe projection and
validated structured output; it never receives repository or modern-crawl
findings.

If a canary secret appears in any persisted or returned surface, treat it as a
security defect and stop the affected workflow.

## Operational expectations

- Run the bootstrap before first use and protect the generated `.env`.
- Keep container digests and dependency locks reviewed and current.
- Update the OSV offline database deliberately before dependency scans.
- Review maintenance dry-runs before adding `--apply`.
- Never automatically prune audit logs, findings, reports, or scan history.
- Use a clean temporary database for release verification and migration tests.
- Restrict API CORS origins and trusted hosts to exact operator-controlled
  values.
- Treat `/health` as liveness only; use authenticated platform health and
  operator logs for diagnostics.

## Explicit non-goals

ScopeHarbor 1.0 does not provide:

- arbitrary public or cloud scanning;
- authorization for any target;
- multi-tenant SaaS hardening, RBAC, or team administration;
- authenticated browser sessions, login automation, or business-logic tests;
- user-to-user IDOR test automation;
- Nuclei, Semgrep, or full SAST coverage;
- remote repository cloning or dependency installation;
- PDF reports;
- a guarantee that an assessed target is secure.

Security findings are signals for qualified human review. Scanner output can be
incomplete, incorrect, or context-dependent.
