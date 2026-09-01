# ScopeHarbor Threat Model

## Scope

This model covers ScopeHarbor 1.1 running locally with the supplied Compose
topology. It addresses malicious/malformed targets, redirects, DNS, repositories,
scanner/provider output, identities, concurrent operations, and local
misconfiguration. A compromised host/kernel/container runtime or fully
compromised operator account is outside the application boundary.

## Assets

- Platform identities, workspace records, and authorization history.
- Target credentials, local secrets, and relay capabilities.
- Authorized applications and their availability.
- Repository contents, relative scope identities, and host paths.
- Findings, reports, scores, audit history, and operator trust in results.
- Destination integrity, scan scope, leases, and scanner availability.

## Trust boundaries

1. Browser to loopback frontend/API.
2. Bearer token to authenticated workspace.
3. API/worker to PostgreSQL and report storage.
4. Trusted operator allowlist/root/CA configuration to launch authority.
5. Worker to minimal relay through signed capabilities.
6. Relay to exact Docker/same-machine target.
7. Worker to ZAP and untrusted repository/tool processes.
8. Normalized findings to deterministic local report guidance, API, audit,
   cache, logs, and explicitly requested optional AI assistance.
9. One-shot OSV updater and CI dependency/vulnerability tooling to the network.
10. Docker-isolated local bootstrap to the operator-owned environment file.

## Threats and controls

| Threat | Primary controls | Residual concern |
| --- | --- | --- |
| Unauthorized/public scanning | exact static v2 policy, connection class/IP pin, authorization/acknowledgements, no worker route | trusted operator can deliberately edit config |
| SSRF/DNS rebinding | prohibited address classes, all-answer validation, signed policy fingerprint, relay re-resolution/pinning, every-hop validation | Docker/host routing remains trusted |
| Path/redirect escape | canonical path rules, segment-boundary prefix, ambiguous encoding rejection, same-origin/base-path redirect policy | target parsing defects |
| TLS interception | verified SNI/hostname, system or confined CA trust, no insecure mode | operator-controlled CA can expand trust |
| Capability theft/replay | HMAC, short expiry, request binding, in-memory single-use nonce cache | relay restart forgets consumed nonces; expiry remains limiting |
| Relay privilege creep | non-root/read-only/capability-free, minimal env/mounts, no data/AI/ZAP/repo access | container-runtime compromise |
| ZAP scope/key escape | internal daemon, exact context, API-key header, `trust_env=False`, no redirects, demo-only policy, serialized cleanup | third-party scanner defect |
| Cross-workspace IDOR | principal plus workspace predicates in API/services/worker | future routes must preserve pattern |
| Credential disclosure | Fernet, write-only schemas, HTTPS submission rule, passive-relay-only injection, multi-boundary redaction | local host/env access can reveal secrets |
| Credential race | profile→target→scan row locks, post-lock revalidation, immutable scan references | direct database administration |
| Malicious repository | immutable asset snapshot, root confinement, regular-file staging, trusted config, no code/build/hooks/network | scanner/parser defect |
| Symlink/path race | relative identity, resolved-root checks, staging metadata checks, no-follow writes | privileged concurrent host mutation |
| Scanner/provider injection | bounded streaming/output, schemas, independent sanitization, Markdown/HTML escaping/CSP | novel secret formats need redactor updates |
| AI disclosure/cost | eligible profiles only, safe projection, atomic reservation, explicit POST, bounded incremental JSON; reports always use local guidance | external provider remains a processor |
| Duplicate/stale worker | row claim, separate-session renewal, owner-fenced writes, lease checkpoints | abrupt process death can delay detection to lease expiry |
| Orphan external work | process groups, descendant termination, ZAP stop/cleanup before unlock | unresponsive third-party process/container |
| Resource exhaustion | request/page/crawl/body/header/staging/tool/finding/time/rate/tmpfs caps and startup cross-validation | trusted operator can raise limits |
| Report race/injection | database uniqueness, nested transaction handling, safe Markdown fences, HTML escaping, exact response/embedded CSP, no scripts or network resources, atomic no-follow writes | direct-file CSP support varies by viewer; artifact remains resource-free |
| Unsafe legacy data | migration cleanup/invalidation tasks; no old-migration rewrite | backups retain pre-upgrade data |
| Log leakage | access log disabled, queryless structured paths, safe request IDs/codes | host/container engine diagnostics |
| Supply-chain compromise | hashes/digests, pinned actions, pinned Gitleaks/OSV, digest-pinned Trivy, SBOM, audits | upstream compromise before pin review |
| Bootstrap image/script compromise | digest-pinned Python image, no network, read-only root/repository, dropped capabilities, no-new-privileges, temporary output-only write mount, no secret-value output | trusted operator checkout and Docker daemon remain authoritative |

## Abuse cases that remain denied

- A URL outside an exact operator policy, including public/private-LAN targets.
- Metadata, loopback, link-local, mixed-DNS, rebinding, or IPv4-mapped bypasses.
- Userinfo/query/fragment target roots or ambiguous/traversal paths.
- Redirects outside origin/base path or credential forwarding across policy.
- Unverified HTTPS, wrong hostname, expired certificate, or insecure TLS.
- ZAP use on a generalized/non-disposable target.
- Another workspace's target, asset, scan, finding, report, or auth profile.
- Auth material in ZAP, repositories, reports, finding guidance, external AI,
  receipts, logs, or status.
- Repository scope outside `REPO_SCAN_ROOT`, symlinks, remote access, dependency
  resolution, repository-supplied scanner config, or code execution.
- Raw bodies/output/query strings/exceptions/evidence crossing a persistence or
  output boundary.
- External AI generation caused by GET.
- State writes after worker lease ownership is lost.
- Automatic active/browser retry after interruption.

## Review invariants

Changes to requests, URLs, policies, capabilities, persistence, reports,
finding guidance, optional AI, auth, artifacts, repositories, migrations, or
worker recovery require success and denial tests. Use synthetic canaries and
verify absence from database, artifacts, reports, AI/cache, audit, API, and
captured real-server logs.

Broader network access, repository execution, authenticated browser workflows,
or public targets change this threat model and require explicit approval.

## Accepted limitations

- The local operator controls `.env`, Docker, mounts, policies, and CAs.
- ScopeHarbor does not isolate mutually hostile operators on one deployment.
- Capability replay memory is process-local; short expiry limits restart risk.
- Static redaction cannot prove every secret format is recognized.
- Third-party tools can be wrong or defective.
- The OIDC-facing UI accepts an already-issued bearer token in memory; it does
  not implement provider redirects, refresh-token storage, or session renewal.
- No scan result is a security guarantee.
