# ScopeHarbor Contributor and Agent Guide

## Purpose

ScopeHarbor is a defensive, local-first AppSec audit platform. Preserve its
deny-by-default authority; do not turn it into an arbitrary public scanner or
hosted scanning service.

Project guidance is subordinate to active system, platform, and user
instructions. Before changing authentication, scanner authority, network
access, persistence, or another trust boundary, read
[`SECURITY.md`](SECURITY.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) completely.

## Safety boundaries

- Enforce security in backend and worker code, not only in UI copy or docs.
- Allow web scans only through an exact operator policy. General local targets
  are passive-only; ZAP requires an explicitly compatible disposable demo.
- Never add arbitrary public/cloud scanning, broader private-network access,
  automatic redirects, insecure TLS, or a direct worker route to targets.
  Revalidate every redirect and bind connections to the approved address and
  port.
- Resolve repository scans below `REPO_SCAN_ROOT`. Never clone, fetch, install,
  build, execute hooks or repository code, or use repository-supplied scanner
  configuration. Gitleaks stays redacted and OSV stays offline.
- Strip URL credentials, queries, and fragments before persistence. Sanitize
  and cap untrusted text independently at persistence, API, report, AI, cache,
  audit, and log boundaries. Never expose raw artifacts, bodies, cookies,
  secrets, absolute local paths, exceptions, or unredacted evidence.
- Preserve workspace predicates on every lookup and recheck workspace ownership
  in asynchronous workers.
- Target credentials may enter only guarded passive HTTP requests after policy
  validation. They must never enter browser/repository scans, findings,
  reports, AI, artifacts, logs, statuses, or audit events.
- Deterministic local guidance is the default and the only report source.
  Optional external AI remains explicit and receives only its documented safe
  projection.
- Keep scanner work bounded, cancellable, lease-owned, and represented by safe
  receipts rather than raw tool output.

Authenticated browser workflows, business-logic automation, online dependency
resolution, Nuclei, Semgrep/full SAST, PDF export, RBAC, and multi-tenant SaaS
operation remain out of scope without explicit approval.

## Working approach

- Inspect relevant code, contracts, tests, and docs before editing. Preserve
  public behavior unless the requested change intentionally alters it.
- Keep APIs under `/api/v1`. Do not expand a trust boundary without explicit
  approval and corresponding denial-path, isolation, redaction, and failure
  tests.
- Never rewrite an existing migration; add and verify a new migration.
- Keep dependencies and container inputs pinned under the release policy.
  Review licensing and provenance before adding third-party material.
- Update the relevant public documentation when contracts change, and preserve
  unrelated user changes in a dirty worktree.
- Use the complete gates in
  [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md). Run targeted checks
  first, then broader tests, static analysis, migrations, builds, dependency and
  container audits, documentation links, and secret scans as appropriate.
- Obtain an independent review for security-sensitive or cross-boundary changes
  when an appropriate reviewer is available; otherwise document a separate
  self-review. State remaining manual or environment-dependent gaps accurately.

## Git and sensitive data

- Verify the active task branch and worktree before editing.
- Use cohesive, reviewable commits and preserve existing authors, author emails,
  and history.
- Do not push, merge, tag, publish, or rewrite history unless the user
  explicitly requests that operation.
- Never commit `.env` files, keys, tokens, target data, scanner output, private
  reports, database dumps, or other local artifacts.
- Report commit hashes, verification performed, unresolved risks, and any user
  action still required.
