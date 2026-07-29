# ScopeHarbor Handoff

## Current state

ScopeHarbor — Local AppSec Audit Platform is at version `1.1.0`. V1 phases
1–19 and the approved post-V1 phases 20–23 are complete. Phase 23 is the
portfolio-ready backend public-release program; the frontend was intentionally
left unchanged for a later integration phase.

The release provides:

- A FastAPI API under `/api/v1`, a Next.js operator UI, PostgreSQL, a separate
  scanner worker, and a minimal guarded relay.
- Provider-neutral dev/OIDC authentication, backend-enforced workspace
  isolation, cursor pagination, RFC 9457-style problems, bounded bodies, exact
  CORS/trusted-host policy, rate limits, and query-free structured request logs.
- Allowlist schema v2 with exact origin/base-path policy, immutable
  fingerprints, explicit profile engines, Docker-service or same-machine
  host-gateway routing, and verified HTTP/HTTPS transport. Legacy policies
  remain readable for migration, but retired AJAX scans cannot launch.
- General local HTTP/HTTPS passive scanning through single-use signed relay
  capabilities. The relay independently validates policy and SSRF boundaries,
  pins the destination IP while preserving `Host`/TLS SNI, accepts system trust
  or a confined custom CA, and has no insecure TLS mode.
- Local-demo-only ZAP Passive, Active Demo, and Client Spider execution for
  explicitly compatible disposable HTTP containers. Historical AJAX records
  remain readable without retaining an AJAX execution surface.
- Workspace-scoped repository assets with immutable relative-path and
  authorization snapshots. Repository scans use pinned Gitleaks 8.30.1 and
  offline OSV-Scanner 2.3.8 with bounded regular-file-only staging.
- Lease-fenced workers with a separate-session heartbeat monitor, cancellation
  and deadline checkpoints, process-group cleanup, ZAP stop/cleanup behavior,
  and proxy-independent ZAP clients.
- Subject-aware findings, lifecycle state, revocable suppressions, audited tag
  assignment history, current-posture dashboards, immutable `risk-v1` scan
  scores, dynamic `posture-v1`, comparisons, and idempotent Markdown/HTML
  reports.
- Deterministic template explanations plus an optional bounded external AI
  provider with atomic capacity reservation, streamed/capped responses, safe
  fingerprints, and explicit generation through `POST`.
- Encrypted passive-relay-only target credentials, rotation/revocation locking,
  dry-run-first maintenance, an idempotent collision-safe demo seed, hardened
  Compose networks, digest-pinned security tooling, CI security gates, an MIT
  license, and public-release documentation.

## Safety invariants

- Never scan arbitrary public URLs or private-LAN destinations. Launchable web
  targets must exactly match `config/scan-allowlist.yml`, pass SSRF validation,
  and have explicit authorization confirmation.
- Supported destinations are exact Docker services and same-machine
  applications reached through Docker's host gateway. Generalized targets are
  passive-only.
- HTTPS always verifies the configured hostname and certificate using system
  trust or one confined operator CA bundle. There is no insecure mode.
- Automatic redirects stay disabled. Every hop is same-origin, stays within
  the configured base-path boundary, and is independently allowlist/SSRF
  revalidated before a destination-pinned connection.
- ZAP Active and Client Spider scans remain disposable-demo-only, strictly
  scoped, bounded, API-key protected, cancellable, and serialized through the
  ZAP advisory lock.
- Repository scans never clone, fetch, install, build, resolve dependencies,
  run scripts/hooks, execute repository code, or trust repository-supplied
  scanner configuration.
- Persist and expose only independently sanitized projections. Raw bodies,
  scanner/provider output, cookies, credentials, query strings, absolute
  repository paths, provider errors, and unredacted evidence must not cross
  database, product API, report, AI, cache, audit, artifact, status, or log
  boundaries.
- Direct IDs are not authorization. API, worker, finding-management, risk,
  report, AI, and repository-asset operations remain workspace-scoped.
- Auth-profile material may enter only ScopeHarbor passive requests through the
  guarded relay. It never enters ZAP, browser, repository, report, AI, receipt,
  status, artifact, audit, or log workflows.

Read `SECURITY.md` and `docs/THREAT_MODEL.md` before changing a trust boundary.

## Runtime map

| Component | Location | Responsibility |
| --- | --- | --- |
| API application | `backend/app/main.py`, `backend/app/api/` | Lifespan validation and workspace API |
| Models and upgrades | `backend/app/models.py`, `backend/alembic/` | Subject-aware persistence, constraints, and cleanup ledger |
| Worker lifecycle | `backend/worker/`, `backend/app/scans/` | Lease ownership, cancellation, execution, and safe receipts |
| Guarded relay | `backend/relay/`, `backend/app/scanner/relay_capability.py` | Independent capability, policy, SSRF, and transport enforcement |
| Web scanners | `backend/app/scanner/`, `backend/app/zap/` | Passive crawling/checks and demo-only ZAP profiles |
| Repository scanners | `backend/app/repo_scanner/` | Bounded staging, redacted Gitleaks, and offline OSV |
| Safety boundary | `backend/app/security/`, `backend/app/findings/redaction.py` | Allowlist, SSRF, URLs, auth, and sanitization |
| Reports and AI | `backend/app/reports/`, `backend/app/ai/` | Safe subject-aware downstream projections |
| Operations | `backend/app/ops/`, `backend/app/maintenance.py` | Audit, health, limits, and dry-run-first maintenance |
| Public contract | `shared/contracts.json` | Profiles, acknowledgements, limits, and version |
| Operator UI | `frontend/src/` | Existing dev-auth and target-based operator workflows |
| Runtime/CI | `docker-compose.yml`, `backend/Dockerfile`, `.github/workflows/` | Network isolation, images, quality, secret, SBOM, and vulnerability gates |

Default host endpoints are frontend `127.0.0.1:3001`, API
`127.0.0.1:8000`, Juice Shop `127.0.0.1:3000`, and PostgreSQL
`127.0.0.1:5432`. ZAP, worker, and relay remain internal-only.

## Public API additions

- Protected target-policy catalog, JSON target validation, and target
  reauthorization.
- Repository-asset create/list/read/archive plus repository dashboard and
  latest-comparison routes.
- Scan creation by either `target_id` or `repository_asset_id`, with a
  deprecated target-repository compatibility adapter for the current UI.
- Subject type/ID and repository-asset identity in scan, finding, risk,
  dashboard, comparison, report, and AI projections while retaining existing
  target fields.
- Current-posture basis and separately labelled historical dashboard metrics.
- Explicit AI generation with `POST /api/v1/scans/{id}/ai-explanations`; GET is
  retrieval-only for external providers.
- Suppression revocation, tag unassignment, and safe tag archiving.

See `docs/API.md` for request/response details.

## Final verification record

- A clean temporary PostgreSQL database migrated from zero through
  `0012_portfolio_readiness`. Upgrade tests from `0008` and `0011`, legacy
  repository-result invalidation, cleanup-task creation, and Alembic model
  drift all passed.
- Backend: 325 tests passed; 2 real-binary tests are intentionally opt-in and
  were exercised separately.
- Backend branch coverage: 85% overall. Focused coverage: authentication
  100.00%, SSRF/redirects 95.07%, persistence redaction 100.00%, artifact paths
  100.00%, and repository runner boundaries 96.42%.
- Ruff and Pyright: clean.
- Frontend lint and production build: passed without changing any file under
  `frontend/`.
- Compose rendering and network/privilege hardening validation: passed.
- Digest-pinned Gitleaks scanned committed history with networking disabled and
  found no unbaselined leaks. Its baseline contains only exact audited
  historical development/CI sentinel fingerprints.
- The real pinned Gitleaks fixture passed. The stale OSV database was correctly
  refused at the configured age boundary; the pinned offline OSV fixture also
  passed with a test-only age override and executed no package scripts.
- `pip check` and the offline npm audit passed. The clean Python 3.12.13 lock
  regeneration, hash-locked clean install, and online dependency audits remain
  release gates because registry egress was unavailable locally.
- API/worker/relay image builds could not complete offline because Python wheel
  caches were incomplete. Full image builds, Compose readiness smoke, Trivy
  image review, and CycloneDX SBOM generation are enforced in CI and must pass
  before tagging.

## Operator actions

1. Run `python3 scripts/bootstrap_env.py`. It adds the relay secret and newly
   introduced settings without replacing a non-empty user-managed
   `AUTH_PROFILE_SECRET_KEY`; review the resulting `.env`.
2. Review every custom v2 allowlist entry, exact host-gateway address, base
   path, profile engine, and custom CA mount before authorizing targets.
3. Refresh the offline advisory database before repository dependency scans:

   ```bash
   docker compose --profile maintenance run --rm osv-db-update
   ```

4. Regenerate and verify both Python locks with Python 3.12.13 and pip-tools
   7.5.3, then run the online Python and npm audits. Exact commands are in
   `docs/RELEASE_CHECKLIST.md`.
5. Require the release CI workflows to pass, including image builds, Compose
   smoke/hardening, Gitleaks, Trivy, and SBOM generation.
6. Enable GitHub Private Vulnerability Reporting and branch protection. While
   the repository is private, enable GitHub Code Security and set
   `SCOPEHARBOR_CODE_SECURITY_ENABLED=true` if CodeQL and Dependency Review
   should run before public visibility.
7. Create the annotated `v1.1.0` tag only after the release checklist and CI
   are green.

## Known limits and future decisions

- ScopeHarbor is portfolio-first, local, and single-operator software. It is
  not designed as a hosted multi-tenant SaaS.
- Linux same-machine applications must listen on an interface reachable from
  Docker's host gateway. Docker Desktop supplies the normal host-local route.
- General local targets receive ScopeHarbor passive scans only. ZAP Passive,
  Active Demo, and Client Spider remain explicitly compatible disposable-demo
  features.
- The current UI supports local dev authentication and existing target-based
  workflows. Full OIDC operator UX and repository-asset UI integration remain
  work for the frontend phase; backend APIs are ready.
- The offline OSV database is operator-managed. Missing or stale data produces
  an explicit warning and skips dependency analysis instead of going online.
- External AI is optional and adds an operator-controlled data processor;
  deterministic template mode remains the safe default.
- Arbitrary public/cloud scanning, SaaS/RBAC administration, authenticated
  browser workflows, business-logic automation, Semgrep/full SAST, Nuclei, and
  PDF export remain out of scope unless explicitly approved.
- The source is released under MIT. The ScopeHarbor name has informal collision
  checking only, not legal trademark clearance.

Do not infer prior decisions that are absent from `AGENTS.md`, this handoff,
`README.md`, or `SECURITY.md`; ask when a missing decision would change scope or
safety.
