# ScopeHarbor Handoff

## Current state

ScopeHarbor — Local AppSec Audit Platform is at version `1.1.0`. V1 phases
1–19 and post-V1 phases 20–24 are merged into `main`. The Phase 24 CI repair
merged as pull request 50 at `2875e65`, and the required GitHub-hosted quality
and container jobs passed. Phase 25 frontend integration is complete on
`phase-25-frontend-integration` and is waiting for the repository owner to push,
review, and merge it before any later phase begins.

Phase 25 implementation and review commits:

- `2bdd078` — `feat(frontend): integrate subject-aware audit workflows`
- `a6ffe16` — `docs(frontend): document integrated operator workflows`
- `f81c3d8` — `fix(frontend): close protected workflow state gaps`
- `8783ec4` — `fix(frontend): clear cross-session form state`
- `d276519` — `fix(frontend): reset cross-session authorization`
- `aac7d75` — `fix(frontend): clear cross-workspace filters`

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
  authorization snapshots. Repository scans use checksum/commit-pinned,
  source-built Gitleaks 8.30.1-scopeharbor.1 and offline OSV-Scanner 2.5.0 with
  bounded regular-file-only staging.
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
| Operator UI | `frontend/src/` | Policy, subject-aware audit, governance, posture, report, AI, and in-memory bearer workflows |
| Runtime/CI | `docker-compose.yml`, `backend/Dockerfile`, `.github/workflows/` | Network isolation, images, quality, secret, SBOM, and vulnerability gates |

Default host endpoints are frontend `127.0.0.1:3001`, API
`127.0.0.1:8000`, Juice Shop `127.0.0.1:3000`, and PostgreSQL
`127.0.0.1:5432`. ZAP, worker, and relay remain internal-only.

## Public API additions

- Protected target-policy catalog, JSON target validation, and target
  reauthorization.
- Repository-asset create/list/read/archive plus repository dashboard and
  latest-comparison routes.
- Scan creation by either `target_id` or `repository_asset_id`. The current UI
  uses first-class subjects; the target-repository adapter remains deprecated
  for historical callers.
- Subject type/ID and repository-asset identity in scan, finding, risk,
  dashboard, comparison, report, and AI projections while retaining existing
  target fields.
- Current-posture basis and separately labelled historical dashboard metrics.
- Explicit AI generation with `POST /api/v1/scans/{id}/ai-explanations`; GET is
  retrieval-only for external providers.
- Suppression revocation, tag unassignment, and safe tag archiving.

See `docs/API.md` for request/response details.

## Phase 24 review decisions

The initial independent review identified five actionable findings. All were
accepted and fixed on the review branch:

- Target-based repository compatibility scans now persist only their
  repository-asset subject. Migration `0013_scan_subject_integrity` repairs
  existing rows and adds a database XOR constraint.
- Relay requests are capped before JSON parsing, including streamed bodies
  without `Content-Length`.
- Cookie handling projects only structured `Secure`, `HttpOnly`, and validated
  `SameSite` attributes; target-controlled names, values, paths, domains, and
  extensions do not cross the relay boundary.
- Relay bodies use a bounded base64 envelope with independently bounded and
  validated URL, header, redirect, and cookie metadata.
- Documentation now states that the relay disables automatic redirects and
  manually revalidates each bounded hop.

One preliminary documentation finding was rejected because commit `bde778a`
had already reconciled the HTTPS wording before the review branch began. A
second independent review of `main...phase-24-backend-review` found no
actionable defects. Its residual gaps were hosted-CI observation, an
independent upstream-archive re-fetch, multi-architecture binary
reproducibility, and migration testing against deployed rather than synthetic
data.

After merge, authenticated inspection of Container builds run `30943834633`
confirmed that the API, worker, relay, and frontend builds, all four Trivy
scans, and all four SBOMs passed. The final Compose readiness step then failed
because `SCOPEHARBOR_ENV_FILE=/dev/null` left required backend settings absent;
the backend correctly exited during startup. Commit `516ef53` generates one
mode-0600 CI environment with the trusted bootstrap, validates the required
rendered backend keys without printing their values, reuses that environment
for hardening/readiness, and installs cleanup before startup. An independent
review found no actionable issues. Its remaining runtime gap is hosted CI
because Docker Desktop was stopped locally.

Authenticated inspection of Backend quality run `30943832795` also showed an
admission-time workflow error rather than a backend test failure: GitHub does
not expose the `runner` context inside job-level `env`, so three
`${{ runner.temp }}` expressions prevented the job from starting. Commit
`ccad9cf` now derives the artifact, repository-staging, OSV-database, and
container-smoke environment paths from `$RUNNER_TEMP` inside executable steps,
exports them through `$GITHUB_ENV` for later steps, and creates the bounded
directories before use. The same correction was applied to the unpushed
container hotfix. Independent follow-up review found no actionable issues.

## Phase 25 review decisions

The independent frontend review found four high-priority state/truthfulness
defects and one testing gap. All were accepted and fixed:

- Authentication replacement, rejection, and logout now gate the UI behind a
  loading state and clear all previously protected workspace data before any
  new session is verified. Credential values, rotation values, form drafts,
  scan acknowledgements, audit phase, workspace-derived filters/messages, and
  pending management actions are cleared as well. A rejected OIDC token
  restores the configured local development session only after reloading it.
- Stale web-target policies are labelled as requiring reauthorization, show no
  eligible profiles, and route the operator back to the Scope phase.
- Finding lifecycle and suppression create/revoke actions refresh workspace
  posture plus the selected subject dashboard and comparison.
- Archived tags remain visible in governance history while any active
  assignments can still be removed.
- Six automated state/contract tests cover auth and credential-form clearing,
  stale policy, posture invalidation for lifecycle/suppression mutations,
  archived-tag assignments, mutually exclusive scan subjects, and explicit AI
  POST behavior. The frontend quality workflow now runs them.

The final follow-up review found no actionable issues and approved Phase 25.

## Final verification record

- A clean temporary PostgreSQL database migrated from zero through
  `0013_scan_subject_integrity`. Upgrade tests from `0008`, `0011`, and `0012`,
  repair/constraint fixtures, cleanup-task creation, and Alembic model drift
  all passed.
- Backend: 333 tests passed; 2 environment-dependent real-binary tests were
  skipped in the full run. The real Gitleaks redaction fixture passed
  separately and executed no repository scripts.
- Backend branch coverage: 85% overall. Focused coverage: authentication
  100.00%, SSRF/redirects 95.07%, persistence redaction 100.00%, artifact paths
  100.00%, and repository runner boundaries 96.42%.
- Ruff and Pyright: clean.
- Frontend: a clean `npm ci`, six Vitest/Testing Library state/contract tests,
  `npm audit --audit-level=high`, lint, and the Next.js 16.3.0 production build
  passed. The audit reported zero vulnerabilities. PostCSS remains pinned to
  8.5.25.
- Both Python production/development locks install with hashes and pass
  `pip-audit`; cryptography is pinned to 50.0.0.
- Compose rendering and network/privilege hardening validation passed. API,
  worker, relay, and frontend images built, and a clean isolated stack migrated
  and reached healthy/ready state before its disposable volumes were removed.
- Digest-pinned Trivy 0.70.0 reported no HIGH or CRITICAL findings for all four
  project images. CycloneDX SBOMs generated and validated for each image.
- The worker reports Gitleaks 8.30.1-scopeharbor.1 and OSV-Scanner 2.5.0. The
  current source-built OSV binary was not exercised against a freshly updated
  offline database during this review; that remains an operator release check.
- The Phase 24 CI repair is merged and its required GitHub-hosted workflows are
  green. Phase 25 frontend CI has not run because this branch has not been
  pushed. Compose hardening passed locally with a temporary validation-only
  relay secret. A local frontend image build could not start because Docker
  Desktop was stopped; the image build and Trivy scan therefore remain required
  pull-request checks.

## Operator actions

1. Push `phase-25-frontend-integration`, open a pull request, and require
   Frontend quality, Container builds / build, and every remaining required
   workflow to pass. Merge the branch into `main`, then confirm the merge before
   any later phase begins.
2. Run `python3 scripts/bootstrap_env.py`. It adds the relay secret and newly
   introduced settings without replacing a non-empty user-managed
   `AUTH_PROFILE_SECRET_KEY`; review the resulting `.env`.
3. Review every custom v2 allowlist entry, exact host-gateway address, base
   path, profile engine, and custom CA mount before authorizing targets.
4. Refresh the offline advisory database before repository dependency scans,
   then run the real OSV fixture:

   ```bash
   docker compose --profile maintenance run --rm osv-db-update
   ```

5. Review the committed Python and npm locks and the source-build pins, then
   repeat the dependency audits on the release commit. Exact commands are in
   `docs/RELEASE_CHECKLIST.md`.
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
- The UI supports local development auth and an operator-supplied OIDC bearer
  token held only in memory for one browser tab. It does not implement provider
  redirects, refresh-token storage, or session renewal.
- The current UI uses first-class repository assets. Deprecated target-based
  repository routes/columns remain only for historical callers and require a
  separately approved backend phase before removal.
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
