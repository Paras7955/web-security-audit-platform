# Defensive Web App Security Audit Platform

Local-first defensive AppSec audit platform for intentionally vulnerable or explicitly authorized web applications.

The project is designed as a cybersecurity resume project. Tools collect evidence; the platform normalizes findings; reports and AI-assisted explanations help developers understand and fix issues. The scanner is not intended for unauthorized testing.

## V1 Architecture

- Frontend: Next.js.
- Backend: FastAPI.
- Worker: Python worker for Postgres-backed scan jobs and bounded passive scanning.
- Database: Postgres.
- Security tooling: conservative custom passive scanning, scoped ZAP integration, and deterministic repo scanner adapters.
- Demo target: OWASP Juice Shop.
- Deployment: local Docker Compose.

Inside Docker, scanner targets use service names. The canonical Juice Shop scanner URL is:

```text
http://juice-shop:3000
```

From the host browser, Juice Shop is exposed as:

```text
http://localhost:3000
```

## Phase 1 Status

Phase 1 scaffolds the application contracts and safety docs. Target creation, scanning, findings, reports, AI, and ZAP workflows are implemented in later phases and must not be implied as production-ready by Phase 1 UI.

## Phase 2 Status

Phase 2 adds target validation and target creation. The backend validates submitted URLs against `config/scan-allowlist.yml`, applies deny-by-default destination checks, and stores authorized targets only after permission confirmation.

Implemented target APIs:

- `GET /targets/validate?target_url=...`
- `POST /targets`
- `GET /targets`
- `GET /targets/{target_id}`

Phase 2 does not run scans. The UI may save an allowlisted target, but scan execution starts in Phase 3.

## Phase 3 Status

Phase 3 adds database-backed scan jobs and a worker lifecycle. The backend can create passive scan jobs, the worker claims queued jobs, updates `status` and `current_step`, creates a bounded scan artifact directory, and completes an internal lifecycle task.

Implemented scan APIs:

- `POST /scans`
- `GET /scans`
- `GET /scans/{scan_id}`

Phase 3 lifecycle jobs do not crawl targets, run passive checks, call ZAP, or generate findings. They exist to prove queueing, worker status transitions, artifact path handling, and dashboard polling before real scanner execution is added in later phases.

## Phase 4 Status

Phase 4 adds normalized finding persistence primitives. The backend now has validated normalized finding inputs, evidence redaction and snippet capping, dedupe key generation, evidence artifact reference persistence, and fixture-backed tests for storing findings against a scan.

Phase 4 does not yet add scanner-produced findings to the UI. Findings storage is ready for later scanner integrations and the dashboard phase.

## Phase 5 Status

Phase 5 adds the conservative custom passive scanner. The worker now runs queued passive scans against allowlisted targets, routes each outbound request through the guarded scanner HTTP client, follows redirects only after manual validation, writes a bounded crawl summary artifact, and persists normalized findings.

Implemented passive scanner capabilities:

- Guarded HTTP requests with automatic redirects disabled.
- Custom scanner HTTP requests connect to the SSRF-validated destination IP to avoid DNS drift between validation and connection.
- Bounded same-target crawl using the configured crawl depth and page cap.
- Link, form, input, header, cookie, status, and redirect metadata collection.
- Missing security header checks.
- Cookie attribute checks.
- Password-form GET-method checks.
- Conservative exposed-file probes.
- Login/admin route hints.

Phase 5 does not call ZAP, run active scans, run AJAX crawling, generate reports, or expose a finished findings dashboard. Those are implemented in later phases.

## Phase 6 Status

Phase 6 adds the findings dashboard. The UI can create allowlisted targets, start passive scans, poll worker progress, show scan history, filter normalized findings by severity, and display finding evidence/details.

Implemented dashboard capabilities:

- Saved target selection for passive scans.
- Scan history and selected-scan progress.
- Current step and status message display.
- Findings table with severity filters.
- Finding detail panel with evidence, rule metadata, CWE/OWASP fields, and redaction status.
- Scan mode safety copy showing Active Demo and AJAX Short as later gated phases.

Phase 6 does not call ZAP. ZAP integration remains planned for later phases.

## Phase 7 Status

Phase 7 adds Markdown and HTML report generation for completed passive scans. Reports are generated from normalized findings that have already passed through the persistence redaction path.

Implemented report capabilities:

- `POST /scans/{scan_id}/reports`
- `GET /scans/{scan_id}/reports`
- `GET /reports/{report_id}`
- `GET /reports/{report_id}/download`
- Deterministic Markdown and escaped HTML report rendering.
- Report artifact persistence under each scan artifact directory.
- Dashboard report generation, view, and download links.
- Responsible-use, limitations, scan mode, ZAP/AJAX/repo-scan, AI, and redaction disclosures.

Phase 7 does not call ZAP, run repo scanning, test authenticated workflows, or perform business logic checks.

## Phase 8 Status

Phase 8 adds AI-assisted explanations for completed passive scan findings. The default provider is deterministic `template`; optional `openai` mode is available through the backend provider interface.

Implemented AI explanation capabilities:

- `GET /scans/{scan_id}/ai-explanations`
- Provider-agnostic explanation service with template and optional OpenAI providers.
- Severity/confidence prioritization and severity grouping.
- OWASP/CWE/remediation explanation helpers.
- Provider fallback to template explanations when optional OpenAI mode is unavailable or fails.
- AI generation is limited to completed passive scans.
- Provider URLs are stripped of query strings and fragments before leaving the backend.
- Dashboard AI explanations panel with provider and fallback disclosure.
- Markdown and HTML reports include generated AI explanation summaries and per-finding notes.

AI provider inputs are restricted to normalized finding fields and redacted evidence snippets. If redaction has not been confirmed for a finding, evidence, reproduction, and remediation text are omitted from provider payloads. Raw response bodies, raw artifacts, raw ZAP output, secret scanner output, and unredacted evidence must not be sent to AI providers.

Relevant environment settings:

```text
AI_PROVIDER=template
OPENAI_MODEL=
OPENAI_API_KEY=
REPO_SCAN_ROOT=/app/repositories
```

Set `AI_PROVIDER=openai` only when an OpenAI API key and model are configured. If OpenAI configuration is missing or the provider request fails, the backend returns template explanations and discloses the fallback.

Phase 8 does not call ZAP, run repo scanning, test authenticated workflows, or perform business logic checks.

## Phase 9A Status

Phase 9A adds scoped ZAP passive analysis to the passive scan worker. The custom guarded crawler still controls target discovery; ZAP receives only allowlisted URLs that were validated against the configured target scope.

Implemented ZAP passive capabilities:

- Creates an isolated ZAP session/context per scan.
- Includes only the exact allowlisted target origin in the ZAP context.
- Serializes access to the shared ZAP daemon with a database advisory lock.
- Submits bounded allowlisted URLs to ZAP as SSRF-validated destination-IP-pinned URLs with automatic redirect following disabled.
- Polls ZAP passive records and normalizes ZAP alerts into persisted findings.
- Paginates ZAP alerts up to the configured cap and reports truncation as a scan warning.
- Stores normalized/redacted ZAP alert metadata only, not raw ZAP output or response bodies.
- Treats ZAP API failures or passive-scan timeouts as scan warnings instead of failing the custom passive scan.
- Dashboard and reports disclose that ZAP passive analysis is used.

Phase 9A does not run ZAP active scans, AJAX crawling, repo scanning, authenticated workflows, or business logic checks.

## Phase 9B Status

Phase 9B adds a bounded Active Demo scan mode for the local OWASP Juice Shop demo target. Active Demo is deliberately narrower than general active scanning and remains unavailable for arbitrary public URLs.

Implemented Active Demo capabilities:

- `POST /scans` accepts `mode: "active_demo"` only for allowlisted `local_demo` targets.
- Active Demo requests require `active_demo_acknowledged: true`.
- The dashboard exposes a mode selector and acknowledgement checkbox before queuing Active Demo scans.
- The worker runs the existing custom passive and ZAP passive checks before the bounded ZAP active step.
- ZAP active traffic is scoped to the exact allowlisted context and submitted through SSRF-validated destination-IP-pinned URLs.
- Shared ZAP daemon access remains serialized with the advisory lock.
- ZAP active alerts are normalized as `zap-active` findings and pass through the same redaction/persistence path.

Phase 9B does not enable arbitrary active scans, AJAX crawling, repo scanning, authenticated workflows, or business logic checks.

## Phase 9C Status

Phase 9C adds a bounded AJAX Short scan mode for the local OWASP Juice Shop demo target. AJAX Short uses ZAP's browser-driven AJAX spider as a short passive crawling aid; it is not an authenticated workflow, business-logic test, or arbitrary public web crawler.

Implemented AJAX Short capabilities:

- `POST /scans` accepts `mode: "ajax_short"` only for allowlisted `local_demo` targets.
- AJAX Short requests require `ajax_short_acknowledged: true`.
- The dashboard exposes AJAX Short selection and acknowledgement before queuing AJAX Short scans.
- The worker runs the existing custom passive and ZAP passive checks before the bounded ZAP AJAX crawl.
- ZAP AJAX traffic is scoped to the exact allowlisted context and submitted through SSRF-validated destination-IP-pinned URLs.
- Shared ZAP daemon access remains serialized with the advisory lock.
- ZAP AJAX alerts are normalized as `zap-ajax` findings and pass through the same redaction/persistence path.

Phase 9C does not enable arbitrary AJAX crawling, authenticated browser sessions, login workflows, repo scanning, public URL scanning, or business logic checks.

## Phase 9D Status

Phase 9D expands reports and AI explanations to normalized Active Demo findings while keeping repo-scan findings out of scope until Phase 10 normalization and redaction exists.

Implemented Phase 9D capabilities:

- Reports support completed `passive` and `active_demo` scans.
- AI explanations support completed `passive` and `active_demo` scans.
- OpenAI remains optional; the default provider remains deterministic `template`.
- Provider payload tests prove AI receives only normalized/redacted fields from Active Demo findings.
- Reports and AI do not receive raw ZAP alerts, raw HTTP bodies, raw artifacts, unredacted evidence, or secrets.
- AJAX Short remains dashboard/findings-only for reports and AI in Phase 9D.
- Repo-scan findings remain out of Phase 9D and should be handled only after Phase 10 normalization/redaction exists.

## Phase 10 Status

Phase 10 adds repo scanning for existing allowlisted targets with a configured local repo path. Repo scanning uses deterministic Docker-contained scanner adapter stubs in this phase; later work can replace the stub internals with real tools behind the same adapter interface.

Implemented Phase 10 capabilities:

- `POST /scans` accepts `mode: "repo"` only for saved allowlisted targets with a valid local repo path.
- Repo paths must be absolute, exist as directories, stay under `REPO_SCAN_ROOT`, and must not be symlinks.
- Docker Compose mounts this project read-only at `/app/repositories/security-project` for local demo repo scans.
- Repo scans do not clone remote code, install dependencies, fetch remote repositories, run package scripts, run builds, or execute repository code.
- Deterministic Gitleaks-style and dependency scanner adapter stubs emit normalized findings.
- Repo findings pass through the same persistence redaction path as web findings.
- Reports support completed `passive`, `active_demo`, and `repo` scans.
- AI explanations remain limited to completed `passive` and `active_demo` scans; repo findings are not sent to AI providers in Phase 10.

## Phase 11 Status

Phase 11 adds provider-agnostic platform authentication foundations, workspace isolation, and persisted worker job context.

Implemented Phase 11 capabilities:

- Platform users and provider-agnostic auth identities using `provider` plus `provider_subject`.
- Auth0 remains the preferred production identity provider, but backend OIDC/JWT validation is provider-agnostic.
- Explicit local dev auth for Docker and tests using `AUTH_MODE=dev`.
- Startup validation fails closed when auth configuration is invalid.
- Dev auth cannot run with `APP_ENV=production`, and dev auth cannot coexist with production OIDC settings.
- Existing target, scan, finding, report, and AI APIs require bearer authentication.
- Backend API access is scoped to the authenticated workspace, including report-by-ID and finding-by-ID routes.
- Scans, findings, evidence artifacts, and report artifacts carry persisted workspace context.
- Scans, targets, evidence artifacts, and report artifacts carry persisted user context where applicable.
- Worker lifecycle validation rejects scan jobs whose persisted workspace does not match the target workspace.
- Frontend local dev API calls attach the configured dev bearer token.

Important local dev auth settings:

```text
APP_ENV=local
AUTH_MODE=dev
AUTH_PROVIDER=dev
DEV_AUTH_TOKEN=dev-token
DEV_AUTH_USER_ID=dev-user
DEV_AUTH_WORKSPACE_ID=dev-workspace
DEV_AUTH_SUBJECT=dev-user
NEXT_PUBLIC_DEV_AUTH_TOKEN=dev-token
```

Production-like auth uses:

```text
AUTH_MODE=required
AUTH_PROVIDER=auth0
AUTH_OIDC_ISSUER=
AUTH_OIDC_AUDIENCE=
AUTH_OIDC_JWKS_URL=
```

Phase 11 does not add target-application authentication profiles. Those remain planned for Phase 14.

## Phase 12 Status

Phase 12 decomposes the frontend dashboard and replaces the old phase-oriented landing page with an authenticated workspace console.

Implemented Phase 12 capabilities:

- Split the large `TargetSetup.tsx` dashboard into focused frontend modules for API types/client helpers, target setup, scan launch/history/progress, reports, AI explanations, and findings.
- Preserved existing target creation, repo path attachment, scan launch, scan polling, findings, reports, and AI explanation behavior.
- Added an authenticated workspace app shell with top navigation, workspace indicator, overview metrics, and safety status chips.
- Replaced the landing/contract overview page with the operational workspace console as the first screen.

Phase 12 does not add finding management, risk scoring, or target-application authentication profiles. Those remain planned for later phases.

## Phase 13 Status

Phase 13 adds code-defined scan profiles while preserving existing scan modes as internal worker execution primitives.

Implemented Phase 13 capabilities:

- Added scan profiles: `passive-web`, `active-demo`, `ajax-short`, and `repository`.
- Added `scan_profile_id` persistence on scans with migration/backfill from existing `mode` values.
- Updated scan creation to accept `scan_profile_id` while temporarily preserving deprecated `mode` input for compatibility.
- Rejects mismatched `scan_profile_id` and `mode` input.
- Routes acknowledgement, local-demo, repo-path, report eligibility, and AI eligibility decisions through scan profile metadata.
- Keeps active/AJAX/repo safety gates enforced in backend code.
- Updated the frontend scan launcher to select profiles and send `scan_profile_id`.

Phase 13 does not add user-editable scan profiles, target-application authentication profiles, finding lifecycle management, risk scoring, or dashboards. Those remain planned for later phases.

## Responsible Use

Only scan apps you own, run locally, or are explicitly authorized to test. Active scanning is restricted to local/demo allowlisted targets. See [SECURITY.md](./SECURITY.md) before running or extending scan features.

## Local Services

Planned Docker Compose services:

- `frontend`: Next.js UI on host port `3001`.
- `backend`: FastAPI API on host port `8000`.
- `worker`: background scan worker.
- `postgres`: database on host port `5432`.
- `zap`: OWASP ZAP daemon/API reachable inside Compose only, not published to the host.
- `juice-shop`: OWASP Juice Shop on host port `3000`.

## Shared Contracts

Scan modes:

- `passive`
- `active_demo`
- `ajax_short`
- `repo`

Scan statuses:

- `queued`
- `validating`
- `running`
- `normalizing`
- `completed`
- `completed_with_warnings`
- `failed`
- `cancelled`

Detailed scan steps:

- `target_validation`
- `custom_crawl`
- `custom_checks`
- `zap_spider`
- `zap_passive`
- `zap_active`
- `zap_ajax`
- `repo_secrets_scan`
- `repo_dependency_scan`
- `normalizing_findings`
- `generating_reports`
- `generating_ai_explanations`

## Roadmap Scope Control

Post-v1 unless explicitly approved:

- Playwright login/session workflows.
- User A/User B IDOR checks.
- Business-logic rule testing.
- MockBank custom demo app.
- Nuclei templates.
- Semgrep/full SAST.
- PDF export.
- RBAC, team administration, and production user-management hardening beyond Phase 11 workspace isolation.
- Public cloud scanning.

## Phase Approval Gate

Implementation stops after each phase. The next phase starts only after explicit user approval.

Within an approved phase, work is split into commit-sized subdivisions. The agent may commit each subdivision, continue through the phase, and then stop at the phase boundary for review and user approval. Subdivisions are the minimum planning unit, not a hard one-commit limit: the agent may use one commit, multiple focused commits, or follow-up fix commits when that makes the history clearer or safer.

Each future phase is developed on its own branch using the `phase-*` naming pattern. The user merges the completed phase branch back into the base branch after phase review. Historical branches may still use the older `codex/phase-*` prefix, but new branches follow the `phase-*` convention.

Planned phase branches:

- Phase 4: `phase-4-findings`
- Phase 5: `phase-5-passive-scanner`
- Phase 6: `phase-6-dashboard`
- Phase 7: `phase-7-reports`
- Phase 8: `phase-8-ai-explanations`
- Phase 9A: `phase-9a-zap-passive`
- Phase 9B: `phase-9b-active-demo`
- Phase 9C: `phase-9c-ajax-short`
- Phase 9D: `phase-9d-multimode-reports-ai`
- Phase 10: `phase-10-repo-scanning`

Before a phase starts, the agent verifies a clean worktree, creates or switches to the phase branch from the current base branch, and confirms the active branch. Do not begin the next phase until the user confirms the previous phase branch has been merged back into the base branch.

Review-agent policy for future phases:

- The review sub-agent is pinned to `gpt-5.4` with `medium` reasoning.
- This pin applies only to the review sub-agent, not to the main implementation chat model or to other spawned agents.
- The main implementation agent manages any follow-up review passes after review-fix commits.
- Review orchestration stays in the main implementation context; reviewer prompts should remain ordinary code-review prompts.
- If the review sub-agent is unavailable, the fallback remains a separate self-review pass using the same checklist.
- If `gpt-5.4` is removed or renamed later, replace this note with the closest supported review-grade successor and keep it aligned with `AGENTS.md`.

## Database Migrations

Docker Compose includes a one-shot `migrate` service that runs:

```text
alembic upgrade head
```

The backend readiness endpoint verifies that the initial schema exists before reporting ready.

## Verification Notes

The full verification path is Docker Compose based because backend tests expect the Compose database and service hostnames by default:

```text
docker compose build backend migrate
docker compose run --rm backend python -m unittest discover tests
docker compose run --rm frontend npm run build
```

Host-side backend tests require an explicit `DATABASE_URL` that points at a reachable Postgres instance with the migrated schema. Host-side frontend builds require local `node_modules`.
