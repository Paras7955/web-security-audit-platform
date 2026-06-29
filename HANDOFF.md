# Defensive Web App Security Audit Platform Handoff

## Purpose

This file gives a new implementation session the project context needed to continue safely. Keep it updated at every phase boundary with current architecture, branch/commit status, verification results, known risks, and the next approved phase.

Do not include private reviewer-loop instructions or any information that should be hidden from review sub-agents. Treat this file as repo-visible project documentation.

## Current Branch And Phase

- Current phase branch: `phase-12-app-shell`
- Current phase: Phase 12, Frontend Decomposition And Authenticated App Shell
- Base branch at phase start: `main`
- Phase gate: stop after Phase 12 is complete and reviewed. Do not start Phase 13 until the user confirms this branch has been merged back into the base branch.

## Mission And Safety Model

The platform is a local-first defensive AppSec audit platform for intentionally vulnerable or explicitly authorized applications. It must not become an unauthorized scanning tool.

Core safety rules:

- Deny by default.
- Scan only exact configured targets from `config/scan-allowlist.yml`.
- Use Docker service names as canonical scanner targets.
- Do not scan arbitrary public URLs.
- Apply SSRF checks to every outbound scanner request.
- Bind custom scanner HTTP requests to the SSRF-validated destination IP.
- Disable automatic redirects and manually revalidate redirect destinations.
- Scope ZAP to the exact allowlisted target/context.
- Active Demo and AJAX Short scans remain local/demo only and require explicit acknowledgement.
- Repo scans require a saved allowlisted target with a configured local repo path under `REPO_SCAN_ROOT`.
- Repo scans must not clone, fetch, install dependencies, run package scripts, build, or execute repository code.
- Store normalized/redacted findings only.
- Do not store full HTTP response bodies by default.
- Never send raw artifacts, raw HTTP bodies, raw scanner output, unredacted evidence, cookies, credentials, or secrets to AI providers or reports.

## Architecture

- Frontend: Next.js on host port `3001`.
- Backend: FastAPI on host port `8000`.
- Worker: Python worker polling Postgres-backed scan jobs.
- Database: Postgres on host port `5432`.
- Scanner tooling: conservative custom passive scanner, scoped ZAP, deterministic repo scanner stubs.
- Demo target: OWASP Juice Shop on host port `3000`.
- ZAP daemon: internal Compose service only.
- Canonical scanner target inside Docker: `http://juice-shop:3000`.

Current scan modes:

- `passive`
- `active_demo`
- `ajax_short`
- `repo`

Reports are available for completed `passive`, `active_demo`, and `repo` scans. AI explanations are available for completed `passive` and `active_demo` scans only; repo findings remain excluded from AI.

## Phase History

- Phases 1-3: scaffold, target allowlist validation, database-backed scan jobs, worker lifecycle.
- Phase 4: normalized finding persistence and redaction.
- Phase 5: guarded passive scanner with SSRF and redirect controls.
- Phase 6: findings dashboard.
- Phase 7: Markdown/HTML reports from normalized findings.
- Phase 8: deterministic template AI and optional OpenAI provider using safe finding projections.
- Phase 9A-9C: scoped ZAP passive, bounded Active Demo, bounded AJAX Short.
- Phase 9D: multimode report/AI hardening for passive and Active Demo.
- Phase 10: deterministic repo scan mode, repo path safety, repo findings in reports, repo findings excluded from AI.
- Phase 11: platform auth, workspace isolation, worker job context, initial repo-visible handoff.
- Phase 12 in progress: frontend decomposition and authenticated workspace app shell.

## Phase 11 Design

Authentication is provider-agnostic OIDC/JWT with Auth0 as the preferred provider. Auth identities use:

- `provider`
- `provider_subject`

Local Docker/tests use explicit dev auth:

- `APP_ENV=local`
- `AUTH_MODE=dev`
- `AUTH_PROVIDER=dev`
- `DEV_AUTH_TOKEN=dev-token`

Production-like configuration must use `AUTH_MODE=required` and complete OIDC settings. Dev auth must not run in production, dev and production auth settings must not coexist, and invalid auth configuration must fail startup.

Workspace isolation is enforced in backend code. Existing protected APIs require bearer auth and scope data to the authenticated principal's workspace. Background-owned records carry persisted workspace/user context rather than relying only on later target ownership lookup.

Phase 11 commits so far:

- `afb63a1 feat: add workspace ownership schema`
- `79019c4 feat: add provider agnostic auth foundation`
- `584349f feat: enforce workspace scoped APIs`
- `50c969b feat: attach auth token in frontend API calls`
- `37f7c18 test: cover auth workspace enforcement`
- `32d6e9a docs: add phase 11 handoff context`
- `f0e500a fix: harden auth workspace review findings`
- `3954958 adding rule to confirm user actions needed`

## Phase 11 Implementation State

Implemented:

- `PlatformUser` and provider-agnostic `AuthIdentity`.
- `Workspace.owner_user_id`.
- Non-null `workspace_id` and `created_by_user_id` context on targets, scans, evidence artifacts, and report artifacts.
- Non-null `workspace_id` on findings.
- Alembic revision `0002_auth_workspaces` to create identity tables, backfill existing rows into deterministic legacy/dev ownership, and add workspace indexes.
- Auth config validation and bearer-token dependency.
- Dev auth that creates a deterministic dev user/workspace.
- OIDC JWT validation foundation using configured issuer, audience, JWKS URL, and provider.
- OIDC/JWT validation errors are returned as authentication failures rather than unhandled server errors.
- Workspace-scoped current target, scan, finding, report, and AI APIs.
- Report-by-ID and finding-by-ID access scoped by workspace.
- Report generation validates scan-target workspace consistency before rendering target metadata.
- Findings/evidence/report artifacts inherit workspace/user context from the persisted scan.
- Worker validation rejects scans whose workspace does not match the target workspace.
- Frontend API calls attach the dev bearer token from `NEXT_PUBLIC_DEV_AUTH_TOKEN`.
- Frontend report view/download now fetch with Authorization headers instead of using plain anchors.
- Backend readiness checks include auth/workspace tables.

Verification so far:

- `python3 -m py_compile` for changed backend source and tests.
- `docker compose build backend migrate`
- `docker compose run --rm migrate`
- `docker compose run --rm backend python -m unittest tests.test_auth_workspaces tests.test_targets_api tests.test_scans_api tests.test_findings_api tests.test_ai_explanations tests.test_reports tests.test_scan_worker`
  - Result: 79 tests OK.
- `docker compose run --rm backend python -m unittest discover tests`
  - Result: 150 tests OK.
- `docker compose build frontend`
- `docker compose run --rm frontend npm run build`
  - Result: passed.
- Review-fix focused tests:
  - `docker compose run --rm backend python -m unittest tests.test_auth_workspaces tests.test_reports`
  - Result: 25 tests OK.
- Final Phase 11 full backend tests:
  - `docker compose run --rm backend python -m unittest discover tests`
  - Result: 153 tests OK.

Phase 11 close status:

- Phase 11 was reviewed, fixed, merged to `main`, and used as the base for Phase 12.

Review decision:
- Finding: Required-mode OIDC/JWT token and JWKS failures could escape as unhandled exceptions.
- Decision: Accepted.
- Rationale: Invalid bearer tokens and validation failures should consistently return authentication failures, not 500 responses.
- Follow-up: Wrapped PyJWT/JWKS validation failures as `AuthError` and added request-time required-mode coverage.

Review decision:
- Finding: Blank `AUTH_PROVIDER` was allowed in required mode.
- Decision: Accepted.
- Rationale: Empty provider namespaces undermine provider-agnostic identity ownership.
- Follow-up: Required non-empty provider in `AUTH_MODE=required` and added config coverage.

Review decision:
- Finding: Report generation did not revalidate target workspace against scan workspace.
- Decision: Accepted.
- Rationale: Reports include target metadata, so corrupted/stale scan-target ownership must fail closed.
- Follow-up: Added scan-target workspace validation, filtered report findings by scan workspace, and added regression coverage.

## Phase 12 Implementation State

Implemented:

- Split the monolithic frontend dashboard workflow into focused modules:
  - `frontend/src/lib/securityAuditApi.ts`
  - `frontend/src/components/dashboard/TargetForm.tsx`
  - `frontend/src/components/dashboard/ScanControls.tsx`
  - `frontend/src/components/dashboard/ReportsPanel.tsx`
  - `frontend/src/components/dashboard/AiExplanationsPanel.tsx`
  - `frontend/src/components/dashboard/FindingsDashboard.tsx`
- Replaced `TargetSetup.tsx` with a smaller workflow controller that owns data loading, polling, selected scan/finding state, and report download/view behavior.
- Added `frontend/src/components/AppShell.tsx` as the authenticated workspace shell with top navigation, workspace indicator, overview metrics, and safety chips.
- Replaced the old landing/contract page with the operational app shell.
- Preserved the existing target creation, repo path attachment, scan launch, scan polling, findings, reports, and AI explanation behavior.

Phase 12 commits so far:

- `b977d1b refactor: split dashboard workflow components`
- `46a4bda feat: add authenticated workspace app shell`
- `691302c docs: update phase 12 handoff`

Verification so far:

- `docker compose build frontend`
- `docker compose run --rm frontend npm run build`
  - Result: passed after each Phase 12 subdivision.
- `docker compose run --rm backend python -m unittest discover tests`
  - Result: 153 tests OK after starting the `juice-shop` Compose service required by allowlist validation tests.

Known verification still needed before Phase 12 close:

- Final frontend production build.
- Review-fix commit and follow-up review.

Review decision:
- Finding: The app shell displayed hard-coded local/dev workspace and auth labels.
- Decision: Accepted.
- Rationale: Phase 12 should present a provider-agnostic authenticated workspace shell and avoid implying the real provider/workspace can be inferred in frontend-only state.
- Follow-up: Replaced the local/dev labels with invariant workspace-scoped data access and bearer-token API boundary language instead of runtime/session claims.

Review decision:
- Finding: App shell navigation links were mostly decorative and the first item was always styled as active.
- Decision: Accepted.
- Rationale: Operational navigation should point to real sections and avoid misleading active state without route/state tracking.
- Follow-up: Added stable section anchors for targets, scans, reports, and findings; changed nav items to those anchors; removed the permanent first-item active style.

## Current API Surface

Protected by bearer auth:

- `GET /targets/validate`
- `POST /targets`
- `GET /targets`
- `GET /targets/{target_id}`
- `PATCH /targets/{target_id}/repo-path`
- `POST /scans`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `GET /findings/{finding_id}`
- `POST /scans/{scan_id}/reports`
- `GET /scans/{scan_id}/reports`
- `GET /reports/{report_id}`
- `GET /reports/{report_id}/download`
- `GET /scans/{scan_id}/ai-explanations`

Public operational endpoints:

- `GET /health`
- `GET /ready`
- `GET /contracts`

## Roadmap Plan

Phase 12, `phase-12-app-shell`:

- Decompose `TargetSetup.tsx`.
- Add authenticated operational app shell.
- Preserve existing functionality behind a typed workspace-aware API client.

Phase 13, `phase-13-scan-profiles`:

- Add code-defined scan profiles: `passive-web`, `active-demo`, `ajax-short`, `repository`.
- Add `scan_profile_id` while keeping current scan modes as internal execution primitives.

Phase 14, `phase-14-auth-profiles`:

- Add target-application auth profiles separate from platform user auth.
- Support conservative bearer/custom header profiles first.
- Encrypt stored secret material and never expose secrets to findings, reports, AI, logs, artifacts, or audit events.

Phase 15, `phase-15-dashboards-risk`:

- Add deterministic, versioned risk scores.
- Add workspace/target dashboards and scan comparison.

Phase 16, `phase-16-finding-management`:

- Add finding lifecycle, suppression, tags, and advanced filtering.
- Suppression applies only after normalization and never consumes raw scanner output.

Phase 17, `phase-17-ai-rate-limits`:

- Add AI request accounting, rate limiting, persisted/cached AI content, and invalidation rules.
- AI explains deterministic risk inputs but does not compute risk.

Phase 18, `phase-18-platform-ops`:

- Add general rate limiting, append-only audit log, scan cancellation, and health dashboard.

Phase 19, `phase-19-demo-seed-docs`:

- Add deterministic demo seed command and documentation hardening.

## Workflow Rules

- Before each phase, verify clean worktree and create/switch to the dedicated `phase-*` branch.
- Use multiple focused commits inside a phase.
- Report each commit hash, message, verification, and next step.
- Run the public review workflow at phase end after implementation commits.
- Treat review findings as advisory; document accepted/rejected findings in implementation summaries.
- Commit accepted review fixes separately.
- Do not push unless the user explicitly asks.
- Stop at phase boundaries and wait for user approval plus merge confirmation before starting the next phase.
- End every implementation or phase summary with a clear user-action note. If the user must do anything before work can continue or a feature can be fully used, state exactly what is needed, such as a URL, `.env` value, API key name, merge confirmation, manual deployment step, or production configuration. If no user action is needed, say so explicitly.
