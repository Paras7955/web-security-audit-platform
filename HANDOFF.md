# Defensive Web App Security Audit Platform Handoff

## Purpose

This file gives a new implementation session the project context needed to continue safely. Keep it updated at every phase boundary with current architecture, branch/commit status, verification results, known risks, and the next approved phase.

Do not include private reviewer-loop instructions or any information that should be hidden from review sub-agents. Treat this file as repo-visible project documentation.

## Current Branch And Phase

- Current phase branch: `phase-13-scan-profiles`
- Current phase: Phase 13, Scan Profiles, complete and awaiting merge
- Base branch at phase start: `main`
- Phase gate: stop after Phase 13 is complete and reviewed. Do not start Phase 14 until the user confirms this branch has been merged back into the base branch.

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

Current scan profiles:

- `passive-web` -> internal mode `passive`
- `active-demo` -> internal mode `active_demo`
- `ajax-short` -> internal mode `ajax_short`
- `repository` -> internal mode `repo`

Current internal worker scan modes:

- `passive`
- `active_demo`
- `ajax_short`
- `repo`

Reports and AI eligibility are determined by scan profile metadata. In the current profile set, reports are available for completed `passive-web`, `active-demo`, and `repository` scans. AI explanations are available for completed `passive-web` and `active-demo` scans only; repository findings remain excluded from AI.

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
- Phase 12: frontend decomposition and authenticated workspace app shell.
- Phase 13: code-defined scan profiles, `scan_profile_id` persistence, compatibility mode input, profile-driven eligibility, and frontend profile selection.

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
- `4511d94 fix: align app shell review findings`
- `041331d fix: avoid session claims in app shell`
- `f377954 docs: close phase 12 handoff`
- `2458515 fix: resolve app shell review loop findings`
- `526af1f docs: record phase 12 review loop`
- `09ee453 fix: surface app shell bootstrap failures`
- `ac3820b fix: clear recovered bootstrap errors`

Verification so far:

- `docker compose build frontend`
- `docker compose run --rm frontend npm run build`
  - Result: passed after each Phase 12 subdivision and after each review-fix commit.
- `docker compose run --rm backend python -m unittest discover tests`
  - Result: 153 tests OK after starting the `juice-shop` Compose service required by allowlist validation tests.

Phase 12 close status:

- Corrected review loop is now using one fresh `gpt-5.4` reviewer with repeated broad passes.
- The first corrected-loop pass found one accepted stale-bootstrap-banner bug and one residual frontend coverage gap.
- Accepted fixes were committed in `ac3820b`.
- Follow-up broad pass from the same reviewer found no additional actionable issues meeting the review bar.
- Phase 12 was merged to `main` and used as the base for Phase 13.

Review decision:
- Finding: The app shell displayed hard-coded local/dev workspace and auth labels.
- Decision: Accepted.
- Rationale: Phase 12 should present a provider-agnostic authenticated workspace shell and avoid implying the real provider/workspace can be inferred in frontend-only state.
- Follow-up: Replaced current-session styled labels with neutral architecture/data-model language and changed auth-related shell copy to describe protected API endpoints rather than a credential mechanism or runtime session state.

Review decision:
- Finding: App shell navigation links were mostly decorative and the first item was always styled as active.
- Decision: Accepted.
- Rationale: Operational navigation should point to real sections and avoid misleading active state without route/state tracking.
- Follow-up: Added stable section anchors for targets, scans, reports, and findings; changed nav items to those anchors; removed the permanent first-item active style.

Review decision:
- Finding: The overview metric grid stayed four columns on narrow viewports.
- Decision: Accepted.
- Rationale: The new first-screen app shell must remain readable on mobile and should follow the existing single-column breakpoint behavior.
- Follow-up: Added `.metricStrip` to the existing `900px` single-column responsive breakpoint.

Review decision:
- Finding: Initial target/scan bootstrap failures were silently treated as empty target/scan data.
- Decision: Accepted.
- Rationale: After Phase 12 made the shell the first screen, unauthenticated, forbidden, or backend-unavailable states must be visible instead of appearing as a valid empty workspace.
- Follow-up: Initial target and scan loaders now use shared response error handling and display a bootstrap error banner on load failure.

Review decision:
- Finding: The bootstrap error banner could remain stale after later successful target or scan loads.
- Decision: Accepted.
- Rationale: A recovered app shell should not continue displaying a false workspace-load failure.
- Follow-up: Successful target and scan history loads now clear the bootstrap error banner.

Review decision:
- Finding: Frontend workflow coverage remains build-only after the decomposition.
- Decision: Deferred.
- Rationale: The gap is real, but introducing a frontend test framework and meaningful React workflow tests is larger than the accepted Phase 12 close-out fixes. Docker production build remains the current verification, and broader frontend interaction tests should be added in a dedicated follow-up.
- Follow-up: Record as residual risk for the phase summary.

## Phase 13 Implementation State

Implemented:

- Added code-defined scan profile metadata in `shared/contracts.json` and mirrored frontend constants in `frontend/src/lib/contracts.ts`.
- Added backend `ScanProfile` registry helpers in `backend/app/core/contracts.py`.
- Added Alembic revision `0003_scan_profiles` with `scans.scan_profile_id`, mode-based backfill, and an index.
- Added `Scan.scan_profile_id` to the SQLAlchemy model and API response schema.
- Updated scan creation to accept `scan_profile_id`.
- Kept deprecated `mode` input for compatibility.
- Rejects `scan_profile_id`/`mode` mismatches when both are supplied.
- Defaults omitted profile/mode input to `passive-web`.
- Keeps internal `mode` as the worker execution primitive.
- Moved active/AJAX acknowledgement, local-demo, repo-path, report eligibility, and AI eligibility decisions to scan profile metadata where appropriate.
- Report and AI eligibility fail closed when a persisted `scan_profile_id` is unknown or inconsistent with the persisted worker `mode`.
- Report generation uses profile `ai_enabled` to decide whether to generate AI explanations or use the disabled placeholder.
- Updated the frontend scan launcher to select profiles and send `scan_profile_id`.
- Updated the app shell to show the number of scan profiles instead of raw worker modes.

Phase 13 commits:

- `99fa7b4 feat: add scan profile schema registry`
- `9f1c200 feat: create scans from profiles`
- `90fe28c feat: select scan profiles in frontend`
- `7d7b170 fix: align profile eligibility with scan mode`
- `4288c40 chore: show scan profile count in shell`
- `6ef4669 fix: enforce authoritative scan profiles`

Verification:

- `python3 -m py_compile backend/app/core/contracts.py backend/app/api/schemas.py backend/app/api/scans.py backend/app/ai/service.py backend/app/reports/service.py backend/tests/test_scans_api.py`
  - Result: passed.
- `docker compose build backend migrate frontend`
  - Result: passed.
- `docker compose run --rm migrate`
  - Result: applied `0003_scan_profiles`.
- `docker compose up -d juice-shop`
  - Result: started local demo target required by allowlist validation tests.
- `docker compose run --rm backend python -m unittest tests.test_scans_api tests.test_reports tests.test_ai_explanations tests.test_scan_worker`
  - Result: 68 tests OK after review fixes.
- `docker compose run --rm backend python -m unittest discover tests`
  - Result: 157 tests OK.
- `docker compose build frontend`
  - Result: passed.
- `docker compose run --rm frontend npm run build`
  - Result: passed.

Phase 13 close status:

- Review loop used one fresh `gpt-5.4` reviewer with repeated broad passes.
- First pass found two accepted metadata/eligibility findings.
- Accepted fixes were committed in `6ef4669`.
- Follow-up broad pass from the same reviewer found no additional actionable issues meeting the review bar.
- Phase 13 is ready for the user to merge back into the base branch.

Review decision:
- Finding: Persisted `scan_profile_id` was treated as advisory because eligibility fell back to mode defaults even when profile ID and mode were inconsistent.
- Decision: Accepted.
- Rationale: Phase 13 makes scan profile identity part of persisted scan context; corrupted or stale profile/mode combinations should fail closed rather than silently borrowing default mode metadata.
- Follow-up: Backend and frontend profile resolution now fall back to mode only when profile ID is missing. Unknown or mismatched persisted profile IDs are invalid for eligibility decisions, and report tests cover inconsistent profile/mode rows.

Review decision:
- Finding: Report generation still used `mode == "repo"` to disable AI instead of profile metadata.
- Decision: Accepted.
- Rationale: Report and AI eligibility should be driven by profile metadata so future reportable/non-AI profiles behave correctly without new mode special cases.
- Follow-up: Report generation now uses resolved profile metadata and `profile.ai_enabled` to choose generated AI explanations versus the disabled placeholder.

Residual risk:

- Frontend profile metadata is mirrored in TypeScript while backend reads `shared/contracts.json`; this is acceptable for Phase 13 but creates future drift risk. A later hardening pass should generate frontend contracts from the shared file or fetch profile metadata from `/contracts`.
- Frontend profile-selection behavior is covered by production build rather than dedicated interaction tests.

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

- Complete and merged.

Phase 13, `phase-13-scan-profiles`:

- Complete and awaiting merge.

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
- Do not edit `HANDOFF.md` after each commit-sized subdivision. Update `HANDOFF.md` only at the end of each phase after implementation, verification, review decisions, and accepted review fixes are complete, unless the user explicitly asks for an out-of-band instruction/documentation update.
- Run the public review workflow at phase end after implementation commits.
- Treat review findings as advisory; document accepted/rejected findings in implementation summaries.
- Commit accepted review fixes separately.
- Do not push unless the user explicitly asks.
- Stop at phase boundaries and wait for user approval plus merge confirmation before starting the next phase.
- End every implementation or phase summary with a clear user-action note. If the user must do anything before work can continue or a feature can be fully used, state exactly what is needed, such as a URL, `.env` value, API key name, merge confirmation, manual deployment step, or production configuration. If no user action is needed, say so explicitly.
