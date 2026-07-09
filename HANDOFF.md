# Defensive Web App Security Audit Platform Handoff

## Purpose

This file gives a new implementation session the project context needed to continue safely. Keep it updated at every phase boundary with current architecture, branch/commit status, verification results, known risks, and the next approved phase.

Do not include private reviewer-loop instructions or any information that should be hidden from review sub-agents. Treat this file as repo-visible project documentation.

## Immediate Handoff Checklist

For a new implementation session taking over from this point:

- Read `AGENTS.md` first. It contains the binding project workflow, phase gate, safety boundaries, review model pin, commit rules, and summary/user-action requirements.
- Read this `HANDOFF.md` next for the current architecture, phase history, verification state, known risks, and next planned phase.
- Skim `README.md` and `SECURITY.md` before making changes, especially the auth, workspace, scan safety, repo-scan, AI, and auth-profile sections.
- Confirm the active branch and clean worktree with `git status --short --branch`.
- Current expected branch is `main`. Phase 18 is complete.
- If Docker Compose commands are needed, ensure a local `.env` or shell environment provides a real generated Fernet `AUTH_PROFILE_SECRET_KEY`. The placeholder in `.env.example` is intentionally unusable.

## Current Branch And Phase

- Current branch: `main`
- Current phase: Phase 18, Platform Ops, complete
- Base branch at phase start: `main`
- Phase gate: Phase 19 is next, but do not start it until the user explicitly approves beginning Phase 19 from clean `main`.

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
- Auth profiles are workspace-owned target-application credentials, not platform user authentication.
- Auth profiles are supported only for guarded passive-web scanner requests in Phase 14.
- Active Demo, AJAX Short, browser/ZAP authenticated behavior, repo scans, login automation, password-form workflows, and business-logic auth testing remain out of scope.
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

Current auth profile types:

- `bearer_token`
- `custom_header`

Allowed custom auth headers in Phase 14:

- `Api-Key`
- `X-API-Key`
- `X-Auth-Token`
- `X-Access-Token`

Current internal worker scan modes:

- `passive`
- `active_demo`
- `ajax_short`
- `repo`

Reports and AI eligibility are determined by scan profile metadata. In the current profile set, reports are available for completed `passive-web`, `active-demo`, and `repository` scans. AI explanations are available for completed `passive-web` and `active-demo` scans only; repository findings remain excluded from AI.

Risk scoring is deterministic and versioned. Phase 15 uses `risk-v1`, persists generated scan scores in `risk_scores`, and displays scores as `0-100` plus Low/Moderate/High/Critical labels. Scores use normalized/redacted persisted finding fields only. AI may later explain score inputs, but must never compute risk scores.

Finding management is workspace-scoped and layered on top of immutable normalized findings. Phase 16 persists lifecycle state by target plus `dedupe_key`, stores occurrence-level lifecycle/suppression state for each finding, and supports suppression rules and tags using normalized persisted fields only. Suppression does not stop scanners from detecting or storing matching findings, and expired suppressions stop applying when findings are read.

AI explanation generation is workspace-scoped, rate-limited, and cached. Phase 17 records AI request accounting by workspace, user, action, provider/model/config hash, input fingerprint, cache hit, allowed/denied outcome, and timestamp. Cache fingerprints use normalized/redacted finding projections plus lifecycle, suppression, deterministic risk-score, provider/model/config, and report context inputs. AI may explain deterministic risk-score inputs but must not compute scores. Fallback results from transient external-provider failures are not cached under the failed provider config.

`AUTH_PROFILE_SECRET_KEY` is required for backend and worker startup/readiness. It must be a valid Fernet key. Production-like environments must not use the local development example key. Docker Compose now expects this value from the caller environment or a local `.env`; `.env.example` intentionally contains a non-usable placeholder.

Local setup note:

- Any developer or future agent running Docker Compose after Phase 14 must provide `AUTH_PROFILE_SECRET_KEY`.
- Generate a deployment-specific Fernet key using a Python environment with `cryptography` available, or another trusted Fernet-key generator.
- Do not commit local `.env` values or real auth-profile keys.
- Most backend/worker test and build commands now need to be prefixed with `AUTH_PROFILE_SECRET_KEY=<generated-fernet-key>` unless the value is already present in the environment.

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
- Phase 13: code-defined scan profiles, `scan_profile_id` persistence, compatibility mode input, profile-driven eligibility, and frontend profile selection. Merged to `main`.
- Phase 14: workspace-owned bearer/custom-header auth profiles, encrypted secret storage, target attachment, passive scan header injection, and frontend auth-profile controls.
- Phase 15: deterministic versioned risk scoring, workspace/target dashboard APIs, same-target scan comparison, and dense operational dashboard UI.
- Phase 16: finding lifecycle management, suppression rules with expiration, tags, expanded finding filters, and dense management UI.
- Phase 17: AI request accounting, rate limits, safe explanation cache, executive/risk explanation metadata, and cache invalidation inputs.
- Phase 18: platform ops controls, API rate limits, audit logs, cooperative scan cancellation, worker heartbeat, and health dashboard.

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
- Phase 13 was merged to `main` and used as the base for the follow-up frontend quality-of-life branch.

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

## Phase 14 Implementation State

Implemented:

- Added auth-profile secret fields to `auth_profiles`:
  - `profile_type`
  - `header_name`
  - `encrypted_secret`
  - `secret_hint`
- Added `scans.auth_profile_id` so scan jobs snapshot the target's selected auth profile at creation time.
- Added Alembic revision `0004_auth_profile_secrets`.
- Added centralized auth-profile validation/encryption service in `backend/app/auth_profiles.py`.
- Added workspace-scoped `/auth-profiles` API:
  - `POST /auth-profiles`
  - `GET /auth-profiles`
  - `GET /auth-profiles/{auth_profile_id}`
- Auth-profile API responses return metadata and `secret_hint` only; they never return secret material.
- Added `PATCH /targets/{target_id}/auth-profile` for attaching/detaching a workspace-owned profile.
- `POST /targets` now accepts an optional `auth_profile_id` after workspace ownership checks.
- `POST /targets` now validates `repo_path` with the same `REPO_SCAN_ROOT` safety checks as the repo-path PATCH endpoint.
- `POST /scans` snapshots `target.auth_profile_id` into `Scan.auth_profile_id`.
- Backend scan creation rejects auth-profile use for non-passive profiles.
- Worker lifecycle validation rejects non-passive jobs that carry an auth profile.
- Worker startup validates auth-profile crypto settings before polling/claiming jobs.
- Guarded custom scanner HTTP requests can inject auth headers while preserving destination-IP pinning and the original `Host` header.
- Auth material is decrypted only inside worker scan execution after scan/target workspace validation.
- ZAP/browser-driven authenticated behavior remains disabled in Phase 14.
- Reports, AI explanations, findings, artifacts, API reads, and scan status messages do not receive auth-profile secrets.
- Frontend auth-profile controls support creating bearer/custom-header profiles, selecting a saved profile, and attaching/detaching it from the selected target.
- Frontend scan launcher blocks authenticated non-passive scan starts and displays the passive-only auth-profile boundary.
- README, SECURITY, and AGENTS document Phase 14 auth-profile safety rules and the required `AUTH_PROFILE_SECRET_KEY`.

Phase 14 commits:

- `a486f45 feat: add encrypted auth profile API`
- `d6e39a1 feat: inject auth profiles into passive scans`
- `73c4832 feat: add auth profile frontend controls`
- `ff983be fix: harden auth profile review findings`
- `f380f4d fix: validate worker auth profile config`
- `e8e9469 docs: document auth profile requirements`
- `3fab121 fix: reject blank auth profile labels`
- `62a4557 fix: align auth profile UI labels`
- `8bfd8ff docs: close phase 14 handoff`

Verification:

- `python3 -m py_compile` for changed backend files/tests
  - Result: passed.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose build backend migrate frontend`
  - Result: passed.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm migrate`
  - Result: applied `0004_auth_profile_secrets`.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest tests.test_auth_profiles_api tests.test_targets_api tests.test_scans_api`
  - Result: 30 tests OK before review fixes.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest tests.test_scanner_http tests.test_scans_api tests.test_scan_worker tests.test_reports tests.test_ai_explanations`
  - Result: 81 tests OK before review fixes.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest tests.test_auth_workspaces tests.test_targets_api tests.test_scans_api tests.test_auth_profiles_api`
  - Result: 38 tests OK after first review fixes.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest tests.test_auth_profiles_api tests.test_scan_worker`
  - Result: 30 tests OK after second review fixes.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest tests.test_auth_profiles_api`
  - Result: 8 tests OK after blank-label fix.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest discover tests`
  - Result: 172 tests OK final.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm frontend npm run build`
  - Result: passed final.

Phase 14 close status:

- Review loop used one fresh `gpt-5.4` reviewer with repeated broad passes.
- First pass found three accepted findings: committed key/default, missing startup crypto validation, and create-time repo-path validation gap.
- Second pass found two accepted findings: worker startup did not validate crypto settings and custom header profile names were too broad.
- Third pass found one accepted low-severity finding: blank auth-profile labels.
- Fourth pass found one accepted low-severity finding: stale Phase 13 UI labels on the auth-profile-enabled screen.
- Final broad pass found no remaining actionable issues at the review bar.
- Phase 14 is ready for the user to merge back into the base branch.

Review decision:
- Finding: Static repo-committed auth-profile encryption key and functional settings default weakened encryption-at-rest.
- Decision: Accepted.
- Rationale: Real deployments must not share a key from the repository, and config should fail closed instead of silently using a known key.
- Follow-up: Removed the functional settings default, changed `.env.example` to a non-usable placeholder, made Docker Compose require `AUTH_PROFILE_SECRET_KEY`, and added production/non-local rejection of the local development example key.

Review decision:
- Finding: Backend/readiness did not validate `AUTH_PROFILE_SECRET_KEY`.
- Decision: Accepted.
- Rationale: Invalid auth-profile crypto configuration should fail startup/readiness rather than surfacing at profile creation or scan execution time.
- Follow-up: Added auth-profile crypto settings validation to backend startup and `/ready`, plus config tests.

Review decision:
- Finding: `POST /targets` stored `repo_path` without the validation used by `PATCH /targets/{target_id}/repo-path`.
- Decision: Accepted.
- Rationale: Repo path safety must be enforced consistently before persistence.
- Follow-up: Added create-time repo path validation and regression coverage.

Review decision:
- Finding: Worker process did not validate `AUTH_PROFILE_SECRET_KEY` before polling jobs.
- Decision: Accepted.
- Rationale: Worker crypto misconfiguration should fail before jobs are claimed.
- Follow-up: Added worker startup validation and focused test coverage.

Review decision:
- Finding: Custom header auth profiles allowed arbitrary header names except a short denylist.
- Decision: Accepted.
- Rationale: Phase 14 scope is API-key/static auth headers, not general request mutation or routing header injection.
- Follow-up: Replaced denylist with an API-key/auth-token header allowlist and added rejection tests for forwarding/routing headers.

Review decision:
- Finding: Whitespace-only auth-profile labels were accepted and stored as empty strings.
- Decision: Accepted.
- Rationale: Blank labels make workspace auth profiles harder to operate and audit.
- Follow-up: Added stripped-label validation and regression coverage.

Review decision:
- Finding: Frontend still displayed Phase 13 labels on the Phase 14 auth-profile workflow.
- Decision: Accepted.
- Rationale: Stale phase labels are confusing in a security workflow and are easy to avoid with capability-based labels.
- Follow-up: Replaced stale phase labels with capability labels.

Residual risk:

- Frontend auth-profile workflow coverage remains production-build-only. There are no UI-level tests that would catch auth-profile copy/state regressions, scan gating drift, or capability-label drift.
- Frontend profile metadata is still mirrored in TypeScript while backend reads `shared/contracts.json`; this drift risk remains from Phase 13.

## Phase 15 Implementation State

Implemented:

- Added Alembic revision `0005_risk_scores`.
- Added `RiskScore` persistence with workspace, target, optional scan, `scoring_model_version`, score, label, and normalized input summary.
- Added deterministic `risk-v1` scoring from normalized persisted findings:
  - severity counts and weights across critical/high/medium/low/info
  - confidence weighting
  - dedupe by normalized finding `dedupe_key`
  - scan profile and mode as metadata, not hidden score modifiers
  - empty lifecycle/suppression adjustment arrays for Phase 16 integration
- Added race-tolerant score persistence for duplicate concurrent read requests.
- Added deterministic duplicate-key handling by choosing the highest-risk representative with stable severity/confidence/timestamp/ID tie-breakers.
- Added target-aware workspace aggregation using target plus `dedupe_key` so same keys on different targets are not collapsed together.
- Added workspace-scoped dashboard and comparison APIs:
  - `GET /dashboard/overview`
  - `GET /targets/{target_id}/dashboard`
  - `GET /scans/{scan_id}/risk-score`
  - `GET /scans/{scan_id}/comparison?baseline_scan_id=...`
  - `GET /targets/{target_id}/latest-comparison`
- Scan comparison accepts only completed or completed-with-warnings scans in the same authenticated workspace and same target.
- Latest completed scan and latest comparison ordering use completion time, then creation time, then scan ID as a deterministic tie-breaker.
- Added dense operational hybrid frontend risk dashboard:
  - latest scan risk card
  - selected target risk card
  - target/workspace counts
  - severity mix bars
  - recent scan table
  - target score inputs
  - latest-vs-previous and manual comparison controls
- Frontend target dashboard and comparison loaders ignore stale responses after target switches.
- README and SECURITY document Phase 15 risk scoring/dashboard behavior and safety boundaries.

Phase 15 commits:

- `cd9f2e8 feat: add versioned risk dashboard APIs`
- `2ce6bda feat: add risk dashboards to workspace UI`
- `cc0582e test: isolate risk dashboard workspace fixtures`
- `017e1f6 docs: document phase 15 risk dashboards`
- `8fd15d4 fix: keep target risk card target scoped`
- `c0c56dc fix: harden risk dashboard review findings`
- `367a3c1 fix: use completion order for risk dashboards`
- `c723733 fix: guard manual risk comparison state`
- `5bb6689 fix: clarify latest scan risk metric`

Verification:

- `python3 -m py_compile backend/app/models.py backend/app/risk.py backend/app/api/schemas.py backend/app/api/dashboard.py backend/app/main.py backend/tests/test_risk_dashboard.py`
  - Result: passed.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose build backend migrate frontend`
  - Result: passed during the phase; later rebuilds of backend/frontend also passed after review fixes.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm migrate`
  - Result: applied `0005_risk_scores`.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest tests.test_risk_dashboard`
  - Result: 13 tests OK final.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm backend python -m unittest discover tests`
  - Result: 185 tests OK final.
- `env AUTH_PROFILE_SECRET_KEY=<temporary local dev Fernet key> docker compose run --rm frontend npm run build`
  - Result: passed final.

Phase 15 close status:

- Review loop used one fresh `gpt-5.4` reviewer with repeated broad passes.
- First pass found three accepted findings: workspace overview dedupe ignored target identity, duplicate dedupe-key score selection was not deterministic, and score persistence was vulnerable to concurrent insert races.
- Second pass found two accepted findings: latest scan behavior used creation time instead of completion time, and target dashboard/comparison loads could show stale target data after fast switches.
- Third pass found one accepted finding and one accepted test gap: manual comparison could still show stale target data, and workspace overview latest-score completion ordering lacked direct coverage.
- Fourth pass found two accepted findings: the UI label overstated latest scan risk as workspace risk, and latest ordering lacked a deterministic scan-ID tie-breaker for timestamp ties.
- Final broad pass found no remaining actionable issues at the review bar.
- Phase 15 has been merged to `main`.

Review decision:
- Finding: Workspace overview collapsed findings with the same `dedupe_key` across different targets.
- Decision: Accepted.
- Rationale: Phase 15 comparison identity is target plus dedupe key; workspace severity aggregation must not undercount repeated issues on separate targets.
- Follow-up: Added target-aware dedupe for workspace severity counts and regression coverage.

Review decision:
- Finding: Duplicate `dedupe_key` rows within a scan could make scoring nondeterministic.
- Decision: Accepted.
- Rationale: `risk-v1` must be deterministic even if duplicate normalized findings exist.
- Follow-up: Dedupe now selects the highest-risk representative with stable tie-breakers and has regression coverage.

Review decision:
- Finding: Score persistence could raise a 500 during concurrent read requests.
- Decision: Accepted.
- Rationale: Dashboard read endpoints should tolerate duplicate concurrent score generation.
- Follow-up: `IntegrityError` handling now rolls back and returns the concurrently-created score row.

Review decision:
- Finding: Latest risk/comparison behavior used scan creation time instead of completion time.
- Decision: Accepted.
- Rationale: In a worker-backed system, completed scans can finish out of creation order; latest completed scan should be completion ordered.
- Follow-up: Latest ordering now uses completion time with deterministic fallbacks, and tests cover out-of-order completion.

Review decision:
- Finding: Frontend target dashboard and comparison requests could show stale data after target switches.
- Decision: Accepted.
- Rationale: Operators should not see one target's dashboard/comparison data under another selected target.
- Follow-up: Target-scoped loaders now ignore stale responses after the selected target changes.

Review decision:
- Finding: The UI labeled latest scan risk as workspace risk.
- Decision: Accepted.
- Rationale: The metric is the latest completed scan score, not an aggregate workspace score.
- Follow-up: Relabeled the card to `Latest scan risk`.

Review decision:
- Finding: Latest ordering lacked a final deterministic tie-breaker for identical timestamps.
- Decision: Accepted.
- Rationale: Deterministic phase behavior should not depend on database return order.
- Follow-up: Added scan ID as the final tie-breaker in Python and SQL ordering plus regression coverage.

Residual risk:

- Dashboard APIs compute and persist scan risk scores on read paths. This is acceptable for Phase 15 after concurrency hardening, but a future optimization could precompute scores at scan completion or in a worker.
- Frontend dashboard behavior remains covered by production build rather than dedicated UI interaction tests.
- Frontend profile metadata is still mirrored in TypeScript while backend reads `shared/contracts.json`; this drift risk remains from Phase 13.

## Phase 16 Implementation State

Implemented:

- Alembic revision `0006_finding_management` creates `finding_states`, `finding_occurrence_states`, `suppression_rules`, `tags`, and `tag_assignments`.
- Finding lifecycle state is workspace-owned and keyed by `(workspace_id, target_id, dedupe_key)`.
- Finding occurrence state is persisted at normalized finding write time, not lazily during GET requests.
- Lifecycle statuses are `open`, `confirmed`, `in_progress`, `resolved`, `suppressed`, and `false_positive`.
- Suppression rules store creator, reason, created timestamp, optional expiration, target, optional dedupe key, optional severity, and optional source tool.
- Suppression matching uses normalized persisted fields and never raw scanner output.
- Suppression applies only after findings are normalized and persisted; scanner detection and finding storage continue normally.
- Suppression expiration is reflected when findings are read.
- Workspace-owned tags can be created and assigned to target, scan, and report resources.
- Finding APIs support current-scan and workspace finding queries with filters for target, scan profile, date, tag, lifecycle, suppression, risk score range, severity, confidence, scanner, OWASP, and CWE.
- The frontend findings dashboard exposes dense management controls for lifecycle, suppression, tag creation/assignment, current-scan vs workspace scope, target/profile filtering, and advanced normalized finding filters.
- The primary findings table preserves occurrence rows instead of collapsing by `dedupe_key`.

Phase 16 commits:

- `24aed83 feat: add finding management APIs`
- `811e029 feat: add finding management UI`
- `3444004 fix: address finding management review issues`
- `a92aae2 fix: complete finding filter and suppression review fixes`

Verification:

- `python3 -m py_compile backend/app/api/findings.py backend/app/finding_management.py backend/tests/test_finding_management.py`
  - Result: passed.
- `docker compose build backend frontend`
  - Result: passed.
- `docker compose run --rm backend python -m unittest tests.test_findings tests.test_finding_management tests.test_findings_api`
  - Result: 19 tests OK.
- `docker compose run --rm frontend npm run build`
  - Result: passed.
- Clean temporary database full backend suite:
  - `docker compose run --rm -e DATABASE_URL=postgresql+psycopg://security_audit:security_audit@postgres:5432/phase16_final_0708 backend python -m unittest discover -s tests`
  - Result: 192 tests OK.

Review decision:
- Finding: Frontend initially omitted most intended Phase 16 filters and tag-management flow.
- Decision: Accepted.
- Rationale: Phase 16 should expose the management/filter capabilities in the shipped dashboard, not only backend APIs.
- Follow-up: Added expanded filter controls, current-scan/workspace scope, target/profile filters, and tag create/assign UI.

Review decision:
- Finding: Occurrence state was initially created lazily during read paths.
- Decision: Accepted.
- Rationale: GET requests should not create management state, and occurrence state must exist when normalized findings are persisted.
- Follow-up: Moved occurrence-state initialization into normalized finding persistence and removed read-side commits.

Review decision:
- Finding: Lazy state creation was race-prone.
- Decision: Accepted.
- Rationale: Moving state creation to the normalized persistence transaction removes the primary concurrent-read insertion path.
- Follow-up: Added persistence-time occurrence-state coverage.

Review decision:
- Finding: Suppression reads omitted `created_by_user_id`, and suppression match fields were insufficiently normalized/validated.
- Decision: Accepted.
- Rationale: Suppression rules require creator metadata and normalized match behavior.
- Follow-up: Added creator to API responses and validation/normalization for severity and source tool match fields.

Review decision:
- Finding: Frontend collapsed occurrence rows by `dedupe_key`.
- Decision: Accepted.
- Rationale: Phase 16 separates immutable occurrences from shared lifecycle state, so the primary table must preserve occurrence visibility.
- Follow-up: Removed dedupe collapsing from the main findings table.

Review decision:
- Finding: Applied suppressions did not stop applying after expiration.
- Decision: Accepted.
- Rationale: Expiration is time-based and should be reflected without requiring another mutation.
- Follow-up: Re-evaluated suppression expiration during read serialization and added regression coverage.

Review decision:
- Finding: Finding query serialization had a high N+1 query shape.
- Decision: Accepted.
- Rationale: The primary findings table should not issue repeated scan/tag/risk lookups for every row.
- Follow-up: Preloaded scan records, tag labels, tag-filter resources, and latest risk scores by scan.

Residual risk:

- Frontend behavior is verified by production build, not end-to-end browser interaction tests.
- Phase 16 records management state but does not yet add audit-log entries; audit logging is planned for Phase 18.

## Phase 17 Implementation State

Implemented:

- Alembic revision `0007_ai_cache_rate_limits` creates `ai_request_logs` and `ai_explanation_cache`.
- AI request accounting records workspace, user, action, provider, model, config hash, input fingerprint, cache-hit state, allow/deny outcome, and timestamp.
- Interactive AI explanations use action `interactive_ai_explanations`; report-triggered AI generation uses action `report_ai_generation`.
- Uncached AI generation is rate-limited by workspace/user/action/provider/model/config window.
- Cache entries are keyed by workspace, scan, action, provider, model, config hash, and deterministic input fingerprint.
- Cache fingerprints include safe finding projections, lifecycle state, occurrence suppression state, suppression rules and expiration state, deterministic `risk-v1` score inputs, scan metadata, provider/model/config, and report context.
- AI responses include executive summary, deterministic risk-score explanation, scoring model version, input fingerprint, and cache-hit metadata.
- Report artifacts include executive and risk-score explanation text, but not volatile cache-hit state.
- External AI provider payloads still receive only normalized/redacted finding fields; repo findings remain excluded from external AI.
- Transient external-provider fallback results are not cached under the failed provider config.
- The dashboard AI panel displays provider, fallback, cache, groups, and risk-model metadata.
- `.env.example`, `README.md`, and `SECURITY.md` document the new AI cache/rate-limit settings and safety boundaries.

Phase 17 commits:

- `2d7972c feat: add AI explanation caching and rate limits`
- `c9cf3ab docs: document AI cache rate limits`
- `8d030e6 fix: return 429 for report AI rate limits`
- `43c4ee3 fix: reuse stable AI cache entries`

Verification:

- `docker compose run --rm migrate`
  - Result: passed after applying Phase 17 migration.
- `docker compose run --rm backend python -m unittest tests.test_ai_explanations tests.test_reports`
  - Result: 42 tests OK after accepted review fixes.
- Clean temporary database migrations from zero through head:
  - `docker compose run --rm -e DATABASE_URL=postgresql+psycopg://security_audit:security_audit@postgres:5432/phase17_test migrate`
  - Result: passed.
- Clean temporary database full backend suite:
  - `docker compose run --rm -e DATABASE_URL=postgresql+psycopg://security_audit:security_audit@postgres:5432/phase17_test backend python -m unittest discover tests`
  - Result: 201 tests OK.
- `docker compose run --rm frontend npm run build`
  - Result: passed before the backend-only accepted review fixes.
  - Final rerun was blocked by the app approval/usage limit, not by a code failure.

Review decision:
- Finding: Report-triggered AI caching initially used a fresh `uuid4()` cache context on every report generation, making unchanged report requests miss the cache and consume uncached rate-limit budget.
- Decision: Accepted.
- Rationale: Report-triggered AI generation must be cacheable for unchanged normalized inputs.
- Follow-up: Replaced the random report cache context with stable `report-v1`, removed report artifacts from AI fingerprints, and added repeated report-generation cache reuse coverage.

Review decision:
- Finding: Transient external-provider failures were cached as template fallback results under the failed provider/config key.
- Decision: Accepted.
- Rationale: Temporary provider failures should not create a persistent downgrade that prevents retrying the configured provider.
- Follow-up: Skipped cache writes for fallback results and added regression coverage proving repeated provider failures retry instead of hitting cache.

Review decision:
- Finding: Report AI rate-limit errors initially bubbled out through report generation as uncaught AI errors.
- Decision: Accepted from local self-review.
- Rationale: Report-triggered AI rate limits should return a clear `429` instead of an internal error.
- Follow-up: Added `ReportGenerationRateLimitError`, API `429` mapping, and report API regression coverage.

Residual risk:

- Frontend behavior is verified by production build, not end-to-end browser interaction tests.
- Phase 17 rate limits are simple rolling-window database checks and are suitable for local/V1 scale, but high-concurrency production use may need atomic counters or advisory locking.
- Tag changes are not included in the Phase 17 AI cache fingerprint because AI provider inputs and AI output do not currently include tag labels. If tags become part of AI prompts or report AI context later, add tag assignments to the fingerprint.

## Phase 18 Implementation State

Implemented:

- Alembic revision `0008_platform_ops` adds scan cancellation fields plus `api_rate_limit_logs`, `audit_logs`, and `worker_heartbeats`.
- General API rate-limit logs now protect scan creation, report generation, and AI explanation requests. Phase 18 uses a PostgreSQL transaction advisory lock per workspace/user/action before admission checks to avoid count-and-insert race bursts.
- Append-only workspace audit records are written for target changes, scan creation/cancellation, report generation, AI requests, finding lifecycle changes, suppressions, tags, and auth profile creation. Audit records store normalized metadata and redact secret-like keys.
- `POST /scans/{scan_id}/cancel` supports cooperative cancellation. Queued scans are cancelled immediately under a row lock. Running scans record a cancellation request and keep the original requester/audit event if cancellation is requested again.
- Worker lifecycle checkpoints stop cancelled scans at safe boundaries for passive, repo, ZAP passive, Active Demo, and AJAX Short work without broadening scanner scope.
- Worker heartbeat records expose worker status, current scan context, and queue depth for health reporting.
- `GET /ops/health` reports database reachability, worker heartbeat freshness, queue depth, ZAP availability, and artifact-root writability without exposing local filesystem paths.
- `GET /audit-logs` returns workspace-scoped audit events.
- The frontend dashboard shell displays platform health and exposes scan cancellation controls for non-terminal scans.
- `.env.example`, `README.md`, and `SECURITY.md` document Phase 18 operational settings and safety boundaries.

Phase 18 commits:

- `16f82e7 feat: add platform ops controls`
- `b250d2d feat: add ops health UI`
- `cf9c50b docs: document platform ops controls`
- `8f402a3 fix: harden platform ops edge cases`
- `d38c05d fix: make scan cancellation requests idempotent`

Verification:

- `python3 -m py_compile backend/app/api/scans.py backend/app/api/ops.py backend/app/ops/rate_limits.py backend/tests/test_platform_ops.py`
  - Result: passed after accepted review fixes.
- `docker compose build backend migrate`
  - Result: passed.
- `docker compose run --rm migrate`
  - Result: passed after applying Phase 18 migration.
- `docker compose run --rm backend python -m unittest tests.test_platform_ops`
  - Result: 8 tests OK after accepted review fixes and backend rebuild.
- `docker compose run --rm backend python -m unittest tests.test_platform_ops tests.test_scan_worker tests.test_reports tests.test_ai_explanations tests.test_targets_api`
  - Result: 83 tests OK after accepted review fixes.
- Clean temporary database migrations from zero through head:
  - `docker compose run --rm -e DATABASE_URL=postgresql+psycopg://security_audit:security_audit@postgres:5432/phase18_final migrate`
  - Result: passed.
- Clean temporary database full backend suite:
  - `docker compose run --rm -e DATABASE_URL=postgresql+psycopg://security_audit:security_audit@postgres:5432/phase18_final backend python -m unittest discover tests`
  - Result: 209 tests OK after accepted review fixes.
- `docker compose run --rm frontend npm run build`
  - Result: passed after accepted review fixes.

Review decision:
- Finding: Queued scan cancellation could race with worker claim and overwrite a worker-claimed scan as `cancelled`.
- Decision: Accepted.
- Rationale: The cancellation endpoint must make the queued-vs-running decision against a locked row.
- Follow-up: Added `FOR UPDATE` locking to scan cancellation before status decisions.

Review decision:
- Finding: DB-backed API rate limiting used a count-then-insert flow without serialization, allowing concurrent requests to exceed the limit.
- Decision: Accepted.
- Rationale: Expensive endpoint protection should hold under local concurrent load.
- Follow-up: Added a PostgreSQL transaction advisory lock per workspace/user/action before rate-limit counting and logging.

Review decision:
- Finding: `/ops/health` returned the absolute artifact-root path to authenticated users.
- Decision: Accepted.
- Rationale: Health endpoints should not expose sensitive local filesystem details.
- Follow-up: Replaced artifact-root details with generic writable/unavailable messages and added regression coverage.

Review decision:
- Finding: Docs advertised login/session audit records even though the app uses stateless bearer authentication without a durable session boundary.
- Decision: Accepted as a documentation correction.
- Rationale: Per-request auth-success audit rows would be noisy and are not the intended durable platform-state audit surface.
- Follow-up: Narrowed Phase 18 audit language to authenticated API actions that change durable platform state.

Review decision:
- Finding: Repeated cancellation requests for the same running scan could overwrite the original requester and append duplicate audit events.
- Decision: Accepted.
- Rationale: Cancellation requests should be idempotent once recorded so the audit trail preserves who initiated cancellation.
- Follow-up: Returned the current scan unchanged when cancellation was already requested and added regression coverage.

Residual risk:

- True concurrent Postgres contention for cancel-vs-worker-claim and simultaneous rate-limited requests is covered by locking design and focused unit/API tests, but not by a two-live-session integration test.
- Frontend behavior is verified by production build, not end-to-end browser interaction tests.

## Current API Surface

Protected by bearer auth:

- `GET /targets/validate`
- `POST /targets`
- `GET /targets`
- `GET /targets/{target_id}`
- `PATCH /targets/{target_id}/repo-path`
- `PATCH /targets/{target_id}/auth-profile`
- `POST /auth-profiles`
- `GET /auth-profiles`
- `GET /auth-profiles/{auth_profile_id}`
- `POST /scans`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `GET /findings`
- `GET /findings/{finding_id}`
- `PATCH /findings/{finding_id}/lifecycle`
- `POST /suppressions`
- `GET /suppressions`
- `POST /tags`
- `GET /tags`
- `POST /tags/assignments`
- `GET /tags/assignments`
- `POST /scans/{scan_id}/reports`
- `GET /scans/{scan_id}/reports`
- `GET /reports/{report_id}`
- `GET /reports/{report_id}/download`
- `GET /dashboard/overview`
- `GET /targets/{target_id}/dashboard`
- `GET /scans/{scan_id}/risk-score`
- `GET /scans/{scan_id}/comparison?baseline_scan_id=...`
- `GET /targets/{target_id}/latest-comparison`
- `GET /scans/{scan_id}/ai-explanations`

Public operational endpoints:

- `GET /health`
- `GET /ready`
- `GET /contracts`
- `GET /ops/health`
- `GET /audit-logs`

## Roadmap Plan

Phase 12, `phase-12-app-shell`:

- Complete and merged.

Phase 13, `phase-13-scan-profiles`:

- Complete and merged.

Phase 14, `phase-14-auth-profiles`:

- Complete and merged.

Phase 15, `phase-15-dashboards-risk`:

- Complete and merged.

Phase 16, `phase-16-finding-management`:

- Complete and merged.

Phase 17, `phase-17-ai-rate-limits`:

- Complete and merged.

Phase 18, `phase-18-platform-ops`:

- Complete.

Phase 19, `phase-19-demo-seed-docs`:

- Add deterministic demo seed command, not an always-on public endpoint.
- Seed a demo user/workspace, demo targets, completed scans, normalized findings, reports, lifecycle/suppression/tag examples, and versioned risk scores.
- Gate seed behavior behind an explicit command/env setting and make it idempotent.
- Seeded demo data must never bypass workspace isolation, scan safety, redaction, auth-profile secrecy, report safety, or AI payload safety.
- Update README, SECURITY, AGENTS, and this handoff with the final post-v1 state and any changed public rules.
- Document local provider-agnostic auth, Auth0 configuration, dev auth, generated `AUTH_PROFILE_SECRET_KEY`, seeded demo workflow, and full Docker verification.
- Test seed idempotency, workspace isolation, demo data invariants, and that seeded data does not weaken safety/redaction behavior.

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
