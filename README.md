# Defensive Web App Security Audit Platform

Local-first defensive AppSec audit platform for intentionally vulnerable or explicitly authorized web applications.

The project is designed as a cybersecurity resume project. Tools collect evidence; the platform normalizes findings; reports and AI-assisted explanations help developers understand and fix issues. The scanner is not intended for unauthorized testing.

## V1 Architecture

- Frontend: Next.js.
- Backend: FastAPI.
- Worker: Python worker for Postgres-backed scan jobs and bounded passive scanning.
- Database: Postgres.
- Security tooling: conservative custom passive scanning, with OWASP ZAP daemon/API integration in later phases.
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
```

Set `AI_PROVIDER=openai` only when an OpenAI API key and model are configured. If OpenAI configuration is missing or the provider request fails, the backend returns template explanations and discloses the fallback.

Phase 8 does not call ZAP, run repo scanning, test authenticated workflows, or perform business logic checks.

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
- Multi-user production auth.
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
