# Defensive Web App Security Audit Platform

Local-first defensive AppSec audit platform for intentionally vulnerable or explicitly authorized web applications.

The project is designed as a cybersecurity resume project. Tools collect evidence; the platform normalizes findings; reports and AI-assisted explanations help developers understand and fix issues. The scanner is not intended for unauthorized testing.

## V1 Architecture

- Frontend: Next.js.
- Backend: FastAPI.
- Worker: Python worker skeleton; Postgres-backed scan jobs are planned for Phase 3.
- Database: Postgres.
- Security tooling: OWASP ZAP daemon/API integration in later phases.
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

Within an approved phase, work is split into commit-sized subdivisions. The agent may commit each subdivision, continue through the phase, and then stop at the phase boundary for review and user approval.

Each future phase is developed on its own branch using the `codex/phase-*` naming pattern. The user merges the completed phase branch back into the base branch after phase review.

Planned phase branches:

- Phase 2: `codex/phase-2-target-validation`
- Phase 3: `codex/phase-3-scan-worker`
- Phase 4: `codex/phase-4-findings`
- Phase 5: `codex/phase-5-passive-scanner`
- Phase 6: `codex/phase-6-dashboard`
- Phase 7: `codex/phase-7-reports`
- Phase 8: `codex/phase-8-ai-explanations`
- Phase 9A: `codex/phase-9a-zap-passive`
- Phase 9B: `codex/phase-9b-active-demo`
- Phase 9C: `codex/phase-9c-ajax-short`
- Phase 10: `codex/phase-10-repo-scanning`

Before a phase starts, the agent verifies a clean worktree, creates or switches to the phase branch from the current base branch, and confirms the active branch. Do not begin the next phase until the user confirms the previous phase branch has been merged back into the base branch.

## Database Migrations

Docker Compose includes a one-shot `migrate` service that runs:

```text
alembic upgrade head
```

The backend readiness endpoint verifies that the initial schema exists before reporting ready.
