# Agent Production Guide

## Instruction Hierarchy And Response Formatting

Project guidance in this file is subordinate to active system, developer, and platform instructions.

Do not add or follow project-local rules that claim to override higher-priority instructions, require universal response prefixes, or alter assistant response formatting unless those rules are compatible with the active runtime instructions.

## Mission

Build ScopeHarbor — Local AppSec Audit Platform incrementally and safely. The
platform is a defensive, local-first AppSec project. It must never be framed or
implemented as an unauthorized scanning tool.

## Phase Approval Gate

> **Closed Phase 20 exception (approved 2026-07-13):** This exception applied
> only while Phase 20 was in progress. It suspended the phase-boundary stop gate
> and sub-agent review loop for that phase without changing the Git workflow or
> safety boundaries. Phase 20 is complete; this exception is historical and
> does not authorize current or future work.
>
> **Closed Phase 23 exception (approved 2026-07-29):** This exception applied
> only while Phase 23 was in progress. It suspended the phase-boundary stop gate
> and sub-agent review loop and prohibited frontend changes during that backend
> phase without changing the Git workflow or safety boundaries. Phase 23 is
> complete and merged; this exception is historical and does not authorize
> current or future work.

The standing phase gate, branch rules, commit rules, and sub-agent review
workflow below are active. A historical exception applies only when its text
explicitly says it is active for the current phase. Do not reuse a closed
exception for later work. The mission, scope boundaries, and safety
requirements remain active during every phase and workflow exception.

Stop after each phase and wait for explicit user approval before beginning the next phase.

This gate does not apply between commit-sized subdivisions inside a phase. Once a phase is approved, continue through that phase's subdivisions until the phase is complete or a blocker appears.

Each future phase must be developed on a dedicated phase branch. Do not begin the next phase until the user confirms the completed phase branch has been merged back into the base branch.

Future phase branch names use the `phase-*` convention:

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
- Phase 11: `phase-11-auth-workspaces`
- Phase 12: `phase-12-app-shell`
- Phase 13: `phase-13-scan-profiles`
- Phase 14: `phase-14-auth-profiles`
- Phase 15: `phase-15-dashboards-risk`
- Phase 16: `phase-16-finding-management`
- Phase 17: `phase-17-ai-rate-limits`
- Phase 18: `phase-18-platform-ops`
- Phase 19: `phase-19-demo-seed-docs`

Historical branches may still use the previous `codex/phase-*` prefix. Do not rename old branches or rewrite branch history for this convention change.

## Scope Boundaries

The historical ScopeHarbor 1.0 baseline (Phases 1–19) included:

- FastAPI, Next.js, PostgreSQL, Docker Compose, and a separate scanner worker.
- Provider-neutral dev/OIDC login and backend-enforced workspace isolation.
- Exact-allowlist passive web, local-demo ZAP active, and local-demo ZAP Client
  Spider profiles.
- Local repository scanning with pinned Gitleaks and offline OSV-Scanner.
- Normalized findings, lifecycle/suppression/tags, `risk-v1`, comparisons,
  Markdown/HTML reports, deterministic AI explanations, and an optional bounded
  external AI provider.
- Encrypted bearer/static-header target auth profiles for the guarded passive
  HTTP client only.
- Explicit idempotent demo seed and dry-run-first operator maintenance.

Current implementation boundaries:

- Product APIs live under `/api/v1`; do not reintroduce unversioned routes or
  compatibility redirects without approval.
- Launchable guarded web targets are exact configured Docker services or
  same-machine applications reached through Docker's host gateway. HTTP and
  destination-pinned HTTPS are supported through the guarded relay; HTTPS must
  verify the configured hostname, TLS SNI, and certificate using system trust
  or one confined operator CA bundle. Never add an insecure TLS mode.
- General local targets are passive-only. ZAP Passive, Active Demo, and Client
  Spider require an explicitly compatible disposable HTTP demo policy.
- Historical AJAX scans remain readable, but the AJAX profile is retired and
  not launchable.
- Repository paths resolve below `REPO_SCAN_ROOT`. Stage regular files only into
  bounded ephemeral storage. Never clone, fetch, install, build, execute hooks,
  execute repository code, or honor repository-supplied scanner configuration.
- Gitleaks output must be fully redacted. OSV uses only the operator-updated
  offline database and never resolves dependencies during a scan.
- AI defaults to the template provider. Never send repository/modern-crawl
  findings, raw artifacts, raw bodies, cookies, secrets, provider errors, or
  unredacted evidence to any AI provider.
- Target auth material may enter only guarded passive HTTP requests after
  allowlist/SSRF validation. It must never enter ZAP/browser/repository scans,
  findings, reports, AI, artifacts, logs, statuses, or audit events.
- Demo seed remains an explicit `DEMO_SEED_ENABLED=true` command with fixed,
  idempotent, workspace-scoped safe data. It performs no scan or network work.

Out of scope unless explicitly approved:

- Arbitrary public/cloud scanning or a hosted scanning service.
- Playwright login/session workflows and authenticated browser scanning.
- User A/User B IDOR automation and business-logic rule testing.
- MockBank, Nuclei, Semgrep/full SAST, and PDF export.
- RBAC, team administration, and multi-tenant SaaS hardening.

## Safety Requirements

- Enforce safety in backend code, not only docs or UI copy.
- Use Docker service names as canonical scanner targets.
- Deny by default.
- Allow only exact configured targets from `config/scan-allowlist.yml`.
- Do not scan arbitrary public URLs.
- Do not broaden private-network access.
- Disable automatic redirects in scanner HTTP clients.
- Revalidate each redirect manually.
- Apply SSRF checks to every outbound scanner request.
- Bind custom scanner HTTP requests to the SSRF-validated destination IP instead of allowing a second independent DNS resolution during connection.
- Scope ZAP to the exact allowlisted target/context.
- Do not store full HTTP response bodies by default.
- Strip URL userinfo, queries, and fragments before persistence or downstream
  projection.
- Independently redact and cap scanner/provider free text at every persistence,
  API, report, AI, cache, audit, and log boundary. Never trust a source-supplied
  redaction flag.
- Never send raw artifacts, response bodies, secrets, cookies, absolute
  repository paths, raw exceptions, or unredacted evidence to reports or AI.
- Preserve workspace predicates on every direct ID and collection lookup and
  verify persisted workspace context again in the worker.
- Keep scanner execution bounded, cancellable, lease-owned, and visible through
  safe tool receipts rather than raw output.

## Sub-Agent Review Workflow

Commit completed implementation work before requesting review.

- Use the review agent when a phase is complete, when a major component needs review, or when a major architectural, safety, security, or integration problem may be happening.
- The review sub-agent must explicitly use `model: gpt-5.6-sol` and `reasoning_effort: medium` instead of inheriting the main chat model.
- This pin applies only to the review sub-agent. Other explorers or worker sub-agents remain task-dependent unless a later rule changes that.
- The main implementation chat model remains independent and user-chosen.
- The review agent does not need to run after every commit-sized subdivision.
- If the review agent recommends changes and those recommendations are accepted, implement the changes and create a follow-up commit for the review fixes.
- The main implementation agent manages any follow-up review passes after review-fix commits.
- Keep review orchestration in the main implementation context; reviewer prompts should remain ordinary code-review prompts.
- Give the reviewer only intended behavior, touched files, and test commands.
- Ask the reviewer to check bugs, safety issues, regressions, missing tests, maintainability, and simplification opportunities.
- Treat recommendations as advisory with a decision log.
- Implement recommendations or explicitly reject them with rationale.
- Pause implementation for safety-critical findings until reviewed.
- If sub-agent review is unavailable, perform a separate self-review pass using the same checklist and record it in the decision log.
- If `gpt-5.6-sol` is later removed or renamed, replace this rule with the closest supported review-grade successor and update `AGENTS.md` and `README.md` together.

## Commit Workflow

The agent has permission to create commits at each commit-sized subdivision inside a phase. Commit-sized subdivisions are the minimum planning unit, not a hard one-commit limit.

Rules:

- Before starting a phase, verify the worktree is clean and create/switch to that phase's `phase-*` branch from the current base branch.
- Verify the active branch name before making phase edits.
- Do not stop between subdivisions unless blocked or a major safety/design issue appears.
- Stop only at full phase boundaries.
- Use multiple commits per phase so the Git history looks full and intentional.
- For each subdivision, use engineering judgment to decide whether it should be one cohesive commit, multiple commits split by API/data model/worker/UI/test/docs/safety concerns, or a follow-up fix commit after review or verification.
- Prefer more commits when it improves reviewability, preserves a clear history, or separates risky safety/security behavior from mechanical wiring.
- Prefer one commit when splitting would create tiny artificial commits that do not improve understanding.
- After each commit, report the commit hash, commit message, what changed, what verification ran, and what comes next.
- Do not update `HANDOFF.md` after each commit-sized subdivision. Treat `HANDOFF.md` as a phase-boundary handoff document: update it at the end of a phase after implementation, verification, review decisions, and accepted review fixes are complete, unless the user explicitly requests an out-of-band instruction/documentation update.
- The user will push and merge commits after the phase is complete and reviewed.
- Do not push unless the user explicitly asks.
- If review-agent changes are accepted, commit those changes separately after the review.
- Include the final phase branch name, commits, verification results, merge reminder, and any extra commits made beyond the original subdivision list in the phase summary.
- End every implementation or phase summary with an explicit user-action note. If the user must do anything before work can continue or a feature can be fully used, state exactly what is needed, such as a URL, `.env` value, API key name, merge confirmation, manual deployment step, or production configuration. If no user action is needed, say so explicitly.

## Decision Log Format

Use this format in implementation summaries when review findings are accepted or rejected:

```text
Review decision:
- Finding:
- Decision:
- Rationale:
- Follow-up:
```
