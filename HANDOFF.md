# ScopeHarbor Handoff

## Current state

ScopeHarbor is a defensive, local-first AppSec audit platform at version
`1.1.0`. Phases 1–26 are merged into `main`; Phase 26 merged through pull
request #72 at `887452ddf26492c47c2c840e6a2c1464055c1730`.

Phase 27 implementation and review fixes are complete and verified on
`phase-27-public-polish` through `c5ba826`. Phase-boundary documentation follows
those implementation commits. The branch has not been pushed or merged.

Phase 27 commits:

- `2283448` — `feat(reports): deliver structured local audit guidance`
- `33fccbc` — `refactor(frontend): simplify the public audit workspace`
- `0b016dc` — `fix(frontend): restore cross-platform clean installs`
- `7acd5da` — `fix(demo): align the seeded public experience`
- `baef303` — `docs(release): present the final public experience`
- `b6be4b0` — `test(ai): align guidance eligibility contract`
- `34bb9e7` — `fix(scanners): reuse relay-validated ZAP destinations`
- `c5ba826` — `fix(release): address independent review findings`

The approval-gated tooling cleanup has **not** run. `.agents/`, `.opencode/`,
`.codex/`, `.impeccable/`, `AGENTS.md`, and this file remain tracked. Do not
remove them until the user explicitly approves the final cleanup step. Do not
rewrite history; existing author emails and historical tooling copies remain
unchanged by decision.

## Release behavior

The release provides:

- Docker-only onboarding through `scripts/setup.sh` and `scripts/setup.ps1`.
  Users need Git to obtain the source and Docker with Compose v2 to run it; no
  host Python, Node.js, PostgreSQL, ZAP, Gitleaks, or OSV-Scanner installation
  is required.
- A FastAPI API under `/api/v1`, Next.js operator UI, PostgreSQL, separate
  scanner worker, guarded scan relay, ZAP, and bundled Juice Shop demo.
- Provider-neutral dev/OIDC authentication, backend-enforced workspace
  isolation, bounded inputs, cursor pagination, rate limits, exact
  CORS/trusted-host policy, and query-free structured request logs.
- Allowlist schema v2 with exact origin/base-path policy, immutable policy
  fingerprints, explicit profile engines, Docker-service or same-machine
  host-gateway connections, and verified HTTP/HTTPS transport.
- ScopeHarbor passive scanning for general authorized local targets. Every ZAP
  engine is restricted to an explicitly compatible disposable HTTP demo.
- Workspace repository assets with bounded regular-file-only staging, pinned
  Gitleaks, and operator-updated offline OSV data. Repository code and hooks are
  never executed.
- Subject-aware findings, lifecycle state, suppressions, tags, current posture,
  comparisons, and structured standalone Markdown/HTML reports.
- Deterministic local Finding Guidance. Optional OpenAI enrichment remains an
  explicit operator-controlled interactive action for eligible redacted web
  findings; report generation is always local and never calls OpenAI.
- A simplified operator shell with Workspace as the initial destination and
  five primary areas: Workspace, Audits, Findings, Intelligence, and Guide.
  Credentials and Operations remain available contextually.
- Public-release documentation, synthetic seeded screenshots, social preview,
  MIT license, third-party notices, sanitized issue forms, a discretionary pull
  request template, dependency audits, image scanning, and CycloneDX SBOMs.

## Safety invariants

- Never scan arbitrary public URLs or unapproved private-network destinations.
  Launchable web targets must exactly match `config/scan-allowlist.yml`, pass
  SSRF validation, and have explicit authorization confirmation.
- Supported destinations are exact configured Docker services or same-machine
  applications reached through Docker's host gateway. General targets remain
  passive-only.
- HTTPS always verifies the configured hostname and certificate with system
  trust or one confined operator CA bundle. There is no insecure TLS mode.
- Automatic redirects remain disabled. Every hop is same-origin, remains in the
  allowed base path, and is independently policy/SSRF checked before a
  destination-pinned request.
- The relay validates and dials the destination IP while preserving the
  configured HTTP `Host` and TLS SNI. Eligible ZAP work receives only the
  relay-validated IP combined with the policy's exact connection port.
- Policy loading and worker execution independently reject ZAP Passive, Active,
  and Client Spider unless the target is an explicitly compatible disposable
  demo. ZAP work remains bounded, API-key protected, cancellable, and scoped.
- Repository scans never clone, fetch, install, build, resolve dependencies,
  execute hooks/scripts/code, or honor repository scanner configuration.
- Persist and expose only independently bounded, redacted projections. Raw
  bodies, scanner/provider output, cookies, credentials, query strings,
  absolute repository paths, provider errors, and unredacted evidence must not
  cross persistence, API, report, AI, cache, audit, artifact, status, or log
  boundaries.
- Direct IDs are not authorization. API, worker, finding, risk, report, AI, and
  repository operations remain workspace-scoped.
- Auth-profile material may enter only guarded passive relay requests. It never
  enters ZAP, browser, repository, report, AI, receipt, status, artifact, audit,
  or log workflows.

Read `SECURITY.md` and `docs/THREAT_MODEL.md` before changing a trust boundary.

## Runtime map

| Component | Location | Responsibility |
| --- | --- | --- |
| API | `backend/app/main.py`, `backend/app/api/` | Workspace-scoped product API and startup validation |
| Models/upgrades | `backend/app/models.py`, `backend/alembic/` | Persistence, constraints, indexes, and migrations |
| Worker | `backend/worker/`, `backend/app/scans/` | Lease ownership, cancellation, scanner execution, receipts |
| Guarded relay | `backend/relay/`, `backend/app/scanner/relay_capability.py` | Capability, policy, SSRF, and transport enforcement |
| Web scanners | `backend/app/scanner/`, `backend/app/zap/` | Passive checks and disposable-demo ZAP profiles |
| Repository scanners | `backend/app/repo_scanner/` | Bounded staging, redacted Gitleaks, offline OSV |
| Safety | `backend/app/security/`, `backend/app/findings/redaction.py` | Allowlist, URL/SSRF/auth, and sanitization controls |
| Reports/guidance | `backend/app/reports/`, `backend/app/ai/` | Safe local reports and optional bounded enrichment |
| Operations | `backend/app/ops/`, `backend/app/maintenance.py` | Health, audit, limits, and dry-run-first maintenance |
| Shared contract | `shared/contracts.json` | Profiles, acknowledgements, limits, and version |
| Operator UI | `frontend/src/` | Workspace, audits, triage, intelligence, and guide |
| Runtime/CI | `docker-compose.yml`, Dockerfiles, `.github/workflows/` | Isolation, setup, builds, audits, scans, and SBOMs |

Default host endpoints are frontend `127.0.0.1:3001`, API
`127.0.0.1:8000`, Juice Shop `127.0.0.1:3000`, and PostgreSQL
`127.0.0.1:5432`. ZAP, relay, and worker remain internal-only.

## Phase 27 decisions

### Reports and guidance

- Markdown and standalone HTML reports now include audit identity, authorization
  context, severity distribution, scope, tool receipts, local prioritized
  guidance, limitations, and structured finding details.
- HTML reports have strict CSP, no script or external resource, safe escaping,
  responsive long-value handling, and print styles.
- “Audit completed at” replaces the misleading “Generated at” label.
- Reports always use deterministic local guidance. `AI_PROVIDER=openai` does not
  create provider calls, AI request logs, cache rows, or rate-limit usage during
  report generation.
- `AiExplanationRead.configured_provider` distinguishes local template guidance
  from configured OpenAI enrichment without exposing provider secrets.

### UI and presentation

- Workspace opens first; the unused WebGL hero and dead runtime/style code were
  removed.
- Audit Review contains a concise outcome and canonical handoffs rather than
  duplicate Findings and Intelligence dashboards.
- Audit Review loads its own unfiltered per-scan findings, so persistent triage
  filters cannot misstate completed-audit totals.
- Report actions match the two-artifact invariant: formatted HTML is primary,
  with explicit HTML and Markdown downloads.
- The shell has explicit action hierarchy, skip navigation, sticky offsets,
  live readiness announcements, state-aware theme control, and keyboard/
  overflow controls for audit phases.
- The deterministic UI detector returned no encoded anti-pattern findings.

### Scanner and supply-chain corrections

- The guarded relay projects the already validated destination IP internally;
  the worker parses and reapplies the address policy before giving eligible ZAP
  jobs the IP. This preserves worker target-network isolation.
- ZAP pinning uses the policy's validated `connection_port`, not the public
  origin port, so legitimate host-gateway remaps reach the intended service.
- Every ZAP engine requires `disposable_demo=true` at policy validation and is
  independently rejected by the worker. Legacy non-demo passive policies
  upgrade to ScopeHarbor Passive only.
- The Gitleaks source build pins `golang.org/x/crypto v0.55.0`, clearing the
  CRITICAL `CVE-2026-56854` finding detected by the current Trivy database.

## Review decisions

Review decision:
- Finding: ZAP combined a relay-validated IP with the origin port rather than
  the validated connection port.
- Decision: accepted.
- Rationale: a legitimate host-gateway port remap could otherwise reach the
  wrong service.
- Follow-up: ZAP now uses `destination.connection_port`; a remapped-port
  regression verifies the exact pinned URL.

Review decision:
- Finding: `zap-passive` could be configured for a non-disposable passive
  target, and the worker lacked an independent all-ZAP recheck.
- Decision: accepted.
- Rationale: every ZAP engine is part of the disposable-demo-only boundary.
- Follow-up: policy and worker checks reject all ZAP engines for non-demo
  targets; legacy passive compatibility drops ZAP; regression tests cover both.

Review decision:
- Finding: Audit Review consumed the persistent triage-filtered finding list and
  could present filtered counts as the complete audit.
- Decision: accepted.
- Rationale: a completed-audit summary must remain independent of triage view
  state.
- Follow-up: Review has independent unfiltered request state and an integration
  regression that applies a severity filter before opening Review.

The independent reviewer returned these three actionable findings but the
available review runtime did not expose model selection or identity. Therefore
the requested `gpt-5.6-sol`/medium pin cannot be certified. After the fixes were
committed, the main implementation agent completed the documented separate
self-review fallback over bugs, safety, regressions, missing tests,
maintainability, and simplification. It found no remaining actionable issue.

## Verification record

- Backend: Ruff and Pyright pass; Alembic upgrades from zero through `0014`,
  migration-path tests, and drift detection pass.
- Backend tests: 353 passed with 2 environment-dependent skips. Overall branch
  coverage is 86%; security slices are authentication 98.94%, SSRF/redirects
  95.07%, persistence redaction 100%, artifact paths 100%, and repository
  runner 96.42%.
- Frontend: 13 Vitest/Testing Library tests, ESLint, and the Next.js 16.3.0
  production build pass. The npm audit reports zero vulnerabilities.
- Python runtime/development hash locks pass `pip-audit` with no known
  vulnerabilities.
- Bash setup syntax, isolated bootstrap, Compose rendering/hardening, image
  builds, and readiness pass. PowerShell is parser-tested in CI; `pwsh` is not
  installed on the local macOS host.
- API, worker, relay, and frontend images build. Digest-pinned Trivy 0.70.0
  reports 0 HIGH/CRITICAL vulnerabilities and 0 secrets for each image.
- CycloneDX SBOMs validate with 142 API, 404 worker, 142 relay, and 43 frontend
  components.
- The explicit demo seed is idempotent at 2 subjects, 3 scans, 7 findings, and
  4 reports. A rebuilt isolated stack completed a real Juice Shop passive audit
  with 13 findings: ScopeHarbor Passive completed with 8 and ZAP Passive with
  5, both without warnings.
- A clean-clone Docker setup from the committed pre-review Phase 27 state
  reached health/readiness and completed the same bounded passive workflow.
  The review fixes subsequently passed the complete test gates and rebuilt live
  stack check.
- Pinned Gitleaks reported no leaks through the 298-commit review-fix state.
  The tracked tree had no unexpected secret findings; its five test/config
  sentinels are explicitly fingerprint-audited. The scan is repeated after
  phase-boundary documentation and again after the approval-gated cleanup.
- Documentation links resolve, no tracked generated/private artifacts were
  found, no real local absolute paths or personal/production data are present,
  and the largest history blob is below 0.5 MB.
- Browser checks covered the seeded workspace and major flows in light/dark
  desktop layouts. Exact 1024 px and 390 px viewport automation and direct blob
  report/print inspection remain manual release checks because those controls
  were unavailable in the local browser runtime; responsive CSS and automated
  tests pass.

## Next required actions

1. Pause and obtain explicit user approval before the tooling cleanup.
2. After approval, remove `.agents/`, `.opencode/`, `.codex/`, `.impeccable/`,
   `AGENTS.md`, and `HANDOFF.md` from the tracked public tree without rewriting
   history. Add them to `.gitignore` and `.dockerignore`; keep ignored local
   copies where practical. Commit cleanup separately, then repeat tracked-file,
   Docker-context, documentation, current-tree/history-secret, and final review
   checks.
3. The user may then push `phase-27-public-polish`, open a pull request, and
   require all backend, frontend, container, secret, CodeQL, and dependency
   checks that are available while the repository remains private. Do not push
   or merge from the agent unless explicitly requested.
4. After merge and private-main verification, rename the repository to
   `scopeharbor`, set its description/topics/social preview, enable Issues and
   private vulnerability reporting, and perform the final secret/file review.
5. Change visibility only after that review. Run public CodeQL and Dependency
   Review, enable public secret scanning/push protection where available, and
   add a `main` ruleset requiring the verified checks.
6. Create annotated tag and GitHub Release `v1.1.0` only after public `main` is
   green. Verify the README/release rendering before adding the repository URL
   to the résumé.

## Known limits

- ScopeHarbor is portfolio-first, local, and single-operator software, not a
  hosted multi-tenant SaaS.
- Linux same-machine applications must listen on an interface reachable from
  Docker's host gateway. Docker Desktop supplies the normal macOS/Windows path.
- General local targets receive ScopeHarbor Passive only. All ZAP profiles are
  explicitly compatible disposable-demo features.
- OIDC support accepts an operator-supplied bearer token held in one browser
  tab; the UI does not implement provider redirects, refresh-token storage, or
  renewal.
- The offline OSV database is operator-managed. Missing/stale data produces an
  explicit warning instead of online resolution.
- Optional OpenAI enrichment adds an operator-controlled external processor;
  deterministic local guidance remains the default and the only report source.
- Arbitrary public/cloud scanning, hosted scanning, SaaS/RBAC administration,
  authenticated browser workflows, business-logic automation, Semgrep/full
  SAST, Nuclei, and PDF export remain out of scope unless explicitly approved.
- The source is MIT licensed. The ScopeHarbor name has informal collision
  checking only, not legal trademark clearance.

Do not infer prior decisions absent from `AGENTS.md`, this handoff, `README.md`,
or `SECURITY.md`; ask when a missing decision would change scope or safety.
