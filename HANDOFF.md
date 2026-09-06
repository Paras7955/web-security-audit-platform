# ScopeHarbor Handoff

## Current state

ScopeHarbor is a defensive, local-first AppSec audit platform at version
`1.1.0`. Phase 27 was fast-forwarded into local `main` at `60cbc3a` after the
user explicitly authorized the merge. Neither local `main` nor the Phase 28
branch has been pushed.

Phase 28's full product audit, bounded live demonstrations, follow-up Juice
Shop walkthrough, accepted fixes, verification, and self-review fallback are
complete on `phase-28-audit-validation` through `ba90d3f`. This handoff follows
those implementation commits.

Phase 27 commits:

- `2283448` — `feat(reports): deliver structured local audit guidance`
- `33fccbc` — `refactor(frontend): simplify the public audit workspace`
- `0b016dc` — `fix(frontend): restore cross-platform clean installs`
- `7acd5da` — `fix(demo): align the seeded public experience`
- `baef303` — `docs(release): present the final public experience`
- `b6be4b0` — `test(ai): align guidance eligibility contract`
- `34bb9e7` — `fix(scanners): reuse relay-validated ZAP destinations`
- `c5ba826` — `fix(release): address independent review findings`
- `56d8f8b` — `docs(handoff): record phase 27 public polish`
- `60cbc3a` — `docs(handoff): clarify phase boundary references`

Phase 28 commits before this handoff:

- `4eb098e` — `fix(scanners): require evidence-specific probe matches`
- `5700138` — `fix(risk): align posture with active evidence`
- `68cb7a9` — `fix(workspace): keep audit state subject-aware`
- `a778fde` — `fix(build): pin patched gRPC-Go scanner dependency`
- `147efa2` — `docs(risk): explain severity-bounded posture scoring`
- `e916952` — `fix(risk): tolerate legacy severity values`
- `857a446` — `docs(handoff): record phase 28 audit validation`
- `4503e19` — `docs(handoff): finalize phase 28 verification record`
- `3e35994` — `fix(audit): surface trustworthy browser scan evidence`
- `ba90d3f` — `fix(compose): execute the webdriver readiness probe`

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
  comparisons, severity-bounded `risk-v2`/`posture-v2`, and structured
  standalone Markdown/HTML reports.
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

## Phase 28 decisions

### Live audit findings and scanner correctness

- A full Juice Shop walkthrough exercised Passive Web, Active Demo, Modern Web
  Crawl, and Repository profiles, plus findings, comparisons, reports, local
  guidance, lifecycle state, suppressions, tags, auth-profile management,
  dashboards, and audit logs.
- The custom sensitive-file probes had treated Juice Shop's HTTP 200 SPA
  fallback pages as exposed `.env`, `.git/config`, ZIP, and PHP files. Probes
  now require content signatures appropriate to the requested file and reject
  HTML fallbacks. Repeated Juice Shop runs contain 9 real normalized findings
  instead of 13: 4 ScopeHarbor Passive and 5 ZAP Passive, with no warnings.
- A second, temporary empty HTTP fixture was admitted through one exact local
  policy, scanned through the relay, and then archived and removed. It produced
  only the expected 4 missing-header findings and no exposed-file false
  positives. The temporary policy was reverted, so scanner authority did not
  expand.
- Web policies can no longer advertise the Repository profile. Repository
  scans remain separately authorized through confined repository assets.

### Risk, governance, and current posture

- Immutable scan scores now use `risk-v2`; dynamic workspace posture uses
  `posture-v2`. The strongest severity/confidence weight is primary, 15% of
  supporting weights reflects volume, and the result is capped to the highest
  observed severity band. Low or medium hygiene findings can no longer be
  presented as high or critical risk solely through accumulation.
- The model retains raw weighted totals and explicit aggregation metadata for
  auditability. Existing `risk-v1` rows remain immutable; current-model rows
  are backfilled only by the explicit maintenance action.
- Current workspace posture excludes archived targets and repository assets,
  while historical totals and scan history remain intact. Current finding
  totals and severity counts now share the same deterministic deduplication.
- Suppression creation now flushes the new rule before applying it in sessions
  with autoflush disabled. Live create/revoke validation proved findings leave
  and re-enter current posture while history remains auditable.
- The risk scorer treats an unknown legacy severity as informational instead of
  raising; this was found during the required self-review fallback and fixed in
  the separate review-fix commit.

### Operator experience and setup

- Completed audit state no longer leaks into a newly selected subject/profile
  draft. Review unlocks only for the matching audit, future wizard phases stay
  pending, and historical evidence is labelled explicitly.
- Creating a repository subject selects the Repository profile. Review actions
  are profile-aware, scan/tool states are humanized, terminal steps are
  labelled accurately, and repository authorization copy describes regular-
  file confinement rather than web redirects.
- The mobile findings toolbar no longer clips its sort control. Browser checks
  covered the workspace, audit workflow, Findings, Intelligence, reports, and
  responsive 1024 px and 390 px layouts.
- Public setup output now uses `localhost` for the browser-facing UI URL, so it
  agrees with the configured CORS origin even when Docker reports a
  `127.0.0.1` port binding.

### Supply-chain correction

- A freshly downloaded digest-pinned Trivy database identified
  `CVE-2026-84304` in OSV-Scanner's transitive gRPC-Go 1.83.0 dependency. The
  source build now pins patched gRPC-Go 1.83.1 without changing the reviewed
  OSV-Scanner source revision. The rebuilt worker passes both real offline
  scanner fixtures and reports no HIGH/CRITICAL vulnerability.

### Follow-up Juice Shop validation

- A second full browser walkthrough found that ZAP's Client Spider and
  browser-backed active rules could not launch Firefox: the extracted
  WebDriver lived on a non-executable tmpfs, while Firefox profile and cache
  paths were read-only. ZAP still returned a terminal percentage, so ScopeHarbor
  recorded false clean completion with zero browser-backed findings.
- ZAP now starts through `zap-x.sh`, keeps its executable WebDriver and writable
  browser state in bounded tmpfs mounts, and remains non-root, read-only,
  capability-free, and confined to the existing scanner networks. Readiness
  locates and actually executes the driver probe before reporting healthy.
- The repaired Active Demo produced 14 normalized findings: ScopeHarbor Passive
  4, ZAP Passive 5, and ZAP Active 5. The repaired Modern Web Crawl produced 82:
  ScopeHarbor Passive 4, ZAP Passive 5, and Client Spider 73. All final receipts
  completed without warnings.
- A forced Client Spider timeout completed with an explicit warning receipt but
  also displayed a contradictory generic hard-failure banner. Warning scans now
  keep their warning status and safe receipt details without claiming failure.
- Scan-history rows now identify their active or archived subject. The
  current-posture table uses the exact active latest-evidence set rather than
  unrelated recent or superseded scans.
- The fresh active report retained all 14 normalized occurrences but repeated
  equivalent prioritized remediation actions and had a CSS selector collision
  that obscured severity counts. Reports now group those to 8 distinct action
  patterns, retain all occurrences in Detailed Findings, and render readable
  summary cards at desktop and mobile widths.
- No ArtiCue source tree was found under the available local user directories.
  The earlier second-site validation was the temporary exact-policy empty HTTP
  fixture described above, not ArtiCue. No public target was substituted and
  the committed allowlist was not expanded.

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

The Phase 28 review runtime likewise did not expose a way to certify the exact
`gpt-5.6-sol`/medium reviewer pin, so the documented self-review fallback was
used instead.

Review decision:
- Finding: severity-bounded aggregation assumed at least one recognized
  severity and could raise for an unknown legacy/imported severity value.
- Decision: accepted.
- Rationale: weighting already treats unknown values as informational, and the
  ceiling calculation must preserve that fail-safe behavior.
- Follow-up: `e916952` adds an informational ceiling fallback and regression;
  the focused risk/dashboard suite, Ruff, and Pyright pass.

The Phase 28 self-review also covered scanner authority, evidence handling,
current-versus-historical semantics, report and guidance output, UI state,
setup behavior, tests, maintainability, and simplification. No other
actionable finding remains.

The follow-up review runtime likewise could not certify the requested exact
`gpt-5.6-sol`/medium identity, so the documented self-review fallback was used.
It found that the new ZAP health check inspected the driver's executable bit
without actually invoking it. `ba90d3f` makes readiness execute
`geckodriver --version` and adds a hardening regression. No further actionable
finding remained after that fix.

## Verification record

- Backend: Ruff and Pyright pass; Alembic upgrades from zero through `0014`,
  migration-path tests, and drift detection pass.
- Backend tests: 366 pass with 2 intentional real-scanner skips in the default
  suite. Overall branch coverage is 86%; security slices are authentication
  98.94%, SSRF/redirects 95.07%, persistence redaction 100%, artifact paths
  100%, and repository runner 96.42%. The two real scanner tests also pass
  separately in the rebuilt networkless, read-only worker image.
- Frontend: 16 Vitest/Testing Library tests, ESLint, and the Next.js 16.3.0
  production build pass. The npm audit reports zero vulnerabilities.
- Python runtime/development hash locks pass `pip-audit` with no known
  vulnerabilities.
- Bash setup syntax, isolated bootstrap, Compose rendering/hardening, image
  builds, health, readiness, and documented endpoint checks pass. PowerShell is
  parser-tested in CI; `pwsh` is not installed on the local macOS host.
- API, worker, relay, and frontend images build. Digest-pinned Trivy 0.70.0
  reports 0 HIGH/CRITICAL vulnerabilities and 0 secrets for each image.
- CycloneDX SBOMs validate with 142 API, 404 worker, 142 relay, and 43 frontend
  components.
- The isolated live stack completed real Juice Shop Passive Web, Active Demo,
  and Modern Web Crawl scans. The follow-up runtime fix changed the final
  Active Demo result from a false-clean 9 to 14 findings and Modern Web Crawl
  from a false-clean 9 to 82; ZAP Active contributed 5 and Client Spider 73,
  with clean final receipts.
- A real confined repository scan produced 26 findings: Gitleaks 21 and offline
  OSV-Scanner 5, with clean receipts and redacted evidence. No repository code,
  hooks, builds, installs, or network resolution ran.
- Fresh standalone Markdown and HTML reports and deterministic local guidance
  were generated for the repaired Active Demo scan. The HTML has exact
  `default-src 'none'` CSP, no scripts or external resources, responsive and
  print styles, legible summary counts, 8 grouped actions, and all 14 detailed
  occurrences. Report generation made no OpenAI call.
- Live governance checks covered lifecycle changes, tag create/assign/
  unassign/archive, auth-profile create/attach/deny-active/rotate/detach/revoke,
  suppression create/revoke, risk backfill preview/apply/idempotence, audit
  logs, active-subject posture, and historical totals.
- Browser automation covered desktop plus exact 1024 px and 390 px responsive
  layouts. Direct report DOM inspection passed; native print-dialog output and
  a single full-height screenshot of the long report remain manual visual
  checks because the local browser controller timed out on those operations.
- The final tracked tree contains 442 files, no unexpected generated/private
  artifact path, and no history blob above 438,644 bytes. All 178 Markdown
  links have valid local targets, and both Dockerfiles pass BuildKit checks.
- The current-tree pinned Gitleaks result exactly matches the five reviewed
  Phase 27 test/config sentinel fingerprints; no new fingerprint appears. The
  full committed history passes the pinned Gitleaks gate with no leak. Repeat
  these checks after any separately approved tooling cleanup.
- The dedicated `scopeharbor-phase28` containers were stopped after
  verification; their named volumes were preserved. The normal
  `security-project` environment was not started or modified.

## Next required actions

1. Pause at the tooling cleanup gate and obtain explicit user approval. The
   requested audit and live demonstrations are complete, but approval has not
   yet been given for removal.
2. Only after approval, remove `.agents/`, `.opencode/`, `.codex/`, `.impeccable/`,
   `AGENTS.md`, and `HANDOFF.md` from the tracked public tree without rewriting
   history. Add them to `.gitignore` and `.dockerignore`; keep ignored local
   copies where practical. Commit cleanup separately, then repeat tracked-file,
   Docker-context, documentation, current-tree/history-secret, and final review
   checks.
3. The user may then push the locally advanced `main` containing Phase 27,
   push `phase-28-audit-validation`, open a Phase 28 pull request, and require
   all backend, frontend, container, secret, CodeQL, and dependency checks that
   are available while the repository remains private. Do not push or merge
   Phase 28 from the agent unless explicitly requested.
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
- No ArtiCue checkout was available for this audit. Testing any future local
  application requires its source/runtime plus an exact reviewed policy; do not
  substitute an arbitrary public deployment.
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
