# ScopeHarbor Handoff

## Current state

ScopeHarbor — Local AppSec Audit Platform is at version `1.0.0`. V1 phases
1–19 and the approved Phase 20 public-readiness program are complete. Any new
development is post-1.0 scope and requires explicit approval.

The release provides:

- A FastAPI API under `/api/v1`, a Next.js operator UI, PostgreSQL, and a
  separately isolated scanner worker.
- Provider-neutral dev/OIDC authentication, workspace isolation, cursor
  pagination, RFC 9457-style problems, request IDs, bounded bodies, exact CORS,
  trusted hosts, security headers, rate limits, and secret-safe structured logs.
- Exact-allowlist passive web scanning, local-demo ZAP Active scanning, and a
  bounded local-demo ZAP Client Spider profile. Historical AJAX records remain
  readable, but the old profile is retired.
- Local repository scanning with pinned Gitleaks 8.30.1 and OSV-Scanner 2.3.8,
  bounded regular-file-only staging, trusted scanner configuration, fully
  redacted evidence, and offline dependency data.
- Safe scanner tool receipts, normalized findings, lifecycle/suppressions/tags,
  `risk-v1`, comparisons, Markdown/HTML reports, template explanations, and an
  optional bounded external AI provider.
- Encrypted passive-client auth profiles with rotation and revocation, worker
  leases, schema/legacy cleanup migrations, dry-run-first maintenance, an
  explicit safe demo seed, and hardened container defaults.

## Safety invariants

- Never scan arbitrary public URLs. Launchable targets must exactly match
  `config/scan-allowlist.yml` and have explicit authorization confirmation.
- Guarded scanner targets are exact HTTP Docker services. HTTPS remains denied
  until destination-pinned TLS correctly verifies SNI and certificates.
- Automatic redirects stay disabled. Every hop is allowlist/SSRF revalidated
  and connected to the validated destination IP.
- ZAP Active and Client Spider scans stay local-demo-only, strictly scoped,
  bounded, API-key protected, and serialized through the ZAP advisory lock.
- Repository scans never clone, fetch, install, build, run scripts/hooks,
  execute repository code, or trust repository-supplied scanner configuration.
- Persist and expose only sanitized projections. Raw bodies, scanner output,
  cookies, secrets, query strings, absolute repository paths, provider errors,
  and unredacted evidence must not cross persistence, API, report, AI, cache,
  audit, artifact, or log boundaries.
- Direct IDs are not authorization. API, artifacts, reports, and worker jobs
  remain workspace-scoped.
- Auth-profile secrets may enter only guarded passive HTTP requests. They never
  enter ZAP, browser, repository, report, AI, audit, or status workflows.

Read `SECURITY.md` and `docs/THREAT_MODEL.md` before changing a trust boundary.

## Runtime map

| Component | Location | Responsibility |
| --- | --- | --- |
| API application | `backend/app/main.py`, `backend/app/api/` | Lifespan validation and workspace API |
| Models and upgrades | `backend/app/models.py`, `backend/alembic/` | Persistence, constraints, and legacy cleanup |
| Worker and web scanners | `backend/worker/`, `backend/app/scans/`, `backend/app/scanner/`, `backend/app/zap/` | Leasing and guarded web execution |
| Repository scanners | `backend/app/repo_scanner/` | Bounded staging, Gitleaks, and offline OSV |
| Safety boundary | `backend/app/security/`, `backend/app/findings/redaction.py` | Allowlist, SSRF, URLs, auth, and sanitization |
| Reports and AI | `backend/app/reports/`, `backend/app/ai/` | Safe downstream projections |
| Operations | `backend/app/ops/`, `backend/app/maintenance.py` | Audit, health, limits, and maintenance |
| Public contract | `shared/contracts.json` | Profiles, acknowledgements, limits, and version |
| Operator UI | `frontend/` | Local frontend |
| Runtime | `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile` | Hardened local deployment |

Default host endpoints are frontend `127.0.0.1:3001`, API
`127.0.0.1:8000`, Juice Shop `127.0.0.1:3000`, and PostgreSQL
`127.0.0.1:5432`. ZAP and the scanner worker are internal only.

## Final verification record

- Clean PostgreSQL migration from zero through `0010`, representative upgrade
  from schema `0008`, and Alembic model-drift check: passed.
- Backend: 263 tests passed; 2 real-binary integration tests are intentionally
  opt-in and were exercised separately with the pinned tools.
- Backend branch coverage: 87% overall. Focused coverage: authentication 100%,
  SSRF/redirects 100%, persistence redaction 96.21%, artifact paths 98.28%, and
  repository runner boundaries 100%.
- Ruff and Pyright: clean.
- Python runtime/dev dependency audits and npm audit: no known vulnerabilities.
- Frontend lint and production build: passed.
- API, worker, and frontend image builds: passed on the pinned runtime inputs.
- Compose bootstrap, migrations, health/readiness, loopback bindings, container
  users/capabilities, and hardened service startup: passed. Runtime processes
  were capability-free; scanner services remained on the internal network.
- Real Gitleaks and offline OSV controlled fixtures: passed, including proof
  that package scripts/build hooks were not executed.
- Real passive, repository, and modern Client Spider demo scans: completed with
  safe findings and versioned scanner receipts.
- Canary-secret boundary tests cover database, artifacts, reports, AI/cache,
  audit, API, and captured logs.

## Operator actions

1. Run `python3 scripts/bootstrap_env.py`. It fills missing local values without
   replacing an existing user-managed `AUTH_PROFILE_SECRET_KEY`.
2. Populate the offline advisory database before repository dependency scans:

   ```bash
   docker compose --profile maintenance run --rm osv-db-update
   ```

3. Enable GitHub Private Vulnerability Reporting and the desired repository
   security features in GitHub settings. While the repository is private, set
   the repository Actions variable `SCOPEHARBOR_CODE_SECURITY_ENABLED=true`
   after GitHub Code Security is enabled; CodeQL and Dependency Review skip
   until then. Public repositories run those checks automatically.
4. For production-like login, replace local dev auth with the documented strict
   OIDC configuration.

See `README.md`, `docs/OPERATOR_GUIDE.md`, and `docs/UPGRADING.md` for setup,
maintenance, seed, key rotation, and upgrade procedures.

## Known limits and future decisions

- ScopeHarbor is local-first and is not designed as a hosted multi-tenant SaaS.
- The offline OSV database is operator-managed. Missing or stale data produces
  an explicit warning and skips dependency analysis instead of going online.
- External AI is optional and adds an operator-controlled data processor;
  deterministic template mode remains the safe default.
- Juice Shop needs a writable root filesystem for its bundled demo database and
  fixtures; it still runs non-root with all capabilities dropped.
- The repository is source-visible and unlicensed, with reuse rights reserved.
  External pull requests are not accepted until licensing is resolved.
- The ScopeHarbor name has informal collision checking only, not legal trademark
  clearance.
- Arbitrary public/cloud scanning, SaaS/RBAC administration, authenticated
  browser workflows, business-logic automation, Semgrep/full SAST, Nuclei, and
  PDF export remain out of scope unless explicitly approved.

Do not infer prior decisions that are absent from `AGENTS.md`, this handoff,
`README.md`, or `SECURITY.md`; ask when a missing decision would change scope or
safety.
