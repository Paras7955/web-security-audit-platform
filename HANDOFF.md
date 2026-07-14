# ScopeHarbor Handoff

## Current state

ScopeHarbor is a local-first defensive AppSec audit platform. V1 phases 1–19
are complete. Phase 20 is the approved post-V1 public-readiness program and is
currently in progress on `phase-20-public-readiness`.

Completed Phase 20 areas:

- ScopeHarbor branding and version `1.0.0`.
- Product API moved to `/api/v1`; root is limited to liveness, readiness, and
  generated API documentation.
- Cursor pagination and workspace-scoped collection reads.
- RFC 9457-style problem responses, request IDs, bounded request bodies,
  security/no-store headers, exact CORS origins, and trusted hosts.
- Safe scan contracts and failure projections, scanner tool receipts, risk-v1
  completion writes, worker leases, and legacy data migration.
- OIDC required-claim/JWKS hardening and constant-time local auth.
- Central persistence sanitization across findings, reports, audit, health,
  worker failures, AI, and cache surfaces.
- Auth-profile rotation/revocation lifecycle and dry-run-first maintenance CLI.
- Real pinned Gitleaks/OSV adapters with bounded ephemeral staging and offline
  dependency data.
- ZAP Client Spider replacement for launchable AJAX scanning; historical AJAX
  records remain readable.
- Non-root, capability-dropped, read-only-oriented Compose services with pinned
  images and loopback host ports.
- Hash-locked Python dependencies, Ruff/Pyright/coverage configuration, and
  frontend compatibility with the public API.
- Public product, security, architecture, threat-model, operator, API, upgrade,
  contribution, and development-history documentation.

Remaining Phase 20 work:

- Add and validate GitHub quality/security automation and Dependabot.
- Raise focused branch coverage to the stated security-boundary targets.
- Run dependency audits, final clean-database migrations/suite, Docker image
  builds, Compose smoke tests, and controlled real scanner demonstrations.
- Perform the final self-review and refresh this handoff with final results.

## Safety invariants

- No arbitrary public URL scanning. Launchable targets must exactly match
  `config/scan-allowlist.yml` and have explicit authorization confirmation.
- Current guarded-scanner support is exact HTTP Docker-service targets. Do not
  admit HTTPS until destination-pinned TLS validates SNI and certificates.
- Automatic redirects stay disabled; every hop is allowlist/SSRF revalidated
  and connected to the validated destination IP.
- ZAP active and Client Spider scans stay local-demo-only and use strict scope,
  bounded execution, a generated API key, and advisory locking.
- Repository scans never clone, install, build, run scripts/hooks, execute code,
  or trust repository-supplied scanner configuration.
- Persist only sanitized projections. Never persist or emit raw bodies, scanner
  output, cookies, secrets, URL query data, absolute repository paths, raw
  provider errors, or unredacted evidence.
- Direct IDs are not authorization. API and worker operations remain
  workspace-scoped.
- Auth-profile secrets stay encrypted and may enter only guarded passive HTTP
  requests. They never enter ZAP/browser/repository workflows.

Read `SECURITY.md` and `docs/THREAT_MODEL.md` before changing a boundary.

## Runtime map

| Component | Location | Responsibility |
| --- | --- | --- |
| FastAPI app | `backend/app/main.py` | API assembly, lifespan validation, root probes |
| Public routes | `backend/app/api/` | Authenticated workspace API under `/api/v1` |
| Models/migrations | `backend/app/models.py`, `backend/alembic/` | Persistence and upgrades |
| Worker | `backend/worker/main.py` | Queue leasing and scan orchestration |
| Web scanning | `backend/app/scanner/`, `backend/app/zap/` | Guarded HTTP and ZAP adapters |
| Repository scanning | `backend/app/repo_scanner/` | Staging, Gitleaks, offline OSV |
| Safety boundary | `backend/app/security/` | Allowlist, SSRF, URLs, auth, redaction |
| Reports/AI | `backend/app/reports/`, `backend/app/ai/` | Safe downstream projections |
| Platform ops | `backend/app/ops/`, `backend/app/maintenance.py` | Audit, health, rate limits, maintenance |
| Shared contract | `shared/contracts.json` | Product, profiles, acknowledgements, limits |
| Frontend | `frontend/` | Local operator interface |
| Runtime | `docker-compose.yml`, `backend/Dockerfile` | Isolated local deployment |

Host defaults: frontend `127.0.0.1:3001`, API `127.0.0.1:8000`, Juice Shop
`127.0.0.1:3000`, PostgreSQL `127.0.0.1:5432`; ZAP is internal only.

## Configuration and operator actions

Run `python3 scripts/bootstrap_env.py` before Compose. It fills missing local
secrets without replacing an existing `AUTH_PROFILE_SECRET_KEY`. The Fernet key
is user-managed and belongs only in `.env` or the shell environment.

Before dependency scanning, populate/update the named offline database:

```bash
docker compose --profile maintenance run --rm osv-db-update
```

For production-like login, replace dev auth with strict OIDC settings. The owner
must separately enable GitHub Private Vulnerability Reporting and desired
repository security features. The repository remains unlicensed/source-visible.

See `docs/OPERATOR_GUIDE.md` for startup, health, maintenance, seed, and key
rotation procedures.

## Verification history

Latest completed checks during Phase 20:

- Backend: 254 tests passed; one intentional real-binary test skipped unless
  `SCOPEHARBOR_REAL_SCANNER_TESTS=1`.
- Backend branch coverage: 86% overall.
- Focused boundary coverage at that checkpoint: auth 91%, redirect validation
  94%, sanitization 98%, SSRF 97%, artifacts 94%, repository adapters 93%.
- Ruff clean and Pyright reported zero errors.
- Frontend lint and production build clean.
- `npm ci` reported zero known audit vulnerabilities.
- Compose configuration validated with a bootstrapped temporary environment.

These are interim results, not the final acceptance record. Dependency audits,
container builds/smoke tests, controlled real scanner runs, and the final clean
database verification remain outstanding.

## Known risks and limits

- Security-critical auth, redirect, artifact, and repository-runner modules do
  not all yet meet the planned 95% branch-coverage threshold.
- The OSV adapter is intentionally unavailable until an operator downloads the
  offline database; stale data yields a visible warning rather than online use.
- External AI is optional and adds an operator-controlled data processor even
  though payloads are bounded and sanitized. Template mode is the safe default.
- ZAP and browser add-ons are third-party scanner engines; strict scope and
  local-demo limits reduce but do not eliminate application-side effects.
- ScopeHarbor is not designed or documented as a hosted multi-tenant service.
- The ScopeHarbor name has only informal collision checking, not legal trademark
  clearance.

## Next implementation actions

1. Add pinned GitHub workflows for backend/frontend quality, CodeQL, dependency
   review, and scheduled dependency update configuration.
2. Add focused tests for remaining uncovered auth, redirect, artifact, repository
   path/staging, and adapter error branches.
3. Run final audits and acceptance verification using a clean temporary database
   and controlled local scanner fixtures.
4. Record final self-review decisions and update this handoff's status and
   verification section.

Do not infer prior chat decisions that are absent from `AGENTS.md`, this handoff,
`README.md`, or `SECURITY.md`; ask the user when a missing decision would change
scope or safety.
