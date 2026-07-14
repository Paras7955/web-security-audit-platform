# ScopeHarbor

**Local AppSec Audit Platform · 1.0.0**

ScopeHarbor is a defensive, local-first application security audit platform for
targets and repositories you are authorized to test. It combines guarded web
scanning, isolated repository analysis, normalized findings, risk tracking,
reports, and optional AI-assisted explanations in one workspace-aware system.

ScopeHarbor is source-visible, not currently open source: no license is granted
and all reuse rights are reserved. See [CONTRIBUTING.md](CONTRIBUTING.md).

## What it does

- Runs a bounded passive crawl against an exact allowlisted HTTP service.
- Runs ZAP passive and active-demo scans against configured local demo targets.
- Uses ZAP Client Spider for a bounded modern web crawl.
- Stages local repository files into an isolated workspace and runs pinned
  Gitleaks and OSV-Scanner binaries without executing repository code.
- Normalizes and redacts findings before they cross persistence, API, report,
  audit, cache, log, or AI boundaries.
- Tracks finding lifecycle, suppressions, tags, scan comparisons, and `risk-v1`
  scores by workspace.
- Produces restrictive Markdown and HTML reports from safe projections.
- Supports encrypted bearer-token and static-header target auth profiles for the
  guarded passive scanner only.

It does **not** scan arbitrary public URLs. Public cloud scanning, authenticated
browser workflows, business-logic testing, RBAC/team administration, full SAST,
and PDF export are outside the 1.0 scope.

## Safety model

The scanner is deny-by-default. A web target must exactly match
[`config/scan-allowlist.yml`](config/scan-allowlist.yml), the user must confirm
authorization, and each scan must supply the acknowledgements published by
`GET /api/v1/contracts`. Outbound web requests are revalidated for SSRF and
bound to the validated destination IP; redirects are handled manually. The
guarded scanner currently supports exact HTTP Docker-service targets only.

Repository scans accept only existing directories below `REPO_SCAN_ROOT`. They
stage regular files while excluding symlinks, special files, `.git`, dependency
trees, caches, and build output. Scans never clone repositories, run package
managers, execute builds/scripts, or use repository-supplied scanner config.

Read [SECURITY.md](SECURITY.md) before changing scanner, auth, report, AI,
repository, seed, or ZAP behavior. The full trust analysis is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Architecture

```text
Browser -> Next.js UI -> FastAPI /api/v1 -> PostgreSQL
                            |                  ^
                            v                  |
                         scan queue -> isolated worker
                                        |       |
                                        ZAP     Gitleaks + offline OSV
```

The API owns authentication, authorization, validation, pagination, and safe
public projections. PostgreSQL holds workspace-scoped application state. A
separate worker leases queued scans and writes only normalized findings and
safe tool receipts. ZAP and the local demo target remain on an internal Compose
network. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start

Requirements: Docker with Compose v2 and Python 3 for the environment bootstrap.

```bash
python3 scripts/bootstrap_env.py
docker compose --profile maintenance run --rm osv-db-update
docker compose up --build
```

The bootstrap creates or completes `.env` and does not overwrite an existing
Fernet key. `AUTH_PROFILE_SECRET_KEY` is user-managed, must never be committed,
and may end in `=`. Do not quote it in `.env` unless your environment format
requires quoting.

Open the UI at <http://localhost:3001>. The bundled target is available at
<http://localhost:3000>. API documentation is at <http://localhost:8000/docs>.

To stop the stack:

```bash
docker compose down
```

Volumes retain PostgreSQL data, reports, and the OSV database. Add `--volumes`
only when you intentionally want to delete local state.

### Optional demo data

Demo seeding is explicit, gated, fixed-ID, and idempotent:

```bash
docker compose run --rm -e DEMO_SEED_ENABLED=true backend python -m app.demo_seed
```

The seed contains illustrative normalized findings, not real secrets or raw
scanner output.

## Local services

| Service | Host address | Purpose |
| --- | --- | --- |
| Frontend | `127.0.0.1:3001` | ScopeHarbor UI |
| Backend | `127.0.0.1:8000` | API and documentation |
| Juice Shop | `127.0.0.1:3000` | Authorized local demo target |
| PostgreSQL | `127.0.0.1:5432` | Local persistence |
| ZAP | not published | Worker-only scanner service |

Published ports bind to loopback by default and can be changed in `.env`.

## Authentication

The generated local environment uses a high-entropy development bearer token.
It is compiled into the local frontend image and accepted only when
`APP_ENV=local`, `AUTH_MODE=dev`, and `AUTH_PROVIDER=dev`. Rebuild the frontend
after changing it.

For OIDC, set `AUTH_MODE=required`, use a non-`dev` provider name, and configure
`AUTH_OIDC_ISSUER`, `AUTH_OIDC_AUDIENCE`, and `AUTH_OIDC_JWKS_URL`. Tokens must be
RS256-signed and contain `sub`, `exp`, and `iat`. Development and OIDC settings
cannot coexist. Every protected lookup is scoped to the authenticated workspace.

Target auth profiles are different from platform login. Their secrets are
Fernet-encrypted, never returned by the API, and available only to future
passive scans. Rotation changes the future secret. Revocation wipes ciphertext,
detaches targets, and preserves a metadata tombstone. Either action is rejected
while a nonterminal scan references the profile.

## Scan profiles

| Profile | Engine | Constraints | Reports | AI |
| --- | --- | --- | --- | --- |
| `passive-web` | guarded crawler + passive checks | exact allowlist; optional static auth profile | yes | yes |
| `active-demo` | ZAP spider/passive/active | local-demo only; explicit active acknowledgement | yes | yes |
| `modern-web-crawl` | ZAP Client Spider | local-demo only; depth/time/scope caps | no | no |
| `repository` | Gitleaks + offline OSV | local path below root; repository code never runs | yes | no |

Historical completed AJAX scans remain readable. The old profile is not
launchable, and any legacy nonterminal AJAX job fails with a safe retired-profile
code.

## Repository tools and OSV data

The worker image pins Gitleaks `8.30.1` and OSV-Scanner `2.3.8`. Gitleaks runs in
directory mode with full redaction. OSV-Scanner runs in source mode with
`--offline-vulnerabilities` and `--no-resolve`. Scanner JSON exists only in
bounded ephemeral storage and is discarded after normalization.

Update the named OSV cache deliberately before dependency scanning and at least
weekly while in use:

```bash
docker compose --profile maintenance run --rm osv-db-update
```

This one-shot command is the only repository-scanner network operation. A
missing or stale database skips the dependency adapter and completes the scan
with a warning receipt; Gitleaks unavailability is fatal.

## Reports and AI

Reports contain normalized, escaped findings and are written atomically with
restrictive permissions and no-follow path checks. HTML report responses carry
a strict content security policy. PDF is not supported.

AI defaults to the deterministic `template` provider. An external provider is
optional and receives a bounded safe projection, never raw bodies, scanner
artifacts, cookies, credentials, or unredacted evidence. Provider errors are
reduced to stable fallback codes. Repository and modern-crawl findings are not
sent to AI.

## Operations

Root `GET /health` is a minimal liveness response. Protected
`GET /api/v1/ops/health` reports safe component status. `GET /ready` validates
configuration and the database migration head. API and worker startup fail
closed on invalid auth, encryption, ZAP, limits, paths, allowlist, migration, or
required-tool configuration.

The maintenance CLI is dry-run-first:

```bash
docker compose run --rm backend python -m app.maintenance verify
docker compose run --rm backend python -m app.maintenance orphan-artifacts
docker compose run --rm backend python -m app.maintenance prune-operational --older-than-days 30
docker compose run --rm backend python -m app.maintenance backfill-risk
```

Add `--apply` only after reviewing the JSON plan. Maintenance never prunes audit
logs, findings, reports, or scan history automatically. Fernet key rotation is
documented in [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md).

## API and verification

All product endpoints live below `/api/v1`; there are no compatibility
redirects. List endpoints return `{"items": [...], "next_cursor": "..."}` with
a default limit of 50 and maximum of 200. Errors use
`application/problem+json` and include a safe code and request ID. See
[`docs/API.md`](docs/API.md).

Local verification commands and expected environment setup are in
[`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md). Upgrade instructions are in
[`docs/UPGRADING.md`](docs/UPGRADING.md). The V1/phase record has moved to
[`docs/DEVELOPMENT_HISTORY.md`](docs/DEVELOPMENT_HISTORY.md).

## Limitations

- ScopeHarbor is a local operator tool, not a multi-tenant SaaS control plane.
- Only exact configured HTTP Docker-service targets are launchable in 1.0.
- ZAP active and Client Spider profiles are restricted to marked local demos.
- Static target credentials work only with the guarded passive HTTP client.
- Findings require human validation; absence of findings is not proof of safety.
- No license or support commitment is currently granted.

Use ScopeHarbor only on systems and repositories you own or are explicitly
authorized to assess.
