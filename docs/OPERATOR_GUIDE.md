# ScopeHarbor Operator Guide

## First start

Requirements: Docker with Compose v2, Python 3, and enough local resources for a
PostgreSQL database, ZAP, a browser crawl, and a 640 MiB worker tmpfs.

```bash
python3 scripts/bootstrap_env.py
docker compose --profile maintenance run --rm osv-db-update
docker compose up --build
```

The bootstrap creates `.env` from `.env.example` when absent and fills only
missing/placeholder secrets. It never replaces an existing
`AUTH_PROFILE_SECRET_KEY`. Protect `.env` as credential material.

Check:

- UI: <http://localhost:3001>
- API liveness: <http://localhost:8000/health>
- API readiness: <http://localhost:8000/ready>
- API docs: <http://localhost:8000/docs>
- demo target: <http://localhost:3000>

The protected `/api/v1/ops/health` response is the useful component view. It
reports safe database, worker, queue, ZAP, and artifact status without secrets or
raw exceptions.

## Configuration rules

- Keep `APP_ENV=local`, `AUTH_MODE=dev`, and `AUTH_PROVIDER=dev` together only
  for local development.
- Use exact JSON arrays for `CORS_ORIGINS` and `TRUSTED_HOSTS`; wildcards are
  rejected.
- Keep `TRUSTED_PROXY_IPS=[]` unless TLS terminates at a reverse proxy. If it
  does, list only the immediate proxy's exact IP address and configure that
  proxy to replace, not preserve, client-supplied forwarding headers.
- Keep `ZAP_API_KEY`, database password, development token, Fernet keys, and AI
  keys out of Git.
- A Fernet key may end in `=`. Do not accidentally truncate it or add literal
  quote characters.
- Do not expose ZAP or change loopback port bindings without a separate network
  security review.
- Do not submit target credentials over a non-local HTTP deployment. ScopeHarbor
  rejects create/rotate requests unless they use HTTPS or the supplied
  loopback-only local workflow.
- Do not raise scan/staging limits until host capacity and denial-of-service
  implications have been reviewed.

## OIDC mode

For a production-like local deployment:

1. Set `AUTH_MODE=required`.
2. Set `AUTH_PROVIDER` to a stable non-`dev` provider identifier.
3. Set exact `AUTH_OIDC_ISSUER`, `AUTH_OIDC_AUDIENCE`, and
   `AUTH_OIDC_JWKS_URL` values.
4. Remove/leave unused the dev-only settings.
5. Configure the frontend or an API client to supply the bearer token.
6. Rebuild and confirm `/ready` plus an authenticated workspace request.

ScopeHarbor accepts RS256 tokens with valid issuer/audience and required `sub`,
`exp`, and `iat` claims. First login creates one user-owned default workspace.

## Allowlisted targets

`config/scan-allowlist.yml` is trusted operator configuration. Each entry must
name an exact Docker-service URL, supported modes, scheme/host/port tuple,
redirect cap, and whether it is a local demo. ScopeHarbor 1.0 accepts launchable
guarded targets over HTTP only.

Changing the allowlist expands scanner authority. Review the target's ownership,
Compose network location, profile needs, and SSRF implications before editing.
Restart API and worker after a configuration change and run:

```bash
docker compose run --rm backend python -m app.maintenance verify --apply
```

Without `--apply`, `verify` only describes the validation it would run.

The operator UI can remove an inactive saved target. This archives the target
instead of cascading through evidence history. ScopeHarbor refuses the action
while a scan is queued or running, clears target authorization and attached
repository/auth configuration, and preserves scans, findings, reports, risk
scores, and audit events. Use this when a target should no longer be launchable;
it is not a data-erasure workflow.

## Repository roots

The supplied Compose file mounts this repository read-only at
`/app/repositories/security-project`. To assess another local repository, add an
explicit read-only bind mount below `/app/repositories`, then configure the
target with that absolute in-container path. Never mount the host filesystem or
a broad home directory.

Ordinary scans have no egress, do not clone or resolve dependencies, and never
run repository code. Update the OSV cache separately:

```bash
docker compose --profile maintenance run --rm osv-db-update
```

Update before first use, after recreating the cache volume, and at least weekly
while dependency scanning is in use. The worker treats data older than the
configured maximum as unavailable and emits a warning receipt.

## Demo seed

Demo data is opt-in and idempotent:

```bash
docker compose run --rm -e DEMO_SEED_ENABLED=true backend python -m app.demo_seed
```

Use it only with local dev auth and the supplied repository/allowlist layout.
It writes fixed sample records and safe report files; it performs no scans or
network activity.

## Maintenance

All maintenance actions are dry-run-first and return a JSON summary:

```bash
docker compose run --rm backend python -m app.maintenance verify
docker compose run --rm backend python -m app.maintenance orphan-artifacts
docker compose run --rm backend python -m app.maintenance prune-operational --older-than-days 30
docker compose run --rm backend python -m app.maintenance backfill-risk
```

After reviewing candidates, repeat the intended command with `--apply`.

- `verify` checks configuration, database head, and scanner versions.
- `orphan-artifacts` removes only unreferenced scan artifact directories.
- `prune-operational` removes old AI request/cache, API rate-limit, and worker
  heartbeat rows.
- `backfill-risk` creates missing `risk-v1` rows for completed legacy scans.

Maintenance never prunes audit logs, findings, reports, or scan history.

## Fernet key rotation

Back up PostgreSQL before key rotation. Ensure no scans or auth-profile writes
are active, then:

1. Stop API and worker.
2. Generate a new Fernet key locally.
3. Set `AUTH_PROFILE_PREVIOUS_SECRET_KEY` to the old key.
4. Set `AUTH_PROFILE_SECRET_KEY` to the new key.
5. Start only the dependencies needed for the maintenance container.
6. Preview and apply:

```bash
docker compose run --rm backend python -m app.maintenance reencrypt-auth-profiles
docker compose run --rm backend python -m app.maintenance reencrypt-auth-profiles --apply
```

7. Verify active profile metadata and a controlled passive scan.
8. Remove `AUTH_PROFILE_PREVIOUS_SECRET_KEY`, restart normally, and protect the
   backup according to its retention policy.

The command validates every active ciphertext before committing and never
prints plaintext. Losing both the current key and a usable backup makes existing
profile secrets unrecoverable.

## Backup and upgrade

Back up PostgreSQL, the `app-artifacts` volume, `.env`/secret records, and any
required OSV cache policy before an upgrade. Reports reference artifact files;
database-only backups are incomplete. Follow [`UPGRADING.md`](UPGRADING.md).

## Troubleshooting

- `/ready` failure: validate auth mode, Fernet/ZAP keys, exact CORS/host values,
  paths, allowlist, limits, and migration head.
- worker degraded: inspect structured worker logs, heartbeat age, queue depth,
  scanner versions, OSV age, and lease state. Do not copy raw target/scanner data
  into an issue.
- dependency scan skipped: run the explicit OSV update and verify the named
  volume is writable by the updater and read-only to the worker.
- report unavailable: confirm the scan is eligible and the artifact volume is
  mounted; do not manually bypass no-follow/path checks.
- stale development data: use a new temporary database for verification instead
  of deleting shared history casually.

Use request IDs to correlate safe structured logs. Logs intentionally omit
authorization values, bodies, query strings, raw exceptions, and scanner output.

## Development verification

Use the hash-locked environment and a disposable PostgreSQL database:

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r backend/requirements-dev.txt
.venv/bin/ruff check backend
.venv/bin/pyright
PYTHONPATH=backend .venv/bin/coverage run --branch -m unittest discover -s backend/tests
.venv/bin/coverage report --fail-under=85
.venv/bin/coverage json -o coverage.json
.venv/bin/python scripts/check_security_coverage.py coverage.json
cd frontend && npm ci && npm run lint && npm run build
```

Set the backend's required database, Fernet, ZAP, artifact, repository, scanner
config, and OSV paths for the test environment. Real adapter tests additionally
require the pinned binaries and `SCOPEHARBOR_REAL_SCANNER_TESTS=1`.

Before release, also run Alembic clean/upgrade tests, `pip-audit`, `npm audit`,
both Docker image builds, Compose configuration/smoke tests, and controlled local
passive, repository, active-demo, and modern-crawl scans.
