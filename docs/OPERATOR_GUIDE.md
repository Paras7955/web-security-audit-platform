# ScopeHarbor Operator Guide

## First start

Requirements: Docker with Compose v2, Python 3, and local capacity for
PostgreSQL, ZAP, and the worker tmpfs.

```bash
python3 scripts/bootstrap_env.py
docker compose --profile maintenance run --rm osv-db-update
docker compose up --build
```

Bootstrap creates or merges `.env`, adds newly introduced settings, generates
missing local secrets, and writes mode `0600`. It never replaces a non-empty
`AUTH_PROFILE_SECRET_KEY`. It also derives the Compose `DATABASE_URL` from the
generated PostgreSQL credentials unless you supplied an external database URL.

Check:

- UI: <http://localhost:3001>
- API liveness/readiness: <http://localhost:8000/health> and
  <http://localhost:8000/ready>
- API docs: <http://localhost:8000/docs>
- bundled demo: <http://localhost:3000>
- protected platform state: `/api/v1/ops/health`

The UI supports local development auth and first-class repository assets. In
strict OIDC mode, paste an already-issued platform bearer token into
**Operations → Operator access**. The token remains only in memory for that
browser tab; ScopeHarbor does not implement an identity-provider redirect flow.

## Configuration rules

- Local UI: keep `APP_ENV=local`, `AUTH_MODE=dev`, and `AUTH_PROVIDER=dev`.
- Use exact JSON arrays for `CORS_ORIGINS`, `TRUSTED_HOSTS`, and
  `TRUSTED_PROXY_IPS`; wildcards and non-IP proxies are rejected.
- Keep `.env`, database/dev/OIDC tokens, Fernet/relay/ZAP secrets, and AI keys
  out of Git.
- Fernet keys commonly end in `=`. Do not truncate them or add literal quotes.
- Never expose ZAP/relay/worker or replace loopback port bindings without a
  separate network review.
- Non-local target credential submission must use direct HTTPS or an exact
  trusted proxy that replaces client-supplied forwarding headers.
- Review host capacity and denial-of-service impact before raising any limit.
- `SCAN_RELAY_URL` and `SCAN_RELAY_SECRET` must be configured together. The
  secret must contain at least 32 bytes.

`.env.example` is the complete settings reference. `/ready` rejects invalid
cross-field relationships rather than running with unsafe defaults.

## OIDC mode

For production-like local use:

1. Set `AUTH_MODE=required`.
2. Set a stable non-`dev` `AUTH_PROVIDER`.
3. Configure exact `AUTH_OIDC_ISSUER`, `AUTH_OIDC_AUDIENCE`, and
   `AUTH_OIDC_JWKS_URL`.
4. Stop using the development token.
5. Open **Operations → Operator access** and supply an already-issued OIDC
   bearer token, or use an API client that supplies it.
6. Rebuild and confirm `/ready` plus one protected request.

ScopeHarbor accepts RS256 tokens with strict issuer/audience and required
`sub`, `exp`, and `iat`. First login creates one user-owned default workspace.

## Allowlist schema v2

`config/scan-allowlist.yml` is trusted launch authority. Start from
[`../config/scan-allowlist.example.yml`](../config/scan-allowlist.example.yml).

Each policy declares:

- stable `id` and display `name`;
- exact HTTP/HTTPS `base_url`, including optional base-path scope;
- `connection.kind`: `compose_service` or `host_gateway`;
- exact connection host/port and, for host gateway, exact expected IPs;
- eligible `profile_engines`;
- `disposable_demo`;
- TLS `system` or `custom_ca` trust;
- redirect limit from 0–10.

Only `scopeharbor-passive` should be configured for an ordinary local
application. ZAP engines require all required engines for that profile and an
explicitly compatible disposable HTTP demo.

The protected operations health response separates core readiness from ZAP
readiness. If ZAP is degraded, only target profiles listed in
`zap_required_scan_profile_ids` are unavailable; do not treat that condition as
an outage for independent passive or repository scans.

### Add another Compose service

1. Attach the application service to ScopeHarbor's `scan-target` network.
2. Give it a stable Compose service name and internal port.
3. Add an exact `compose_service` policy whose connection host matches that
   service.
4. Restart API, worker, and relay.
5. Validate with `GET /api/v1/targets/policies`, then
   `POST /api/v1/targets/validate`.
6. Create the target with `permission_confirmed=true`.

The browser-facing host URL is not scanner authority; the policy uses the
internal service identity.

### Add a same-machine HTTP application

1. Ensure the application listens on an interface reachable through Docker's
   host gateway. On Linux, loopback-only listeners are normally unreachable;
   Docker Desktop supplies the usual host-local path.
2. Resolve the canonical gateway alias from the relay:

   ```bash
   docker compose run --rm relay getent hosts scopeharbor-host
   ```

3. Add a `host_gateway` policy using origin/connection host
   `scopeharbor-host`, the application port, and the exact returned RFC1918
   address in `expected_ips`.
4. Permit only `passive-web: ["scopeharbor-passive"]`.
5. Restart/validate/create as above.

Do not substitute a LAN address, public address, `localhost`, `127.0.0.1`, or a
metadata/link-local address.

### Add same-machine HTTPS

The certificate SAN must match the configured origin host.

- Use `tls: {trust: system}` for a publicly/system-trusted local certificate.
- For a local CA, place one reviewed PEM bundle below `config/` and set:

  ```yaml
  tls:
    trust: custom_ca
    ca_bundle_path: /app/config/certs/local-development-ca.pem
  ```

The bundle must be a regular file no larger than 1 MiB. There is no insecure
mode; wrong hostname, expired, malformed, or untrusted certificates fail.

### Scope/path rules

`base_url: https://scopeharbor-host:8443/app/` permits `/app` and descendants
on segment boundaries, not `/application`. Userinfo, query, fragment, invalid
percent escapes, encoded NUL/dot/slash/backslash, raw backslash, repeated
separators, and dot traversal are rejected.

Redirects must stay on the same origin and inside the base path. Credential
headers are never carried across a policy/origin boundary.

### Policy changes and reauthorization

The fingerprint covers connection identity, engines, disposable-demo status,
TLS policy/CA digest, scope, and redirect limit. Changing launch authority makes
saved targets stale and blocks scans. Review the new policy, then call:

```http
POST /api/v1/targets/{target_id}/reauthorize
{"permission_confirmed": true}
```

If origin or base path changed, create a new target. Do not rewrite historical
identity.

Legacy v1 entries (`schemes`, `hosts`, `ports`, `allowed_modes`,
`local_demo`) still load for upgrade compatibility when they describe one exact
HTTP Compose service. Migrate them to v2. Legacy AJAX entries do not make AJAX
launchable.

## Repository assets

The supplied Compose file mounts this repository read-only at
`/app/repositories/security-project`. To scan another repository, add one narrow
read-only bind mount below `/app/repositories`; never mount a home directory or
host filesystem root.

In **Audits → Scope**, create a repository asset using the absolute in-container
path and explicit permission confirmation. The UI uses
`/api/v1/repository-assets`; ScopeHarbor returns and displays only the confined
relative identity. Each scan snapshots it, so later path changes cannot retarget
queued work.

The existing target `repo_path` route remains a deprecated compatibility
adapter for historical callers. The current UI does not use it.

Ordinary scans never access a remote or resolve dependencies. Refresh offline
OSV data before first use, after cache recreation, and at least weekly:

```bash
docker compose --profile maintenance run --rm osv-db-update
```

Stale/missing OSV data yields a warning receipt and skip, never online fallback.

## Demo seed

```bash
docker compose run --rm -e DEMO_SEED_ENABLED=true backend python -m app.demo_seed
```

Seed preflights every fixed ID and refuses cross-workspace collisions before
writing. It is idempotent, contains safe normalized data, and performs no
network/scan work.

## Maintenance

Preview:

```bash
docker compose run --rm backend python -m app.maintenance verify
docker compose run --rm backend python -m app.maintenance orphan-artifacts
docker compose run --rm backend python -m app.maintenance scheduled-artifacts
docker compose run --rm backend python -m app.maintenance prune-operational --older-than-days 30
docker compose run --rm backend python -m app.maintenance backfill-risk
```

Repeat only the reviewed command with `--apply`.

- `verify`: configuration, schema, and scanner versions.
- `orphan-artifacts`: unreferenced scan directories.
- `scheduled-artifacts`: migration-recorded legacy artifact cleanup tasks.
- `prune-operational`: old AI/cache/rate/heartbeat operational rows; heartbeat
  age uses `last_seen_at`.
- `backfill-risk`: missing immutable `risk-v1` rows.

Maintenance never prunes audit logs, findings, reports, or scan history.

## Fernet key rotation

Back up PostgreSQL and stop auth-profile/scan writes:

1. Keep the old key as `AUTH_PROFILE_PREVIOUS_SECRET_KEY`.
2. Set a newly generated Fernet key as `AUTH_PROFILE_SECRET_KEY`.
3. Preview, then apply:

   ```bash
   docker compose run --rm backend python -m app.maintenance reencrypt-auth-profiles
   docker compose run --rm backend python -m app.maintenance reencrypt-auth-profiles --apply
   ```

4. Verify metadata and one controlled passive scan.
5. Remove the previous key and restart.

The command validates all active ciphertext before commit and never prints
plaintext. Losing the key and backup makes existing secrets unrecoverable.

## Backup and troubleshooting

Back up PostgreSQL, `app-artifacts`, `.env`/secret records, and policy/CA files
together. Database-only backups are incomplete because report rows reference
files. Follow [UPGRADING.md](UPGRADING.md).

- `/ready` failure: check auth/Fernet/relay/ZAP settings, limits, policy/CA
  files, storage, and schema head.
- target stale: inspect the policy diff; reauthorize only if identity is
  unchanged.
- relay failure: verify exact expected IP, host listening interface, base path,
  certificate hostname/trust, and relay health. Never enable insecure TLS.
- worker degraded: inspect safe heartbeat/queue/receipt state and structured
  logs; do not paste raw target/tool data into issues.
- ZAP degraded with core status healthy: inspect the internal ZAP service and
  worker connectivity; independent non-ZAP profiles can continue safely.
- dependency warning: refresh the OSV cache.
- stale development rows: use a clean temporary database for verification.

Logs intentionally omit query strings, authorization values, bodies, raw
exceptions, and scanner output.

## Development verification

Use Python `3.12.13`, the hash lock, and a disposable PostgreSQL database:

```bash
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r backend/requirements-dev.txt
.venv/bin/ruff check backend scripts
.venv/bin/pyright
PYTHONPATH=backend .venv/bin/coverage run --branch -m unittest discover -s backend/tests
.venv/bin/coverage report --fail-under=85
.venv/bin/coverage json -o coverage.json
.venv/bin/python scripts/check_security_coverage.py coverage.json
```

Also run frontend `npm ci`, audit, state/contract tests, lint, and production build;
migration upgrades from zero/0008/0011; runtime+dev dependency audits; real
pinned scanner fixtures; image builds; Compose hardening/readiness; SBOM;
vulnerability review; and controlled local HTTP/HTTPS scans. The release
checklist contains the complete sequence.
