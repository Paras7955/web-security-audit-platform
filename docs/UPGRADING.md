# Upgrading ScopeHarbor

## Before upgrading

1. Read the target README, security policy, changelog, and migrations.
2. Stop new scans; finish or deliberately cancel active work.
3. Back up PostgreSQL and `app-artifacts` together.
4. Back up `.env`, the current Fernet key, allowlist, and custom CA files
   securely. Never commit the backup.
5. Record the Alembic revision and test restoration.
6. Review new environment settings and policy-schema changes.

Never run a destructive downgrade against the only data copy.

## Upgrade to 1.1.0

```bash
python3 scripts/bootstrap_env.py
docker compose build migrate backend worker relay frontend
docker compose run --rm migrate
docker compose --profile maintenance run --rm osv-db-update
docker compose up -d
docker compose run --rm backend python -m app.maintenance verify --apply
docker compose run --rm backend python -m app.maintenance scheduled-artifacts
```

Review the scheduled-artifact dry run, then repeat it with `--apply` if the
listed legacy paths match the backup and policy.

Bootstrap merges newly required keys, generates `SCAN_RELAY_SECRET`, keeps the
Compose database URL consistent, and never replaces a non-empty
`AUTH_PROFILE_SECRET_KEY`.

After startup confirm `/health`, `/ready`, protected `/api/v1/ops/health`,
worker heartbeat/queue, report reads, target-policy status, and one controlled
scan per profile you use.

## Allowlist v1 to v2

Legacy entries continue to load when they describe one exact scheme, host, and
port. They are only an upgrade adapter and should be rewritten.

Old:

```yaml
- id: local-app
  name: Local App
  base_url: http://local-app:8080
  schemes: [http]
  hosts: [local-app]
  ports: [8080]
  allowed_modes: [passive]
  max_redirects: 3
  local_demo: false
```

V2:

```yaml
- id: local-app
  name: Local App
  base_url: http://local-app:8080/
  connection:
    kind: compose_service
    host: local-app
    port: 8080
  profile_engines:
    passive-web: [scopeharbor-passive]
  disposable_demo: false
  tls:
    trust: system
  max_redirects: 3
```

Review [`../config/scan-allowlist.example.yml`](../config/scan-allowlist.example.yml)
for host-gateway and HTTPS examples. Do not mechanically mark ordinary targets
as disposable or add ZAP engines. AJAX configuration is ignored for launch and
must not be migrated to another browser engine automatically.

Any authority-changing rewrite changes the fingerprint and makes saved targets
stale. Reauthorize only if origin/base path is unchanged. Otherwise create a new
target.

## Schema 0012

`0012_portfolio_readiness` upgrades from `0011_target_archiving` and adds:

- workspace-scoped repository assets;
- immutable web/repository scan authority snapshots;
- subject-aware finding state, suppressions, and risk identities;
- suppression revocation and tag archive history;
- report-generation uniqueness;
- artifact-cleanup tasks for retired data.

It removes the dormant `evidence_artifacts` table and raw-artifact reference
columns. It does not rewrite old migrations.

Legacy repository results without trustworthy tool receipts are invalidated.
Derived report/risk rows are removed where necessary, affected scans receive a
safe rerun warning, and confined artifact paths are recorded for dry-run-first
cleanup. Completed historical AJAX records remain readable; nonterminal AJAX
work remains retired.

Migration tests cover upgrades from zero, `0008`, and `0011`, legacy zero-finding
repository cleanup, cleanup tasks, and Alembic model drift.

## Schema 0013

`0013_scan_subject_integrity` upgrades from `0012_portfolio_readiness`. It
repairs any scan created by the temporary target-based repository compatibility
adapter that has both subject columns populated by retaining the repository
asset and clearing the target subject. It then adds a database constraint that
requires exactly one of `target_id` or `repository_asset_id` on every scan.

The compatibility request remains accepted, but its persisted scan and response
use only the repository-asset subject.

## Repository-asset compatibility

`Target.repo_path` and target-based repository launch remain temporarily
accepted for historical callers. The current frontend uses
`/api/v1/repository-assets` directly. Compatibility launch still creates/reuses
a repository asset and executes its immutable snapshot.

The frontend migration is complete. Do not delete compatibility columns/routes
until historical callers have been reviewed in a separately approved backend
phase.

## API behavior changes

- Target policy catalog, JSON validation, and reauthorization are new. GET
  validation is deprecated.
- Scan create accepts exactly one of `target_id`/`repository_asset_id`.
- Subject IDs/types are additive to scan/finding/risk responses.
- Dashboards distinguish current posture from historical totals.
- External AI generation moved to POST; GET is retrieval-only externally.
- Suppression revoke, tag unassign/archive, and repository dashboard/comparison
  routes are available.
- Historical target-based repository payloads remain accepted in 1.1.0; the
  current frontend no longer sends them.

Read `/api/v1/contracts` and `/openapi.json` at runtime.

## Earlier upgrades

From schema `0008`, migrations `0009`–`0011` first sanitize legacy failures and
findings, remove deterministic repository stubs, invalidate derived results,
retire nonterminal AJAX work, add receipts/leases/indexes, and introduce
history-preserving target archive. Then `0012` and `0013` apply the changes
above.

Review backups because intentionally removed unsafe/stub data is not
reconstructable from the upgraded database.

## Fernet keys

An ordinary upgrade must preserve `AUTH_PROFILE_SECRET_KEY`. Key rotation is a
separate operation using `AUTH_PROFILE_PREVIOUS_SECRET_KEY` and the
dry-run-first procedure in [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md). Never let
bootstrap or automation silently replace the key for an existing database.

## Rollback

Prefer restoring the matched pre-upgrade database, artifact volume, policy/CA
files, secrets, and prior images. Downgrade scripts are for development and
cannot reconstruct data intentionally sanitized or removed.

If verification fails, stop API/worker/relay, preserve safe diagnostics and the
failed database, and restore the matched backup. Never paste secrets, raw
scanner output, target data, or repository contents into an issue.
