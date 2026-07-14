# Upgrading ScopeHarbor

## Before upgrading

1. Read the target version's README, security policy, handoff, and migrations.
2. Stop new scans and allow active work to finish or cancel it deliberately.
3. Back up PostgreSQL and the report artifact volume together.
4. Back up local secret configuration securely, especially the current Fernet
   key. Do not commit the backup.
5. Record the current Alembic revision and verify the backup can be restored.
6. Update the OSV database after the new worker image is available.

Never run a destructive downgrade against the only copy of operator data.

## Standard upgrade

```bash
python3 scripts/bootstrap_env.py
docker compose build backend worker frontend
docker compose run --rm migrate
docker compose --profile maintenance run --rm osv-db-update
docker compose up -d
docker compose run --rm backend python -m app.maintenance verify --apply
```

The bootstrap adds newly required settings without replacing an existing
`AUTH_PROFILE_SECRET_KEY`. Review `.env.example` for new operator choices before
starting services.

After startup, confirm `/health`, `/ready`, authenticated
`/api/v1/ops/health`, worker heartbeat, queue depth, report reads, and one
controlled scan for each profile you use.

## Upgrading from schema 0008

Migrations `0009_public_readiness` and `0010_public_indexes` add scanner tool
receipts, auth-profile lifecycle timestamps, target authorization timestamps,
worker leases/counters, constraints, and cursor indexes.

The 0009 upgrade deliberately:

- clears raw legacy worker error details;
- resanitizes persisted finding URLs and free text;
- removes deterministic repository stub findings;
- invalidates reports and risk scores derived from those stub findings;
- marks affected repository scans `completed_with_warnings` with rerun guidance;
- leaves completed historical AJAX scans readable;
- fails nonterminal historical AJAX jobs with the retired-profile code;
- clears unsafe absolute/traversal-style stored repository paths.

Review the backup before applying because removed stub-derived artifacts are not
reconstructable from the upgraded database. Rerun affected repository scans
with the pinned real tools after updating OSV data.

## API compatibility

ScopeHarbor 1.0 has no unversioned product API and provides no compatibility
redirects. Clients must use `/api/v1`, cursor pages, generic acknowledgement
codes, and safe failure objects. The deprecated public scan `mode`, mode-specific
booleans, raw artifact references, cancellation-user IDs, and raw error detail
are not available.

Read `/api/v1/contracts` at runtime rather than hard-coding profile
acknowledgements. See [`API.md`](API.md).

## Fernet changes

An ordinary upgrade must preserve `AUTH_PROFILE_SECRET_KEY`. A key change is a
separate planned operation using `AUTH_PROFILE_PREVIOUS_SECRET_KEY` and the
dry-run-first re-encryption command documented in
[`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md). Do not silently generate a replacement
key for an existing database.

## Rollback

Prefer restoring the matched pre-upgrade database and artifact backups with the
previous images/configuration. Database downgrade scripts are for development
and may not reconstruct data intentionally sanitized or removed by an upgrade.

If verification fails, stop API/worker, preserve logs and the failed database
for diagnosis, and restore the complete matched backup. Never paste secrets,
raw scanner output, or production data into an issue.
