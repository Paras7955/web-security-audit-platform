# ScopeHarbor 1.1 Release Checklist

This checklist is for the repository owner. Do not mark an item complete from a
planned or mocked result.

## Source and scope

- [ ] Branch is `phase-23-backend-public-readiness`; worktree is clean.
- [ ] No `frontend/` source file changed in Phase 23.
- [ ] Version is `1.1.0` in backend and shared contracts.
- [ ] MIT license has `Copyright (c) 2026 Paras Atwal`.
- [ ] README, SECURITY, architecture, threat model, API, operator, upgrade,
  development history, changelog, and handoff agree.
- [ ] Public/private-LAN scanning remains denied; only exact local policies are
  documented and tested.

## Local secrets and policies

- [ ] Back up `.env` and `AUTH_PROFILE_SECRET_KEY`.
- [ ] Run `python3 scripts/bootstrap_env.py`.
- [ ] Confirm bootstrap added `SCAN_RELAY_SECRET` and did not replace the Fernet
  key.
- [ ] Review every custom allowlist entry, expected host-gateway IP, base path,
  eligible engine, redirect cap, and custom CA.
- [ ] Reauthorize only unchanged target identities; create new targets for
  origin/base-path changes.
- [ ] Refresh offline OSV data.

## Dependency locks and audits

- [ ] Regenerate both Python locks using Python `3.12.13` and pip-tools `7.5.3`:

  ```bash
  python3.12 -m venv .lock-venv
  .lock-venv/bin/pip install pip-tools==7.5.3
  cd backend
  ../.lock-venv/bin/pip-compile --generate-hashes --strip-extras --output-file=requirements.txt requirements.in
  ../.lock-venv/bin/pip-compile --allow-unsafe --generate-hashes --strip-extras --output-file=requirements-dev.txt requirements-dev.in
  ```

- [ ] Confirm no `httpx2`, `httpcore2`, or orphan `truststore` entry remains.
- [ ] Install both locks with `--require-hashes` on Python 3.12.13.
- [ ] `pip-audit` passes for runtime and development locks.
- [ ] `npm audit --audit-level=high` passes.

## Backend verification

- [ ] Ruff passes for `backend` and `scripts`.
- [ ] Pyright passes.
- [ ] Migrations pass from zero, `0008`, and `0011`; head is
  `0012_portfolio_readiness`; `alembic check` is clean.
- [ ] Full backend suite passes on a clean temporary PostgreSQL database.
- [ ] Overall branch coverage is at least 85%; security-boundary gates pass.
- [ ] Real pinned Gitleaks and offline OSV fixtures pass.
- [ ] Two-worker long scan proves continuous heartbeat, lease loss fencing,
  cancellation, descendant termination, and ZAP stop/lock cleanup.
- [ ] Auth attach/launch/rotation/revocation races pass with real PostgreSQL.
- [ ] Report race, malicious Markdown, oversized AI, seed collision, workspace
  IDOR, and filtered pagination tests pass.

## Local target verification

- [ ] Generic Compose HTTP service scans successfully through the relay.
- [ ] Same-machine HTTP application scans through exact host-gateway policy.
- [ ] System-trusted and custom-CA HTTPS fixtures succeed.
- [ ] Wrong hostname, expired/untrusted certificate, and any attempted insecure
  TLS fail.
- [ ] Public, metadata, loopback, link-local, mixed DNS, rebinding,
  IPv4-mapped-IPv6, redirect escape, ambiguous path, stale policy, and
  capability replay tests fail closed.
- [ ] Canary is absent from target creation/relay failures/crawler output,
  database, artifacts, reports, AI/cache, audit, API, and real-server logs.

## Containers and CI

- [ ] Frontend `npm ci`, lint, and production build pass without source changes.
- [ ] API, worker, relay, and frontend images build.
- [ ] `python3 scripts/check_compose_hardening.py` passes.
- [ ] Compose migration/readiness smoke passes with non-root,
  capability-dropped, read-only services and expected networks/mounts.
- [ ] Pinned Gitleaks history scan passes.
- [ ] Digest-pinned Trivy `0.70.0` image scans are reviewed. Do not replace it
  with mutable Trivy action tags; review the
  [2026 supply-chain advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
  before updating the pin.
- [ ] CycloneDX SBOMs are generated and reviewed for all four project images.
- [ ] All GitHub Actions checks pass on the release commit.

## Repository owner actions

- [ ] Review the Phase 23 commits and merge/push the phase branch.
- [ ] Enable GitHub Private Vulnerability Reporting.
- [ ] Enable branch protection and require the release CI checks.
- [ ] Enable GitHub Code Security as desired; for a private repository set
  `SCOPEHARBOR_CODE_SECURITY_ENABLED=true`.
- [ ] After CI passes on the merged release commit, create and push annotated
  tag `v1.1.0`.
- [ ] Do not publish local `.env`, reports, target data, SBOMs containing
  private image metadata, database dumps, or scanner artifacts.
