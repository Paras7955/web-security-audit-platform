# ScopeHarbor 1.1 Release Checklist

This checklist is for the repository owner. Do not mark an item complete from a
planned or mocked result.

## Source and scope

- [ ] Release branch worktree is clean and based on merged Phase 26 `main`.
- [ ] UI product changes remain contract-only: they do not broaden scanner
  authority, retain bearer tokens, expose raw scanner data, or bypass backend
  workspace/policy enforcement.
- [ ] Version is `1.1.0` in backend, shared contracts, and the frontend package.
- [ ] MIT license has `Copyright (c) 2026 Paras Atwal`.
- [ ] Third-party notices match the direct dependency locks, pinned tools, base
  images, Compose services, and current asset provenance.
- [ ] README, SECURITY, architecture, threat model, API, operator, upgrade,
  development history, changelog, and handoff agree.
- [ ] Public screenshots use only the explicit synthetic demo seed and show
  Workspace, Audits, Findings/Intelligence, and the formatted report accurately.
- [ ] The final public tree contains none of `.agents/`, `.opencode/`,
  `.codex/`, `.impeccable/`, `AGENTS.md`, or `HANDOFF.md` after the separate
  approval-gated cleanup commit.
- [ ] Issue forms sanitize public reports, blank issues are disabled, security
  reports route to private disclosure, and the PR template promises no SLA.
- [ ] Public/private-LAN scanning remains denied; only exact local policies are
  documented and tested.

## Local secrets and policies

- [ ] Back up `.env` and `AUTH_PROFILE_SECRET_KEY`.
- [ ] Run `./scripts/setup.sh --bootstrap-only` or the PowerShell equivalent.
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
- [ ] Confirm the development lock uses non-yanked `build==1.5.0`.
- [ ] Install both locks with `--require-hashes` on Python 3.12.13.
- [ ] Confirm the development lock installs pip 26.2 or later and that the lock
  compiler itself remains a documented, reproducible version.
- [ ] `pip-audit` passes for runtime and development locks.
- [ ] `npm audit --audit-level=high` passes.

## Backend verification

- [ ] Ruff passes for `backend` and `scripts`.
- [ ] Pyright passes.
- [ ] Migrations pass from zero, `0008`, `0011`, and `0012`; head is
  `0014_worker_scanner_readiness`; `alembic check` is clean.
- [ ] Full backend suite passes on a clean temporary PostgreSQL database.
- [ ] Overall branch coverage is at least 85%; security-boundary gates pass.
- [ ] Real pinned Gitleaks and offline OSV fixtures pass.
- [ ] Two-worker long scan proves continuous heartbeat, lease loss fencing,
  cancellation, descendant termination, and ZAP stop/lock cleanup.
- [ ] Auth attach/launch/rotation/revocation races pass with real PostgreSQL.
- [ ] Report race, malicious Markdown/fences, exact CSP, external-resource
  absence, local-only report guidance, oversized AI, seed collision, workspace
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

- [ ] Frontend `npm ci`, audit, state/contract tests, lint, and production build
  pass.
- [ ] Bash and PowerShell public setup wrappers parse successfully.
- [ ] A fresh clone reaches healthy UI, API, worker, relay, ZAP, PostgreSQL, and
  bundled demo services using only its documented Docker setup command.
- [ ] Responsive keyboard and reduced-motion checks cover the target-policy,
  repository, subject-aware scan, governance, finding-guidance, report,
  theme/readiness, and OIDC-facing workflows.
- [ ] API, worker, relay, and frontend images build.
- [ ] Source-built scanner binaries use Go 1.26.6 or later; review the explicit
  OSV-Scanner go-git and x/mod security pins before changing them.
- [ ] `python3 scripts/check_compose_hardening.py` passes.
- [ ] Compose migration/readiness smoke passes with non-root,
  capability-dropped, read-only services and expected networks/mounts.
- [ ] Stopping ZAP leaves core status healthy, keeps non-ZAP profiles
  launchable, and blocks each policy profile that explicitly requires ZAP.
- [ ] Pinned Gitleaks history scan passes.
- [ ] Digest-pinned Trivy `0.70.0` image scans are reviewed. Do not replace it
  with mutable Trivy action tags; review the
  [2026 supply-chain advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
  before updating the pin.
- [ ] CycloneDX SBOMs are generated for all four project images, uploaded as a
  14-day CI artifact, and reviewed before release.
- [ ] All GitHub Actions checks pass on the release commit.

## Repository owner actions

- [ ] Review and merge Phase 27, requiring all release checks to pass before
  tagging.
- [ ] Rename the still-private repository to `scopeharbor`, validate public
  links/assets, then complete the final file/history secret review before
  changing visibility.
- [ ] Enable GitHub Private Vulnerability Reporting.
- [ ] Enable branch protection and require the release CI checks.
- [ ] Enable GitHub Code Security as desired; for a private repository set
  `SCOPEHARBOR_CODE_SECURITY_ENABLED=true`.
- [ ] After CI passes on the merged release commit, create and push annotated
  tag `v1.1.0`.
- [ ] Do not publish local `.env`, reports, target data, SBOMs containing
  private image metadata, database dumps, or scanner artifacts.
