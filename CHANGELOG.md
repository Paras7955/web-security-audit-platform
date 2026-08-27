# Changelog

All notable ScopeHarbor changes are recorded here. Versions follow semantic
versioning for the public source contract.

## [1.1.0] - 2026-07-29

### Fixed

- Development dependency auditing now pins pip 26.2, resolving
  `PYSEC-2026-3721` while retaining a Python 3.12 hash-locked environment.
- Source-built scanner tools now use digest-pinned Go 1.26.6; OSV-Scanner also
  pins go-git 5.19.2 and x/mod 0.40.0 to clear the current HIGH Trivy findings.
- Scanner readiness is now probed by the isolated worker and projected through
  its safe heartbeat instead of being probed from the API container, which has
  no scanner-control network access.
- The operator UI gates launches by the selected profile's actual dependencies:
  degraded ZAP readiness blocks ZAP profiles without disabling independent
  ScopeHarbor-passive or repository scans.

### Added

- Docker-only Bash and PowerShell onboarding with isolated secret bootstrap,
  offline advisory refresh, image builds, and readiness waiting.
- Recruiter-facing product tour, synthetic screenshots, social preview, and
  fresh-clone setup guidance for macOS, Windows, and Linux.
- Allowlist schema v2 with exact origin/base-path scope, Compose/host-gateway
  connection policies, verified HTTP/HTTPS trust, explicit engines, redirect
  limits, policy fingerprints, catalog/JSON validation, and reauthorization.
- Minimal signed-capability scan relay and separated Compose network topology.
- Generic local Docker and same-machine passive target support.
- Workspace repository assets, immutable web/repository scan authority
  snapshots, repository dashboards, and repository comparisons.
- Separate-session lease renewal, owner-fenced state writes, process-group
  termination, deadline/cancellation checkpoints, and guaranteed ZAP stop.
- Suppression revocation, audited tag unassignment/archive, current-posture
  dashboards, `posture-v1`, explicit external AI generation POST, bounded AI
  streaming, and race-safe report generation.
- Schemas `0012_portfolio_readiness`, `0013_scan_subject_integrity`, and
  `0014_worker_scanner_readiness`,
  artifact-cleanup tasks, complete environment reference/bootstrap merging,
  Compose hardening assertions, secret scanning, image vulnerability gates, and
  CycloneDX SBOM generation.
- MIT license and public release/operator documentation.

### Changed

- General local targets use the ScopeHarbor passive engine; ZAP engines remain
  explicitly compatible disposable-demo-only.
- Workers execute immutable launch snapshots instead of mutable target
  repository/authorization fields.
- Finding filters execute in SQL before cursor pagination.
- Dashboards distinguish current posture from separately labelled history.
- External AI GET is retrieval-only; template GET remains in-memory.
- Uvicorn raw access logs are disabled in favor of bounded queryless structured
  diagnostics.
- Product and public contracts are version `1.1.0`.
- The operator UI now uses first-class repository assets and subject-aware
  target/repository workflows, displays current posture separately from
  history, and exposes policy reauthorization and finding-governance controls.
- OIDC bearer tokens can be supplied for one browser tab and remain in memory;
  local development authentication remains available.

### Removed

- Dormant `EvidenceArtifact` persistence and raw-artifact reference fields.
- Passive crawl-summary artifacts.
- Dead AJAX execution methods and the unused `httpx2` development dependency.

### Compatibility

- Legacy allowlists still load as a migration aid.
- Historical AJAX records remain readable; AJAX cannot launch.
- Existing target-based repository requests create/reuse repository assets for
  historical callers; the current frontend no longer sends them.

### Fixed

- Repository compatibility launches now persist only their repository-asset
  subject, backed by a repair migration and database constraint.
- Relay requests are bounded before JSON parsing; relay responses use a bounded
  base64 envelope and expose only structured cookie security attributes.
- Frontend dependencies were advanced to audit-clean patched releases.
- Container CI readiness now uses one bootstrapped runtime environment for
  Compose interpolation, service startup validation, and guaranteed ordinary
  failure cleanup.
- Backend and container workflows now initialize runner-temporary paths inside
  executable steps, avoiding invalid job-level GitHub context expressions.

## [1.0.0] - 2026-07-14

- First public source contract after V1 phases 1–19 and the initial
  public-readiness work.
- Versioned workspace API, local web/repository scans, normalized findings,
  risk, reports, optional AI, operations, and the current operator UI.
