# Changelog

All notable ScopeHarbor changes are recorded here. Versions follow semantic
versioning for the public source contract.

## [1.1.0] - 2026-07-29

### Added

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
- Schemas `0012_portfolio_readiness` and `0013_scan_subject_integrity`,
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

### Removed

- Dormant `EvidenceArtifact` persistence and raw-artifact reference fields.
- Passive crawl-summary artifacts.
- Dead AJAX execution methods and the unused `httpx2` development dependency.

### Compatibility

- Legacy allowlists still load as a migration aid.
- Historical AJAX records remain readable; AJAX cannot launch.
- Existing target-based repository requests create/reuse repository assets.
- Existing frontend routes/payloads remain accepted. Frontend source was not
  changed.

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
