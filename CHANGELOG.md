# Changelog

All notable ScopeHarbor changes are recorded here. Versions follow semantic
versioning for the public source contract.

## [1.1.0] - Unreleased

### Fixed

- Browser-backed ZAP work now starts through the image's Xvfb wrapper with
  writable ephemeral browser state and an executable ephemeral WebDriver;
  readiness also rejects a non-executable driver instead of allowing Active
  Demo or Client Spider scans to report false clean completions.
- Scan history now identifies each active or archived subject, and the
  workspace posture table lists only the latest active scan per
  subject/profile instead of mixing in unrelated recent history.
- Completed-with-warnings audits no longer display a contradictory generic
  hard-failure message; warning state remains explicit in status and scanner
  receipts.
- Standalone report prioritization now groups equivalent remediation actions
  while retaining every normalized occurrence in the detailed evidence.
- Standalone report severity badges no longer override the summary-card
  palette and obscure the severity counts.
- Risk scoring now uses the versioned, severity-bounded `risk-v2` and
  `posture-v2` aggregation, preventing a collection of low/medium hygiene
  findings from being presented as high or critical risk.
- OSV-Scanner is pinned to the reviewed upstream cache-path correction and
  repository scans use its fail-loud offline mode, preventing a 2.5.0 cache
  regression from silently returning an empty vulnerability result.
- Development dependency auditing now pins pip 26.2, resolving
  `PYSEC-2026-3721` while retaining a Python 3.12 hash-locked environment.
- The development lock pins `build` 1.5.0 instead of the yanked 1.5.1 release.
- Source-built scanner tools now use digest-pinned Go 1.26.6; Gitleaks pins
  x/crypto 0.55.0, while OSV-Scanner pins go-git 5.19.2, gRPC-Go 1.83.1,
  and x/mod 0.40.0, clearing the current HIGH/CRITICAL Trivy findings.
- Scanner readiness is now probed by the isolated worker and projected through
  its safe heartbeat instead of being probed from the API container, which has
  no scanner-control network access.
- The operator UI gates launches by the selected profile's actual dependencies:
  degraded ZAP readiness blocks ZAP profiles without disabling independent
  ScopeHarbor-passive or repository scans.
- Repository compatibility records no longer appear as duplicate web subjects
  or inflate public dashboard counts.
- The explicit demo seed now uses the production structured report renderer and
  deterministic audit/report timestamps instead of its legacy basic HTML.
- Eligible ZAP scans now reuse the guarded relay's validated destination IP
  projection, so the network-isolated worker does not need target DNS access
  and bundled demo scans no longer degrade with a resolution warning.
- ZAP pinning now preserves the policy's exact connection port, every ZAP
  engine is denied for non-disposable targets in both policy and worker checks,
  and Audit Review uses an independent unfiltered finding set.

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
  dashboards, `posture-v2`, explicit external AI generation POST, bounded AI
  streaming, and race-safe report generation.
- Schemas `0012_portfolio_readiness`, `0013_scan_subject_integrity`, and
  `0014_worker_scanner_readiness`,
  artifact-cleanup tasks, complete environment reference/bootstrap merging,
  Compose hardening assertions, secret scanning, image vulnerability gates, and
  CycloneDX SBOM generation.
- MIT license and public release/operator documentation.
- Direct third-party notices, synthetic product screenshots, a social-preview
  asset, sanitized issue forms, and a discretionary pull-request template.
- Four image CycloneDX SBOMs uploaded as short-retention CI artifacts.

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
- Structured Markdown and standalone HTML reports now include an audit
  overview, severity distribution, authorization/data-handling context,
  scanner receipts, prioritized local guidance, and print-friendly finding
  detail with exact CSP and no script or external resource dependency.
- Report generation always uses deterministic local guidance. Configuring
  OpenAI affects only explicit interactive generation and cannot create report
  network work, AI request logs, cache rows, or AI rate-limit reservations.
- The operator shell opens on Workspace, uses five primary destinations,
  exposes Credentials and Operations contextually, and keeps Audit Review
  focused on outcome, priority signals, and canonical handoffs.
- Finding guidance replaces misleading default “AI explanations” terminology;
  optional external assistance now has provider-aware consent copy.
- Frontend accessibility now includes skip navigation, measured sticky offsets,
  live readiness status, state-aware theme semantics, and visible mobile audit
  phase controls.
- Browserslist was advanced to a patched release after two HIGH advisories were
  published; frontend dependency audit remains clean.

### Removed

- Dormant `EvidenceArtifact` persistence and raw-artifact reference fields.
- Passive crawl-summary artifacts.
- Dead AJAX execution methods and the unused `httpx2` development dependency.
- The persistent WebGL hero, its runtime/styling, and Three.js dependencies.

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
