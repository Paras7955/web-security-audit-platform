# ScopeHarbor Development History

This document preserves the roadmap context that previously dominated the
README. It is historical, not the current operator or security contract. Use
`README.md`, `SECURITY.md`, `HANDOFF.md`, and the current code for present
behavior.

## V1 phases

| Phase | Delivered |
| --- | --- |
| 1 | FastAPI/Next.js/PostgreSQL/Compose foundation and shared contracts |
| 2 | Exact target allowlist, URL normalization, SSRF validation, and target API |
| 3 | Initial scan lifecycle, worker queue, cancellation, and artifacts |
| 4 | Normalized finding model and finding APIs |
| 5 | Conservative custom passive crawler/checks and redirect controls |
| 6 | Findings dashboard, progress, filtering, and details |
| 7 | Workspace-ready Markdown and HTML report generation |
| 8 | Deterministic AI explanation templates and optional provider boundary |
| 9A | ZAP passive integration with strict local scope |
| 9B | Local-demo-only bounded ZAP active scanning |
| 9C | Short historical ZAP AJAX browser profile |
| 9D | Multi-mode report/AI normalization and leakage hardening |
| 10 | Local repository scan model, path confinement, and initial adapters |
| 11 | Provider-neutral identities, dev/OIDC auth, and workspace isolation |
| 12 | Authenticated application shell and workspace-aware UI |
| 13 | Shared scan-profile contracts and acknowledgement-driven launch controls |
| 14 | Encrypted bearer/custom-header target auth profiles for passive HTTP |
| 15 | `risk-v1`, dashboards, scan comparisons, and target summaries |
| 16 | Finding lifecycle, suppressions, tags, and occurrence synchronization |
| 17 | AI cache/rate limits, safe fallback behavior, and provider controls |
| 18 | Platform health, audit trail, API rate limits, and operational state |
| 19 | Explicit idempotent demo seed and V1 documentation completion |

V1 phases 1–19 were completed before the public-readiness work. Historical
branches may use either `phase-*` or the older `codex/phase-*` prefix. Git
history is the detailed record of implementation and review fixes.

## Phase 20: public readiness

Phase 20 is an approved post-V1 hardening program. It introduced the ScopeHarbor
name and `1.0.0` public contract, versioned APIs, cursor pagination, safe problem
responses, lifecycle/startup validation, central persistence redaction, scanner
receipts, worker leases, migrations from schema 0008, real pinned repository
tools, offline OSV operation, ZAP Client Spider, auth-profile rotation/revocation,
maintenance commands, hardened containers, refreshed locked dependencies,
frontend compatibility, and a public-facing documentation set.

The launchable AJAX profile was retired in favor of Modern Web Crawl. Completed
AJAX history remains readable. Repository adapter stubs were replaced by real
Gitleaks and OSV-Scanner execution; migration removes deterministic stub results
and marks affected scans for rerun.

Current completion and verification status belongs in `HANDOFF.md`, not this
historical summary.

## Phase 21: operator workspace redesign

Phase 21 is the approved post-1.0 frontend redesign. It replaced the single
stacked console with a responsive six-tab workspace for overview, targets and
scans, finding triage, risk/report/AI intelligence, target credentials, and
platform operations. It added a persistent light/dark theme, a native WebGL
scope visualization with reduced-motion and non-WebGL behavior, consistent
design tokens, responsive layouts, and keyboard-aware confirmation UX.

Daily workflow improvements include searchable saved targets, scan-history
search/status/profile filters, finding free-text search and filter reset,
workspace refresh, clearer readiness and activity states, and history-preserving
target removal. Schema `0011_target_archiving` and the target API enforce that
removal clears launch configuration without deleting scan, finding, report,
risk, or audit history; nonterminal scans block the operation.

## Phase 22: guided audit design language

Phase 22 refined the frontend into a dark-first guided
`Ready → Scope → Profile → Authorize → Run → Review` experience. It improved
visual hierarchy, design tokens, compact finding triage, responsive behavior,
accessibility, reduced motion, and the security-path visualization. It was a
frontend-only phase and did not broaden scanner authority.

## Phase 23: portfolio-ready backend release

Phase 23 prepared version `1.1.0` as an MIT-licensed portfolio project. It added
allowlist schema v2, exact base-path and verified TLS policies, a minimal signed
capability relay, separated Compose networks, generic local HTTP/HTTPS passive
targets, workspace repository assets, immutable launch snapshots, stronger
lease/cancellation/process/ZAP handling, subject-aware posture and finding
management, explicit external AI generation, idempotent reports, schema `0012`,
release CI/SBOM/vulnerability gates, and reconciled public documentation.

The current frontend was intentionally preserved. It supports local development
auth and existing target workflows; OIDC login UX and repository-asset UI
integration are future frontend work.

## Scope decisions retained through 1.1

- The product remains defensive and local-first.
- Arbitrary public/cloud scanning remains denied.
- OWASP Juice Shop remains the bundled controlled web demo; generalized local
  applications receive passive scanning only.
- Static target auth is passive-client-only; browser login workflows are not
  implemented.
- Repository scans never clone, install, build, or execute repository code.
- Reports and AI consume only normalized/redacted projections.
- RBAC/team administration, business-logic testing, user-pair IDOR automation,
  Nuclei, Semgrep/full SAST, PDF export, and SaaS hardening remain outside scope.

The repository is available under the MIT License. Phase history does not imply
a support commitment or change the defensive-use boundaries.
