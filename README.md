# ScopeHarbor

**Local AppSec Audit Platform · 1.1.0**

ScopeHarbor is a defensive, local-first application security audit platform for
web applications and repositories you own or are explicitly authorized to test.
It combines guarded web scanning, isolated repository analysis, normalized
findings, current-posture risk tracking, reports, and optional AI explanations.

This is a portfolio project for local, single-operator use—not a hosted scanning
service or a multi-tenant SaaS product. It is available under the
[MIT License](LICENSE).

## Capabilities

- Bounded passive scanning for exact configured Docker services and
  same-machine applications.
- Verified HTTP and HTTPS transport through a non-root guarded relay. HTTPS uses
  system trust or an operator-mounted CA bundle; insecure TLS is not supported.
- ZAP Passive, Active Demo, and Client Spider for explicitly compatible,
  disposable HTTP demo containers only.
- Workspace-scoped repository assets and immutable repository scan snapshots
  below `REPO_SCAN_ROOT`.
- Pinned Gitleaks and offline OSV-Scanner execution without cloning, installing,
  building, running hooks, resolving dependencies, or executing repository code.
- Normalized findings with lifecycle state, revocable suppressions, auditable
  tags, scan comparisons, immutable `risk-v1`, and dynamic `posture-v1`.
- Idempotent Markdown/HTML reports and deterministic template explanations.
- Optional bounded external AI explanations with retrieval-only GET and
  explicit generation POST behavior.
- Encrypted bearer/static-header target credentials for passive requests only.
- Lease-fenced, cancellable worker execution with safe scanner receipts,
  structured logs, and dry-run-first maintenance.

ScopeHarbor never accepts an arbitrary public URL. Private-LAN and public
destinations remain denied.

## Safety model

Web authority comes from allowlist schema v2 in
[`config/scan-allowlist.yml`](config/scan-allowlist.yml). A policy fixes the
origin, base path, connection class, destination identity, transport trust,
redirect cap, and eligible engines. Target creation also requires an explicit
authorization confirmation.

The worker cannot connect directly to host or public networks. Passive requests
use short-lived, signed, single-use capabilities sent to the guarded relay. The
relay independently validates the capability, allowlist, destination IP,
method, headers, TLS policy, and response limits. It permits only `GET`, disables
automatic redirects, and preserves the configured HTTP `Host` and TLS SNI while
dialing the validated IP. The relay manually follows a bounded redirect only
after same-origin, base-path, allowlist, and SSRF revalidation.

Changing launch authority makes saved targets stale. A stale target must be
reauthorized; an origin or base-path change requires a new target so historical
identity is never rewritten.

Repository authority comes from a workspace-scoped `RepositoryAsset`. Scans
persist the authorized relative path and acknowledgement snapshot and execute
only that immutable snapshot.

Queries may exist transiently while making a request, but URL userinfo, query,
and fragment data never cross database, API, artifact, report, AI, cache, audit,
or log boundaries. Raw bodies, cookies, credentials, scanner output, provider
errors, and unredacted evidence are likewise prohibited.

Read [SECURITY.md](SECURITY.md) and the
[threat model](docs/THREAT_MODEL.md) before changing a trust boundary.

## Architecture

```text
Operator browser -> Next.js UI -> FastAPI /api/v1 -> PostgreSQL
                                      |                  ^
                                      v                  |
                                  scan queue -> lease-fenced worker
                                                     |          |
                                             signed capability  |
                                                     v          v
                                            guarded relay     ZAP
                                                 |       pinned repo tools
                                    exact local target
```

Compose separates data, scanner-control, scan-target, host-access,
operator-access, and updater networks. Only the relay receives host-gateway
access; the relay receives no database, artifact, ZAP, AI, repository, or
platform-auth access. See [Architecture](docs/ARCHITECTURE.md).

## Quick start

Requirements: Docker with Compose v2 and Python 3.

```bash
python3 scripts/bootstrap_env.py
docker compose --profile maintenance run --rm osv-db-update
docker compose up --build
```

Bootstrap creates or merges `.env`, generates missing local secrets including
`SCAN_RELAY_SECRET`, and keeps the Compose PostgreSQL URL consistent. It never
replaces a non-empty user-managed `AUTH_PROFILE_SECRET_KEY`. A Fernet key may
end in `=` and should not be quoted unless the environment format requires it.

Open:

- UI: <http://localhost:3001>
- API/docs: <http://localhost:8000/docs>
- bundled Juice Shop: <http://localhost:3000>
- readiness: <http://localhost:8000/ready>

Stop without deleting local data:

```bash
docker compose down
```

Add `--volumes` only when you intentionally want to remove PostgreSQL, reports,
and the offline OSV cache.

### Current UI boundary

The UI consumes the protected `/api/v1` contracts for target policies,
first-class repository assets, subject-aware scans, posture, comparisons,
finding governance, reports, and explicit AI generation. Local development
tokens remain supported. In strict OIDC mode an operator can supply an
identity-provider-issued bearer token for the current browser tab; the UI keeps
it in memory and never writes it to browser storage. ScopeHarbor does not
implement an identity-provider redirect or browser login flow.

### Demo data

Demo seed is explicit, fixed-ID, collision-preflighted, idempotent, and performs
no scan or network work:

```bash
docker compose run --rm -e DEMO_SEED_ENABLED=true backend python -m app.demo_seed
```

## Scanning another local application

Use [`config/scan-allowlist.example.yml`](config/scan-allowlist.example.yml) as
a schema v2 reference.

- For another Compose application, attach it to `scan-target` and use an exact
  `compose_service` policy.
- For an application running on the same machine, use `host_gateway`, the
  canonical `scopeharbor-host` name, and the exact gateway IP observed inside
  the relay container.
- A Linux-host application must listen on an interface reachable through the
  Docker host gateway. Docker Desktop provides the normal host-local route.
- For HTTPS, the certificate hostname must match the configured host. Use
  system trust or mount one confined CA bundle below `/app/config`; there is no
  certificate-verification bypass.
- General local applications are eligible for the ScopeHarbor passive engine
  only. Do not mark a target disposable merely to enable ZAP.

Policies reject roots with userinfo, queries, or fragments and reject ambiguous
encoded separators, backslashes, repeated separators, or dot traversal.
Redirects must remain on the same origin and within the configured base path.
Detailed migration and validation steps are in the
[Operator Guide](docs/OPERATOR_GUIDE.md).

## Local services

| Service | Host address | Purpose |
| --- | --- | --- |
| Frontend | `127.0.0.1:3001` | Current operator UI |
| Backend | `127.0.0.1:8000` | API and OpenAPI documentation |
| Juice Shop | `127.0.0.1:3000` | Bundled disposable demo |
| PostgreSQL | `127.0.0.1:5432` | Local persistence |
| Worker | not published | Lease-owned scan execution |
| Relay | not published | Guarded local-target transport |
| ZAP | not published | Demo-only scanner daemon |

Published ports bind to loopback by default.

## Authentication

Local bootstrap generates a development bearer token. It is accepted only when
`APP_ENV=local`, `AUTH_MODE=dev`, and `AUTH_PROVIDER=dev`; rebuild the frontend
after changing it.

Strict OIDC mode requires `AUTH_MODE=required`, a non-`dev` provider identifier,
and exact issuer, audience, and JWKS URL values. Tokens must be RS256-signed and
contain `sub`, `exp`, and `iat`. Every protected lookup remains workspace
scoped.

Target auth profiles are separate from platform login. Secrets are
Fernet-encrypted and write-only. Plaintext credential submission is permitted
only in local mode; non-local access requires direct HTTPS or an exact trusted
proxy that asserts HTTPS. Auth material can enter only guarded passive requests
and never ZAP, repository scans, reports, AI, receipts, status, audit, or logs.

## Scan profiles

| Profile | Engine | Constraints | Reports | AI |
| --- | --- | --- | --- | --- |
| `passive-web` | ScopeHarbor passive; optional ZAP Passive only when policy permits | exact v2 policy; optional static auth | yes | yes |
| `active-demo` | passive checks + ZAP Active | explicitly compatible disposable HTTP demo | yes | yes |
| `modern-web-crawl` | passive checks + ZAP Client Spider | explicitly compatible disposable HTTP demo | no | no |
| `repository` | Gitleaks + offline OSV | repository asset below root; no code execution | yes | no |

Historical AJAX records remain readable, but AJAX is not launchable.

## Repository tools

The worker image builds checksum-pinned Gitleaks `8.30.1` and OSV-Scanner `2.5.0`
source with a digest-pinned Go toolchain and explicit security module updates.
Scanner output exists only in bounded ephemeral storage and is discarded after normalization.
Update the offline OSV cache before first use and at least weekly while active:

```bash
docker compose --profile maintenance run --rm osv-db-update
```

A missing or stale database skips OSV with a warning receipt; it never falls
back to online resolution during a scan.

## Reports and AI

Report generation is idempotent and race-safe. Markdown structure is escaped,
code fences exceed any input fence, HTML is escaped, and files use atomic
no-follow writes with restrictive permissions. PDF is not supported.

`AI_PROVIDER=template` is deterministic and local. For an external provider,
`POST /api/v1/scans/{id}/ai-explanations` explicitly performs generation;
`GET` retrieves existing external results only. Provider responses are streamed
under a hard cap and incrementally validated. Repository and modern-crawl data
are never sent to an AI provider.

## Operations and verification

`/health` is liveness. `/ready` validates runtime configuration and schema
`0013_scan_subject_integrity`. Protected `/api/v1/ops/health` provides safe
component state.

Maintenance is dry-run-first:

```bash
docker compose run --rm backend python -m app.maintenance verify
docker compose run --rm backend python -m app.maintenance orphan-artifacts
docker compose run --rm backend python -m app.maintenance scheduled-artifacts
docker compose run --rm backend python -m app.maintenance prune-operational --older-than-days 30
docker compose run --rm backend python -m app.maintenance backfill-risk
```

Add `--apply` only after reviewing the JSON plan. See the
[Operator Guide](docs/OPERATOR_GUIDE.md), [API reference](docs/API.md),
[upgrade guide](docs/UPGRADING.md), and
[release checklist](docs/RELEASE_CHECKLIST.md).

CI runs migrations, backend branch/security coverage, Ruff, Pyright, dependency
audits, frontend state/contract tests plus lint/build, Compose hardening/readiness, pinned Gitleaks,
digest-pinned Trivy image scans, and CycloneDX SBOM generation.

Phase-end independent reviews use `gpt-5.6-sol` with medium reasoning, the
current review-grade successor to the retired `gpt-5.4` reviewer pin.

## Limitations

- ScopeHarbor is a local portfolio project, not a hosted scanner or SaaS control
  plane.
- Authorization is the operator's responsibility; the platform cannot grant it.
- General local web targets receive passive scans only.
- Authenticated browser sessions, business-logic automation, RBAC/team
  administration, public scanning, remote repository cloning, full SAST,
  Nuclei, Semgrep, PDF export, and security guarantees remain out of scope.
- Findings require human validation. No findings is not proof of safety.

Use ScopeHarbor only on systems and repositories you own or are explicitly
authorized to assess.
