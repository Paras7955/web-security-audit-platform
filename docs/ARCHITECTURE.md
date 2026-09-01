# ScopeHarbor Architecture

## Design goals

ScopeHarbor 1.1 is a local, single-operator portfolio application. It prioritizes
exact launch authority, immutable scan scope, workspace isolation, bounded and
cancellable execution, safe persistence, and inspectable receipts over scanner
breadth. It is not a hosted multi-tenant architecture.

## Components

```text
Operator browser
      |
      v
Next.js frontend (operator-access)
      |
      v
FastAPI API (operator-access + data) ---> optional OIDC / external AI
      |                    |
      |                    +------> report volume
      v
PostgreSQL (data) <------ lease monitor + scanner worker
                                      |
                         +------------+-------------+
                         |                          |
                  scanner-control             repository tmpfs
                         |                          |
                  +------+-------+          Gitleaks + offline OSV
                  |              |
              guarded relay     ZAP
                  |              |
          scan-target / host   scan-target
                  |
          exact local application
```

### Frontend

The Next.js UI consumes `/api/v1` for target-policy, repository-asset,
subject-aware scan, posture, finding-governance, report, and finding-guidance
workflows. It supports the build-provided local development token and an
in-memory OIDC bearer session supplied by the operator. It does not implement
provider redirects, persist bearer tokens, or make authorization decisions.

### Local bootstrap

The public Bash and PowerShell setup wrappers require only Docker with Compose
v2. They run the repository-owned environment bootstrap inside a digest-pinned
Python container with no network, a read-only root filesystem, no Linux
capabilities, `no-new-privileges`, and a read-only repository mount. The
container can write only to a fresh temporary output directory. The wrapper
then moves the completed environment file into the repository and never prints
secret values. OSV refresh remains a separate one-shot Compose service attached
only to the updater network.

### API

FastAPI owns platform authentication, workspace authorization, target/repository
asset creation, policy catalog and validation, scan launch, safe projections,
reports, deterministic local guidance, optional AI orchestration, rate limits,
and audit events. It never runs scan
jobs inline.

All product routes are below `/api/v1`. `/health` is minimal liveness; `/ready`
validates runtime settings and schema head. Startup rejects inconsistent
resource limits, auth/provider configuration, unsafe sentinels, relay/ZAP
configuration, invalid paths, malformed allowlists, and stale schema.

### PostgreSQL

PostgreSQL stores identities, workspaces, targets, repository assets,
auth-profile ciphertext, immutable scan authority snapshots, leases, receipts,
normalized findings, subject-aware lifecycle/suppressions/tags/risk, reports,
safe AI/cache/rate records, cleanup tasks, heartbeats, and audit events.

Every user-data lookup carries a workspace predicate. Alembic schema head is
`0014_worker_scanner_readiness`; API and worker fail closed if the database is
not at that head.

### Worker and lease guard

The worker claims one queued scan, records `lease_owner`/expiry, and executes
under a `ScanExecutionMonitor`. A separate database session renews the scan
lease and worker heartbeat. All state writes are fenced by the current owner.
Because the API is intentionally absent from `scanner-control`, the worker also
performs the bounded, proxy-independent ZAP readiness probe and records only a
safe status/detail in its heartbeat. The API's core status remains independent
of this optional profile dependency.
Cancellation, deadline, or ownership loss interrupts passive requests, ZAP
polling, and repository subprocess polling.

Repository tools run in isolated process groups; abort terminates descendants.
ZAP work is explicitly stopped and cleaned before its advisory lock is
released. Interrupted active/browser scans are not automatically replayed.

The worker executes only launch snapshots:

- web: target URL, allowlist ID, policy fingerprint, auth-profile ID,
  authorization and acknowledgement snapshot;
- repository: repository-asset ID and relative path snapshot.

Mutable target/repository path fields are not worker authority.

### Guarded relay

The relay is a separate non-root ASGI service with one worker. It has the
allowlist, a capability secret, a small tmpfs, scanner-control, scan-target, and
host-access networks. It has no database, artifact, repository, ZAP, AI, OIDC,
or platform-auth configuration.

For each request it independently:

1. verifies an HMAC-signed, expiring, single-use capability;
2. reloads/matches the allowlist policy and fingerprint;
3. accepts only `GET`;
4. validates the exact connection class/host/port/IP and path;
5. strips hop-by-hop/routing headers and caps all headers;
6. dials the validated IP with configured `Host` and TLS SNI;
7. verifies system trust or a confined CA bundle;
8. disables automatic redirects, manually validates bounded hops, and caps the
   response body;
9. returns body content in a bounded base64 envelope and only structured cookie
   security attributes.

It never offers insecure TLS and never logs URLs, credentials, headers, or
bodies.

### Web scan engines

The ScopeHarbor passive crawler sends capabilities to the relay, evaluates
bounded response metadata/body content in memory, and persists only normalized
findings. It does not create a crawl-summary artifact. The relay follows each
redirect only after it is confirmed same-origin, within the base path, and
independently revalidated. Credentials do not cross an origin/policy boundary.

ZAP is internal and API-key protected. Its clients set `trust_env=False` and
disable redirects so the API key cannot enter an inherited proxy. ZAP Passive,
Active Demo, and Client Spider run only where the policy explicitly permits the
engine and marks the HTTP target as a compatible disposable demo.

### Repository scanners

Repository assets store a workspace-scoped relative path below
`REPO_SCAN_ROOT`. The worker resolves the immutable snapshot, stages eligible
regular files into a `0700` tmpfs directory, and enforces file-count, per-file,
total-byte, timeout, output, and finding limits.

Pinned Gitleaks and OSV-Scanner use ScopeHarbor-owned configuration. Gitleaks
redacts all secret material. OSV uses the operator-updated offline database with
`--no-resolve`. No repository code/config is executed or honored; raw tool
output is ephemeral.

### Reports and finding guidance

Report creation is unique per `(workspace, scan, format)` and race-safe.
Markdown structure/fences and HTML are escaped. The standalone light HTML
artifact is responsive, print-friendly, script-free, resource-free, and
protected by exact response and embedded CSP. Writes are atomic and no-follow.

Reports always calculate deterministic local guidance in memory, even when an
external provider is configured. Report creation never performs provider
network work or writes AI cache/request-log/rate-limit records. Interactive
local guidance remains available through the compatibility AI endpoints.
Optional external generation is explicit POST, atomically rate-reserved, safely
projected, streamed under a hard cap, and incrementally JSON-validated. External
GET is retrieval-only. Repository and modern-crawl findings are ineligible.

## Data flow

```text
Untrusted target/tool/provider input
        |
        v
bounded read + parse/schema validation
        |
        v
independent URL/text/metadata redaction
        |
        v
normalized subject/workspace object
        |
        +-> PostgreSQL
        +-> API projection
        +-> report projection + deterministic local guidance
        +-> explicitly requested eligible external-AI projection
        +-> bounded structured log/audit metadata
```

Every downstream boundary sanitizes independently. URL userinfo, queries, and
fragments are removed before any write. Failures become stable safe codes.

## Compose topology

| Network | Members | External route |
| --- | --- | --- |
| `data` | PostgreSQL, API, worker, migration | no |
| `scanner-control` | worker, relay, ZAP | no |
| `scan-target` | relay, ZAP, configured demo services | no |
| `host-access` | relay only | yes, host gateway |
| `operator-access` | frontend, API, PostgreSQL, bundled demo | local published ports |
| `updater` | OSV updater only | yes |

The worker is deliberately absent from `host-access`, `scan-target`, and
`operator-access`. The migration container receives only the database URL and
data network. The OSV updater receives only three lockfiles and its cache.

## Extension rules

A new scan adapter must define an exact policy/profile contract, remain
allowlist/root-confined, be bounded/cancellable/lease-aware, avoid executing
repository code, emit only independently sanitized findings/receipts, define
safe failure behavior, prove workspace isolation and canary containment, and
update the threat model plus operator documentation.

Capabilities cannot be broadened only in the frontend.
