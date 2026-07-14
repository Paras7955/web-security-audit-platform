# ScopeHarbor Architecture

## Design goals

ScopeHarbor is designed for a single local operator or trusted local deployment,
with defense in depth around scanning and data disclosure. The architecture
prioritizes exact authorization scope, workspace isolation, bounded execution,
safe persistence, inspectable tool receipts, and deterministic operation over
scanner breadth.

It is not a hosted multi-tenant service architecture.

## Components

```text
Operator browser
      |
      v
Next.js frontend (loopback)
      |
      v
FastAPI API (loopback) -----> optional OIDC / optional external AI
      |
      +-----> PostgreSQL <----- scanner worker lease/heartbeat
      |                              |
      +-----> report volume          +-----> guarded HTTP client
                                     +-----> ZAP (internal network)
                                     +-----> staged repo tmpfs
                                                  |
                                                  +-> Gitleaks
                                                  +-> offline OSV database
```

### Frontend

The Next.js frontend is an operator interface. It consumes only `/api/v1`, uses
the cursor-page contract, displays safe scan failures and scanner receipts, and
does not make scanning authorization decisions. Its development token is a
local build-time convenience, not a production credential mechanism.

### API

FastAPI owns authentication, workspace authorization, request validation,
target allowlist matching, public response projections, report access, and
audit events. Lifespan startup validates authentication, encryption, paths,
limits, allowlist, ZAP configuration, and migration head. The API does not run
scanner jobs inline.

The public surface is versioned under `/api/v1`. Root `/health` and `/ready` are
minimal probes; `/docs`, `/redoc`, and `/openapi.json` are framework-generated
documentation endpoints.

### Database

PostgreSQL stores users, identities, workspaces, targets, auth-profile
ciphertext, scans, scanner receipts, normalized findings, lifecycle state,
suppressions, tags, risk scores, report metadata, safe AI cache/request records,
rate-limit records, worker heartbeats, and audit events.

Rows carrying user data include a workspace identifier. Query code applies the
workspace predicate even when a globally unique resource ID is supplied.
Migrations are managed by Alembic; the API and worker refuse to start when the
database is not at the expected head.

### Worker and leases

The worker polls queued scans, locks a candidate, records ownership and a lease,
and refreshes its heartbeat while executing. State transitions are persisted at
safe checkpoints. Expired ownership is converted to the stable
`worker_interrupted` failure. Active-demo and browser scans are not retried
automatically because replay may repeat side effects.

The worker rechecks persisted workspace, target, allowlist, repository path,
auth-profile lifecycle, and acknowledgements-derived profile state. It never
trusts the UI to have enforced these boundaries.

### Web scanners

The guarded passive scanner manually resolves and validates each destination,
connects to the validated IP while preserving the HTTP host header, disables
automatic redirects, and validates every hop. It stores only bounded,
normalized findings.

ZAP is a daemon on the internal Compose network. ScopeHarbor sends a generated
API key through the supported header and uses exact contexts plus an advisory
lock. Active Demo and Modern Web Crawl are restricted to configured local demo
targets. Modern Web Crawl uses Client Spider with one headless browser and
strict depth, time, destination, and alert caps.

### Repository scanners

The worker resolves a stored relative path below `REPO_SCAN_ROOT`, stages only
eligible regular files into a per-scan `0700` tmpfs directory, and enforces file,
per-file byte, total byte, tool time, output byte, and finding limits.

Gitleaks and OSV-Scanner run as pinned binaries with ScopeHarbor-owned config.
Gitleaks redacts secrets. OSV uses a named offline database and performs no
dependency resolution. Raw JSON is ephemeral. The database receives only safe
rule/advisory IDs, relative locations, line/package metadata, bounded evidence,
and remediation.

## Data flow and safety boundary

```text
Untrusted scanner/provider input
        |
        v
parse + schema/type checks
        |
        v
independent URL/text/metadata sanitization + size caps
        |
        v
normalized domain object
        |
        +-> database
        +-> API projection
        +-> report projection
        +-> bounded AI projection
        +-> structured safe log/audit metadata
```

Each downstream boundary sanitizes independently. A scanner-provided redaction
flag is informational and is never sufficient. URL userinfo, queries, and
fragments are removed before writes. Internal failures become stable codes with
operator-safe messages.

## Network topology

The `internal` Compose network has no external gateway and contains PostgreSQL,
ZAP, Juice Shop, API, and worker as needed. The worker has no egress network.
The API has egress only for configured OIDC/JWKS and optional AI calls. The
one-shot OSV updater has egress and writes only the named database cache.

Frontend, API, demo target, and PostgreSQL ports bind to loopback. ZAP is never
published to the host.

## Extension rules

A new scan adapter must:

1. define an explicit profile and acknowledgement contract;
2. remain exact-allowlist-only or below the repository root;
3. have bounded resources and deterministic cancellation;
4. avoid executing target/repository code;
5. produce only normalized, independently sanitized findings and receipts;
6. define fatal, warning, and unavailable behavior with stable codes;
7. prove workspace isolation and canary-secret containment in tests;
8. update the threat model and operator documentation.

Scanner capability must not be added solely in the frontend.
