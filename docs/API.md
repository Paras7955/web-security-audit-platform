# ScopeHarbor API 1.0

## Conventions

The product API base path is `/api/v1`. Root `/health` and `/ready`, plus
`/docs`, `/redoc`, and `/openapi.json`, are the only non-versioned HTTP
surfaces. There are no compatibility redirects.

All product endpoints except `/api/v1/contracts` require:

```http
Authorization: Bearer <token>
```

Resources are scoped to the token's workspace. A valid ID from another
workspace is returned as not found, not as an authorization oracle.

Responses include `X-Request-ID`, `Cache-Control: no-store`, and security
headers. A valid caller-supplied `X-Request-ID` of at most 64 conservative
characters is preserved; otherwise ScopeHarbor generates one. Request bodies
are limited by `MAX_REQUEST_BODY_BYTES` (1 MiB by default).

The generated OpenAPI document at `/openapi.json` is the canonical field-level
schema.

## Cursor pagination

Collection reads use stable descending `created_at`/ID order:

```json
{
  "items": [],
  "next_cursor": null
}
```

Use `limit` from 1 to 200 (default 50). Pass the opaque `next_cursor` value as
the next request's `cursor`; do not decode, modify, or persist assumptions about
its format.

## Problems

Errors use `application/problem+json`:

```json
{
  "type": "https://scopeharbor.local/problems/request_validation_failed",
  "title": "Unprocessable Entity",
  "status": 422,
  "detail": "The request did not pass validation.",
  "instance": "/api/v1/scans",
  "code": "request_validation_failed",
  "request_id": "c7c0d7e1-35ce-4e67-8e7f-6090112d0b54"
}
```

Validation problems may include a bounded `errors` array. Internal exceptions,
tracebacks, scanner output, provider details, and secret-bearing data are never
part of the problem response. Support workflows should use `request_id` and the
stable `code`.

## Contracts and starting a scan

`GET /api/v1/contracts` is public and returns product/version information,
launchable scan profiles, their required acknowledgement codes, statuses, and
pagination limits. Clients should read this contract instead of hard-coding
acknowledgements.

Create an exact allowlisted target:

```http
POST /api/v1/targets
Content-Type: application/json

{
  "target_url": "http://juice-shop:3000",
  "permission_confirmed": true,
  "repo_path": null,
  "auth_profile_id": null
}
```

Start a passive scan:

```http
POST /api/v1/scans
Content-Type: application/json

{
  "target_id": "<target-id>",
  "scan_profile_id": "passive-web",
  "acknowledgements": ["authorized_target"]
}
```

`target_id`, `scan_profile_id`, and `acknowledgements` are required. Deprecated
mode fields and per-mode booleans are rejected. Scan reads expose only profile,
status/progress/timing, cancellation timing, and a safe optional failure:

```json
{
  "code": "worker_interrupted",
  "message": "The scanner worker was interrupted before completion."
}
```

Use `GET /api/v1/scans/{scan_id}/tool-runs` for scanner name/version, status,
safe warning code, normalized finding count, and timing. Raw output and artifact
paths are not public fields.

## Endpoint index

### Targets

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/targets/validate?target_url=...` | Validate an exact allowlist match without creating it |
| POST | `/targets` | Create an authorized workspace target |
| GET | `/targets` | List targets |
| GET | `/targets/{target_id}` | Read target metadata |
| PATCH | `/targets/{target_id}/repo-path` | Set/clear confined repository path |
| PATCH | `/targets/{target_id}/auth-profile` | Attach/detach workspace auth profile |
| DELETE | `/targets/{target_id}` | Archive an inactive target while preserving history |

Target reads expose `has_repo_path`, never the absolute stored path. `DELETE`
returns `409` while any nonterminal scan references the target. A successful
archive clears authorization timestamps, repository configuration, and the
auth-profile attachment; active target reads no longer return it, while prior
scans, findings, reports, scores, and audit records remain workspace-readable.

### Auth profiles

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth-profiles` | Create `bearer_token` or allowed `custom_header` profile |
| GET | `/auth-profiles` | List metadata/tombstones |
| GET | `/auth-profiles/{id}` | Read metadata only |
| POST | `/auth-profiles/{id}/rotate` | Replace future secret with `{"secret":"..."}` |
| POST | `/auth-profiles/{id}/revoke` | Wipe ciphertext and detach targets |

Secrets are write-only. Responses include only a short hint and lifecycle
metadata. Rotation/revocation return `409` while a nonterminal scan references
the profile.

Create and rotate payloads contain the target application's token or static
header value, never `AUTH_PROFILE_SECRET_KEY`. Plain HTTP is accepted only for
the local-only workflow. Non-local credential submission must arrive over
HTTPS. If TLS terminates at a reverse proxy, list only that immediate proxy's
exact IP in `TRUSTED_PROXY_IPS`; forwarded scheme headers from other peers are
ignored. All API responses carry `Cache-Control: no-store`.

### Scans and findings

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/scans` | Queue a validated scan |
| GET | `/scans` | List scans |
| GET | `/scans/{scan_id}` | Read safe scan state |
| POST | `/scans/{scan_id}/cancel` | Request safe cancellation |
| GET | `/scans/{scan_id}/tool-runs` | List safe scanner receipts |
| GET | `/scans/{scan_id}/findings` | List findings for a scan |
| GET | `/findings` | Search workspace findings |
| GET | `/findings/{finding_id}` | Read a normalized finding |
| PATCH | `/findings/{finding_id}/lifecycle` | Set lifecycle status |

Finding collection filters include target/profile, created range, severity,
confidence, scanner, OWASP, CWE, lifecycle status, suppression, tag, and risk
range where applicable. Lifecycle values are `open`, `confirmed`,
`in_progress`, `resolved`, `suppressed`, and `false_positive`.

### Suppressions and tags

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/suppressions` | Create a target-scoped suppression rule |
| GET | `/suppressions` | List rules, optionally by target |
| POST | `/tags` | Create/idempotently find a workspace tag |
| GET | `/tags` | List tags |
| POST | `/tags/assignments` | Tag a target, scan, or report |
| GET | `/tags/assignments` | List/filter assignments |

Suppressions are history-preserving rules, not finding deletion.

### Risk and dashboards

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/dashboard/overview` | Workspace totals and recent scans |
| GET | `/targets/{target_id}/dashboard` | Target risk/findings summary |
| GET | `/scans/{scan_id}/risk-score` | Read `risk-v1` score |
| GET | `/scans/{scan_id}/comparison?baseline_scan_id=...` | Compare completed scans from the same target and audit profile |
| GET | `/targets/{target_id}/latest-comparison` | Compare the latest scan with its newest same-profile baseline |

Scores are written when scans finish. Legacy missing scores may be calculated
in memory during reads; GET requests do not persist them.

Comparison deliberately requires matching target and `scan_profile_id` so an
absence outside one profile's coverage is never mislabeled as resolved.

### Reports and AI

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/scans/{scan_id}/reports` | Generate eligible Markdown/HTML artifacts |
| GET | `/scans/{scan_id}/reports` | List report metadata |
| GET | `/reports/{report_id}` | View escaped report content |
| GET | `/reports/{report_id}/download` | Download report content |
| GET | `/scans/{scan_id}/ai-explanations` | Generate/read safe explanations |

Report metadata supplies versioned view/download paths. AI eligibility is
profile-restricted, rate-limited, and bounded; template mode is deterministic.

### Operations

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/ops/health` | Safe protected component health and queue depth |
| GET | `/audit-logs` | Cursor-paginated safe audit metadata |

Prefix every path in the endpoint tables with `/api/v1`.

## Client security notes

- Never put bearer tokens or target secrets in URLs.
- Treat cursors, IDs, findings, and reports as workspace-confidential data.
- Do not display `detail` as trusted HTML.
- Honor `429` and do not blindly retry scan creation or report generation.
- Poll scan state conservatively and stop after a terminal status.
- A `completed_with_warnings` scan is usable but requires inspection of tool
  receipts before relying on coverage.
