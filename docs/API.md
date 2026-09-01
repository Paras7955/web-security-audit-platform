# ScopeHarbor API 1.1

## Conventions

The product API base path is `/api/v1`. Root `/health`, `/ready`, `/docs`,
`/redoc`, and `/openapi.json` are the only non-versioned surfaces. There are no
compatibility redirects.

All product endpoints except `/api/v1/contracts` require:

```http
Authorization: Bearer <platform-token>
```

Resources are scoped to the token's workspace. Another workspace's valid ID is
returned as not found. Responses include `X-Request-ID`,
`Cache-Control: no-store`, and security headers. Bodies are capped by
`MAX_REQUEST_BODY_BYTES`.

The generated OpenAPI document is the canonical field-level schema.

## Cursor pagination and filtering

Collections return:

```json
{
  "items": [],
  "next_cursor": null
}
```

Use `limit` from 1–200 (default 50), then pass opaque `next_cursor` as
`cursor`. Finding lifecycle, suppression, tag, and risk filters are applied in
SQL before pagination; a cursor is derived from the filtered order.

## Problems

Errors use `application/problem+json` with a stable safe `code` and
`request_id`. Validation may include a bounded `errors` array. Raw exceptions,
scanner/provider output, URLs with queries, and secret-bearing values are never
returned.

## Contracts and policies

`GET /api/v1/contracts` is public and returns product version, launchable
profiles, acknowledgement codes, statuses, and pagination limits.

Protected target-policy routes:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/targets/policies` | List configured safe policy metadata and truthful eligible profiles |
| POST | `/targets/validate` | Validate `{"target_url":"..."}` against v2 policy and SSRF rules |
| GET | `/targets/validate?target_url=...` | Deprecated compatibility validator |
| POST | `/targets/{id}/reauthorize` | Confirm a stale policy fingerprint without changing target identity |

Target roots reject userinfo, queries, fragments, ambiguous separators, and
traversal. Reauthorization returns `409` if origin/base path changed; create a
new target instead. Target, policy, and validation responses include
`zap_required_scan_profile_ids`, derived from the exact policy engines, so a
client can gate only the profiles that depend on ZAP.

## Create subjects and scans

Create a web target:

```http
POST /api/v1/targets
Content-Type: application/json

{
  "target_url": "http://juice-shop:3000/",
  "permission_confirmed": true,
  "auth_profile_id": null
}
```

Create a repository asset:

```http
POST /api/v1/repository-assets
Content-Type: application/json

{
  "name": "ScopeHarbor",
  "repo_path": "/app/repositories/security-project",
  "permission_confirmed": true
}
```

The response exposes a confined relative path, never an absolute path.

Queue one subject:

```http
POST /api/v1/scans
Content-Type: application/json

{
  "target_id": "<target-id>",
  "repository_asset_id": null,
  "scan_profile_id": "passive-web",
  "acknowledgements": ["authorized_target"]
}
```

Exactly one of `target_id` or `repository_asset_id` is accepted. Repository
launches use `scan_profile_id=repository` and `authorized_repository`.

Legacy target-based repository launch remains temporarily accepted for
historical callers. The current frontend uses first-class repository assets.
The adapter creates/reuses an asset and snapshots it; `Target.repo_path` is not
worker authority and can be removed only after historical callers are reviewed.

Scan responses retain existing `target_id` fields and add
`repository_asset_id`, `subject_type`, and `subject_id`. They never expose
auth-profile IDs, capability tokens, raw errors, artifact paths, or snapshots
containing sensitive data.

## Endpoint index

Prefix each path below with `/api/v1`.

### Targets

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/targets` | Create an authorized exact-policy web target |
| GET | `/targets` | List active targets |
| GET | `/targets/{id}` | Read policy/status metadata |
| POST | `/targets/{id}/reauthorize` | Refresh authorization after non-identity policy changes |
| PATCH | `/targets/{id}/repo-path` | Deprecated repository compatibility configuration |
| PATCH | `/targets/{id}/auth-profile` | Attach/detach a workspace auth profile |
| DELETE | `/targets/{id}` | Archive inactive target while preserving history |

Reads add `connection_class`, `scope_path`, `tls_trust`, `policy_status`,
`policy_fingerprint`, and policy-derived `available_scan_profile_ids`.

### Repository assets

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/repository-assets` | Create/restore an authorized repository identity |
| GET | `/repository-assets` | List active assets |
| GET | `/repository-assets/{id}` | Read asset metadata |
| DELETE | `/repository-assets/{id}` | Archive an asset with no active scan |
| GET | `/repository-assets/{id}/dashboard` | Repository posture/dashboard |
| GET | `/repository-assets/{id}/latest-comparison` | Latest same-profile repository comparison |

Archive clears launch authorization but preserves historical scans/findings.

### Auth profiles

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth-profiles` | Create bearer/static-header profile |
| GET | `/auth-profiles` | List safe metadata/tombstones |
| GET | `/auth-profiles/{id}` | Read metadata |
| POST | `/auth-profiles/{id}/rotate` | Replace future secret |
| POST | `/auth-profiles/{id}/revoke` | Wipe ciphertext and detach targets |

Secrets are write-only. Create/rotate payloads contain the target application's
secret, never the Fernet key. Plain HTTP credential submission is local-only;
non-local requests require direct HTTPS or an exact trusted proxy.

### Scans and findings

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/scans` | Queue validated web/repository scan |
| GET | `/scans` | List scans |
| GET | `/scans/{id}` | Read safe state |
| POST | `/scans/{id}/cancel` | Request cancellation |
| GET | `/scans/{id}/tool-runs` | Safe tool/version/status receipts |
| GET | `/scans/{id}/findings` | Paginated scan findings |
| GET | `/findings` | Filter workspace findings |
| GET | `/findings/{id}` | Read normalized finding |
| PATCH | `/findings/{id}/lifecycle` | Change effective lifecycle |

Lifecycle values are `open`, `confirmed`, `in_progress`, `resolved`,
`suppressed`, and `false_positive`.

### Suppressions and tags

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/suppressions` | Create web-target or repository-asset rule |
| GET | `/suppressions` | List/filter rules |
| POST | `/suppressions/{id}/revoke` | Stop application while preserving history |
| POST | `/tags` | Create/restore workspace tag |
| GET | `/tags` | List tags; `include_archived=true` includes history |
| POST | `/tags/{id}/archive` | Archive tag without deleting history |
| POST | `/tags/assignments` | Assign tag |
| GET | `/tags/assignments` | List/filter assignments |
| DELETE | `/tags/assignments/{id}` | Audited unassignment |

### Risk, posture, and comparisons

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/dashboard/overview` | Workspace current posture plus historical totals |
| GET | `/targets/{id}/dashboard` | Web-target posture |
| GET | `/repository-assets/{id}/dashboard` | Repository posture |
| GET | `/scans/{id}/risk-score` | Immutable per-scan `risk-v1` |
| GET | `/scans/{id}/comparison?baseline_scan_id=...` | Same-subject/profile comparison |
| GET | `/targets/{id}/latest-comparison` | Latest web comparison |
| GET | `/repository-assets/{id}/latest-comparison` | Latest repository comparison |

Dashboard `findings_count` and `severity_counts` represent the latest completed
scan for each subject/profile after effective lifecycle and active-suppression
rules. `current_posture_score` uses dynamic `posture-v1`.
`historical_findings_count` and `historical_severity_counts` are separately
labelled all-history totals.

GET score/dashboard requests do not persist missing scores.

### Reports and finding guidance

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/scans/{id}/reports` | Idempotently generate eligible Markdown/HTML with local guidance |
| GET | `/scans/{id}/reports` | List report metadata |
| GET | `/reports/{id}` | View escaped content |
| GET | `/reports/{id}/download` | Download content |
| GET | `/scans/{id}/ai-explanations` | Retrieve cached output or calculate local guidance in memory |
| POST | `/scans/{id}/ai-explanations` | Explicitly generate/cache eligible configured-provider guidance |

The compatibility response contract includes non-secret
`configured_provider` (`template` or `openai`) in addition to the provider that
actually produced the result. Clients use it to label explicit consent before
optional external generation without exposing a model or key. Report creation
always uses local deterministic guidance and never calls the configured
external provider. External-provider GET never starts paid/network work.
Repository and modern-crawl scans are ineligible for external AI.

### Operations

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/ops/health` | Protected core readiness plus worker-mediated, bounded ZAP readiness |
| GET | `/audit-logs` | Cursor-paginated safe audit metadata |

The top-level `status` covers database, worker, and artifact readiness. `zap`
is an independent dependency signal reported by the worker; clients must use
the selected target's `zap_required_scan_profile_ids` before treating degraded
ZAP readiness as a launch blocker.

## Client security notes

- Never place tokens, credentials, or target queries in URLs.
- Treat cursors, IDs, findings, reports, and relative repository identities as
  workspace-confidential.
- Do not display problem `detail` as trusted HTML.
- Honor `429`; do not blindly retry launch, reports, or optional AI generation.
- Poll conservatively and stop after terminal state.
- Inspect tool receipts for `completed_with_warnings` before relying on coverage.
- A stale target needs operator reauthorization, not an automated retry.
