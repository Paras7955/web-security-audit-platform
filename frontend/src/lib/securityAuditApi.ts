export type ValidationResult = {
  allowlist_id: string;
  name: string;
  base_url: string;
  available_scan_profile_ids: string[];
  zap_required_scan_profile_ids: string[];
  max_redirects: number;
  local_demo: boolean;
  connection_class: string;
  scope_path: string;
  tls_trust: string;
  policy_fingerprint: string;
};

export type TargetPolicy = {
  allowlist_id: string;
  name: string;
  base_url: string;
  connection_class: string;
  scope_path: string;
  tls_trust: string;
  available_scan_profile_ids: string[];
  zap_required_scan_profile_ids: string[];
  max_redirects: number;
  disposable_demo: boolean;
  policy_fingerprint: string;
};

export type Target = {
  id: string;
  allowlist_id: string;
  name: string;
  base_url: string;
  permission_confirmed: boolean;
  has_repo_path: boolean;
  auth_profile_id: string | null;
  available_scan_profile_ids: string[];
  zap_required_scan_profile_ids: string[];
  connection_class: string;
  scope_path: string;
  tls_trust: string;
  policy_status: "current" | "stale" | string;
  policy_fingerprint: string | null;
  created_at: string;
};

export type RepositoryAsset = {
  id: string;
  name: string;
  relative_path: string;
  permission_confirmed: boolean;
  authorization_confirmed_at: string | null;
  archived_at: string | null;
  created_at: string;
};

export type AuditSubject = {
  id: string;
  subjectType: "web_target" | "repository_asset";
  name: string;
  detail: string;
  availableScanProfileIds: string[];
  target: Target | null;
  repositoryAsset: RepositoryAsset | null;
};

export type AuthProfile = {
  id: string;
  label: string;
  profile_type: "bearer_token" | "custom_header" | string;
  header_name: string | null;
  secret_hint: string;
  status: "active" | "revoked" | string;
  rotated_at: string | null;
  revoked_at: string | null;
  rotation_count: number;
  created_at: string;
};

export type ScanFailure = {
  code: string;
  message: string;
};

export type Scan = {
  id: string;
  target_id: string | null;
  repository_asset_id: string | null;
  subject_type: "web_target" | "repository_asset" | string;
  subject_id: string;
  scan_profile_id: string;
  status: string;
  current_step: string | null;
  status_message: string | null;
  progress_percent: number;
  started_at: string | null;
  completed_at: string | null;
  cancellation_requested_at: string | null;
  failure: ScanFailure | null;
  created_at: string;
};

export type ScannerToolRun = {
  id: string;
  scan_id: string;
  tool_name: string;
  tool_version: string | null;
  status: string;
  warning_code: string | null;
  finding_count: number;
  started_at: string | null;
  completed_at: string | null;
};

export type Finding = {
  id: string;
  scan_id: string;
  target_id: string | null;
  repository_asset_id: string | null;
  title: string;
  severity: string;
  confidence: string;
  affected_url: string | null;
  affected_file: string | null;
  evidence: string | null;
  source_tool: string;
  scanner_rule_id: string | null;
  dedupe_key: string;
  owasp_category: string | null;
  cwe: string | null;
  reproduction_steps: string | null;
  remediation: string | null;
  false_positive_notes: string | null;
  lifecycle_status: string;
  suppressed: boolean;
  suppression_rule_id: string | null;
  tags: string[];
  created_at: string;
};

export type Tag = {
  id: string;
  label: string;
  created_at: string;
  archived_at: string | null;
};

export type SuppressionRule = {
  id: string;
  target_id: string | null;
  repository_asset_id: string | null;
  dedupe_key: string | null;
  severity: string | null;
  source_tool: string | null;
  reason: string;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
};

export type TagAssignment = {
  id: string;
  tag_id: string;
  resource_type: string;
  resource_id: string;
  created_at: string;
};

export type ReportArtifact = {
  id: string;
  scan_id: string;
  report_type: string;
  view_url: string;
  download_url: string;
  created_at: string;
};

export type AiExplanationGroup = {
  label: string;
  count: number;
  finding_ids: string[];
};

export type FindingExplanation = {
  finding_id: string;
  priority: number;
  summary: string;
  why_it_matters: string;
  recommended_action: string;
  owasp_mapping: string;
  limitations: string;
};

export type AiExplanation = {
  scan_id: string;
  provider: string;
  configured_provider: "template" | "openai";
  fallback_used: boolean;
  provider_error_code: string | null;
  summary: string;
  executive_summary: string;
  risk_score_explanation: string;
  scoring_model_version: string;
  input_fingerprint: string | null;
  cache_hit: boolean;
  groups: AiExplanationGroup[];
  explanations: FindingExplanation[];
};

export type HealthComponent = {
  status: string;
  detail: string | null;
};

export type PlatformHealth = {
  status: string;
  database: HealthComponent;
  worker: HealthComponent;
  queue_depth: number;
  zap: HealthComponent;
  artifact_root: HealthComponent;
};

export type AuditLogEntry = {
  id: string;
  event_type: string;
  resource_type: string | null;
  resource_id: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

export type RiskScore = {
  id: string;
  target_id: string | null;
  repository_asset_id: string | null;
  scan_id: string | null;
  scoring_model_version: string;
  score: number;
  label: string;
  input_summary: {
    finding_count?: number;
    severity_counts?: Record<string, number>;
    confidence_counts?: Record<string, number>;
    weighted_total?: number;
    scan_profile_id?: string;
    [key: string]: unknown;
  };
  created_at: string;
};

export type DashboardScanSummary = {
  id: string;
  target_id: string | null;
  repository_asset_id: string | null;
  subject_type: "web_target" | "repository_asset" | string;
  subject_id: string;
  target_name: string;
  scan_profile_id: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  risk_score: RiskScore | null;
};

export type DashboardOverview = {
  targets_count: number;
  repository_assets_count: number;
  scans_count: number;
  completed_scans_count: number;
  findings_count: number;
  severity_counts: Record<string, number>;
  latest_risk_score: RiskScore | null;
  recent_scans: DashboardScanSummary[];
  current_posture_scans: DashboardScanSummary[];
  posture_basis: string;
  current_posture_score: RiskScore | null;
  historical_findings_count: number;
  historical_severity_counts: Record<string, number>;
};

export type TargetDashboard = {
  target_id: string;
  target_name: string;
  base_url: string;
  scan_count: number;
  completed_scan_count: number;
  findings_count: number;
  severity_counts: Record<string, number>;
  latest_risk_score: RiskScore | null;
  recent_scans: DashboardScanSummary[];
  posture_basis: string;
  current_posture_score: RiskScore | null;
  historical_findings_count: number;
  historical_severity_counts: Record<string, number>;
};

export type RepositoryDashboard = {
  repository_asset_id: string;
  repository_asset_name: string;
  relative_path: string;
  scan_count: number;
  completed_scan_count: number;
  findings_count: number;
  severity_counts: Record<string, number>;
  latest_risk_score: RiskScore | null;
  recent_scans: DashboardScanSummary[];
  posture_basis: string;
  current_posture_score: RiskScore | null;
  historical_findings_count: number;
  historical_severity_counts: Record<string, number>;
};

export type FindingChange = {
  dedupe_key: string;
  title: string;
  source_tool: string;
  location: string | null;
  previous_severity: string | null;
  current_severity: string | null;
};

export type ScanComparison = {
  target_id: string | null;
  repository_asset_id: string | null;
  subject_type: "web_target" | "repository_asset" | string;
  subject_id: string;
  baseline_scan_id: string;
  comparison_scan_id: string;
  scoring_model_version: string;
  baseline_score: RiskScore;
  comparison_score: RiskScore;
  score_delta: number;
  new_findings: FindingChange[];
  resolved_findings: FindingChange[];
  unchanged_findings: FindingChange[];
  severity_changed_findings: FindingChange[];
};

export type CursorPage<Item> = {
  items: Item[];
  next_cursor: string | null;
};

export type ApiProblem = {
  detail?: string;
  code?: string;
  request_id?: string;
};

const apiProblemGuidance: ReadonlyArray<{ match: RegExp; message: string }> = [
  {
    match: /policy changed|reauthoriz|stale policy/i,
    message: "This target no longer matches its approved policy. Reauthorize it in Scope before retrying.",
  },
  {
    match: /tls|certificate|custom ca|ca bundle/i,
    message: "TLS verification failed. Confirm the configured hostname and trust bundle; insecure TLS is not available.",
  },
  {
    match: /relay/i,
    message: "The guarded relay could not complete this request. Check relay health and policy alignment before retrying.",
  },
  {
    match: /lease|worker interrupted|worker stopped/i,
    message: "The worker lost scan ownership before completion. Check worker health, then start a new audit.",
  },
  {
    match: /cancel/i,
    message: "Cancellation is handled at a safe worker checkpoint; refresh the scan status if it remains in progress.",
  },
];

export const apiOrigin = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");
export const apiBaseUrl = `${apiOrigin}/api/v1`;
const devAuthToken = process.env.NEXT_PUBLIC_DEV_AUTH_TOKEN ?? "";
let sessionAuthToken = "";

export type AuthSessionSource = "oidc" | "development" | "none";

export function scanLaunchPayload(subject: AuditSubject, scanProfileId: string, acknowledgements: string[]) {
  const targetId = subject.target?.id ?? null;
  const repositoryAssetId = subject.repositoryAsset?.id ?? null;
  if ((targetId === null) === (repositoryAssetId === null)) {
    throw new Error("Select exactly one authorized audit subject before launch.");
  }
  return {
    target_id: targetId,
    repository_asset_id: repositoryAssetId,
    scan_profile_id: scanProfileId,
    acknowledgements,
  };
}

export function aiExplanationRequest(scanId: string, generate = false) {
  return {
    url: `${apiBaseUrl}/scans/${encodeURIComponent(scanId)}/ai-explanations`,
    init: generate ? { method: "POST" } satisfies RequestInit : undefined,
  };
}

export function setSessionAuthToken(token: string) {
  sessionAuthToken = token.trim();
}

export function clearSessionAuthToken() {
  sessionAuthToken = "";
}

export function authSessionSource(): AuthSessionSource {
  if (sessionAuthToken) return "oidc";
  if (devAuthToken) return "development";
  return "none";
}

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  const authToken = sessionAuthToken || devAuthToken;
  if (authToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }
  return fetch(input, { ...init, headers });
}

export async function readJson<T>(response: Response, fallbackMessage: string): Promise<T> {
  const body = (await response.json().catch(() => ({}))) as T & ApiProblem;
  if (!response.ok) {
    const detail = typeof body.detail === "string" ? body.detail : "";
    const code = typeof body.code === "string" ? body.code : "";
    const guidance = apiProblemGuidance.find(({ match }) => match.test(`${code} ${detail}`))?.message;
    const requestSuffix = body.request_id ? ` Request ID: ${body.request_id}.` : "";
    throw new Error(`${guidance ?? (detail || fallbackMessage)}${requestSuffix}`);
  }
  return body as T;
}

export async function readPage<Item>(response: Response, fallbackMessage: string): Promise<CursorPage<Item>> {
  return readJson<CursorPage<Item>>(response, fallbackMessage);
}

export async function readAllPages<Item>(endpoint: string, fallbackMessage: string): Promise<Item[]> {
  const items: Item[] = [];
  let cursor: string | null = null;

  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const url = new URL(endpoint);
    url.searchParams.set("limit", "200");
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }
    const page = await readPage<Item>(await apiFetch(url), fallbackMessage);
    items.push(...page.items);
    if (!page.next_cursor) {
      return items;
    }
    cursor = page.next_cursor;
  }

  throw new Error(`${fallbackMessage} The collection exceeded the client paging safety limit.`);
}
