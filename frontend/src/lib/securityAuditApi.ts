export type ValidationResult = {
  allowlist_id: string;
  name: string;
  base_url: string;
  available_scan_profile_ids: string[];
  max_redirects: number;
  local_demo: boolean;
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
  created_at: string;
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
  target_id: string;
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

export type RiskScore = {
  id: string;
  target_id: string;
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
  target_id: string;
  target_name: string;
  scan_profile_id: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  risk_score: RiskScore | null;
};

export type DashboardOverview = {
  targets_count: number;
  scans_count: number;
  completed_scans_count: number;
  findings_count: number;
  severity_counts: Record<string, number>;
  latest_risk_score: RiskScore | null;
  recent_scans: DashboardScanSummary[];
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
  target_id: string;
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

export const apiOrigin = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");
export const apiBaseUrl = `${apiOrigin}/api/v1`;
const devAuthToken = process.env.NEXT_PUBLIC_DEV_AUTH_TOKEN ?? "";

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (devAuthToken) {
    headers.set("Authorization", `Bearer ${devAuthToken}`);
  }
  return fetch(input, { ...init, headers });
}

export async function readJson<T>(response: Response, fallbackMessage: string): Promise<T> {
  const body = (await response.json()) as T & ApiProblem;
  if (!response.ok) {
    const requestSuffix = body.request_id ? ` Request ID: ${body.request_id}.` : "";
    throw new Error(`${body.detail ?? fallbackMessage}${requestSuffix}`);
  }
  return body as T;
}

export async function readPage<Item>(response: Response, fallbackMessage: string): Promise<CursorPage<Item>> {
  return readJson<CursorPage<Item>>(response, fallbackMessage);
}
