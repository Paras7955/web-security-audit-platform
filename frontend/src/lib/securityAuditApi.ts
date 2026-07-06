export type ValidationResult = {
  allowlist_id: string;
  name: string;
  base_url: string;
  allowed_modes: string[];
  max_redirects: number;
  local_demo: boolean;
};

export type Target = {
  id: string;
  allowlist_id: string;
  name: string;
  base_url: string;
  allowed_modes: string[];
  repo_path: string | null;
  auth_profile_id: string | null;
  created_at: string;
};

export type Scan = {
  id: string;
  target_id: string;
  mode: string;
  scan_profile_id: string;
  status: string;
  current_step: string | null;
  status_message: string | null;
  progress_percent: number;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: string;
};

export type Finding = {
  id: string;
  scan_id: string;
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
  redaction_applied: boolean;
  raw_artifact_ref: string | null;
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
  provider_error: string | null;
  summary: string;
  groups: AiExplanationGroup[];
  explanations: FindingExplanation[];
};

export const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
const devAuthToken = process.env.NEXT_PUBLIC_DEV_AUTH_TOKEN ?? "";

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (devAuthToken) {
    headers.set("Authorization", `Bearer ${devAuthToken}`);
  }
  return fetch(input, { ...init, headers });
}

export async function readJson<T>(response: Response, fallbackMessage: string): Promise<T> {
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.detail ?? fallbackMessage);
  }
  return body as T;
}
