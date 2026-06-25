export const SCAN_MODES = ["passive", "active_demo", "ajax_short", "repo"] as const;

export const SCAN_STATUSES = [
  "queued",
  "validating",
  "running",
  "normalizing",
  "completed",
  "completed_with_warnings",
  "failed",
  "cancelled"
] as const;

export const SCAN_STEPS = [
  "target_validation",
  "custom_crawl",
  "custom_checks",
  "zap_spider",
  "zap_passive",
  "zap_active",
  "zap_ajax",
  "repo_secrets_scan",
  "repo_dependency_scan",
  "normalizing_findings",
  "generating_reports",
  "generating_ai_explanations"
] as const;

export const DEFAULT_LIMITS = {
  crawl_depth: 2,
  page_cap: 100,
  request_timeout_seconds: 10,
  scan_timeout_seconds: 600,
  zap_active_timeout_seconds: 600,
  zap_ajax_timeout_seconds: 120,
  evidence_snippet_bytes: 2048,
  redirect_cap: 5
} as const;
