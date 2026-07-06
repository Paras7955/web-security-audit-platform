export const SCAN_MODES = ["passive", "active_demo", "ajax_short", "repo"] as const;

export const SCAN_PROFILES = [
  {
    id: "passive-web",
    label: "Passive Web",
    mode: "passive",
    description: "Custom crawl plus passive checks for allowlisted web targets.",
    requires_active_demo_acknowledgement: false,
    requires_ajax_short_acknowledgement: false,
    requires_repo_path: false,
    local_demo_only: false,
    reports_enabled: true,
    ai_enabled: true
  },
  {
    id: "active-demo",
    label: "Active Demo",
    mode: "active_demo",
    description: "Bounded ZAP active scan for configured local/demo targets.",
    requires_active_demo_acknowledgement: true,
    requires_ajax_short_acknowledgement: false,
    requires_repo_path: false,
    local_demo_only: true,
    reports_enabled: true,
    ai_enabled: true
  },
  {
    id: "ajax-short",
    label: "AJAX Short",
    mode: "ajax_short",
    description: "Bounded ZAP browser crawl for configured local/demo targets.",
    requires_active_demo_acknowledgement: false,
    requires_ajax_short_acknowledgement: true,
    requires_repo_path: false,
    local_demo_only: true,
    reports_enabled: false,
    ai_enabled: false
  },
  {
    id: "repository",
    label: "Repository",
    mode: "repo",
    description: "Deterministic local repository scanner adapters without executing repository code.",
    requires_active_demo_acknowledgement: false,
    requires_ajax_short_acknowledgement: false,
    requires_repo_path: true,
    local_demo_only: false,
    reports_enabled: true,
    ai_enabled: false
  }
] as const;

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
