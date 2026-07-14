export const SCAN_MODES = ["passive", "active_demo", "modern_web_crawl", "repo"] as const;

export const ACKNOWLEDGEMENT_LABELS: Record<string, string> = {
  authorized_target: "I confirm I am authorized to assess this saved web target.",
  active_testing_local_demo: "I understand Active Demo sends bounded active test traffic only to the configured local demo.",
  browser_crawl_local_demo: "I understand Modern Web Crawl drives one bounded browser crawler only against the configured local demo.",
  authorized_repository: "I confirm I am authorized to inspect this saved local repository."
};

export const SCAN_PROFILES = [
  {
    id: "passive-web",
    label: "Passive Web",
    mode: "passive",
    description: "Custom crawl plus passive checks for allowlisted web targets.",
    required_acknowledgements: ["authorized_target"],
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
    required_acknowledgements: ["authorized_target", "active_testing_local_demo"],
    requires_repo_path: false,
    local_demo_only: true,
    reports_enabled: true,
    ai_enabled: true
  },
  {
    id: "modern-web-crawl",
    label: "Modern Web Crawl",
    mode: "modern_web_crawl",
    description: "Bounded ZAP Client Spider crawl for configured local/demo targets.",
    required_acknowledgements: ["authorized_target", "browser_crawl_local_demo"],
    requires_repo_path: false,
    local_demo_only: true,
    reports_enabled: false,
    ai_enabled: false
  },
  {
    id: "repository",
    label: "Repository",
    mode: "repo",
    description: "Pinned Gitleaks and offline OSV scanning without executing repository code.",
    required_acknowledgements: ["authorized_repository"],
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
  "zap_client_spider",
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
  zap_client_spider_timeout_seconds: 120,
  evidence_snippet_bytes: 2048,
  redirect_cap: 5
} as const;
