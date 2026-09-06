import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AppShell } from "@/components/AppShell";
import { AuditReviewSummary } from "@/components/dashboard/AuditReviewSummary";
import { FindingGuidancePanel } from "@/components/dashboard/FindingGuidancePanel";
import { ReportsPanel } from "@/components/dashboard/ReportsPanel";
import type { AiExplanation, Finding, ReportArtifact, Scan } from "@/lib/securityAuditApi";

beforeEach(() => {
  document.documentElement.dataset.theme = "dark";
  vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    callback(0);
    return 1;
  });
  vi.stubGlobal("cancelAnimationFrame", vi.fn());
  vi.stubGlobal("ResizeObserver", class {
    observe() {}
    disconnect() {}
  });
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "Authentication required." }), {
    status: 401,
    headers: { "Content-Type": "application/json" }
  })));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Phase 27 public polish", () => {
  it("opens on Workspace with a skip link, five primary destinations, and a state-aware theme control", async () => {
    render(<AppShell />);

    expect(screen.getByRole("link", { name: "Skip to workspace" }).getAttribute("href")).toBe("#workspace-console");
    const navigation = screen.getByRole("navigation", { name: "Primary workspace navigation" });
    expect(navigation.querySelectorAll("button")).toHaveLength(5);
    expect(screen.getByRole("button", { name: "Workspace" }).getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("button", { name: "Credentials" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Operations" })).toBeNull();

    const themeControl = screen.getByRole("button", { name: "Switch to light mode" });
    expect(themeControl.getAttribute("aria-pressed")).toBe("false");
    await userEvent.click(themeControl);
    expect(screen.getByRole("button", { name: "Switch to dark mode" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("presents one formatted report action and two portable downloads", async () => {
    const onViewReport = vi.fn();
    const onDownloadReport = vi.fn();
    const reports = reportFixtures();
    render(
      <ReportsPanel
        scan={scanFixture()}
        reports={reports}
        message="Reports are ready."
        isGenerating={false}
        pendingAction={null}
        onGenerate={vi.fn()}
        onViewReport={onViewReport}
        onDownloadReport={onDownloadReport}
      />
    );

    await userEvent.click(screen.getByRole("button", { name: "Open formatted report" }));
    expect(onViewReport).toHaveBeenCalledWith(reports[0]);
    await userEvent.click(screen.getByRole("button", { name: "HTML" }));
    await userEvent.click(screen.getByRole("button", { name: "Markdown" }));
    expect(onDownloadReport).toHaveBeenNthCalledWith(1, reports[0]);
    expect(onDownloadReport).toHaveBeenNthCalledWith(2, reports[1]);
    expect(screen.queryByText(/older reports/i)).toBeNull();
  });

  it("requires clear provider-aware consent copy only for optional AI assistance", () => {
    const { rerender } = render(
      <FindingGuidancePanel
        explanation={guidanceFixture("openai")}
        message="Ready."
        canGenerate
        isGenerating={false}
        onGenerate={vi.fn()}
      />
    );

    expect(screen.getByRole("button", { name: "Generate AI-assisted guidance" })).toBeTruthy();
    expect(screen.getByText(/only bounded, normalized, independently redacted web-finding fields/i)).toBeTruthy();

    rerender(
      <FindingGuidancePanel
        explanation={guidanceFixture("template")}
        message="Ready."
        canGenerate
        isGenerating={false}
        onGenerate={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: "Refresh local guidance" })).toBeTruthy();
    expect(screen.queryByText(/leave the machine/i)).toBeNull();
  });

  it("keeps Audit Review concise and hands canonical work to Findings and Intelligence", async () => {
    const onOpenFindings = vi.fn();
    const onOpenIntelligence = vi.fn();
    const onOpenScanHistory = vi.fn();
    const { rerender } = render(
      <AuditReviewSummary
        scan={scanFixture()}
        findings={[findingFixture()]}
        subjectName="Demo storefront"
        onOpenFindings={onOpenFindings}
        onOpenIntelligence={onOpenIntelligence}
        onOpenScanHistory={onOpenScanHistory}
      />
    );

    expect(screen.queryByRole("heading", { name: "Findings" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Reports" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Finding guidance" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Triage findings" }));
    await userEvent.click(screen.getByRole("button", { name: "Open reports and guidance" }));
    expect(onOpenFindings).toHaveBeenCalledOnce();
    expect(onOpenIntelligence).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole("button", { name: "Open scan history" }));
    expect(onOpenScanHistory).toHaveBeenCalledOnce();

    rerender(
      <AuditReviewSummary
        scan={scanFixture({ scan_profile_id: "repository", target_id: null, repository_asset_id: "repo-1", subject_type: "repository_asset", subject_id: "repo-1" })}
        findings={[findingFixture()]}
        subjectName="Repository"
        onOpenFindings={onOpenFindings}
        onOpenIntelligence={onOpenIntelligence}
        onOpenScanHistory={onOpenScanHistory}
      />
    );
    expect(screen.getByRole("button", { name: "Open reports" })).toBeTruthy();

    rerender(
      <AuditReviewSummary
        scan={scanFixture({ scan_profile_id: "modern-web-crawl" })}
        findings={[findingFixture()]}
        subjectName="Demo storefront"
        onOpenFindings={onOpenFindings}
        onOpenIntelligence={onOpenIntelligence}
        onOpenScanHistory={onOpenScanHistory}
      />
    );
    expect(screen.getByRole("button", { name: "Open risk intelligence" })).toBeTruthy();
  });
});

function scanFixture(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "scan-27",
    target_id: "target-1",
    repository_asset_id: null,
    subject_type: "web_target",
    subject_id: "target-1",
    scan_profile_id: "passive-web",
    status: "completed",
    current_step: "complete",
    status_message: "Completed safely.",
    progress_percent: 100,
    started_at: "2026-09-01T12:00:00Z",
    completed_at: "2026-09-01T12:01:00Z",
    cancellation_requested_at: null,
    failure: null,
    created_at: "2026-09-01T12:00:00Z",
    ...overrides
  };
}

function reportFixtures(): ReportArtifact[] {
  return [
    { id: "report-html", scan_id: "scan-27", report_type: "html", view_url: "/reports/report-html", download_url: "/reports/report-html/download", created_at: "2026-09-01T12:01:00Z" },
    { id: "report-markdown", scan_id: "scan-27", report_type: "markdown", view_url: "/reports/report-markdown", download_url: "/reports/report-markdown/download", created_at: "2026-09-01T12:01:00Z" }
  ];
}

function guidanceFixture(configuredProvider: "template" | "openai"): AiExplanation {
  return {
    scan_id: "scan-27",
    provider: "template",
    configured_provider: configuredProvider,
    fallback_used: false,
    provider_error_code: null,
    summary: "One normalized finding was recorded.",
    executive_summary: "Review the high-priority signal first.",
    risk_score_explanation: "The risk score reflects normalized severity and confidence.",
    scoring_model_version: "risk-v2",
    input_fingerprint: "fixture",
    cache_hit: false,
    groups: [{ label: "high severity", count: 1, finding_ids: ["finding-1"] }],
    explanations: [{
      finding_id: "finding-1",
      priority: 44,
      summary: "High finding: missing response protection.",
      why_it_matters: "The control should be reviewed early.",
      recommended_action: "Apply the missing protection and rescan.",
      owasp_mapping: "A05",
      limitations: "Based only on normalized, redacted evidence."
    }]
  };
}

function findingFixture(): Finding {
  return {
    id: "finding-1",
    scan_id: "scan-27",
    target_id: "target-1",
    repository_asset_id: null,
    title: "Missing response protection",
    severity: "high",
    confidence: "high",
    affected_url: "http://juice-shop:3000/",
    affected_file: null,
    evidence: "Normalized evidence",
    source_tool: "scopeharbor-passive",
    scanner_rule_id: "header-rule",
    dedupe_key: "header-dedupe",
    owasp_category: "A05",
    cwe: "CWE-693",
    reproduction_steps: null,
    remediation: "Apply the missing response protection.",
    false_positive_notes: null,
    lifecycle_status: "open",
    suppressed: false,
    suppression_rule_id: null,
    tags: [],
    created_at: "2026-09-01T12:01:00Z"
  };
}
