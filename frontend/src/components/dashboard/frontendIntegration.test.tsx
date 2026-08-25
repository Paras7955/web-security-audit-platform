import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TargetSetup } from "@/components/TargetSetup";
import { FindingGovernancePanel } from "@/components/dashboard/FindingGovernancePanel";
import { WorkspaceOverview } from "@/components/dashboard/WorkspaceOverview";
import {
  aiExplanationRequest,
  clearSessionAuthToken,
  scanLaunchPayload,
  setSessionAuthToken,
  type AuditSubject,
  type Target,
} from "@/lib/securityAuditApi";

afterEach(() => {
  cleanup();
  clearSessionAuthToken();
  vi.unstubAllGlobals();
});

describe("Phase 25 protected workflow state", () => {
  it("clears a previously rendered workspace when the operator session is removed", async () => {
    setSessionAuthToken("valid-session");
    vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: vi.fn() });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const authorization = new Headers(init?.headers).get("Authorization");
      if (authorization !== "Bearer valid-session") {
        return jsonResponse({ detail: "Authentication required." }, 401);
      }
      return protectedApiResponse(String(input), init?.method ?? "GET");
    }));

    const props = {
      onActiveViewChange: vi.fn(),
      onHeroStateChange: vi.fn(),
    };
    const view = render(<TargetSetup activeView="operations" {...props} />);
    const clearButton = await screen.findByRole("button", { name: "Clear session token" });
    await waitFor(() => expect((clearButton as HTMLButtonElement).disabled).toBe(false));

    view.rerender(<TargetSetup activeView="credentials" {...props} />);
    await userEvent.type(screen.getByLabelText("Profile label"), "Cross-workspace credential");
    await userEvent.type(screen.getByPlaceholderText("Token or API key used by the target"), "target-secret-canary");
    view.rerender(<TargetSetup activeView="scanning" {...props} />);
    await userEvent.click(screen.getByRole("tab", { name: /Authorize/ }));
    const priorAcknowledgement = screen.getByRole("checkbox", { name: "I confirm I am authorized to assess this saved web target." });
    await userEvent.click(priorAcknowledgement);
    expect((priorAcknowledgement as HTMLInputElement).checked).toBe(true);
    await userEvent.click(screen.getByRole("tab", { name: /Scope/ }));
    await userEvent.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText("Target is allowlisted. Confirm authorization before saving it.")).toBeTruthy();
    await userEvent.click(screen.getByRole("checkbox", { name: "I am authorized to inspect this local repository." }));
    await userEvent.click(screen.getByRole("button", { name: "Save repository" }));
    expect(await screen.findByText("Repository fixture is saved as a confined repository subject.")).toBeTruthy();
    view.rerender(<TargetSetup activeView="findings" {...props} />);
    await screen.findAllByText("Authentication transition finding");
    await selectFindingFilter("Scope", "workspace");
    await selectFindingFilter("Subject", "target:target-1");
    await selectFindingFilter("Profile", "passive-web");
    await selectFindingFilter("Tag", "tag-auth");
    view.rerender(<TargetSetup activeView="overview" {...props} />);
    expect(await screen.findByText("Previously authorized target")).toBeTruthy();
    view.rerender(<TargetSetup activeView="operations" {...props} />);

    await userEvent.click(screen.getByRole("button", { name: "Clear session token" }));
    expect(await screen.findByText("Authentication required")).toBeTruthy();
    view.rerender(<TargetSetup activeView="overview" {...props} />);
    expect(screen.queryByText("Previously authorized target")).toBeNull();
    expect(screen.getByText("Choose an authorized subject")).toBeTruthy();
    view.rerender(<TargetSetup activeView="credentials" {...props} />);
    expect(screen.getByLabelText("Profile label")).toHaveProperty("value", "");
    expect(screen.getByPlaceholderText("Token or API key used by the target")).toHaveProperty("value", "");
    view.rerender(<TargetSetup activeView="operations" {...props} />);
    await userEvent.type(screen.getByPlaceholderText("Paste an OIDC access token"), "valid-session");
    await userEvent.click(screen.getByRole("button", { name: "Use token for this tab" }));
    await screen.findByText("OIDC bearer active");
    view.rerender(<TargetSetup activeView="scanning" {...props} />);
    await userEvent.click(screen.getByRole("tab", { name: /Authorize/ }));
    const newAcknowledgement = screen.getByRole("checkbox", { name: "I confirm I am authorized to assess this saved web target." });
    expect((newAcknowledgement as HTMLInputElement).checked).toBe(false);
    expect(screen.getByRole("button", { name: /Continue to launch review/ })).toHaveProperty("disabled", true);
    view.rerender(<TargetSetup activeView="findings" {...props} />);
    await screen.findAllByText("Authentication transition finding");
    fireEvent.click(screen.getByText("Filters & tags"));
    expect(screen.getByLabelText("Scope")).toHaveProperty("value", "scan");
    expect(screen.getByLabelText("Subject")).toHaveProperty("value", "");
    expect(screen.getByLabelText("Profile")).toHaveProperty("value", "");
    expect(screen.getByLabelText("Tag")).toHaveProperty("value", "");
    view.rerender(<TargetSetup activeView="scanning" {...props} />);
    await userEvent.click(screen.getByRole("tab", { name: /Scope/ }));
    expect(screen.getByText("Enter an allowlisted local/demo target.")).toBeTruthy();
    expect(screen.getByText("Authorize a confined local repository path to save it as a scan subject.")).toBeTruthy();
  });

  it("presents a stale web policy as requiring reauthorization", () => {
    const staleTarget = targetFixture({ policy_status: "stale", available_scan_profile_ids: [] });
    render(
      <WorkspaceOverview
        overview={null}
        health={null}
        selectedScan={null}
        selectedSubject={webSubject(staleTarget)}
        onNavigate={vi.fn()}
        onOpenScanHistory={vi.fn()}
      />
    );

    expect(screen.getByText("Reauthorization required")).toBeTruthy();
    expect(screen.getByText("Destination policy stale")).toBeTruthy();
    expect(screen.queryByText("Destination policy current")).toBeNull();
    expect(screen.getByRole("button", { name: /Reauthorize target/ })).toBeTruthy();
  });

  it("keeps archived tags visible while their assignments can be removed", async () => {
    const onUnassignTag = vi.fn();
    render(
      <FindingGovernancePanel
        suppressions={[]}
        tags={[{ id: "tag-1", label: "legacy", created_at: "2026-01-01T00:00:00Z", archived_at: "2026-01-02T00:00:00Z" }]}
        assignments={[{ id: "assignment-1", tag_id: "tag-1", resource_type: "scan", resource_id: "scan-1", created_at: "2026-01-01T00:00:00Z" }]}
        busyActionId=""
        onRevokeSuppression={vi.fn()}
        onArchiveTag={vi.fn()}
        onUnassignTag={onUnassignTag}
      />
    );

    fireEvent.click(screen.getByText("Suppression and tag history"));
    expect(screen.getByText("Archived · 1 active assignment")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Remove legacy" }));
    expect(onUnassignTag).toHaveBeenCalledWith(expect.objectContaining({ id: "assignment-1" }));
  });

  it("keeps non-ZAP passive audits launchable when worker-reported ZAP readiness is degraded", async () => {
    const target = targetFixture({
      available_scan_profile_ids: ["passive-web"],
      zap_required_scan_profile_ids: [],
    });
    vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: vi.fn() });
    vi.stubGlobal("fetch", readinessApi(target, "degraded"));
    render(<TargetSetup activeView="scanning" onActiveViewChange={vi.fn()} onHeroStateChange={vi.fn()} />);

    await screen.findByText("Allowed for the selected subject");
    await userEvent.click(screen.getByRole("tab", { name: /Authorize/ }));
    await userEvent.click(screen.getByRole("checkbox", { name: "I confirm I am authorized to assess this saved web target." }));
    await userEvent.click(screen.getByRole("button", { name: /Continue to launch review/ }));

    expect(screen.getByRole("button", { name: /Launch Passive Web/ })).toHaveProperty("disabled", false);
    expect(screen.getByText("Ready", { selector: "dd" })).toBeTruthy();
  });

  it("blocks only the selected target profiles whose policy requires degraded ZAP", async () => {
    const target = targetFixture({
      available_scan_profile_ids: ["passive-web"],
      zap_required_scan_profile_ids: ["passive-web"],
    });
    vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: vi.fn() });
    vi.stubGlobal("fetch", readinessApi(target, "degraded"));
    render(<TargetSetup activeView="scanning" onActiveViewChange={vi.fn()} onHeroStateChange={vi.fn()} />);

    await screen.findByText("Allowed for the selected subject");
    await userEvent.click(screen.getByRole("tab", { name: /Authorize/ }));
    await userEvent.click(screen.getByRole("checkbox", { name: "I confirm I am authorized to assess this saved web target." }));
    await userEvent.click(screen.getByRole("button", { name: /Continue to launch review/ }));

    expect(screen.getByRole("button", { name: /Launch Passive Web/ })).toHaveProperty("disabled", true);
    expect(screen.getByText(/This target policy requires ZAP/)).toBeTruthy();
  });

  it("refreshes workspace, subject, and comparison posture after every finding-governance mutation", async () => {
    setSessionAuthToken("valid-session");
    const fixture = postureMutationApi();
    vi.stubGlobal("fetch", fixture.fetchMock);
    render(<TargetSetup activeView="findings" onActiveViewChange={vi.fn()} onHeroStateChange={vi.fn()} />);

    await screen.findAllByText("Posture regression finding");
    await waitFor(() => {
      expect(fixture.counts.overview).toBeGreaterThan(0);
      expect(fixture.counts.subject).toBeGreaterThan(0);
      expect(fixture.counts.comparison).toBeGreaterThan(0);
    });

    let previous = { ...fixture.counts };
    await userEvent.selectOptions(screen.getByDisplayValue("open"), "confirmed");
    await expectEveryPostureLayerRefreshed(fixture.counts, previous);

    previous = { ...fixture.counts };
    await userEvent.type(screen.getByLabelText("Suppression reason"), "Accepted local fixture decision");
    await userEvent.click(screen.getByRole("button", { name: "Suppress" }));
    await expectEveryPostureLayerRefreshed(fixture.counts, previous);

    previous = { ...fixture.counts };
    fireEvent.click(screen.getByText("Suppression and tag history"));
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await expectEveryPostureLayerRefreshed(fixture.counts, previous);
  });
});

describe("Phase 25 API contract helpers", () => {
  it("builds mutually exclusive web and repository launch bodies", () => {
    const target = targetFixture();
    expect(scanLaunchPayload(webSubject(target), "passive-web", ["authorized_target"])).toMatchObject({
      target_id: target.id,
      repository_asset_id: null,
    });
    expect(scanLaunchPayload({
      id: "repository_asset:repo-1",
      subjectType: "repository_asset",
      name: "Repository",
      detail: "project",
      availableScanProfileIds: ["repository"],
      target: null,
      repositoryAsset: { id: "repo-1", name: "Repository", relative_path: "project", permission_confirmed: true, authorization_confirmed_at: "2026-01-01T00:00:00Z", archived_at: null, created_at: "2026-01-01T00:00:00Z" },
    }, "repository", ["authorized_repository"])).toMatchObject({
      target_id: null,
      repository_asset_id: "repo-1",
    });
  });

  it("keeps AI retrieval on GET semantics and generation explicit POST", () => {
    expect(aiExplanationRequest("scan-1").init).toBeUndefined();
    expect(aiExplanationRequest("scan-1", true).init).toEqual({ method: "POST" });
  });
});

function webSubject(target: Target): AuditSubject {
  return {
    id: `web_target:${target.id}`,
    subjectType: "web_target",
    name: target.name,
    detail: target.base_url,
    availableScanProfileIds: target.policy_status === "current" ? target.available_scan_profile_ids : [],
    target,
    repositoryAsset: null,
  };
}

function targetFixture(overrides: Partial<Target> = {}): Target {
  return {
    id: "target-1",
    allowlist_id: "local-demo",
    name: "Previously authorized target",
    base_url: "http://juice-shop:3000/",
    permission_confirmed: true,
    has_repo_path: false,
    auth_profile_id: null,
    available_scan_profile_ids: ["passive-web"],
    zap_required_scan_profile_ids: [],
    connection_class: "compose_service",
    scope_path: "/",
    tls_trust: "system",
    policy_status: "current",
    policy_fingerprint: "fingerprint",
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function page(items: unknown[] = []) {
  return { items, next_cursor: null };
}

function protectedApiResponse(url: string, method = "GET") {
  if (url.includes("/targets/validate") && method === "POST") return jsonResponse({
    allowlist_id: "local-demo", name: "Local demo", base_url: "http://juice-shop:3000/", available_scan_profile_ids: ["passive-web"],
    zap_required_scan_profile_ids: [],
    max_redirects: 2, local_demo: true, connection_class: "compose_service", scope_path: "/", tls_trust: "system",
    policy_fingerprint: "fingerprint",
  });
  if (url.endsWith("/repository-assets") && method === "POST") return jsonResponse({
    id: "repo-auth", name: "Repository fixture", relative_path: "security-project", permission_confirmed: true,
    authorization_confirmed_at: "2026-01-01T00:00:00Z", archived_at: null, created_at: "2026-01-01T00:00:00Z",
  }, 201);
  if (url.includes("/targets/policies")) return jsonResponse([]);
  if (url.includes("/targets/target-1/dashboard")) return jsonResponse({
    target_id: "target-1", target_name: "Previously authorized target", base_url: "http://juice-shop:3000/", scan_count: 0,
    completed_scan_count: 0, findings_count: 0, severity_counts: {}, latest_risk_score: null, recent_scans: [],
    posture_basis: "latest completed scan per subject and profile", current_posture_score: null, historical_findings_count: 0,
    historical_severity_counts: {},
  });
  if (url.includes("/targets")) return jsonResponse(page([targetFixture()]));
  if (url.includes("/repository-assets")) return jsonResponse(page());
  if (url.includes("/auth-profiles")) return jsonResponse(page());
  if (url.includes("/scans/auth-scan/findings")) return jsonResponse(page([authenticationTransitionFinding()]));
  if (url.includes("/findings?")) return jsonResponse(page([authenticationTransitionFinding()]));
  if (url.includes("/scans/auth-scan/tool-runs")) return jsonResponse(page());
  if (url.includes("/scans/auth-scan/reports")) return jsonResponse(page());
  if (url.includes("/scans/auth-scan/ai-explanations")) return jsonResponse({ detail: "No explanation yet." }, 404);
  if (url.includes("/scans")) return jsonResponse(page([scanFixture("auth-scan", "2026-01-01T00:00:00Z")]));
  if (url.includes("/dashboard/overview")) return jsonResponse({
    targets_count: 1, repository_assets_count: 0, scans_count: 0, completed_scans_count: 0, findings_count: 0,
    severity_counts: {}, latest_risk_score: null, recent_scans: [], posture_basis: "latest completed scan per subject and profile",
    current_posture_score: null, historical_findings_count: 0, historical_severity_counts: {},
  });
  if (url.includes("/tags/assignments")) return jsonResponse(page());
  if (url.includes("/tags")) return jsonResponse(page([{ id: "tag-auth", label: "auth-transition", created_at: "2026-01-01T00:00:00Z", archived_at: null }]));
  if (url.includes("/suppressions")) return jsonResponse(page());
  if (url.includes("/ops/health")) return jsonResponse({
    status: "ok", database: { status: "ok", detail: null }, worker: { status: "ok", detail: null }, queue_depth: 0,
    zap: { status: "ok", detail: null }, artifact_root: { status: "ok", detail: null },
  });
  if (url.includes("/audit-logs")) return jsonResponse(page());
  return jsonResponse({ detail: `Unexpected test request: ${url}` }, 500);
}

function authenticationTransitionFinding() {
  return {
    id: "auth-finding", scan_id: "auth-scan", target_id: "target-1", repository_asset_id: null,
    title: "Authentication transition finding", severity: "medium", confidence: "high", affected_url: "http://juice-shop:3000/",
    affected_file: null, evidence: "Normalized evidence", source_tool: "scopeharbor-passive", scanner_rule_id: "auth-rule",
    dedupe_key: "auth-dedupe", owasp_category: "A05", cwe: "CWE-693", reproduction_steps: null, remediation: null,
    false_positive_notes: null, lifecycle_status: "open", suppressed: false, suppression_rule_id: null, tags: ["auth-transition"],
    created_at: "2026-01-01T00:00:00Z",
  };
}

async function expectEveryPostureLayerRefreshed(
  counts: { overview: number; subject: number; comparison: number },
  previous: { overview: number; subject: number; comparison: number },
) {
  await waitFor(() => {
    expect(counts.overview).toBeGreaterThan(previous.overview);
    expect(counts.subject).toBeGreaterThan(previous.subject);
    expect(counts.comparison).toBeGreaterThan(previous.comparison);
  });
}

async function selectFindingFilter(label: string, value: string) {
  const summary = screen.getByText("Filters & tags");
  const details = summary.closest("details");
  if (!details?.open) fireEvent.click(summary);
  await userEvent.selectOptions(screen.getByLabelText(label), value);
  await screen.findAllByText("Authentication transition finding");
}

function postureMutationApi() {
  const counts = { overview: 0, subject: 0, comparison: 0 };
  const finding = {
    id: "finding-1", scan_id: "scan-2", target_id: "target-1", repository_asset_id: null,
    title: "Posture regression finding", severity: "high", confidence: "high", affected_url: "http://juice-shop:3000/",
    affected_file: null, evidence: "Normalized evidence", source_tool: "scopeharbor-passive", scanner_rule_id: "test-rule",
    dedupe_key: "finding-dedupe", owasp_category: "A05", cwe: "CWE-693", reproduction_steps: null,
    remediation: "Apply the missing control.", false_positive_notes: null, lifecycle_status: "open", suppressed: false,
    suppression_rule_id: null, tags: [], created_at: "2026-01-02T00:00:00Z",
  };
  const suppression = {
    id: "suppression-1", target_id: "target-1", repository_asset_id: null, dedupe_key: "finding-dedupe", severity: "high",
    source_tool: "scopeharbor-passive", reason: "Fixture suppression", expires_at: null, revoked_at: null,
    created_at: "2026-01-02T00:00:00Z",
  };
  const scans = [scanFixture("scan-2", "2026-01-02T00:00:00Z"), scanFixture("scan-1", "2026-01-01T00:00:00Z")];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/findings/finding-1/lifecycle") && method === "PATCH") return jsonResponse({ ...finding, lifecycle_status: "confirmed" });
    if (url.endsWith("/suppressions") && method === "POST") return jsonResponse(suppression, 201);
    if (url.includes("/suppressions/suppression-1/revoke") && method === "POST") return jsonResponse({ ...suppression, revoked_at: "2026-01-03T00:00:00Z" });
    if (url.includes("/targets/target-1/latest-comparison")) {
      counts.comparison += 1;
      return jsonResponse(comparisonFixture());
    }
    if (url.includes("/targets/target-1/dashboard")) {
      counts.subject += 1;
      return jsonResponse(targetDashboardFixture());
    }
    if (url.includes("/dashboard/overview")) {
      counts.overview += 1;
      return jsonResponse(overviewFixture(scans));
    }
    if (url.includes("/targets/policies")) return jsonResponse([]);
    if (url.includes("/targets")) return jsonResponse(page([targetFixture()]));
    if (url.includes("/repository-assets")) return jsonResponse(page());
    if (url.includes("/auth-profiles")) return jsonResponse(page());
    if (url.includes("/scans/scan-2/findings")) return jsonResponse(page([finding]));
    if (url.includes("/scans/scan-2/tool-runs")) return jsonResponse(page());
    if (url.includes("/scans/scan-2/reports")) return jsonResponse(page());
    if (url.includes("/scans/scan-2/ai-explanations")) return jsonResponse({ detail: "No explanation yet." }, 404);
    if (url.includes("/scans")) return jsonResponse(page(scans));
    if (url.includes("/tags/assignments")) return jsonResponse(page());
    if (url.includes("/tags")) return jsonResponse(page());
    if (url.includes("/suppressions")) return jsonResponse(page([suppression]));
    if (url.includes("/ops/health")) return jsonResponse(healthFixture());
    if (url.includes("/audit-logs")) return jsonResponse(page());
    return jsonResponse({ detail: `Unexpected mutation test request: ${method} ${url}` }, 500);
  });
  return { counts, fetchMock };
}

function scanFixture(id: string, createdAt: string) {
  return {
    id, target_id: "target-1", repository_asset_id: null, subject_type: "web_target", subject_id: "target-1",
    scan_profile_id: "passive-web", status: "completed", current_step: "complete", status_message: "Completed safely.",
    progress_percent: 100, started_at: createdAt, completed_at: createdAt, cancellation_requested_at: null,
    failure: null, created_at: createdAt,
  };
}

function overviewFixture(scans: ReturnType<typeof scanFixture>[]) {
  return {
    targets_count: 1, repository_assets_count: 0, scans_count: scans.length, completed_scans_count: scans.length,
    findings_count: 1, severity_counts: { high: 1 }, latest_risk_score: null, recent_scans: [],
    posture_basis: "latest completed scan per subject and profile", current_posture_score: null,
    historical_findings_count: 1, historical_severity_counts: { high: 1 },
  };
}

function targetDashboardFixture() {
  return {
    target_id: "target-1", target_name: "Previously authorized target", base_url: "http://juice-shop:3000/", scan_count: 2,
    completed_scan_count: 2, findings_count: 1, severity_counts: { high: 1 }, latest_risk_score: null, recent_scans: [],
    posture_basis: "latest completed scan per subject and profile", current_posture_score: null,
    historical_findings_count: 1, historical_severity_counts: { high: 1 },
  };
}

function comparisonFixture() {
  const score = {
    id: "risk-1", target_id: "target-1", repository_asset_id: null, scan_id: "scan-1", scoring_model_version: "risk-v1",
    score: 20, label: "low", input_summary: {}, created_at: "2026-01-01T00:00:00Z",
  };
  return {
    target_id: "target-1", repository_asset_id: null, subject_type: "web_target", subject_id: "target-1",
    baseline_scan_id: "scan-1", comparison_scan_id: "scan-2", scoring_model_version: "risk-v1",
    baseline_score: score, comparison_score: { ...score, id: "risk-2", scan_id: "scan-2" }, score_delta: 0,
    new_findings: [], resolved_findings: [], unchanged_findings: [], severity_changed_findings: [],
  };
}

function healthFixture() {
  return {
    status: "ok", database: { status: "ok", detail: null }, worker: { status: "ok", detail: null }, queue_depth: 0,
    zap: { status: "ok", detail: null }, artifact_root: { status: "ok", detail: null },
  };
}

function readinessApi(target: Target, zapStatus: "ok" | "degraded") {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/targets?") || url.endsWith("/targets")) return jsonResponse(page([target]));
    if (url.includes("/ops/health")) return jsonResponse({
      ...healthFixture(),
      zap: { status: zapStatus, detail: zapStatus === "ok" ? "zap reachable from worker" : "zap unavailable to worker" },
    });
    return protectedApiResponse(url, init?.method ?? "GET");
  });
}
