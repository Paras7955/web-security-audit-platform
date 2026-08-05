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
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const authorization = new Headers(init?.headers).get("Authorization");
      if (authorization !== "Bearer valid-session") {
        return jsonResponse({ detail: "Authentication required." }, 401);
      }
      return protectedApiResponse(String(input));
    }));

    const props = {
      onActiveViewChange: vi.fn(),
      onHeroStateChange: vi.fn(),
    };
    const view = render(<TargetSetup activeView="operations" {...props} />);
    const clearButton = await screen.findByRole("button", { name: "Clear session token" });
    await waitFor(() => expect((clearButton as HTMLButtonElement).disabled).toBe(false));

    view.rerender(<TargetSetup activeView="overview" {...props} />);
    expect(await screen.findByText("Previously authorized target")).toBeTruthy();
    view.rerender(<TargetSetup activeView="operations" {...props} />);

    await userEvent.click(screen.getByRole("button", { name: "Clear session token" }));
    expect(await screen.findByText("Authentication required")).toBeTruthy();
    view.rerender(<TargetSetup activeView="overview" {...props} />);
    expect(screen.queryByText("Previously authorized target")).toBeNull();
    expect(screen.getByText("Choose an authorized subject")).toBeTruthy();
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

function protectedApiResponse(url: string) {
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
  if (url.includes("/scans")) return jsonResponse(page());
  if (url.includes("/dashboard/overview")) return jsonResponse({
    targets_count: 1, repository_assets_count: 0, scans_count: 0, completed_scans_count: 0, findings_count: 0,
    severity_counts: {}, latest_risk_score: null, recent_scans: [], posture_basis: "latest completed scan per subject and profile",
    current_posture_score: null, historical_findings_count: 0, historical_severity_counts: {},
  });
  if (url.includes("/tags/assignments")) return jsonResponse(page());
  if (url.includes("/tags")) return jsonResponse(page());
  if (url.includes("/suppressions")) return jsonResponse(page());
  if (url.includes("/ops/health")) return jsonResponse({
    status: "ok", database: { status: "ok", detail: null }, worker: { status: "ok", detail: null }, queue_depth: 0,
    zap: { status: "ok", detail: null }, artifact_root: { status: "ok", detail: null },
  });
  if (url.includes("/audit-logs")) return jsonResponse(page());
  return jsonResponse({ detail: `Unexpected test request: ${url}` }, 500);
}
