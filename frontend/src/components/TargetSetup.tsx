"use client";

/* eslint-disable react-hooks/exhaustive-deps, react-hooks/set-state-in-effect -- Async loaders reject stale responses with selected-resource refs. */

import { FormEvent, KeyboardEvent as ReactKeyboardEvent, useEffect, useMemo, useRef, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import { ConfirmActionDialog } from "@/components/ConfirmActionDialog";
import { AiExplanationsPanel } from "@/components/dashboard/AiExplanationsPanel";
import { AuthProfilesPanel } from "@/components/dashboard/AuthProfilesPanel";
import { FindingsDashboard, severityRank } from "@/components/dashboard/FindingsDashboard";
import { OpsHealthPanel } from "@/components/dashboard/OpsHealthPanel";
import { ReportsPanel } from "@/components/dashboard/ReportsPanel";
import { RiskDashboardPanel } from "@/components/dashboard/RiskDashboardPanel";
import {
  ScanHistory,
  ScanAuthorization,
  ScanLaunchPanel,
  ScanProfileSelector,
  ScanProgress,
  canUseAi,
  canUseReports,
  mergeScan,
  terminalStatuses
} from "@/components/dashboard/ScanControls";
import { SCAN_PROFILES } from "@/lib/contracts";
import { TargetForm } from "@/components/dashboard/TargetForm";
import { TargetLibrary } from "@/components/dashboard/TargetLibrary";
import { WorkspaceOverview } from "@/components/dashboard/WorkspaceOverview";
import {
  AiExplanation,
  AuthProfile,
  DashboardOverview,
  Finding,
  PlatformHealth,
  ReportArtifact,
  ScanComparison,
  Scan,
  ScannerToolRun,
  Tag,
  Target,
  TargetDashboard,
  ValidationResult,
  apiBaseUrl,
  apiOrigin,
  apiFetch,
  readJson,
  readPage
} from "@/lib/securityAuditApi";

export const workspaceViews = [
  { id: "overview", label: "Workspace", description: "Workspace signal", icon: "overview" },
  { id: "scanning", label: "Audits", description: "Configure and launch", icon: "scan" },
  { id: "findings", label: "Findings", description: "Triage evidence", icon: "finding" },
  { id: "intelligence", label: "Intelligence", description: "Risk, reports & AI", icon: "intelligence" },
  { id: "credentials", label: "Credentials", description: "Target auth profiles", icon: "credential" },
  { id: "operations", label: "Operations", description: "Platform readiness", icon: "operations" }
] as const;

export type WorkspaceView = (typeof workspaceViews)[number]["id"];

type AuditPhase = "ready" | "scope" | "profile" | "authorize" | "run" | "review";

const auditPhases: Array<{ id: AuditPhase; label: string; description: string; icon: "operations" | "target" | "scan" | "shield" | "activity" | "finding" }> = [
  { id: "ready", label: "Ready", description: "Platform check", icon: "operations" },
  { id: "scope", label: "Scope", description: "Approved target", icon: "target" },
  { id: "profile", label: "Profile", description: "Audit approach", icon: "scan" },
  { id: "authorize", label: "Authorize", description: "Confirm boundaries", icon: "shield" },
  { id: "run", label: "Run", description: "Launch & monitor", icon: "activity" },
  { id: "review", label: "Review", description: "Findings & reports", icon: "finding" }
];

export function TargetSetup({
  activeView,
  onActiveViewChange,
  onHeroStateChange
}: {
  activeView: WorkspaceView;
  onActiveViewChange: (view: WorkspaceView) => void;
  onHeroStateChange: (state: { activeProfile: string; currentStep: string | null; status: string }) => void;
}) {
  const [auditPhase, setAuditPhase] = useState<AuditPhase>("ready");
  const [targetUrl, setTargetUrl] = useState("http://juice-shop:3000");
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [repoPath, setRepoPath] = useState("/app/repositories/security-project");
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [authProfiles, setAuthProfiles] = useState<AuthProfile[]>([]);
  const [selectedAuthProfileId, setSelectedAuthProfileId] = useState("");
  const [authProfileLabel, setAuthProfileLabel] = useState("");
  const [authProfileType, setAuthProfileType] = useState("bearer_token");
  const [authProfileHeaderName, setAuthProfileHeaderName] = useState("");
  const [authProfileSecret, setAuthProfileSecret] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanProfileId, setScanProfileId] = useState("passive-web");
  const [acknowledgements, setAcknowledgements] = useState<string[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [toolRuns, setToolRuns] = useState<ScannerToolRun[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [reports, setReports] = useState<ReportArtifact[]>([]);
  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [dashboardOverview, setDashboardOverview] = useState<DashboardOverview | null>(null);
  const [targetDashboard, setTargetDashboard] = useState<TargetDashboard | null>(null);
  const [scanComparison, setScanComparison] = useState<ScanComparison | null>(null);
  const [platformHealth, setPlatformHealth] = useState<PlatformHealth | null>(null);
  const [baselineScanId, setBaselineScanId] = useState("");
  const [comparisonScanId, setComparisonScanId] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [lifecycleFilter, setLifecycleFilter] = useState("all");
  const [suppressionFilter, setSuppressionFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [scannerFilter, setScannerFilter] = useState("");
  const [owaspFilter, setOwaspFilter] = useState("");
  const [cweFilter, setCweFilter] = useState("");
  const [tagFilter, setTagFilter] = useState("");
  const [dateAfterFilter, setDateAfterFilter] = useState("");
  const [dateBeforeFilter, setDateBeforeFilter] = useState("");
  const [riskMinFilter, setRiskMinFilter] = useState("");
  const [riskMaxFilter, setRiskMaxFilter] = useState("");
  const [findingSearchQuery, setFindingSearchQuery] = useState("");
  const [findingScope, setFindingScope] = useState("scan");
  const [targetFilter, setTargetFilter] = useState("");
  const [profileFilter, setProfileFilter] = useState("");
  const [tagLabel, setTagLabel] = useState("");
  const [tagResourceType, setTagResourceType] = useState("target");
  const [suppressionReason, setSuppressionReason] = useState("");
  const [message, setMessage] = useState("Enter an allowlisted local/demo target.");
  const [authProfileMessage, setAuthProfileMessage] = useState("Create an optional target-app auth profile for passive scans.");
  const [reportMessage, setReportMessage] = useState("Reports are available after a passive, Active Demo, or Repo scan completes.");
  const [aiMessage, setAiMessage] = useState("AI explanations are available after a passive or Active Demo scan completes.");
  const [riskMessage, setRiskMessage] = useState("Risk scores are generated for completed scans using risk-v1.");
  const [opsMessage, setOpsMessage] = useState("Platform health has not been loaded.");
  const [bootstrapError, setBootstrapError] = useState("");
  const [archiveCandidate, setArchiveCandidate] = useState<Target | null>(null);
  const [revokeCandidate, setRevokeCandidate] = useState<AuthProfile | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isGeneratingReports, setIsGeneratingReports] = useState(false);
  const [isCancellingScan, setIsCancellingScan] = useState(false);
  const selectedScanIdRef = useRef("");
  const selectedTargetIdRef = useRef("");

  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedScan = scanHistory.find((scan) => scan.id === selectedScanId) ?? null;
  const selectedProfile = SCAN_PROFILES.find((profile) => profile.id === scanProfileId) ?? SCAN_PROFILES[0];
  const platformReady = platformHealth?.status === "ok";
  const canCreate = useMemo(() => Boolean(validation && permissionConfirmed && !isBusy), [validation, permissionConfirmed, isBusy]);
  const profileReady = Boolean(
    selectedTarget &&
      selectedTarget.available_scan_profile_ids.includes(selectedProfile.id) &&
      (!selectedProfile.requires_repo_path || selectedTarget.has_repo_path) &&
      (!selectedTarget.auth_profile_id || selectedProfile.mode === "passive")
  );
  const authorizationReady = Boolean(
    profileReady &&
      selectedProfile.required_acknowledgements.every((code) => acknowledgements.includes(code))
  );
  const canStartScan = authorizationReady && platformReady && !isBusy;
  const reviewReady = Boolean(selectedScan && ["completed", "completed_with_warnings"].includes(selectedScan.status));
  const displayFindings = findings;
  const displayAiExplanation = useMemo(() => uniqueAiExplanation(aiExplanation, findings), [aiExplanation, findings]);
  const filteredFindings = useMemo(() => {
    const query = findingSearchQuery.trim().toLowerCase();
    return [...displayFindings]
      .filter((finding) => {
        if (!query) {
          return true;
        }
        return [
          finding.title,
          finding.source_tool,
          finding.affected_url,
          finding.affected_file,
          finding.owasp_category,
          finding.cwe,
          finding.severity,
          finding.lifecycle_status,
          ...finding.tags
        ].some((value) => value?.toLowerCase().includes(query));
      })
      .sort((left, right) => (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0));
  }, [displayFindings, findingSearchQuery]);
  const selectedFinding = filteredFindings.find((finding) => finding.id === selectedFindingId) ?? filteredFindings[0] ?? null;

  useEffect(() => {
    void loadInitialData();
  }, []);

  useEffect(() => {
    selectedScanIdRef.current = selectedScanId;
  }, [selectedScanId]);

  useEffect(() => {
    selectedTargetIdRef.current = selectedTargetId;
  }, [selectedTargetId]);

  useEffect(() => {
    const scanDrivesHero = activeView === "scanning" && (auditPhase === "run" || auditPhase === "review");
    onHeroStateChange({
      activeProfile: scanProfileId,
      currentStep: scanDrivesHero ? selectedScan?.current_step ?? null : null,
      status: scanDrivesHero && selectedScan ? selectedScan.status : platformHealth?.status === "ok" ? "ready" : "validating"
    });
  }, [activeView, auditPhase, onHeroStateChange, platformHealth?.status, scanProfileId, selectedScan?.current_step, selectedScan?.status]);

  useEffect(() => {
    setSuppressionReason("");
  }, [selectedFindingId]);

  useEffect(() => {
    if (!selectedScan || terminalStatuses.has(selectedScan.status)) {
      return;
    }

    const timer = window.setInterval(() => {
      void refreshScan(selectedScan.id);
    }, 1500);
    return () => window.clearInterval(timer);
  }, [selectedScan]);

  useEffect(() => {
    if (!selectedScanId) {
      setFindings([]);
      setReports([]);
      setToolRuns([]);
      setAiExplanation(null);
      setSelectedFindingId("");
      return;
    }
    void loadFindings(selectedScanId, { onlyIfSelected: true });
    void loadToolRuns(selectedScanId, { onlyIfSelected: true });
    if (selectedScan && canUseReports(selectedScan)) {
      void loadReports(selectedScanId, { onlyIfSelected: true });
    } else {
      setReports([]);
      setReportMessage("Reports remain available for passive, Active Demo, and Repo scans.");
    }
    if (selectedScan && canUseAi(selectedScan)) {
      void loadAiExplanation(selectedScanId, { onlyIfSelected: true });
      return;
    }
    setAiExplanation(null);
    setAiMessage("AI explanations remain available for passive and Active Demo scans.");
  }, [
    selectedScanId,
    selectedScan?.scan_profile_id,
    severityFilter,
    lifecycleFilter,
    suppressionFilter,
    confidenceFilter,
    scannerFilter,
    owaspFilter,
    cweFilter,
    tagFilter,
    dateAfterFilter,
    dateBeforeFilter,
    riskMinFilter,
    riskMaxFilter,
    findingScope,
    targetFilter,
    profileFilter,
    selectedTargetId
  ]);

  useEffect(() => {
    if (!selectedTargetId) {
      setTargetDashboard(null);
      setScanComparison(null);
      setBaselineScanId("");
      setComparisonScanId("");
      return;
    }
    void loadTargetDashboard(selectedTargetId);
    void loadLatestComparison(selectedTargetId);
  }, [selectedTargetId]);

  async function loadInitialData() {
    setBootstrapError("");
    const results = await Promise.allSettled([loadTargets(), loadAuthProfiles(), loadScanHistory(), loadDashboardOverview(), loadTags(), loadPlatformHealth()]);
    const failed = results.find((result) => result.status === "rejected");
    if (failed?.status === "rejected") {
      const error = failed.reason;
      const detail = error instanceof Error ? error.message : "Workspace data could not be loaded.";
      setBootstrapError(`Workspace data could not be loaded. ${detail}`);
    }
  }

  async function validateTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsBusy(true);
    setValidation(null);
    setMessage("Validating target against the local allowlist...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/validate?target_url=${encodeURIComponent(targetUrl)}`);
      setValidation(await readJson<ValidationResult>(response, "Target validation failed."));
      setMessage("Target is allowlisted. Confirm authorization before saving it.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target validation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function createTarget() {
    setIsBusy(true);
    setMessage("Saving target...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/targets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          permission_confirmed: permissionConfirmed,
          repo_path: repoPath.trim() || null,
          auth_profile_id: selectedAuthProfileId || null
        })
      });
      const body = await readJson<Target>(response, "Target creation failed.");
      await loadTargets(body.id);
      setMessage("Target saved. Available scan modes are shown below.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function archiveTarget() {
    if (!archiveCandidate) {
      return;
    }

    const target = archiveCandidate;
    setIsBusy(true);
    setMessage(`Removing ${target.name} from saved targets...`);
    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/${target.id}`, { method: "DELETE" });
      if (!response.ok) {
        await readJson<never>(response, "Target removal failed.");
      }
      setArchiveCandidate(null);
      if (selectedTargetIdRef.current === target.id) {
        setSelectedTargetId("");
      }
      await Promise.all([loadTargets(""), loadDashboardOverview()]);
      setMessage(`${target.name} was removed from saved targets. Its scan, finding, report, and audit history remains available.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target removal failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function refreshWorkspace() {
    setIsRefreshing(true);
    try {
      await loadInitialData();
      const scanId = selectedScanIdRef.current;
      const targetId = selectedTargetIdRef.current;
      await Promise.allSettled([
        scanId ? refreshScan(scanId) : Promise.resolve(),
        targetId ? loadTargetDashboard(targetId) : Promise.resolve(),
        targetId ? loadLatestComparison(targetId) : Promise.resolve()
      ]);
    } finally {
      setIsRefreshing(false);
    }
  }

  function resetFindingFilters() {
    setFindingSearchQuery("");
    setSeverityFilter("all");
    setLifecycleFilter("all");
    setSuppressionFilter("all");
    setConfidenceFilter("all");
    setScannerFilter("");
    setOwaspFilter("");
    setCweFilter("");
    setTagFilter("");
    setDateAfterFilter("");
    setDateBeforeFilter("");
    setRiskMinFilter("");
    setRiskMaxFilter("");
    setTargetFilter("");
    setProfileFilter("");
  }

  function handlePhaseKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>, index: number) {
    let nextIndex = index;
    if (event.key === "ArrowRight") {
      nextIndex = (index + 1) % auditPhases.length;
    } else if (event.key === "ArrowLeft") {
      nextIndex = (index - 1 + auditPhases.length) % auditPhases.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = auditPhases.length - 1;
    } else {
      return;
    }
    event.preventDefault();
    setAuditPhase(auditPhases[nextIndex].id);
    const tabs = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>("[role='tab']");
    tabs?.[nextIndex]?.focus();
  }

  async function startScan() {
    if (!selectedTarget) {
      return;
    }
    if (selectedTarget.auth_profile_id && selectedProfile.mode !== "passive") {
      setMessage("Auth profiles are currently supported only for passive-web scans.");
      return;
    }

    setIsBusy(true);
    setMessage(`Creating ${selectedProfile.label} scan...`);

    try {
      const response = await apiFetch(`${apiBaseUrl}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: selectedTarget.id,
          scan_profile_id: selectedProfile.id,
          acknowledgements
        })
      });
      const scan = await readJson<Scan>(response, "Scan creation failed.");
      setSelectedScanId(scan.id);
      setFindings([]);
      setToolRuns([]);
      setReports([]);
      setAiExplanation(null);
      setSelectedFindingId("");
      setAcknowledgements([]);
      setReportMessage("Reports are available after this passive, Active Demo, or Repo scan completes.");
      setAiMessage("AI explanations are available after this passive or Active Demo scan completes.");
      setMessage("Scan queued. Worker status will update below.");
      setAuditPhase("run");
      await loadScanHistory(scan.id);
      await loadDashboardOverview();
      await loadTargetDashboard(selectedTarget.id);
      await loadLatestComparison(selectedTarget.id);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function updateSelectedTargetRepoPath() {
    if (!selectedTarget) {
      return;
    }

    setIsBusy(true);
    setMessage("Attaching repo path to selected target...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/${selectedTarget.id}/repo-path`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath.trim() || null })
      });
      const updatedTarget = await readJson<Target>(response, "Repo path update failed.");
      setTargets((current) => current.map((target) => (target.id === updatedTarget.id ? updatedTarget : target)));
      setSelectedTargetId(updatedTarget.id);
      setMessage("Repo path attached. Repo scans are available for this target.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Repo path update failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function createAuthProfile() {
    setIsBusy(true);
    setAuthProfileMessage("Saving auth profile...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/auth-profiles`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: authProfileLabel,
          profile_type: authProfileType,
          header_name: authProfileType === "custom_header" ? authProfileHeaderName : null,
          secret: authProfileSecret
        })
      });
      const profile = await readJson<AuthProfile>(response, "Auth profile creation failed.");
      setSelectedAuthProfileId(profile.id);
      setAuthProfileLabel("");
      setAuthProfileHeaderName("");
      setAuthProfileSecret("");
      await loadAuthProfiles(profile.id);
      setAuthProfileMessage("Auth profile saved. Attach it to a target before starting an authenticated passive scan.");
    } catch (error) {
      setAuthProfileMessage(error instanceof Error ? error.message : "Auth profile creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function rotateSelectedAuthProfile() {
    if (!selectedAuthProfileId || !authProfileSecret.trim()) {
      return;
    }
    setIsBusy(true);
    setAuthProfileMessage("Rotating auth profile secret for future scans...");
    try {
      const response = await apiFetch(`${apiBaseUrl}/auth-profiles/${selectedAuthProfileId}/rotate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret: authProfileSecret })
      });
      const profile = await readJson<AuthProfile>(response, "Auth profile rotation failed.");
      setAuthProfileSecret("");
      await loadAuthProfiles(profile.id);
      setAuthProfileMessage("Auth profile rotated. Existing scan snapshots were not changed.");
    } catch (error) {
      setAuthProfileMessage(error instanceof Error ? error.message : "Auth profile rotation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function revokeSelectedAuthProfile() {
    if (!revokeCandidate) {
      return;
    }
    const profile = revokeCandidate;
    setIsBusy(true);
    setAuthProfileMessage("Revoking auth profile and detaching it from targets...");
    try {
      const response = await apiFetch(`${apiBaseUrl}/auth-profiles/${profile.id}/revoke`, { method: "POST" });
      const revokedProfile = await readJson<AuthProfile>(response, "Auth profile revocation failed.");
      setRevokeCandidate(null);
      await Promise.all([loadAuthProfiles(revokedProfile.id), loadTargets(selectedTargetId)]);
      setAuthProfileMessage("Auth profile revoked. Its encrypted secret was erased and attached targets were detached.");
    } catch (error) {
      setAuthProfileMessage(error instanceof Error ? error.message : "Auth profile revocation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function updateSelectedTargetAuthProfile() {
    if (!selectedTarget) {
      return;
    }

    setIsBusy(true);
    setAuthProfileMessage(selectedAuthProfileId ? "Attaching auth profile to target..." : "Detaching auth profile from target...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/${selectedTarget.id}/auth-profile`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ auth_profile_id: selectedAuthProfileId || null })
      });
      const updatedTarget = await readJson<Target>(response, "Auth profile update failed.");
      setTargets((current) => current.map((target) => (target.id === updatedTarget.id ? updatedTarget : target)));
      setSelectedTargetId(updatedTarget.id);
      setAuthProfileMessage(updatedTarget.auth_profile_id ? "Auth profile attached to selected target." : "Auth profile detached from selected target.");
    } catch (error) {
      setAuthProfileMessage(error instanceof Error ? error.message : "Auth profile update failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function refreshScan(scanId: string) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${scanId}`);
      const scan = await readJson<Scan>(response, "Scan status refresh failed.");
      setScanHistory((current) => mergeScan(current, scan));
      if (terminalStatuses.has(scan.status)) {
        await loadToolRuns(scan.id, { onlyIfSelected: true });
        await loadFindings(scan.id, { onlyIfSelected: true });
        if (canUseReports(scan)) {
          await loadReports(scan.id, { onlyIfSelected: true });
        } else if (selectedScanIdRef.current === scan.id) {
          setReports([]);
          setReportMessage("Reports remain available for passive, Active Demo, and Repo scans.");
        }
        if (canUseAi(scan)) {
          await loadAiExplanation(scan.id, { onlyIfSelected: true });
        } else if (selectedScanIdRef.current === scan.id) {
          setAiExplanation(null);
          setAiMessage("AI explanations remain available for passive and Active Demo scans.");
        }
        await loadDashboardOverview();
        await loadTargetDashboard(scan.target_id);
        await loadLatestComparison(scan.target_id);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan status refresh failed.");
    }
  }

  async function cancelSelectedScan() {
    if (!selectedScan) {
      return;
    }
    setIsCancellingScan(true);
    setMessage("Requesting scan cancellation...");
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${selectedScan.id}/cancel`, { method: "POST" });
      const scan = await readJson<Scan>(response, "Scan cancellation failed.");
      setScanHistory((current) => mergeScan(current, scan));
      setMessage(scan.status === "cancelled" ? "Scan cancelled." : "Cancellation requested. Worker will stop at a safe checkpoint.");
      await loadDashboardOverview();
      await loadPlatformHealth();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan cancellation failed.");
    } finally {
      setIsCancellingScan(false);
    }
  }

  async function loadTargets(preferredTargetId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/targets?limit=200`);
    const page = await readPage<Target>(response, "Target list load failed.");
    setTargets(page.items);
    const requestedTargetId = preferredTargetId ?? selectedTargetId;
    const nextTargetId = page.items.some((target) => target.id === requestedTargetId) ? requestedTargetId : page.items[0]?.id ?? "";
    setSelectedTargetId(nextTargetId);
    setBootstrapError("");
  }

  async function loadDashboardOverview() {
    const response = await apiFetch(`${apiBaseUrl}/dashboard/overview`);
    const body = await readJson<DashboardOverview>(response, "Dashboard overview load failed.");
    setDashboardOverview(body);
    setBootstrapError("");
  }

  async function loadPlatformHealth() {
    try {
      const response = await apiFetch(`${apiBaseUrl}/ops/health`);
      const body = await readJson<PlatformHealth>(response, "Platform health load failed.");
      setPlatformHealth(body);
      setOpsMessage(body.status === "ok" ? "Platform components are healthy." : "One or more platform components are degraded.");
      setBootstrapError("");
    } catch (error) {
      setPlatformHealth(null);
      setOpsMessage(error instanceof Error ? error.message : "Platform health load failed.");
    }
  }

  async function loadTargetDashboard(targetId: string) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/${targetId}/dashboard`);
      const body = await readJson<TargetDashboard>(response, "Target dashboard load failed.");
      if (selectedTargetIdRef.current !== targetId) {
        return;
      }
      setTargetDashboard(body);
    } catch (error) {
      if (selectedTargetIdRef.current !== targetId) {
        return;
      }
      setTargetDashboard(null);
      setRiskMessage(error instanceof Error ? error.message : "Target dashboard load failed.");
    }
  }

  async function loadLatestComparison(targetId: string) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/${targetId}/latest-comparison`);
      if (!response.ok) {
        if (selectedTargetIdRef.current !== targetId) {
          return;
        }
        setScanComparison(null);
        setRiskMessage("At least two completed scans are required for latest-vs-previous comparison.");
        return;
      }
      const body = (await response.json()) as ScanComparison;
      if (selectedTargetIdRef.current !== targetId) {
        return;
      }
      setScanComparison(body);
      setBaselineScanId(body.baseline_scan_id);
      setComparisonScanId(body.comparison_scan_id);
      setRiskMessage("Latest-vs-previous comparison is ready.");
    } catch {
      if (selectedTargetIdRef.current !== targetId) {
        return;
      }
      setScanComparison(null);
      setRiskMessage("Latest comparison could not be loaded.");
    }
  }

  async function loadManualComparison() {
    if (!baselineScanId || !comparisonScanId || baselineScanId === comparisonScanId) {
      setRiskMessage("Choose two different completed scans for the same target.");
      return;
    }

    const requestTargetId = selectedTargetIdRef.current;
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${comparisonScanId}/comparison?baseline_scan_id=${encodeURIComponent(baselineScanId)}`);
      const body = await readJson<ScanComparison>(response, "Scan comparison failed.");
      if (selectedTargetIdRef.current !== requestTargetId) {
        return;
      }
      setScanComparison(body);
      setRiskMessage("Manual scan comparison is ready.");
    } catch (error) {
      if (selectedTargetIdRef.current !== requestTargetId) {
        return;
      }
      setScanComparison(null);
      setRiskMessage(error instanceof Error ? error.message : "Scan comparison failed.");
    }
  }

  async function loadAuthProfiles(preferredAuthProfileId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/auth-profiles?limit=200`);
    const page = await readPage<AuthProfile>(response, "Auth profile list load failed.");
    setAuthProfiles(page.items);
    const requestedProfileId = preferredAuthProfileId ?? selectedAuthProfileId;
    const nextProfileId = page.items.some((profile) => profile.id === requestedProfileId) ? requestedProfileId : page.items[0]?.id ?? "";
    setSelectedAuthProfileId(nextProfileId);
    setBootstrapError("");
  }

  async function loadScanHistory(preferredScanId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/scans?limit=200`);
    const page = await readPage<Scan>(response, "Scan history load failed.");
    setScanHistory(page.items);
    const requestedScanId = preferredScanId ?? selectedScanId;
    const nextScanId = page.items.some((scan) => scan.id === requestedScanId) ? requestedScanId : page.items[0]?.id ?? "";
    setSelectedScanId(nextScanId);
    setBootstrapError("");
  }

  async function loadTags(preferredTagId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/tags?limit=200`);
    const page = await readPage<Tag>(response, "Tag list load failed.");
    setTags(page.items);
    setTagFilter(preferredTagId ?? tagFilter);
    setBootstrapError("");
  }

  async function loadFindings(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const params = findingFilterParams();
      const query = params.toString();
      const endpoint = findingScope === "workspace" ? `${apiBaseUrl}/findings` : `${apiBaseUrl}/scans/${scanId}/findings`;
      const response = await apiFetch(`${endpoint}${query ? `?${query}` : ""}`);
      if (!response.ok) {
        if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
          return;
        }
        setFindings([]);
        return;
      }
      const body = ((await response.json()) as { items: Finding[] }).items;
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setFindings(body);
      setSelectedFindingId((current) => {
        return body.some((finding) => finding.id === current) ? current : body[0]?.id ?? "";
      });
    } catch {
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setFindings([]);
    }
  }

  function findingFilterParams() {
    const params = new URLSearchParams();
    params.set("limit", "200");
    if (findingScope === "workspace") {
      if (targetFilter) {
        params.set("target_id", targetFilter);
      }
      if (profileFilter) {
        params.set("scan_profile_id", profileFilter);
      }
    }
    if (severityFilter !== "all") {
      params.set("severity", severityFilter);
    }
    if (lifecycleFilter !== "all") {
      params.set("lifecycle_status", lifecycleFilter);
    }
    if (suppressionFilter === "active") {
      params.set("suppressed", "true");
    } else if (suppressionFilter === "not_suppressed") {
      params.set("suppressed", "false");
    }
    if (confidenceFilter !== "all") {
      params.set("confidence", confidenceFilter);
    }
    if (scannerFilter.trim()) {
      params.set("scanner", scannerFilter.trim());
    }
    if (owaspFilter.trim()) {
      params.set("owasp", owaspFilter.trim());
    }
    if (cweFilter.trim()) {
      params.set("cwe", cweFilter.trim());
    }
    if (tagFilter) {
      params.set("tag_id", tagFilter);
    }
    if (dateAfterFilter) {
      params.set("created_after", dateTimeLocalToIso(dateAfterFilter));
    }
    if (dateBeforeFilter) {
      params.set("created_before", dateTimeLocalToIso(dateBeforeFilter));
    }
    if (riskMinFilter.trim()) {
      params.set("risk_min", riskMinFilter.trim());
    }
    if (riskMaxFilter.trim()) {
      params.set("risk_max", riskMaxFilter.trim());
    }
    return params;
  }

  async function updateFindingLifecycle(findingId: string, lifecycleStatus: string) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/findings/${findingId}/lifecycle`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lifecycle_status: lifecycleStatus })
      });
      await readJson<Finding>(response, "Finding lifecycle update failed.");
      if (selectedScanIdRef.current) {
        await loadFindings(selectedScanIdRef.current, { onlyIfSelected: true });
      }
      setMessage("Finding lifecycle updated.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Finding lifecycle update failed.");
    }
  }

  async function suppressFinding(finding: Finding) {
    if (!finding.target_id || !suppressionReason.trim()) {
      return;
    }
    try {
      const response = await apiFetch(`${apiBaseUrl}/suppressions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: finding.target_id,
          dedupe_key: finding.dedupe_key,
          severity: finding.severity,
          source_tool: finding.source_tool,
          reason: suppressionReason.trim()
        })
      });
      await readJson<unknown>(response, "Suppression rule creation failed.");
      setSuppressionReason("");
      if (selectedScanIdRef.current) {
        await loadFindings(selectedScanIdRef.current, { onlyIfSelected: true });
      }
      setMessage("Finding suppression saved.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Suppression rule creation failed.");
    }
  }

  async function createTag() {
    if (!tagLabel.trim()) {
      return;
    }
    try {
      const response = await apiFetch(`${apiBaseUrl}/tags`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: tagLabel.trim() })
      });
      const tag = await readJson<Tag>(response, "Tag creation failed.");
      setTagLabel("");
      await loadTags(tag.id);
      setMessage("Tag created.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Tag creation failed.");
    }
  }

  async function assignTag() {
    const resourceId = tagResourceType === "scan" ? selectedFinding?.scan_id : selectedFinding?.target_id;
    if (!tagFilter || !resourceId) {
      return;
    }
    try {
      const response = await apiFetch(`${apiBaseUrl}/tags/assignments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tag_id: tagFilter,
          resource_type: tagResourceType,
          resource_id: resourceId
        })
      });
      await readJson<unknown>(response, "Tag assignment failed.");
      if (selectedScanIdRef.current) {
        await loadFindings(selectedScanIdRef.current, { onlyIfSelected: true });
      }
      setMessage("Tag assigned.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Tag assignment failed.");
    }
  }

  async function loadReports(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${scanId}/reports?limit=200`);
      if (!response.ok) {
        if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
          return;
        }
        setReports([]);
        return;
      }
      const body = ((await response.json()) as { items: ReportArtifact[] }).items;
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setReports(body);
      setReportMessage(body.length > 0 ? "Reports are ready." : "Generate Markdown and HTML reports for this completed scan.");
    } catch {
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setReports([]);
    }
  }

  async function loadToolRuns(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${scanId}/tool-runs?limit=200`);
      const page = await readPage<ScannerToolRun>(response, "Scanner receipts could not be loaded.");
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setToolRuns(page.items);
    } catch {
      if (!options.onlyIfSelected || selectedScanIdRef.current === scanId) {
        setToolRuns([]);
      }
    }
  }

  async function loadAiExplanation(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${scanId}/ai-explanations`);
      if (!response.ok) {
        if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
          return;
        }
        setAiExplanation(null);
        setAiMessage("AI explanations are available after this passive or Active Demo scan completes.");
        return;
      }
      const body = (await response.json()) as AiExplanation;
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setAiExplanation(body);
      setAiMessage(body.fallback_used ? "Template fallback explanation is ready." : "AI explanations are ready.");
    } catch {
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setAiExplanation(null);
      setAiMessage("AI explanations could not be loaded.");
    }
  }

  async function generateReports() {
    if (!selectedScan) {
      return;
    }
    setIsGeneratingReports(true);
    setReportMessage("Generating Markdown and HTML reports...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${selectedScan.id}/reports`, { method: "POST" });
      const page = await readPage<ReportArtifact>(response, "Report generation failed.");
      setReports(page.items);
      setReportMessage("Reports are ready.");
    } catch (error) {
      setReportMessage(error instanceof Error ? error.message : "Report generation failed.");
    } finally {
      setIsGeneratingReports(false);
    }
  }

  async function viewReport(report: ReportArtifact) {
    try {
      const response = await apiFetch(`${apiOrigin}${report.view_url}`);
      if (!response.ok) {
        await readJson<never>(response, "Report view failed.");
      }
      const content = await response.text();
      const mediaType = report.report_type === "html" ? "text/html" : "text/markdown";
      const url = window.URL.createObjectURL(new Blob([content], { type: mediaType }));
      window.open(url, "_blank", "noopener,noreferrer");
    } catch (error) {
      setReportMessage(error instanceof Error ? error.message : "Report view failed.");
    }
  }

  async function downloadReport(report: ReportArtifact) {
    try {
      const response = await apiFetch(`${apiOrigin}${report.download_url}`);
      if (!response.ok) {
        await readJson<never>(response, "Report download failed.");
      }
      const content = await response.text();
      const extension = report.report_type === "html" ? "html" : "md";
      const url = window.URL.createObjectURL(new Blob([content], { type: "application/octet-stream" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `scan-${report.scan_id}-report.${extension}`;
      anchor.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setReportMessage(error instanceof Error ? error.message : "Report download failed.");
    }
  }

  function renderFindingsDashboard() {
    return (
      <FindingsDashboard
        findings={filteredFindings}
        selectedFinding={selectedFinding}
        severityFilter={severityFilter}
        lifecycleFilter={lifecycleFilter}
        suppressionFilter={suppressionFilter}
        confidenceFilter={confidenceFilter}
        scannerFilter={scannerFilter}
        owaspFilter={owaspFilter}
        cweFilter={cweFilter}
        tagFilter={tagFilter}
        dateAfterFilter={dateAfterFilter}
        dateBeforeFilter={dateBeforeFilter}
        riskMinFilter={riskMinFilter}
        riskMaxFilter={riskMaxFilter}
        findingScope={findingScope}
        targetFilter={targetFilter}
        profileFilter={profileFilter}
        targets={targets}
        scanProfiles={SCAN_PROFILES}
        tags={tags}
        tagLabel={tagLabel}
        tagResourceType={tagResourceType}
        suppressionReason={suppressionReason}
        onSeverityFilter={setSeverityFilter}
        onLifecycleFilter={setLifecycleFilter}
        onSuppressionFilter={setSuppressionFilter}
        onConfidenceFilter={setConfidenceFilter}
        onScannerFilter={setScannerFilter}
        onOwaspFilter={setOwaspFilter}
        onCweFilter={setCweFilter}
        onTagFilter={setTagFilter}
        onDateAfterFilter={setDateAfterFilter}
        onDateBeforeFilter={setDateBeforeFilter}
        onRiskMinFilter={setRiskMinFilter}
        onRiskMaxFilter={setRiskMaxFilter}
        onFindingScope={setFindingScope}
        onTargetFilter={setTargetFilter}
        onProfileFilter={setProfileFilter}
        onTagLabelChange={setTagLabel}
        onTagResourceTypeChange={setTagResourceType}
        onCreateTag={createTag}
        onAssignTag={assignTag}
        onSelectFinding={setSelectedFindingId}
        onUpdateLifecycle={updateFindingLifecycle}
        onSuppressionReasonChange={setSuppressionReason}
        onSuppressFinding={suppressFinding}
      />
    );
  }

  const phaseComplete: Record<AuditPhase, boolean> = {
    ready: platformReady,
    scope: Boolean(selectedTarget),
    profile: profileReady,
    authorize: authorizationReady,
    run: Boolean(selectedScan && terminalStatuses.has(selectedScan.status)),
    review: reviewReady && findings.length > 0
  };

  return (
    <section className="dashboard" aria-label="ScopeHarbor workspace">
      <div className="workspaceUtilityBar">
        <span><AppIcon name={workspaceViews.find((view) => view.id === activeView)?.icon ?? "overview"} size={16} />{workspaceViews.find((view) => view.id === activeView)?.description}</span>
        <button className="refreshButton" type="button" onClick={refreshWorkspace} disabled={isRefreshing}>
          <AppIcon name="refresh" size={16} />
          {isRefreshing ? "Refreshing…" : "Refresh workspace"}
        </button>
      </div>

      {bootstrapError ? (
        <div className="statusBanner statusBannerError" role="alert">
          {bootstrapError}
        </div>
      ) : null}

      <div id="workspace-panel" className="workspaceTabPanel">
        {activeView === "overview" ? (
          <WorkspaceOverview
            overview={dashboardOverview}
            health={platformHealth}
            selectedScan={selectedScan}
            selectedTarget={selectedTarget}
            onNavigate={(view) => onActiveViewChange(view as WorkspaceView)}
          />
        ) : null}

        {activeView === "scanning" ? (
          <div className="auditWorkspace">
            <div className="viewIntro">
              <div><h2>Run a guided security audit</h2><p>Move from readiness to review without losing sight of scope, safety, or the next decision.</p></div>
              <span className="safetyPill"><AppIcon name="shield" size={15} /> Public URLs remain blocked</span>
            </div>

            <nav className="auditPhaseTabs" role="tablist" aria-label="Audit phases">
              {auditPhases.map((phase, index) => {
                const isActive = auditPhase === phase.id;
                const isComplete = phaseComplete[phase.id] && !isActive;
                const isPriority = phase.id === "profile" || phase.id === "review";
                return (
                  <button
                    key={phase.id}
                    type="button"
                    role="tab"
                    aria-selected={isActive}
                    aria-controls="audit-phase-panel"
                    className={`auditPhaseTab${isActive ? " auditPhaseTabActive" : ""}${isComplete ? " auditPhaseTabComplete" : ""}${isPriority ? " auditPhaseTabPriority" : ""}`}
                    onClick={() => setAuditPhase(phase.id)}
                    onKeyDown={(event) => handlePhaseKeyDown(event, index)}
                  >
                    <span className="auditPhaseMarker">{isComplete ? <AppIcon name="check" size={15} /> : <AppIcon name={phase.icon} size={16} />}</span>
                    <span><strong>{phase.label}</strong><small>{phase.description}</small></span>
                  </button>
                );
              })}
            </nav>

            <div id="audit-phase-panel" className="auditPhasePanel" role="tabpanel" tabIndex={0}>
              {auditPhase === "ready" ? (
                <div className="auditPhaseContent">
                  <div className="phaseHeading">
                    <div><span>Before you scope an audit</span><h3>Confirm the local platform is ready</h3><p>The database, worker, queue, scanner dependencies, and artifact storage must be visible before launch.</p></div>
                    <span className={platformReady ? "readinessState readinessStateReady" : "readinessState"}><span className="statusDot" />{platformReady ? "Ready to audit" : "Needs attention"}</span>
                  </div>
                  <OpsHealthPanel health={platformHealth} message={opsMessage} onRefresh={loadPlatformHealth} />
                  <div className="boundaryStrip" aria-label="Persistent platform boundaries">
                    <span><AppIcon name="target" size={16} /><strong>Exact targets</strong> only</span>
                    <span><AppIcon name="shield" size={16} /><strong>Workspace context</strong> rechecked</span>
                    <span><AppIcon name="operations" size={16} /><strong>Bounded tools</strong> with safe receipts</span>
                  </div>
                  <div className="phaseFooter"><span>{platformReady ? "All required components report healthy." : "Resolve degraded components, then refresh readiness."}</span><button type="button" onClick={() => setAuditPhase("scope")} disabled={!platformReady}>Continue to scope <AppIcon name="arrow" size={15} /></button></div>
                </div>
              ) : null}

              {auditPhase === "scope" ? (
                <div className="auditPhaseContent">
                  <div className="phaseHeading"><div><span>Authorized scope</span><h3>Choose a saved target or validate a new one</h3><p>Every audit starts from an exact allowlist entry. A local repository path remains attached to its saved target.</p></div></div>
                  <div className="targetManagementGrid">
                    <TargetLibrary
                      targets={targets}
                      selectedTargetId={selectedTargetId}
                      isBusy={isBusy}
                      onSelectTarget={(targetId) => {
                        setSelectedTargetId(targetId);
                        setAcknowledgements([]);
                      }}
                      onRequestArchive={setArchiveCandidate}
                    />
                    <TargetForm
                      targetUrl={targetUrl}
                      repoPath={repoPath}
                      permissionConfirmed={permissionConfirmed}
                      validation={validation}
                      message={message}
                      isBusy={isBusy}
                      canCreate={canCreate}
                      onTargetUrlChange={(value) => {
                        setTargetUrl(value);
                        setValidation(null);
                        setPermissionConfirmed(false);
                      }}
                      onRepoPathChange={setRepoPath}
                      onPermissionChange={setPermissionConfirmed}
                      onValidate={validateTarget}
                      onCreateTarget={createTarget}
                    />
                  </div>
                  <div className="phaseFooter"><span>{selectedTarget ? `${selectedTarget.name} is selected as the audit scope.` : "Select or save one allowlisted target to continue."}</span><button type="button" onClick={() => setAuditPhase("profile")} disabled={!selectedTarget}>Choose an audit profile <AppIcon name="arrow" size={15} /></button></div>
                </div>
              ) : null}

              {auditPhase === "profile" ? (
                <div className="auditPhaseContent auditPhaseContentPriority">
                  <ScanProfileSelector
                    targets={targets}
                    selectedTargetId={selectedTargetId}
                    repoPath={repoPath}
                    scanProfileId={scanProfileId}
                    isBusy={isBusy}
                    onSelectTarget={(targetId) => {
                      setSelectedTargetId(targetId);
                      setAcknowledgements([]);
                    }}
                    onSelectScanProfile={(profileId) => {
                      setScanProfileId(profileId);
                      setAcknowledgements([]);
                    }}
                    onAttachRepoPath={updateSelectedTargetRepoPath}
                    onContinue={() => setAuditPhase("authorize")}
                  />
                </div>
              ) : null}

              {auditPhase === "authorize" ? (
                <div className="auditPhaseContent">
                  <ScanAuthorization
                    target={selectedTarget}
                    scanProfileId={scanProfileId}
                    acknowledgements={acknowledgements}
                    profileReady={profileReady}
                    onAcknowledgementChange={(code, acknowledged) => {
                      setAcknowledgements((current) => acknowledged ? [...new Set([...current, code])] : current.filter((value) => value !== code));
                    }}
                    onOpenCredentials={() => onActiveViewChange("credentials")}
                    onContinue={() => setAuditPhase("run")}
                  />
                </div>
              ) : null}

              {auditPhase === "run" ? (
                <div className="auditPhaseContent">
                  <ScanLaunchPanel
                    target={selectedTarget}
                    scanProfileId={scanProfileId}
                    canStartScan={canStartScan}
                    platformReady={platformReady}
                    isBusy={isBusy}
                    onStartScan={startScan}
                  />
                  <div className="runWorkspaceGrid">
                    {selectedScan ? <ScanProgress scan={selectedScan} toolRuns={toolRuns} isCancelling={isCancellingScan} onCancel={cancelSelectedScan} /> : <div className="emptyState richEmptyState"><AppIcon name="activity" size={24} /><strong>No scan selected</strong><span>Launch this audit or choose a historical scan to monitor it.</span></div>}
                    <ScanHistory scans={scanHistory} selectedScanId={selectedScanId} onSelectScan={setSelectedScanId} />
                  </div>
                  <div className="phaseFooter"><span>{reviewReady ? "Normalized results are ready for triage." : "Review unlocks after a scan completes or completes with warnings."}</span><button type="button" onClick={() => setAuditPhase("review")} disabled={!reviewReady}>Review findings <AppIcon name="arrow" size={15} /></button></div>
                </div>
              ) : null}

              {auditPhase === "review" ? (
                <div className="auditPhaseContent auditPhaseContentPriority">
                  <div className="phaseHeading reviewPhaseHeading">
                    <div><span>Normalized evidence</span><h3>Turn scanner output into decisions</h3><p>Triage lifecycle, suppression, and tags here, then generate sanitized reports or bounded explanations when the profile supports them.</p></div>
                    <div className="viewToolbarActions">
                      <label className="searchField"><AppIcon name="search" size={17} /><span className="srOnly">Search loaded findings</span><input value={findingSearchQuery} onChange={(event) => setFindingSearchQuery(event.target.value)} placeholder="Search finding, tool, URL, CWE…" /></label>
                      <button type="button" className="secondaryButton" onClick={resetFindingFilters}>Reset filters</button>
                    </div>
                  </div>
                  {reviewReady ? renderFindingsDashboard() : <div className="emptyState richEmptyState"><AppIcon name="finding" size={24} /><strong>No completed audit selected</strong><span>Choose a completed scan in Run to review its normalized findings.</span><button type="button" onClick={() => setAuditPhase("run")}>Open scan history</button></div>}
                  <div className="reviewOutputs">
                    <ReportsPanel scan={selectedScan} reports={reports} message={reportMessage} isGenerating={isGeneratingReports} onGenerate={generateReports} onViewReport={viewReport} onDownloadReport={downloadReport} />
                    <AiExplanationsPanel explanation={displayAiExplanation} message={aiMessage} />
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        {activeView === "findings" ? (
          <div className="findingsWorkspace">
            <div className="viewToolbar">
              <div><p className="panelKicker">Normalized evidence</p><h3>Finding triage</h3></div>
              <div className="viewToolbarActions">
                <label className="searchField">
                  <AppIcon name="search" size={17} />
                  <span className="srOnly">Search loaded findings</span>
                  <input value={findingSearchQuery} onChange={(event) => setFindingSearchQuery(event.target.value)} placeholder="Search finding, tool, URL, CWE…" />
                </label>
                <button type="button" className="secondaryButton" onClick={resetFindingFilters}>Reset filters</button>
              </div>
            </div>
            {renderFindingsDashboard()}
          </div>
        ) : null}

        {activeView === "intelligence" ? (
          <div className="intelligenceWorkspace">
            <div className="viewIntro"><div><p className="panelKicker">Decision support</p><h3>Risk intelligence</h3><p>Compare security posture, generate sanitized reports, and review bounded explanations.</p></div></div>
            <RiskDashboardPanel
              overview={dashboardOverview}
              targetDashboard={targetDashboard}
              targets={targets}
              scans={scanHistory}
              selectedTargetId={selectedTargetId}
              baselineScanId={baselineScanId}
              comparisonScanId={comparisonScanId}
              comparison={scanComparison}
              message={riskMessage}
              onBaselineScanChange={setBaselineScanId}
              onComparisonScanChange={setComparisonScanId}
              onCompare={loadManualComparison}
            />
            <div className="intelligenceGrid">
              <ReportsPanel
                scan={selectedScan}
                reports={reports}
                message={reportMessage}
                isGenerating={isGeneratingReports}
                onGenerate={generateReports}
                onViewReport={viewReport}
                onDownloadReport={downloadReport}
              />
              <AiExplanationsPanel explanation={displayAiExplanation} message={aiMessage} />
            </div>
          </div>
        ) : null}

        {activeView === "credentials" ? (
          <div className="credentialWorkspace">
            <div className="viewIntro">
              <div><p className="panelKicker">Encrypted target access</p><h3>Credential profiles</h3><p>Manage target-application secrets used only by guarded passive requests. Secret values never return through the API.</p></div>
              <span className="safetyPill"><AppIcon name="credential" size={15} /> Fernet encrypted</span>
            </div>
            <AuthProfilesPanel
              authProfiles={authProfiles}
              selectedTarget={selectedTarget}
              selectedAuthProfileId={selectedAuthProfileId}
              label={authProfileLabel}
              profileType={authProfileType}
              headerName={authProfileHeaderName}
              secret={authProfileSecret}
              message={authProfileMessage}
              isBusy={isBusy}
              onSelectAuthProfile={setSelectedAuthProfileId}
              onLabelChange={setAuthProfileLabel}
              onProfileTypeChange={setAuthProfileType}
              onHeaderNameChange={setAuthProfileHeaderName}
              onSecretChange={setAuthProfileSecret}
              onCreateProfile={createAuthProfile}
              onAttachProfile={updateSelectedTargetAuthProfile}
              onRotateProfile={rotateSelectedAuthProfile}
              onRevokeProfile={() => {
                const profile = authProfiles.find((item) => item.id === selectedAuthProfileId);
                if (profile) {
                  setRevokeCandidate(profile);
                }
              }}
            />
          </div>
        ) : null}

        {activeView === "operations" ? (
          <div className="operationsWorkspace">
            <div className="viewIntro"><div><p className="panelKicker">Local platform</p><h3>Operations & readiness</h3><p>Confirm the worker, database, artifacts, queue, and scanner dependencies before running an audit.</p></div></div>
            <OpsHealthPanel health={platformHealth} message={opsMessage} onRefresh={loadPlatformHealth} />
            <div className="boundaryGrid">
              <article><AppIcon name="target" /><strong>Exact target scope</strong><p>Only explicitly configured Docker-service targets can be launched.</p></article>
              <article><AppIcon name="shield" /><strong>Safe persistence</strong><p>URLs and evidence are sanitized before database, report, or AI boundaries.</p></article>
              <article><AppIcon name="operations" /><strong>Local ownership</strong><p>Workspace records and generated artifacts stay isolated inside this deployment.</p></article>
            </div>
          </div>
        ) : null}
      </div>

      {archiveCandidate ? (
        <ConfirmActionDialog
          eyebrow="Remove saved target"
          title={`Remove ${archiveCandidate.name}?`}
          description="The target will disappear from your active list and its attached credential and repository path will be cleared."
          note="Scan, finding, report, and audit history will be preserved."
          confirmLabel="Remove target"
          busyLabel="Removing…"
          icon="trash"
          isBusy={isBusy}
          onCancel={() => setArchiveCandidate(null)}
          onConfirm={archiveTarget}
        />
      ) : null}

      {revokeCandidate ? (
        <ConfirmActionDialog
          eyebrow="Revoke credential profile"
          title={`Revoke ${revokeCandidate.label}?`}
          description="The encrypted secret will be erased and this profile will be detached from every target."
          note="Historical metadata and existing scan snapshots remain unchanged."
          confirmLabel="Revoke profile"
          busyLabel="Revoking…"
          icon="credential"
          isBusy={isBusy}
          onCancel={() => setRevokeCandidate(null)}
          onConfirm={revokeSelectedAuthProfile}
        />
      ) : null}
    </section>
  );
}

function uniqueAiExplanation(explanation: AiExplanation | null, findings: Finding[]): AiExplanation | null {
  if (!explanation) {
    return null;
  }

  const canonicalFindingIdByKey = new Map<string, string>();
  const findingKeyById = new Map<string, string>();
  for (const finding of findings) {
    const key = finding.dedupe_key || finding.id;
    findingKeyById.set(finding.id, key);
    if (!canonicalFindingIdByKey.has(key)) {
      canonicalFindingIdByKey.set(key, finding.id);
    }
  }

  const keptExplanationKeys = new Set<string>();
  const keptFindingIds = new Set<string>();
  const explanations = explanation.explanations.filter((item) => {
    const key = explanationSignature(item);
    if (keptExplanationKeys.has(key)) {
      return false;
    }
    keptExplanationKeys.add(key);
    keptFindingIds.add(item.finding_id);
    return true;
  });

  const groups = explanation.groups.map((group) => {
    const ids: string[] = [];
    const seenKeys = new Set<string>();
    for (const findingId of group.finding_ids) {
      if (!keptFindingIds.has(findingId)) {
        continue;
      }
      const key = findingKeyById.get(findingId) ?? findingId;
      if (seenKeys.has(key)) {
        continue;
      }
      seenKeys.add(key);
      ids.push(canonicalFindingIdByKey.get(key) ?? findingId);
    }
    return { ...group, count: ids.length, finding_ids: ids };
  }).filter((group) => group.count > 0);

  return { ...explanation, groups, explanations };
}

function dateTimeLocalToIso(value: string) {
  return new Date(value).toISOString();
}

function explanationSignature(item: AiExplanation["explanations"][number]): string {
  return [item.summary, item.recommended_action, item.owasp_mapping, item.limitations].map(normalizeExplanationText).join("|");
}

function normalizeExplanationText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}
