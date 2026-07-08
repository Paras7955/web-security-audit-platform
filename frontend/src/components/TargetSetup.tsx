"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import { AiExplanationsPanel } from "@/components/dashboard/AiExplanationsPanel";
import { AuthProfilesPanel } from "@/components/dashboard/AuthProfilesPanel";
import { FindingsDashboard, severityRank } from "@/components/dashboard/FindingsDashboard";
import { ReportsPanel } from "@/components/dashboard/ReportsPanel";
import { RiskDashboardPanel } from "@/components/dashboard/RiskDashboardPanel";
import {
  ScanHistory,
  ScanLauncher,
  ScanProgress,
  canUseAi,
  canUseReports,
  mergeScan,
  terminalStatuses
} from "@/components/dashboard/ScanControls";
import { SCAN_PROFILES } from "@/lib/contracts";
import { TargetForm } from "@/components/dashboard/TargetForm";
import {
  AiExplanation,
  AuthProfile,
  DashboardOverview,
  Finding,
  ReportArtifact,
  ScanComparison,
  Scan,
  Tag,
  Target,
  TargetDashboard,
  ValidationResult,
  apiBaseUrl,
  apiFetch,
  readJson
} from "@/lib/securityAuditApi";

export function TargetSetup() {
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
  const [activeDemoAcknowledged, setActiveDemoAcknowledged] = useState(false);
  const [ajaxShortAcknowledged, setAjaxShortAcknowledged] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [reports, setReports] = useState<ReportArtifact[]>([]);
  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [dashboardOverview, setDashboardOverview] = useState<DashboardOverview | null>(null);
  const [targetDashboard, setTargetDashboard] = useState<TargetDashboard | null>(null);
  const [scanComparison, setScanComparison] = useState<ScanComparison | null>(null);
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
  const [bootstrapError, setBootstrapError] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  const [isGeneratingReports, setIsGeneratingReports] = useState(false);
  const selectedScanIdRef = useRef("");
  const selectedTargetIdRef = useRef("");

  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedScan = scanHistory.find((scan) => scan.id === selectedScanId) ?? null;
  const selectedProfile = SCAN_PROFILES.find((profile) => profile.id === scanProfileId) ?? SCAN_PROFILES[0];
  const canCreate = useMemo(() => Boolean(validation && permissionConfirmed && !isBusy), [validation, permissionConfirmed, isBusy]);
  const canStartScan = Boolean(
    selectedTarget &&
      selectedTarget.allowed_modes.includes(selectedProfile.mode) &&
      !isBusy &&
      (!selectedProfile.requires_repo_path || Boolean(selectedTarget.repo_path)) &&
      (!selectedTarget.auth_profile_id || selectedProfile.mode === "passive") &&
      (!selectedProfile.requires_active_demo_acknowledgement || activeDemoAcknowledged) &&
      (!selectedProfile.requires_ajax_short_acknowledgement || ajaxShortAcknowledged)
  );
  const displayFindings = findings;
  const displayAiExplanation = useMemo(() => uniqueAiExplanation(aiExplanation, findings), [aiExplanation, findings]);
  const filteredFindings = useMemo(() => {
    return [...displayFindings].sort((left, right) => (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0));
  }, [displayFindings]);
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
      setAiExplanation(null);
      setSelectedFindingId("");
      return;
    }
    void loadFindings(selectedScanId, { onlyIfSelected: true });
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
    selectedScan?.mode,
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
    const results = await Promise.allSettled([loadTargets(), loadAuthProfiles(), loadScanHistory(), loadDashboardOverview(), loadTags()]);
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
          active_demo_acknowledged: activeDemoAcknowledged,
          ajax_short_acknowledged: ajaxShortAcknowledged
        })
      });
      const scan = await readJson<Scan>(response, "Scan creation failed.");
      setSelectedScanId(scan.id);
      setFindings([]);
      setReports([]);
      setAiExplanation(null);
      setSelectedFindingId("");
      setReportMessage("Reports are available after this passive, Active Demo, or Repo scan completes.");
      setAiMessage("AI explanations are available after this passive or Active Demo scan completes.");
      setMessage("Scan queued. Worker status will update below.");
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

  async function loadTargets(preferredTargetId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/targets`);
    const body = await readJson<Target[]>(response, "Target list load failed.");
    setTargets(body);
    setSelectedTargetId(preferredTargetId ?? selectedTargetId ?? body[0]?.id ?? "");
    setBootstrapError("");
  }

  async function loadDashboardOverview() {
    const response = await apiFetch(`${apiBaseUrl}/dashboard/overview`);
    const body = await readJson<DashboardOverview>(response, "Dashboard overview load failed.");
    setDashboardOverview(body);
    setBootstrapError("");
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
    const response = await apiFetch(`${apiBaseUrl}/auth-profiles`);
    const body = await readJson<AuthProfile[]>(response, "Auth profile list load failed.");
    setAuthProfiles(body);
    setSelectedAuthProfileId(preferredAuthProfileId ?? selectedAuthProfileId ?? body[0]?.id ?? "");
    setBootstrapError("");
  }

  async function loadScanHistory(preferredScanId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/scans`);
    const body = await readJson<Scan[]>(response, "Scan history load failed.");
    setScanHistory(body);
    setSelectedScanId(preferredScanId ?? selectedScanId ?? body[0]?.id ?? "");
    setBootstrapError("");
  }

  async function loadTags(preferredTagId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/tags`);
    const body = await readJson<Tag[]>(response, "Tag list load failed.");
    setTags(body);
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
      const body = (await response.json()) as Finding[];
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
    const resourceId = tagResourceType === "scan" ? selectedScanId : selectedTargetId;
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
      const response = await apiFetch(`${apiBaseUrl}/scans/${scanId}/reports`);
      if (!response.ok) {
        if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
          return;
        }
        setReports([]);
        return;
      }
      const body = (await response.json()) as ReportArtifact[];
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
      setReports(await readJson<ReportArtifact[]>(response, "Report generation failed."));
      setReportMessage("Reports are ready.");
    } catch (error) {
      setReportMessage(error instanceof Error ? error.message : "Report generation failed.");
    } finally {
      setIsGeneratingReports(false);
    }
  }

  async function viewReport(report: ReportArtifact) {
    try {
      const response = await apiFetch(`${apiBaseUrl}${report.view_url}`);
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
      const response = await apiFetch(`${apiBaseUrl}${report.download_url}`);
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

  return (
    <section className="dashboard" aria-labelledby="dashboard-heading">
      <div className="sectionHeader">
        <div>
          <p className="eyebrow">Workspace Console</p>
          <h2 id="dashboard-heading">Run authorized scans, review normalized findings, and manage reportable evidence</h2>
        </div>
        <span className="phaseBadge">Profiles + auth</span>
      </div>

      {bootstrapError ? (
        <div className="statusBanner statusBannerError" role="alert">
          {bootstrapError}
        </div>
      ) : null}

      <div className="dashboardGrid" id="targets">
        <div className="workflowPanel">
          <TargetForm
            targetUrl={targetUrl}
            repoPath={repoPath}
            permissionConfirmed={permissionConfirmed}
            validation={validation}
            message={message}
            isBusy={isBusy}
            canCreate={canCreate}
            onTargetUrlChange={setTargetUrl}
            onRepoPathChange={setRepoPath}
            onPermissionChange={setPermissionConfirmed}
            onValidate={validateTarget}
            onCreateTarget={createTarget}
          />
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
          />
          <ScanLauncher
            targets={targets}
            selectedTargetId={selectedTargetId}
            repoPath={repoPath}
            scanProfileId={scanProfileId}
            activeDemoAcknowledged={activeDemoAcknowledged}
            ajaxShortAcknowledged={ajaxShortAcknowledged}
            canStartScan={canStartScan}
            isBusy={isBusy}
            onSelectTarget={setSelectedTargetId}
            onSelectScanProfile={setScanProfileId}
            onAttachRepoPath={updateSelectedTargetRepoPath}
            onActiveDemoAcknowledged={setActiveDemoAcknowledged}
            onAjaxShortAcknowledged={setAjaxShortAcknowledged}
            onStartScan={startScan}
          />
        </div>

        <div id="scans">
          <ScanHistory scans={scanHistory} selectedScanId={selectedScanId} onSelectScan={setSelectedScanId} />
        </div>
      </div>

      {selectedScan ? <ScanProgress scan={selectedScan} /> : null}

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

      <div id="reports">
        <ReportsPanel
          scan={selectedScan}
          reports={reports}
          message={reportMessage}
          isGenerating={isGeneratingReports}
          onGenerate={generateReports}
          onViewReport={viewReport}
          onDownloadReport={downloadReport}
        />
      </div>

      <AiExplanationsPanel explanation={displayAiExplanation} message={aiMessage} />

      <div id="findings">
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
      </div>
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
