"use client";

/* eslint-disable react-hooks/exhaustive-deps, react-hooks/set-state-in-effect -- Async loaders reject stale responses with selected-resource refs. */

import { FormEvent, KeyboardEvent as ReactKeyboardEvent, useEffect, useMemo, useRef, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import { ConfirmActionDialog } from "@/components/ConfirmActionDialog";
import { AuditReviewSummary } from "@/components/dashboard/AuditReviewSummary";
import { FindingGuidancePanel } from "@/components/dashboard/FindingGuidancePanel";
import { AuditLogPanel } from "@/components/dashboard/AuditLogPanel";
import { AuthProfilesPanel } from "@/components/dashboard/AuthProfilesPanel";
import { FindingsDashboard, severityRank } from "@/components/dashboard/FindingsDashboard";
import { FindingGovernancePanel } from "@/components/dashboard/FindingGovernancePanel";
import { OpsHealthPanel } from "@/components/dashboard/OpsHealthPanel";
import { OperatorSessionPanel } from "@/components/dashboard/OperatorSessionPanel";
import { ProductGuide } from "@/components/dashboard/ProductGuide";
import { ReportsPanel } from "@/components/dashboard/ReportsPanel";
import { RepositoryAssetsPanel } from "@/components/dashboard/RepositoryAssetsPanel";
import { RiskDashboardPanel } from "@/components/dashboard/RiskDashboardPanel";
import {
  ScanHistory,
  ScanAuthorization,
  ScanLaunchPanel,
  ScanProfileSelector,
  ScanProgress,
  canUseAi,
  canUseReports,
  formatScanProfileLabel,
  mergeScan,
  terminalStatuses
} from "@/components/dashboard/ScanControls";
import { SCAN_PROFILES } from "@/lib/contracts";
import { TargetForm } from "@/components/dashboard/TargetForm";
import { TargetLibrary } from "@/components/dashboard/TargetLibrary";
import { TargetPolicyCatalog } from "@/components/dashboard/TargetPolicyCatalog";
import { WorkspaceOverview } from "@/components/dashboard/WorkspaceOverview";
import {
  AiExplanation,
  AuditSubject,
  AuditLogEntry,
  AuthProfile,
  DashboardOverview,
  Finding,
  PlatformHealth,
  ReportArtifact,
  RepositoryAsset,
  RepositoryDashboard,
  ScanComparison,
  Scan,
  ScannerToolRun,
  SuppressionRule,
  Tag,
  TagAssignment,
  Target,
  TargetDashboard,
  TargetPolicy,
  ValidationResult,
  apiBaseUrl,
  apiOrigin,
  aiExplanationRequest,
  apiFetch,
  readAllPages,
  readJson,
  readPage,
  scanLaunchPayload
} from "@/lib/securityAuditApi";

export const workspaceViews = [
  { id: "overview", label: "Workspace", description: "Workspace signal", icon: "overview" },
  { id: "scanning", label: "Audits", description: "Configure and launch", icon: "scan" },
  { id: "findings", label: "Findings", description: "Triage evidence", icon: "finding" },
  { id: "intelligence", label: "Intelligence", description: "Risk, reports & guidance", icon: "intelligence" },
  { id: "guide", label: "Guide", description: "Project and workflow guide", icon: "guide" }
] as const;

const contextualWorkspaceViews = [
  { id: "credentials", label: "Credentials", description: "Target auth profiles", icon: "credential" },
  { id: "operations", label: "Operations", description: "Platform readiness", icon: "operations" }
] as const;

const workspaceViewMetadata = [...workspaceViews, ...contextualWorkspaceViews];

export type WorkspaceView = (typeof workspaceViewMetadata)[number]["id"];

type AuditPhase = "ready" | "scope" | "profile" | "authorize" | "run" | "review";
type ActionFeedback = { tone: "info" | "success" | "error"; text: string };
type PendingReportAction = { reportId: string; action: "view" | "download" } | null;

const auditPhases: Array<{ id: AuditPhase; label: string; icon: "operations" | "target" | "scan" | "shield" | "activity" | "finding" }> = [
  { id: "ready", label: "Preflight", icon: "operations" },
  { id: "scope", label: "Scope", icon: "target" },
  { id: "profile", label: "Profile", icon: "scan" },
  { id: "authorize", label: "Authorize", icon: "shield" },
  { id: "run", label: "Run", icon: "activity" },
  { id: "review", label: "Review", icon: "finding" }
];

export function TargetSetup({
  activeView,
  onActiveViewChange,
  onPlatformStatusChange
}: {
  activeView: WorkspaceView;
  onActiveViewChange: (view: WorkspaceView) => void;
  onPlatformStatusChange: (status: string) => void;
}) {
  const [auditPhase, setAuditPhase] = useState<AuditPhase>("ready");
  const [targetUrl, setTargetUrl] = useState("http://juice-shop:3000");
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [repoPath, setRepoPath] = useState("/app/repositories/security-project");
  const [repositoryName, setRepositoryName] = useState("ScopeHarbor");
  const [repositoryPermissionConfirmed, setRepositoryPermissionConfirmed] = useState(false);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetPolicies, setTargetPolicies] = useState<TargetPolicy[]>([]);
  const [repositoryAssets, setRepositoryAssets] = useState<RepositoryAsset[]>([]);
  const [selectedRepositoryAssetId, setSelectedRepositoryAssetId] = useState("");
  const [selectedSubjectId, setSelectedSubjectId] = useState("");
  const [authProfiles, setAuthProfiles] = useState<AuthProfile[]>([]);
  const [selectedAuthProfileId, setSelectedAuthProfileId] = useState("");
  const [authProfileLabel, setAuthProfileLabel] = useState("");
  const [authProfileType, setAuthProfileType] = useState("bearer_token");
  const [authProfileHeaderName, setAuthProfileHeaderName] = useState("");
  const [authProfileSecret, setAuthProfileSecret] = useState("");
  const [authProfileRotationSecret, setAuthProfileRotationSecret] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanProfileId, setScanProfileId] = useState("passive-web");
  const [acknowledgements, setAcknowledgements] = useState<string[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [currentAuditScanId, setCurrentAuditScanId] = useState("");
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [toolRuns, setToolRuns] = useState<ScannerToolRun[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [governanceTags, setGovernanceTags] = useState<Tag[]>([]);
  const [suppressions, setSuppressions] = useState<SuppressionRule[]>([]);
  const [tagAssignments, setTagAssignments] = useState<TagAssignment[]>([]);
  const [reports, setReports] = useState<ReportArtifact[]>([]);
  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [dashboardOverview, setDashboardOverview] = useState<DashboardOverview | null>(null);
  const [targetDashboard, setTargetDashboard] = useState<TargetDashboard | null>(null);
  const [repositoryDashboard, setRepositoryDashboard] = useState<RepositoryDashboard | null>(null);
  const [scanComparison, setScanComparison] = useState<ScanComparison | null>(null);
  const [platformHealth, setPlatformHealth] = useState<PlatformHealth | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
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
  const [assignmentTagId, setAssignmentTagId] = useState("");
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
  const [repositoryMessage, setRepositoryMessage] = useState("Authorize a confined local repository path to save it as a scan subject.");
  const [authProfileMessage, setAuthProfileMessage] = useState("Create an optional target-app auth profile for passive scans.");
  const [reportMessage, setReportMessage] = useState("Reports are available after a passive, Active Demo, or Repo scan completes.");
  const [aiMessage, setAiMessage] = useState("Finding guidance is available after a passive or Active Demo scan completes.");
  const [riskMessage, setRiskMessage] = useState("Risk scores are generated for completed scans using risk-v1.");
  const [opsMessage, setOpsMessage] = useState("Platform health has not been loaded.");
  const [auditLogMessage, setAuditLogMessage] = useState("Workspace activity has not been loaded.");
  const [actionFeedback, setActionFeedback] = useState<ActionFeedback | null>(null);
  const [bootstrapError, setBootstrapError] = useState("");
  const [archiveCandidate, setArchiveCandidate] = useState<Target | null>(null);
  const [repositoryArchiveCandidate, setRepositoryArchiveCandidate] = useState<RepositoryAsset | null>(null);
  const [revokeCandidate, setRevokeCandidate] = useState<AuthProfile | null>(null);
  const [confirmActionError, setConfirmActionError] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  const [isBootstrapping, setIsBootstrapping] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isCheckingPlatform, setIsCheckingPlatform] = useState(false);
  const [isRefreshingActivity, setIsRefreshingActivity] = useState(false);
  const [isComparingScans, setIsComparingScans] = useState(false);
  const [isSuppressingFinding, setIsSuppressingFinding] = useState(false);
  const [updatingFindingId, setUpdatingFindingId] = useState("");
  const [isCreatingTag, setIsCreatingTag] = useState(false);
  const [isAssigningTag, setIsAssigningTag] = useState(false);
  const [governanceActionId, setGovernanceActionId] = useState("");
  const [isLoadingScanEvidence, setIsLoadingScanEvidence] = useState(false);
  const [isLoadingTargetRisk, setIsLoadingTargetRisk] = useState(false);
  const [isGeneratingReports, setIsGeneratingReports] = useState(false);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [pendingReportAction, setPendingReportAction] = useState<PendingReportAction>(null);
  const [isCancellingScan, setIsCancellingScan] = useState(false);
  const [platformHealthCheckedAt, setPlatformHealthCheckedAt] = useState("");
  const [auditLogCheckedAt, setAuditLogCheckedAt] = useState("");
  const selectedScanIdRef = useRef("");
  const selectedTargetIdRef = useRef("");
  const selectedRepositoryAssetIdRef = useRef("");
  const selectedSubjectIdRef = useRef("");
  const baselineScanIdRef = useRef("");
  const comparisonScanIdRef = useRef("");
  const findingsRequestIdRef = useRef(0);
  const auditPhaseTabsRef = useRef<HTMLElement>(null);
  const activeAuditPhaseRef = useRef<HTMLButtonElement>(null);

  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const auditSubjects = useMemo<AuditSubject[]>(() => [
    ...targets.map((target) => ({
      id: `web_target:${target.id}`,
      subjectType: "web_target" as const,
      name: target.name,
      detail: target.base_url,
      availableScanProfileIds: target.policy_status === "current" ? target.available_scan_profile_ids : [],
      target,
      repositoryAsset: null
    })),
    ...repositoryAssets.map((asset) => ({
      id: `repository_asset:${asset.id}`,
      subjectType: "repository_asset" as const,
      name: asset.name,
      detail: asset.relative_path,
      availableScanProfileIds: ["repository"],
      target: null,
      repositoryAsset: asset
    }))
  ], [repositoryAssets, targets]);
  const selectedAuditSubject = auditSubjects.find((subject) => subject.id === selectedSubjectId) ?? auditSubjects[0] ?? null;
  const selectedScan = scanHistory.find((scan) => scan.id === selectedScanId) ?? null;
  const currentAuditScan = scanHistory.find((scan) => scan.id === currentAuditScanId) ?? null;
  const selectedScanSubject = selectedScan ? auditSubjects.find((subject) =>
    subject.subjectType === selectedScan.subject_type &&
    (subject.target?.id === selectedScan.target_id || subject.repositoryAsset?.id === selectedScan.repository_asset_id)
  ) ?? null : null;
  const selectedProfile = SCAN_PROFILES.find((profile) => profile.id === scanProfileId) ?? SCAN_PROFILES[0];
  const platformReady = platformHealth?.status === "ok";
  const selectedProfileRequiresZap = Boolean(
    selectedAuditSubject?.target?.zap_required_scan_profile_ids.includes(selectedProfile.id)
  );
  const scanDependenciesReady = Boolean(
    platformReady && (!selectedProfileRequiresZap || platformHealth?.zap.status === "ok")
  );
  const scanReadinessMessage = selectedProfileRequiresZap && platformHealth?.zap.status !== "ok"
    ? "This target policy requires the ZAP web scanner for the selected profile. Restore worker-reported ZAP readiness, then run Preflight again."
    : "Confirm core platform readiness before launch. Run Preflight again after the worker and database are healthy.";
  const canCreate = useMemo(() => Boolean(validation && permissionConfirmed && !isBusy), [validation, permissionConfirmed, isBusy]);
  const profileReady = Boolean(
    selectedAuditSubject &&
      selectedAuditSubject.availableScanProfileIds.includes(selectedProfile.id) &&
      (!selectedAuditSubject.target?.auth_profile_id || selectedProfile.mode === "passive")
  );
  const authorizationReady = Boolean(
    profileReady &&
      selectedProfile.required_acknowledgements.every((code) => acknowledgements.includes(code))
  );
  const canStartScan = authorizationReady && scanDependenciesReady && !isBusy;
  const reviewReady = Boolean(selectedScan && ["completed", "completed_with_warnings"].includes(selectedScan.status));
  const currentAuditReviewReady = Boolean(currentAuditScan && ["completed", "completed_with_warnings"].includes(currentAuditScan.status));
  const selectedScanMatchesDraft = Boolean(
    selectedScan && selectedAuditSubject && selectedScan.subject_id === (selectedAuditSubject.target?.id ?? selectedAuditSubject.repositoryAsset?.id) && selectedScan.scan_profile_id === scanProfileId
  );
  const viewingPastAudit = Boolean(selectedScan && selectedScan.id !== currentAuditScanId);
  const hasCompletedScan = scanHistory.some((scan) => ["completed", "completed_with_warnings"].includes(scan.status));
  const hasComparableScansForSelectedSubject = useMemo(
    () => hasComparableScanCoverage(scanHistory, selectedAuditSubject?.subjectType ?? "", selectedAuditSubject?.target?.id ?? selectedAuditSubject?.repositoryAsset?.id ?? ""),
    [scanHistory, selectedAuditSubject]
  );
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
    void (async () => {
      try {
        await loadInitialData();
      } finally {
        setIsBootstrapping(false);
      }
    })();
  }, []);

  useEffect(() => {
    selectedScanIdRef.current = selectedScanId;
  }, [selectedScanId]);

  useEffect(() => {
    selectedTargetIdRef.current = selectedTargetId;
  }, [selectedTargetId]);

  useEffect(() => {
    selectedRepositoryAssetIdRef.current = selectedRepositoryAssetId;
  }, [selectedRepositoryAssetId]);

  useEffect(() => {
    selectedSubjectIdRef.current = selectedSubjectId;
  }, [selectedSubjectId]);

  useEffect(() => {
    if (!selectedSubjectId && auditSubjects[0]) {
      setSelectedSubjectId(auditSubjects[0].id);
      return;
    }
    if (selectedSubjectId && !auditSubjects.some((subject) => subject.id === selectedSubjectId)) {
      setSelectedSubjectId(auditSubjects[0]?.id ?? "");
    }
  }, [auditSubjects, selectedSubjectId]);

  useEffect(() => {
    baselineScanIdRef.current = baselineScanId;
  }, [baselineScanId]);

  useEffect(() => {
    comparisonScanIdRef.current = comparisonScanId;
  }, [comparisonScanId]);

  useEffect(() => {
    setActionFeedback(null);
  }, [activeView]);

  useEffect(() => {
    if (activeView !== "findings" && activeView !== "intelligence") {
      return;
    }
    const selectedScanMatchesView = Boolean(
      selectedScan &&
      ["completed", "completed_with_warnings"].includes(selectedScan.status) &&
      (activeView !== "intelligence" || selectedScan.subject_id === (selectedAuditSubject?.target?.id ?? selectedAuditSubject?.repositoryAsset?.id))
    );
    if (selectedScanMatchesView) {
      return;
    }
    const latestCompletedScan = scanHistory.find((scan) =>
      ["completed", "completed_with_warnings"].includes(scan.status) &&
      (activeView !== "intelligence" || scan.subject_id === (selectedAuditSubject?.target?.id ?? selectedAuditSubject?.repositoryAsset?.id))
    );
    const nextScanId = latestCompletedScan?.id ?? "";
    if (nextScanId !== selectedScanIdRef.current) {
      setSelectedScanId(nextScanId);
    }
  }, [activeView, scanHistory, selectedAuditSubject, selectedScan?.id, selectedScan?.status, selectedScan?.subject_id]);

  useEffect(() => {
    const centerActivePhase = () => {
      const tabs = auditPhaseTabsRef.current;
      const activeTab = activeAuditPhaseRef.current;
      if (!tabs || !activeTab) {
        return;
      }
      const targetLeft = activeTab.offsetLeft - (tabs.clientWidth - activeTab.offsetWidth) / 2;
      tabs.scrollTo({
        left: Math.max(0, targetLeft),
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth"
      });
    };
    centerActivePhase();
    window.addEventListener("resize", centerActivePhase);
    return () => window.removeEventListener("resize", centerActivePhase);
  }, [activeView, auditPhase, isBootstrapping]);

  useEffect(() => {
    const activeAudit = currentAuditScan ?? selectedScan;
    const status = activeView === "scanning" && (auditPhase === "run" || auditPhase === "review") && activeAudit
      ? activeAudit.status
      : platformHealth?.status === "ok" ? "ready" : "validating";
    onPlatformStatusChange(status);
  }, [activeView, auditPhase, currentAuditScan, onPlatformStatusChange, platformHealth?.status, selectedScan]);

  useEffect(() => {
    setSuppressionReason("");
  }, [selectedFindingId]);

  useEffect(() => {
    if (tagResourceType === "scan") return;
    setTagResourceType(selectedFinding?.repository_asset_id ? "repository_asset" : "target");
  }, [selectedFinding?.repository_asset_id, tagResourceType]);

  useEffect(() => {
    const scansToPoll = [currentAuditScan, selectedScan].filter(
      (scan, index, scans): scan is Scan => Boolean(
        scan && !terminalStatuses.has(scan.status) && scans.findIndex((candidate) => candidate?.id === scan.id) === index
      )
    );
    if (scansToPoll.length === 0) {
      return;
    }

    const timer = window.setInterval(() => {
      scansToPoll.forEach((scan) => void refreshScan(scan.id));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [currentAuditScan?.id, currentAuditScan?.status, selectedScan?.id, selectedScan?.status]);

  useEffect(() => {
    findingsRequestIdRef.current += 1;
    setFindings([]);
    setReports([]);
    setToolRuns([]);
    setAiExplanation(null);
    setSelectedFindingId("");
    if (!selectedScanId) {
      setIsLoadingScanEvidence(false);
      return;
    }
    setIsLoadingScanEvidence(true);
    setReportMessage("Loading reports for the selected audit…");
    setAiMessage("Loading finding guidance for the selected audit…");
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
    setAiMessage("Finding guidance remains available for passive and Active Demo scans.");
  }, [
    selectedScanId,
    selectedScan?.scan_profile_id
  ]);

  useEffect(() => {
    if (!selectedScanId) {
      setIsLoadingScanEvidence(false);
      return;
    }
    findingsRequestIdRef.current += 1;
    setIsLoadingScanEvidence(true);
    const timer = window.setTimeout(() => {
      void loadFindings(selectedScanId, { onlyIfSelected: true });
    }, 250);
    return () => window.clearTimeout(timer);
  }, [
    selectedScanId,
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
    selectedTargetId,
    selectedRepositoryAssetId
  ]);

  useEffect(() => {
    setTargetDashboard(null);
    setRepositoryDashboard(null);
    setScanComparison(null);
    setBaselineScanId("");
    setComparisonScanId("");
    if (!selectedAuditSubject) {
      setIsLoadingTargetRisk(false);
      return;
    }
    setIsLoadingTargetRisk(true);
    setRiskMessage("Loading subject posture data…");
    const loaders = [loadSubjectDashboard(selectedAuditSubject)];
    if (hasComparableScansForSelectedSubject) {
      loaders.push(loadLatestComparison(selectedAuditSubject));
    } else {
      setRiskMessage("Complete at least two audits with the same profile to compare matching coverage.");
    }
    void Promise.allSettled(loaders).finally(() => {
      if (selectedSubjectIdRef.current === selectedAuditSubject.id) {
        setIsLoadingTargetRisk(false);
      }
    });
  }, [hasComparableScansForSelectedSubject, selectedAuditSubject]);

  async function loadInitialData() {
    setBootstrapError("");
    const results = await Promise.allSettled([loadTargets(), loadTargetPolicies(), loadRepositoryAssets(), loadAuthProfiles(), loadScanHistory(), loadDashboardOverview(), loadTags(), loadSuppressions(), loadTagAssignments(), loadPlatformHealth(), loadAuditLogs()]);
    const failed = results.find((result) => result.status === "rejected");
    if (failed?.status === "rejected") {
      const error = failed.reason;
      const detail = error instanceof Error ? error.message : "Workspace data could not be loaded.";
      setBootstrapError(`Workspace data could not be loaded. ${detail}`);
    }
  }

  async function reloadAuthenticatedWorkspace() {
    setIsBootstrapping(true);
    clearProtectedWorkspaceState();
    try {
      const response = await apiFetch(`${apiBaseUrl}/dashboard/overview`);
      await readJson<DashboardOverview>(response, "Operator authentication failed.");
      await loadInitialData();
      return true;
    } catch (error) {
      setBootstrapError(error instanceof Error ? error.message : "Operator authentication failed.");
      return false;
    } finally {
      setIsBootstrapping(false);
    }
  }

  function clearProtectedWorkspaceState() {
    setValidation(null);
    setTargets([]);
    setTargetPolicies([]);
    setRepositoryAssets([]);
    setAuthProfiles([]);
    setSelectedAuthProfileId("");
    setAuthProfileLabel("");
    setAuthProfileType("bearer_token");
    setAuthProfileHeaderName("");
    setAuthProfileSecret("");
    setAuthProfileRotationSecret("");
    setAuthProfileMessage("Create an optional target-app auth profile for passive scans.");
    setScanHistory([]);
    setToolRuns([]);
    setFindings([]);
    setTags([]);
    setGovernanceTags([]);
    setSuppressions([]);
    setTagAssignments([]);
    setReports([]);
    setAiExplanation(null);
    setDashboardOverview(null);
    setTargetDashboard(null);
    setRepositoryDashboard(null);
    setScanComparison(null);
    setPlatformHealth(null);
    setAuditLogs([]);
    setSelectedTargetId("");
    setSelectedRepositoryAssetId("");
    setSelectedSubjectId("");
    setSelectedScanId("");
    setCurrentAuditScanId("");
    setScanProfileId("passive-web");
    setAcknowledgements([]);
    setAuditPhase("ready");
    setSelectedFindingId("");
    setBaselineScanId("");
    setComparisonScanId("");
    setTargetUrl("");
    setPermissionConfirmed(false);
    setRepoPath("");
    setRepositoryName("");
    setRepositoryPermissionConfirmed(false);
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
    setFindingSearchQuery("");
    setFindingScope("scan");
    setTargetFilter("");
    setProfileFilter("");
    setTagLabel("");
    setAssignmentTagId("");
    setTagResourceType("target");
    setSuppressionReason("");
    setMessage("Enter an allowlisted local/demo target.");
    setRepositoryMessage("Authorize a confined local repository path to save it as a scan subject.");
    setReportMessage("Reports are available after a passive, Active Demo, or Repo scan completes.");
    setAiMessage("Finding guidance is available after a passive or Active Demo scan completes.");
    setRiskMessage("Risk scores are generated for completed scans using risk-v1.");
    setOpsMessage("Platform health has not been loaded.");
    setAuditLogMessage("Workspace activity has not been loaded.");
    setPlatformHealthCheckedAt("");
    setAuditLogCheckedAt("");
    setArchiveCandidate(null);
    setRepositoryArchiveCandidate(null);
    setRevokeCandidate(null);
    setConfirmActionError("");
    setActionFeedback(null);
  }

  async function validateTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsBusy(true);
    setValidation(null);
    setMessage("Validating target against the local allowlist...");

    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl })
      });
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
          auth_profile_id: null
        })
      });
      const body = await readJson<Target>(response, "Target creation failed.");
      await loadTargets(body.id);
      setSelectedSubjectId(`web_target:${body.id}`);
      setMessage("Target saved. Available scan modes are shown below.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function reauthorizeTarget(target: Target) {
    setIsBusy(true);
    setMessage(`Reauthorizing ${target.name} against the current policy…`);
    try {
      const response = await apiFetch(`${apiBaseUrl}/targets/${target.id}/reauthorize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ permission_confirmed: true })
      });
      const updatedTarget = await readJson<Target>(response, "Target reauthorization failed.");
      await loadTargets(updatedTarget.id);
      setSelectedSubjectId(`web_target:${updatedTarget.id}`);
      setMessage(`${updatedTarget.name} is authorized under the current policy fingerprint.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target reauthorization failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function createRepositoryAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!repositoryName.trim() || !repoPath.trim() || !repositoryPermissionConfirmed) return;
    setIsBusy(true);
    setRepositoryMessage("Saving the authorized repository identity…");
    try {
      const response = await apiFetch(`${apiBaseUrl}/repository-assets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: repositoryName.trim(),
          repo_path: repoPath.trim(),
          permission_confirmed: true
        })
      });
      const asset = await readJson<RepositoryAsset>(response, "Repository asset creation failed.");
      await loadRepositoryAssets(asset.id);
      setSelectedSubjectId(`repository_asset:${asset.id}`);
      setRepositoryPermissionConfirmed(false);
      setRepositoryMessage(`${asset.name} is saved as a confined repository subject.`);
    } catch (error) {
      setRepositoryMessage(error instanceof Error ? error.message : "Repository asset creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function archiveRepositoryAsset() {
    if (!repositoryArchiveCandidate) return;
    const asset = repositoryArchiveCandidate;
    setIsBusy(true);
    setConfirmActionError("");
    setRepositoryMessage(`Archiving ${asset.name}…`);
    try {
      const response = await apiFetch(`${apiBaseUrl}/repository-assets/${asset.id}`, { method: "DELETE" });
      if (!response.ok) await readJson<never>(response, "Repository archive failed.");
      setRepositoryArchiveCandidate(null);
      if (selectedRepositoryAssetIdRef.current === asset.id) setSelectedRepositoryAssetId("");
      if (selectedSubjectIdRef.current === `repository_asset:${asset.id}`) setSelectedSubjectId("");
      await Promise.all([loadRepositoryAssets(), loadDashboardOverview()]);
      setRepositoryMessage(`${asset.name} was archived. Its historical scans and findings remain available.`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Repository archive failed.";
      setRepositoryMessage(detail);
      setConfirmActionError(detail);
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
    setConfirmActionError("");
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
      const preferredTargetId = selectedTargetIdRef.current === target.id ? "" : selectedTargetIdRef.current;
      await Promise.all([loadTargets(preferredTargetId), loadDashboardOverview()]);
      setMessage(`${target.name} was removed from saved targets. Its scan, finding, report, and audit history remains available.`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Target removal failed.";
      setMessage(detail);
      setConfirmActionError(detail);
    } finally {
      setIsBusy(false);
    }
  }

  async function refreshWorkspace() {
    setIsRefreshing(true);
    try {
      await loadInitialData();
      const scanId = selectedScanIdRef.current;
      const subject = auditSubjects.find((item) => item.id === selectedSubjectIdRef.current) ?? null;
      await Promise.allSettled([
        scanId ? refreshScan(scanId) : Promise.resolve(),
        subject ? loadSubjectDashboard(subject) : Promise.resolve(),
        subject ? loadLatestComparison(subject) : Promise.resolve()
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

  function moveAuditPhase(offset: -1 | 1) {
    const currentIndex = auditPhases.findIndex((phase) => phase.id === auditPhase);
    const nextIndex = (currentIndex + offset + auditPhases.length) % auditPhases.length;
    setAuditPhase(auditPhases[nextIndex].id);
    window.requestAnimationFrame(() => activeAuditPhaseRef.current?.focus());
  }

  async function startScan() {
    if (!selectedAuditSubject) {
      return;
    }
    if (selectedAuditSubject.target?.auth_profile_id && selectedProfile.mode !== "passive") {
      setActionFeedback({ tone: "error", text: "Credential profiles are supported only for guarded Passive Web scans." });
      return;
    }

    setIsBusy(true);
    setActionFeedback({ tone: "info", text: `Creating ${selectedProfile.label} scan…` });

    try {
      const response = await apiFetch(`${apiBaseUrl}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scanLaunchPayload(selectedAuditSubject, selectedProfile.id, acknowledgements))
      });
      const scan = await readJson<Scan>(response, "Scan creation failed.");
      setScanHistory((current) => mergeScan(current, scan));
      setCurrentAuditScanId(scan.id);
      setSelectedScanId(scan.id);
      setFindings([]);
      setToolRuns([]);
      setReports([]);
      setAiExplanation(null);
      setSelectedFindingId("");
      setReportMessage("Reports are available after this passive, Active Demo, or Repo scan completes.");
      setAiMessage("Finding guidance is available after this passive or Active Demo scan completes.");
      setActionFeedback({ tone: "success", text: "Audit queued. Worker status will update in the Run phase." });
      setAuditPhase("run");
      await loadScanHistory(scan.id);
      await loadDashboardOverview();
      await loadSubjectDashboard(selectedAuditSubject);
      await loadLatestComparison(selectedAuditSubject);
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Scan creation failed." });
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
    if (!selectedAuthProfileId || !authProfileRotationSecret.trim()) {
      return;
    }
    setIsBusy(true);
    setAuthProfileMessage("Rotating auth profile secret for future scans...");
    try {
      const response = await apiFetch(`${apiBaseUrl}/auth-profiles/${selectedAuthProfileId}/rotate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret: authProfileRotationSecret })
      });
      const profile = await readJson<AuthProfile>(response, "Auth profile rotation failed.");
      setAuthProfileRotationSecret("");
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
    setConfirmActionError("");
    setAuthProfileMessage("Revoking auth profile and detaching it from targets...");
    try {
      const response = await apiFetch(`${apiBaseUrl}/auth-profiles/${profile.id}/revoke`, { method: "POST" });
      const revokedProfile = await readJson<AuthProfile>(response, "Auth profile revocation failed.");
      setRevokeCandidate(null);
      setAuthProfileRotationSecret("");
      await Promise.all([loadAuthProfiles(revokedProfile.id), loadTargets(selectedTargetId)]);
      setAuthProfileMessage("Auth profile revoked. Its encrypted secret was erased and attached targets were detached.");
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Auth profile revocation failed.";
      setAuthProfileMessage(detail);
      setConfirmActionError(detail);
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
          setAiMessage("Finding guidance remains available for passive and Active Demo scans.");
        }
        await loadDashboardOverview();
        const subject = auditSubjects.find((item) =>
          item.subjectType === scan.subject_type &&
          (item.target?.id === scan.target_id || item.repositoryAsset?.id === scan.repository_asset_id)
        );
        if (subject) {
          await loadSubjectDashboard(subject);
          await loadLatestComparison(subject);
        }
      }
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Scan status refresh failed." });
    }
  }

  async function cancelSelectedScan() {
    if (!selectedScan) {
      return;
    }
    setIsCancellingScan(true);
    setActionFeedback({ tone: "info", text: "Requesting audit cancellation…" });
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${selectedScan.id}/cancel`, { method: "POST" });
      const scan = await readJson<Scan>(response, "Scan cancellation failed.");
      setScanHistory((current) => mergeScan(current, scan));
      setActionFeedback({ tone: "success", text: scan.status === "cancelled" ? "Audit cancelled." : "Cancellation requested. The worker will stop at a safe checkpoint." });
      await loadDashboardOverview();
      await loadPlatformHealth();
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Scan cancellation failed." });
    } finally {
      setIsCancellingScan(false);
    }
  }

  async function loadTargets(preferredTargetId?: string) {
    const items = await readAllPages<Target>(`${apiBaseUrl}/targets`, "Target list load failed.");
    setTargets(items);
    const requestedTargetId = preferredTargetId ?? selectedTargetId;
    const nextTargetId = items.some((target) => target.id === requestedTargetId) ? requestedTargetId : items[0]?.id ?? "";
    setSelectedTargetId(nextTargetId);
    setBootstrapError("");
  }

  async function loadTargetPolicies() {
    const response = await apiFetch(`${apiBaseUrl}/targets/policies`);
    setTargetPolicies(await readJson<TargetPolicy[]>(response, "Target policy catalog load failed."));
  }

  async function loadRepositoryAssets(preferredAssetId?: string) {
    const items = await readAllPages<RepositoryAsset>(`${apiBaseUrl}/repository-assets`, "Repository asset list load failed.");
    setRepositoryAssets(items);
    const requestedAssetId = preferredAssetId ?? selectedRepositoryAssetIdRef.current;
    const nextAssetId = items.some((asset) => asset.id === requestedAssetId) ? requestedAssetId : items[0]?.id ?? "";
    setSelectedRepositoryAssetId(nextAssetId);
    setBootstrapError("");
  }

  async function loadDashboardOverview() {
    const response = await apiFetch(`${apiBaseUrl}/dashboard/overview`);
    const body = await readJson<DashboardOverview>(response, "Dashboard overview load failed.");
    setDashboardOverview(body);
    setBootstrapError("");
  }

  async function loadPlatformHealth() {
    setIsCheckingPlatform(true);
    setOpsMessage("Running local readiness checks…");
    try {
      const response = await apiFetch(`${apiBaseUrl}/ops/health`);
      const body = await readJson<PlatformHealth>(response, "Platform health load failed.");
      setPlatformHealth(body);
      setOpsMessage(
        body.status !== "ok"
          ? "One or more core platform components are degraded."
          : body.zap.status === "ok"
            ? "Core platform components and ZAP are healthy."
            : "Core platform components are healthy. ZAP-required profiles remain unavailable."
      );
      setBootstrapError("");
    } catch (error) {
      setPlatformHealth(null);
      setOpsMessage(error instanceof Error ? error.message : "Platform health load failed.");
    } finally {
      setPlatformHealthCheckedAt(new Date().toISOString());
      setIsCheckingPlatform(false);
    }
  }

  async function loadAuditLogs() {
    setIsRefreshingActivity(true);
    setAuditLogMessage("Refreshing safe workspace activity…");
    try {
      setAuditLogs(await readAllPages<AuditLogEntry>(`${apiBaseUrl}/audit-logs`, "Workspace activity could not be loaded."));
      setAuditLogMessage("Workspace activity is up to date.");
    } catch (error) {
      setAuditLogs([]);
      setAuditLogMessage(error instanceof Error ? error.message : "Workspace activity could not be loaded.");
    } finally {
      setAuditLogCheckedAt(new Date().toISOString());
      setIsRefreshingActivity(false);
    }
  }

  async function loadSubjectDashboard(subject: AuditSubject) {
    const subjectId = subject.target?.id ?? subject.repositoryAsset?.id;
    if (!subjectId) return;
    try {
      const endpoint = subject.subjectType === "repository_asset"
        ? `${apiBaseUrl}/repository-assets/${subjectId}/dashboard`
        : `${apiBaseUrl}/targets/${subjectId}/dashboard`;
      const response = await apiFetch(endpoint);
      if (subject.subjectType === "repository_asset") {
        const body = await readJson<RepositoryDashboard>(response, "Repository dashboard load failed.");
        if (selectedSubjectIdRef.current !== subject.id) return;
        setRepositoryDashboard(body);
        setTargetDashboard(null);
        return;
      }
      const body = await readJson<TargetDashboard>(response, "Target dashboard load failed.");
      if (selectedSubjectIdRef.current !== subject.id) return;
      setTargetDashboard(body);
      setRepositoryDashboard(null);
    } catch (error) {
      if (selectedSubjectIdRef.current !== subject.id) return;
      setTargetDashboard(null);
      setRepositoryDashboard(null);
      setRiskMessage(error instanceof Error ? error.message : "Subject dashboard load failed.");
    }
  }

  async function loadLatestComparison(subject: AuditSubject) {
    const subjectId = subject.target?.id ?? subject.repositoryAsset?.id;
    if (!subjectId) return;
    if (!hasComparableScanCoverage(scanHistory, subject.subjectType, subjectId)) {
      if (selectedSubjectIdRef.current === subject.id) {
        setScanComparison(null);
        setRiskMessage("Complete at least two audits with the same profile to compare matching coverage.");
      }
      return;
    }
    try {
      const endpoint = subject.subjectType === "repository_asset"
        ? `${apiBaseUrl}/repository-assets/${subjectId}/latest-comparison`
        : `${apiBaseUrl}/targets/${subjectId}/latest-comparison`;
      const response = await apiFetch(endpoint);
      if (!response.ok) {
        if (selectedSubjectIdRef.current !== subject.id) return;
        setScanComparison(null);
        setRiskMessage("At least two completed scans are required for latest-vs-previous comparison.");
        return;
      }
      const body = (await response.json()) as ScanComparison;
      if (selectedSubjectIdRef.current !== subject.id) return;
      setScanComparison(body);
      setBaselineScanId(body.baseline_scan_id);
      setComparisonScanId(body.comparison_scan_id);
      setRiskMessage("Latest-vs-previous comparison is ready.");
    } catch {
      if (selectedSubjectIdRef.current !== subject.id) return;
      setScanComparison(null);
      setRiskMessage("Latest comparison could not be loaded.");
    }
  }

  async function loadManualComparison() {
    if (!baselineScanId || !comparisonScanId || baselineScanId === comparisonScanId) {
      setRiskMessage("Choose two different completed scans for the same subject and audit profile.");
      return;
    }
    const baselineScan = scanHistory.find((scan) => scan.id === baselineScanId);
    const comparisonScan = scanHistory.find((scan) => scan.id === comparisonScanId);
    if (
      !baselineScan ||
      !comparisonScan ||
      !selectedAuditSubject ||
      baselineScan.subject_type !== selectedAuditSubject.subjectType ||
      comparisonScan.subject_type !== selectedAuditSubject.subjectType ||
      baselineScan.subject_id !== (selectedAuditSubject.target?.id ?? selectedAuditSubject.repositoryAsset?.id) ||
      comparisonScan.subject_id !== (selectedAuditSubject.target?.id ?? selectedAuditSubject.repositoryAsset?.id) ||
      baselineScan.scan_profile_id !== comparisonScan.scan_profile_id
    ) {
      setScanComparison(null);
      setRiskMessage("Comparisons require two completed scans from the same subject and audit profile.");
      return;
    }

    const requestSubjectId = selectedSubjectIdRef.current;
    const requestBaselineScanId = baselineScanId;
    const requestComparisonScanId = comparisonScanId;
    setIsComparingScans(true);
    setRiskMessage("Comparing normalized findings…");
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${comparisonScanId}/comparison?baseline_scan_id=${encodeURIComponent(baselineScanId)}`);
      const body = await readJson<ScanComparison>(response, "Scan comparison failed.");
      if (
        selectedSubjectIdRef.current !== requestSubjectId ||
        baselineScanIdRef.current !== requestBaselineScanId ||
        comparisonScanIdRef.current !== requestComparisonScanId
      ) {
        return;
      }
      setScanComparison(body);
      setRiskMessage("Manual scan comparison is ready.");
    } catch (error) {
      if (
        selectedSubjectIdRef.current !== requestSubjectId ||
        baselineScanIdRef.current !== requestBaselineScanId ||
        comparisonScanIdRef.current !== requestComparisonScanId
      ) {
        return;
      }
      setScanComparison(null);
      setRiskMessage(error instanceof Error ? error.message : "Scan comparison failed.");
    } finally {
      setIsComparingScans(false);
    }
  }

  async function loadAuthProfiles(preferredAuthProfileId?: string) {
    const items = await readAllPages<AuthProfile>(`${apiBaseUrl}/auth-profiles`, "Auth profile list load failed.");
    setAuthProfiles(items);
    const requestedProfileId = preferredAuthProfileId ?? selectedAuthProfileId;
    const nextProfileId = items.some((profile) => profile.id === requestedProfileId) ? requestedProfileId : items[0]?.id ?? "";
    setSelectedAuthProfileId(nextProfileId);
    setBootstrapError("");
  }

  async function loadScanHistory(preferredScanId?: string) {
    const items = await readAllPages<Scan>(`${apiBaseUrl}/scans`, "Scan history load failed.");
    setScanHistory(items);
    const requestedScanId = preferredScanId ?? selectedScanId;
    const nextScanId = items.some((scan) => scan.id === requestedScanId) ? requestedScanId : items[0]?.id ?? "";
    setSelectedScanId(nextScanId);
    setBootstrapError("");
  }

  async function loadTags(preferredTagId?: string) {
    const allItems = await readAllPages<Tag>(`${apiBaseUrl}/tags?include_archived=true`, "Tag list load failed.");
    const items = allItems.filter((tag) => !tag.archived_at);
    setTags(items);
    setGovernanceTags(allItems);
    const requestedTagId = preferredTagId ?? assignmentTagId;
    setAssignmentTagId(items.some((tag) => tag.id === requestedTagId) ? requestedTagId : items[0]?.id ?? "");
    setBootstrapError("");
  }

  async function loadSuppressions() {
    setSuppressions(await readAllPages<SuppressionRule>(`${apiBaseUrl}/suppressions`, "Suppression history load failed."));
  }

  async function loadTagAssignments() {
    setTagAssignments(await readAllPages<TagAssignment>(`${apiBaseUrl}/tags/assignments`, "Tag assignment history load failed."));
  }

  async function loadFindings(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    const requestId = ++findingsRequestIdRef.current;
    try {
      const params = findingFilterParams();
      const query = params.toString();
      const endpoint = findingScope === "workspace" ? `${apiBaseUrl}/findings` : `${apiBaseUrl}/scans/${scanId}/findings`;
      const body = await readAllPages<Finding>(`${endpoint}${query ? `?${query}` : ""}`, "Findings could not be loaded.");
      if (requestId !== findingsRequestIdRef.current) {
        return;
      }
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setFindings(body);
      setSelectedFindingId((current) => {
        const firstBySeverity = [...body].sort(
          (left, right) => (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0)
        )[0];
        return body.some((finding) => finding.id === current) ? current : firstBySeverity?.id ?? "";
      });
    } catch (error) {
      if (requestId !== findingsRequestIdRef.current) {
        return;
      }
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setFindings([]);
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Findings could not be loaded." });
    } finally {
      if (requestId === findingsRequestIdRef.current && (!options.onlyIfSelected || selectedScanIdRef.current === scanId)) {
        setIsLoadingScanEvidence(false);
      }
    }
  }

  function findingFilterParams() {
    const params = new URLSearchParams();
    params.set("limit", "200");
    if (findingScope === "workspace") {
      if (targetFilter) {
        const [subjectType, subjectId] = targetFilter.split(":", 2);
        if (subjectType === "target" && subjectId) params.set("target_id", subjectId);
        if (subjectType === "repository" && subjectId) params.set("repository_asset_id", subjectId);
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
    if (updatingFindingId) {
      return;
    }
    setUpdatingFindingId(findingId);
    setActionFeedback({ tone: "info", text: "Saving finding lifecycle…" });
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
      const affectedFinding = findings.find((finding) => finding.id === findingId) ?? null;
      await refreshDerivedPosture(affectedFinding?.target_id ?? null, affectedFinding?.repository_asset_id ?? null);
      setActionFeedback({ tone: "success", text: "Finding lifecycle updated." });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Finding lifecycle update failed." });
    } finally {
      setUpdatingFindingId("");
    }
  }

  async function suppressFinding(finding: Finding) {
    if ((!finding.target_id && !finding.repository_asset_id) || !suppressionReason.trim()) {
      return;
    }
    setIsSuppressingFinding(true);
    setActionFeedback({ tone: "info", text: "Saving the suppression decision…" });
    try {
      const response = await apiFetch(`${apiBaseUrl}/suppressions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: finding.target_id,
          repository_asset_id: finding.repository_asset_id,
          dedupe_key: finding.dedupe_key,
          severity: finding.severity,
          source_tool: finding.source_tool,
          reason: suppressionReason.trim()
        })
      });
      await readJson<unknown>(response, "Suppression rule creation failed.");
      setSuppressionReason("");
      await loadSuppressions();
      if (selectedScanIdRef.current) {
        await loadFindings(selectedScanIdRef.current, { onlyIfSelected: true });
      }
      await refreshDerivedPosture(finding.target_id, finding.repository_asset_id);
      setActionFeedback({ tone: "success", text: "Finding suppression saved." });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Suppression rule creation failed." });
    } finally {
      setIsSuppressingFinding(false);
    }
  }

  async function createTag() {
    if (!tagLabel.trim() || isCreatingTag) {
      return;
    }
    setIsCreatingTag(true);
    setActionFeedback({ tone: "info", text: "Creating tag…" });
    try {
      const response = await apiFetch(`${apiBaseUrl}/tags`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: tagLabel.trim() })
      });
      const tag = await readJson<Tag>(response, "Tag creation failed.");
      setTagLabel("");
      await loadTags(tag.id);
      setActionFeedback({ tone: "success", text: "Tag created and selected for assignment." });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Tag creation failed." });
    } finally {
      setIsCreatingTag(false);
    }
  }

  async function assignTag() {
    const resourceId = tagResourceType === "scan"
      ? selectedFinding?.scan_id
      : tagResourceType === "repository_asset"
        ? selectedFinding?.repository_asset_id
        : selectedFinding?.target_id;
    if (!assignmentTagId || !resourceId || isAssigningTag) {
      return;
    }
    setIsAssigningTag(true);
    setActionFeedback({ tone: "info", text: `Assigning tag to the selected ${tagResourceType}…` });
    try {
      const response = await apiFetch(`${apiBaseUrl}/tags/assignments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tag_id: assignmentTagId,
          resource_type: tagResourceType,
          resource_id: resourceId
        })
      });
      await readJson<unknown>(response, "Tag assignment failed.");
      await loadTagAssignments();
      if (selectedScanIdRef.current) {
        await loadFindings(selectedScanIdRef.current, { onlyIfSelected: true });
      }
      setActionFeedback({ tone: "success", text: `Tag assigned to the selected ${tagResourceType}.` });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Tag assignment failed." });
    } finally {
      setIsAssigningTag(false);
    }
  }

  async function revokeSuppression(rule: SuppressionRule) {
    setGovernanceActionId(rule.id);
    setActionFeedback({ tone: "info", text: "Revoking suppression while preserving its audit history…" });
    try {
      const response = await apiFetch(`${apiBaseUrl}/suppressions/${rule.id}/revoke`, { method: "POST" });
      await readJson<SuppressionRule>(response, "Suppression revocation failed.");
      await Promise.all([loadSuppressions(), selectedScanIdRef.current ? loadFindings(selectedScanIdRef.current, { onlyIfSelected: true }) : Promise.resolve()]);
      await refreshDerivedPosture(rule.target_id, rule.repository_asset_id);
      setActionFeedback({ tone: "success", text: "Suppression revoked. Current posture has been refreshed." });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Suppression revocation failed." });
    } finally {
      setGovernanceActionId("");
    }
  }

  async function archiveTag(tag: Tag) {
    setGovernanceActionId(tag.id);
    setActionFeedback({ tone: "info", text: `Archiving ${tag.label} without deleting assignment history…` });
    try {
      const response = await apiFetch(`${apiBaseUrl}/tags/${tag.id}/archive`, { method: "POST" });
      await readJson<Tag>(response, "Tag archive failed.");
      await Promise.all([loadTags(), loadTagAssignments()]);
      setActionFeedback({ tone: "success", text: `${tag.label} archived.` });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Tag archive failed." });
    } finally {
      setGovernanceActionId("");
    }
  }

  async function unassignTag(assignment: TagAssignment) {
    setGovernanceActionId(assignment.id);
    setActionFeedback({ tone: "info", text: "Removing the selected tag assignment…" });
    try {
      const response = await apiFetch(`${apiBaseUrl}/tags/assignments/${assignment.id}`, { method: "DELETE" });
      if (!response.ok) await readJson<never>(response, "Tag unassignment failed.");
      await Promise.all([loadTagAssignments(), selectedScanIdRef.current ? loadFindings(selectedScanIdRef.current, { onlyIfSelected: true }) : Promise.resolve()]);
      setActionFeedback({ tone: "success", text: "Tag assignment removed and recorded in the audit log." });
    } catch (error) {
      setActionFeedback({ tone: "error", text: error instanceof Error ? error.message : "Tag unassignment failed." });
    } finally {
      setGovernanceActionId("");
    }
  }

  async function refreshDerivedPosture(targetId: string | null, repositoryAssetId: string | null) {
    await loadDashboardOverview();
    const subject = auditSubjects.find((item) =>
      item.target?.id === targetId || item.repositoryAsset?.id === repositoryAssetId
    );
    if (!subject || selectedSubjectIdRef.current !== subject.id) return;
    await Promise.allSettled([loadSubjectDashboard(subject), loadLatestComparison(subject)]);
  }

  async function loadReports(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const body = await readAllPages<ReportArtifact>(`${apiBaseUrl}/scans/${scanId}/reports`, "Reports could not be loaded.");
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
      const items = await readAllPages<ScannerToolRun>(`${apiBaseUrl}/scans/${scanId}/tool-runs`, "Scanner receipts could not be loaded.");
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setToolRuns(items);
    } catch {
      if (!options.onlyIfSelected || selectedScanIdRef.current === scanId) {
        setToolRuns([]);
      }
    }
  }

  async function loadAiExplanation(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const request = aiExplanationRequest(scanId);
      const response = await apiFetch(request.url, request.init);
      if (!response.ok) {
        if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
          return;
        }
        setAiExplanation(null);
        setAiMessage("Finding guidance is available after this passive or Active Demo scan completes.");
        return;
      }
      const body = (await response.json()) as AiExplanation;
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setAiExplanation(body);
      setAiMessage(body.fallback_used ? "Local fallback guidance is ready." : body.configured_provider === "openai" && body.provider === "openai" ? "AI-assisted guidance is ready." : "Local finding guidance is ready.");
    } catch {
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setAiExplanation(null);
      setAiMessage("Finding guidance could not be loaded.");
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

  async function generateAiExplanation() {
    if (!selectedScan || !canUseAi(selectedScan) || isGeneratingAi) return;
    setIsGeneratingAi(true);
    setAiMessage(aiExplanation?.configured_provider === "openai" ? "Generating AI-assisted guidance from bounded normalized findings…" : "Refreshing deterministic local guidance…");
    try {
      const request = aiExplanationRequest(selectedScan.id, true);
      const response = await apiFetch(request.url, request.init);
      const body = await readJson<AiExplanation>(response, "Finding guidance generation failed.");
      setAiExplanation(body);
      setAiMessage(body.fallback_used ? "The safe local fallback is ready." : body.provider === "openai" ? "AI-assisted guidance is ready." : "Local finding guidance is ready.");
    } catch (error) {
      setAiMessage(error instanceof Error ? error.message : "Finding guidance generation failed.");
    } finally {
      setIsGeneratingAi(false);
    }
  }

  async function viewReport(report: ReportArtifact) {
    if (pendingReportAction) {
      return;
    }
    const previewWindow = window.open("about:blank", "_blank");
    if (!previewWindow) {
      setReportMessage("The browser blocked the report preview. Allow pop-ups for this local workspace or use Download.");
      return;
    }
    previewWindow.opener = null;
    setPendingReportAction({ reportId: report.id, action: "view" });
    setReportMessage(`Opening the ${report.report_type.toUpperCase()} report…`);
    try {
      const response = await apiFetch(`${apiOrigin}${report.view_url}`);
      if (!response.ok) {
        await readJson<never>(response, "Report view failed.");
      }
      const content = await response.text();
      const mediaType = report.report_type === "html" ? "text/html" : "text/markdown";
      const url = window.URL.createObjectURL(new Blob([content], { type: mediaType }));
      previewWindow.location.replace(url);
      window.setTimeout(() => window.URL.revokeObjectURL(url), 60_000);
      setReportMessage("Report opened in a new tab.");
    } catch (error) {
      previewWindow.close();
      setReportMessage(error instanceof Error ? error.message : "Report view failed.");
    } finally {
      setPendingReportAction(null);
    }
  }

  async function downloadReport(report: ReportArtifact) {
    if (pendingReportAction) {
      return;
    }
    setPendingReportAction({ reportId: report.id, action: "download" });
    setReportMessage(`Preparing the ${report.report_type.toUpperCase()} report download…`);
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
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(url), 1_000);
      setReportMessage("Report download started.");
    } catch (error) {
      setReportMessage(error instanceof Error ? error.message : "Report download failed.");
    } finally {
      setPendingReportAction(null);
    }
  }

  function renderFindingsDashboard() {
    if (isLoadingScanEvidence) {
      return <EvidenceLoadingState />;
    }
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
        repositoryAssets={repositoryAssets}
        scanProfiles={SCAN_PROFILES}
        tags={tags}
        tagLabel={tagLabel}
        assignmentTagId={assignmentTagId}
        tagResourceType={tagResourceType}
        suppressionReason={suppressionReason}
        isSuppressing={isSuppressingFinding}
        updatingFindingId={updatingFindingId}
        isCreatingTag={isCreatingTag}
        isAssigningTag={isAssigningTag}
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
        onAssignmentTagChange={setAssignmentTagId}
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

  function renderHistoricalAuditNotice() {
    if (!viewingPastAudit || !selectedScan) {
      return null;
    }
    return (
      <aside className="historicalAuditNotice" aria-label="Historical audit context">
        <AppIcon name="activity" size={18} />
        <div>
          <strong>Viewing a past audit</strong>
          <p>
            {selectedScanSubject?.name ?? "Historical subject"} · {formatScanProfileLabel(selectedScan.scan_profile_id)} · {formatShortDate(selectedScan.completed_at ?? selectedScan.created_at)}.
            This evidence does not mark the audit you are configuring as complete.
          </p>
        </div>
        {currentAuditScan ? (
          <button type="button" className="secondaryButton" onClick={() => setSelectedScanId(currentAuditScan.id)}>
            Return to current audit
          </button>
        ) : null}
      </aside>
    );
  }

  const phaseComplete: Record<AuditPhase, boolean> = {
    ready: platformReady,
    scope: Boolean(selectedAuditSubject),
    profile: profileReady,
    authorize: authorizationReady,
    run: currentAuditReviewReady,
    review: currentAuditReviewReady
  };

  if (isBootstrapping) {
    return (
      <section className="dashboard" aria-label="ScopeHarbor workspace">
        <WorkspaceLoadingState />
      </section>
    );
  }

  return (
    <section className="dashboard" aria-label="ScopeHarbor workspace">
      {activeView !== "scanning" && activeView !== "guide" ? (
        <div className="workspaceUtilityBar">
          <span><AppIcon name={workspaceViewMetadata.find((view) => view.id === activeView)?.icon ?? "overview"} size={16} />{workspaceViewMetadata.find((view) => view.id === activeView)?.description}</span>
          <button className="refreshButton" type="button" onClick={refreshWorkspace} disabled={isRefreshing}>
            <AppIcon name="refresh" size={16} />
            {isRefreshing ? "Refreshing…" : "Refresh workspace"}
          </button>
        </div>
      ) : null}

      {bootstrapError ? (
        <div className="statusBanner statusBannerError" role="alert">
          {bootstrapError}
        </div>
      ) : null}

      {actionFeedback ? (
        <div className={`workspaceActionStatus workspaceActionStatus-${actionFeedback.tone}`} role={actionFeedback.tone === "error" ? "alert" : "status"}>
          <AppIcon name={actionFeedback.tone === "error" ? "finding" : actionFeedback.tone === "success" ? "check" : "activity"} size={16} />
          <span>{actionFeedback.text}</span>
        </div>
      ) : null}

      <div id="workspace-panel" className="workspaceTabPanel">
        {activeView === "overview" ? (
          <WorkspaceOverview
            overview={dashboardOverview}
            health={platformHealth}
            selectedScan={selectedScan}
            selectedSubject={selectedAuditSubject}
            onNavigate={(view) => {
              if (view === "scanning") {
                setAuditPhase(selectedAuditSubject?.target?.policy_status === "current" || selectedAuditSubject?.repositoryAsset ? "profile" : "scope");
              }
              onActiveViewChange(view as WorkspaceView);
            }}
            onOpenScanHistory={() => {
              setAuditPhase("run");
              onActiveViewChange("scanning");
            }}
          />
        ) : null}

        {activeView === "scanning" ? (
          <div className="auditWorkspace">
            <div className="auditPhaseNavigation">
              <button className="phaseScrollButton" type="button" onClick={() => moveAuditPhase(-1)} aria-label="Previous audit phase"><span aria-hidden="true">‹</span></button>
              <nav ref={auditPhaseTabsRef} className="auditPhaseTabs" role="tablist" aria-label="Audit phases">
                {auditPhases.map((phase, index) => {
                  const isActive = auditPhase === phase.id;
                  const isComplete = phaseComplete[phase.id] && !isActive;
                  const isRunInterrupted = phase.id === "run" && Boolean(currentAuditScan && ["failed", "cancelled"].includes(currentAuditScan.status));
                  const phaseState = auditPhaseState(phase.id, isActive, isComplete, currentAuditScan);
                  return (
                    <button
                      ref={isActive ? activeAuditPhaseRef : undefined}
                      key={phase.id}
                      type="button"
                      role="tab"
                      id={`audit-phase-${phase.id}`}
                      aria-selected={isActive}
                      aria-controls="audit-phase-panel"
                      tabIndex={isActive ? 0 : -1}
                      className={`auditPhaseTab${isActive ? " auditPhaseTabActive" : ""}${isComplete ? " auditPhaseTabComplete" : ""}${isRunInterrupted ? " auditPhaseTabInterrupted" : ""}`}
                      onClick={() => setAuditPhase(phase.id)}
                      onKeyDown={(event) => handlePhaseKeyDown(event, index)}
                    >
                      <span className="auditPhaseMarker">{isComplete ? <AppIcon name="check" size={15} /> : index + 1}</span>
                      <span><strong>{phase.label}</strong><small>{phaseState}</small></span>
                    </button>
                  );
                })}
              </nav>
              <button className="phaseScrollButton" type="button" onClick={() => moveAuditPhase(1)} aria-label="Next audit phase"><span aria-hidden="true">›</span></button>
            </div>

            <div id="audit-phase-panel" className="auditPhasePanel" role="tabpanel" aria-labelledby={`audit-phase-${auditPhase}`} tabIndex={0}>
              {auditPhase === "ready" ? (
                <div className="auditPhaseContent">
                  <div className="phaseHeading">
                    <div><span>Before any target is contacted</span><h2>Run the local audit preflight</h2><p>This read-only check confirms ScopeHarbor can validate scope, run bounded tools, and save sanitized results. It does not scan a target.</p></div>
                    <span className={platformReady ? "readinessState readinessStateReady" : "readinessState"}><span className="statusDot" />{platformReady ? "Ready to audit" : "Needs attention"}</span>
                  </div>
                  <div className="readinessGuide" aria-label="How audit preflight works">
                    <div><span>01</span><strong>Check local services</strong><p>Database, worker, approved scanner support, and artifact storage report their state.</p></div>
                    <div><span>02</span><strong>Resolve only flagged items</strong><p>Healthy rows need no action. A degraded row explains which local dependency needs attention.</p></div>
                    <div><span>03</span><strong>Continue to authorized scope</strong><p>When all required services are healthy, choose the exact target this audit may inspect.</p></div>
                  </div>
                  <OpsHealthPanel
                    health={platformHealth}
                    message={opsMessage}
                    isRefreshing={isCheckingPlatform}
                    checkedAt={platformHealthCheckedAt}
                    onRefresh={loadPlatformHealth}
                    context="audit"
                  />
                  <div className="boundaryStrip" aria-label="Persistent platform boundaries">
                    <span><AppIcon name="target" size={16} /><strong>Exact targets</strong> only</span>
                    <span><AppIcon name="shield" size={16} /><strong>Workspace context</strong> rechecked</span>
                    <span><AppIcon name="operations" size={16} /><strong>Bounded tools</strong> with safe receipts</span>
                  </div>
                  <div className="phaseFooter"><span>{platformReady ? "All required components report healthy." : "Resolve degraded components, then refresh readiness."}</span><button className="primaryButton" type="button" onClick={() => setAuditPhase("scope")} disabled={!platformReady}>Continue to scope <AppIcon name="arrow" size={15} /></button></div>
                </div>
              ) : null}

              {auditPhase === "scope" ? (
                <div className="auditPhaseContent">
                  <div className="phaseHeading"><div><span>Authorized scope</span><h2>Choose a web target or repository subject</h2><p>Web audits start from exact configured policies. Repository audits start from a separately authorized, confined local identity.</p></div></div>
                  <TargetPolicyCatalog policies={targetPolicies} />
                  <div className="targetManagementGrid">
                    <TargetLibrary
                      targets={targets}
                      selectedTargetId={selectedTargetId}
                      isBusy={isBusy}
                      onSelectTarget={(targetId) => {
                        setSelectedTargetId(targetId);
                        setSelectedSubjectId(targetId ? `web_target:${targetId}` : "");
                        setAcknowledgements([]);
                      }}
                      onReauthorizeTarget={reauthorizeTarget}
                      onRequestArchive={(target) => {
                        setConfirmActionError("");
                        setArchiveCandidate(target);
                      }}
                    />
                    <TargetForm
                      targetUrl={targetUrl}
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
                      onPermissionChange={setPermissionConfirmed}
                      onValidate={validateTarget}
                      onCreateTarget={createTarget}
                    />
                  </div>
                  <RepositoryAssetsPanel
                    assets={repositoryAssets}
                    selectedAssetId={selectedRepositoryAssetId}
                    name={repositoryName}
                    path={repoPath}
                    permissionConfirmed={repositoryPermissionConfirmed}
                    message={repositoryMessage}
                    isBusy={isBusy}
                    onSelectAsset={(assetId) => {
                      setSelectedRepositoryAssetId(assetId);
                      setSelectedSubjectId(assetId ? `repository_asset:${assetId}` : "");
                      setScanProfileId("repository");
                      setAcknowledgements([]);
                    }}
                    onNameChange={setRepositoryName}
                    onPathChange={setRepoPath}
                    onPermissionChange={setRepositoryPermissionConfirmed}
                    onCreateAsset={createRepositoryAsset}
                    onRequestArchive={(asset) => {
                      setConfirmActionError("");
                      setRepositoryArchiveCandidate(asset);
                    }}
                  />
                  <div className="phaseFooter"><span>{selectedAuditSubject ? `${selectedAuditSubject.name} is selected as the audit subject.` : "Select or save one authorized subject to continue."}</span><button type="button" onClick={() => setAuditPhase("profile")} disabled={!selectedAuditSubject}>Choose an audit profile <AppIcon name="arrow" size={15} /></button></div>
                </div>
              ) : null}

              {auditPhase === "profile" ? (
                <div className="auditPhaseContent auditPhaseContentPriority profilePhaseContent">
                  <ScanProfileSelector
                    subjects={auditSubjects}
                    selectedSubjectId={selectedAuditSubject?.id ?? ""}
                    scanProfileId={scanProfileId}
                    onSelectSubject={(subjectId) => {
                      const subject = auditSubjects.find((item) => item.id === subjectId);
                      setSelectedSubjectId(subjectId);
                      if (subject?.target) setSelectedTargetId(subject.target.id);
                      if (subject?.repositoryAsset) {
                        setSelectedRepositoryAssetId(subject.repositoryAsset.id);
                        setScanProfileId("repository");
                      } else if (scanProfileId === "repository") {
                        setScanProfileId("passive-web");
                      }
                      setAcknowledgements([]);
                    }}
                    onSelectScanProfile={(profileId) => {
                      setScanProfileId(profileId);
                      setAcknowledgements([]);
                    }}
                    onContinue={() => setAuditPhase("authorize")}
                  />
                  {reviewReady && selectedScanMatchesDraft && filteredFindings.length > 0 ? (
                    <section className="recentFindingsPreview" aria-labelledby="recent-findings-title">
                      <div className="recentFindingsHeader">
                        <div><h3 id="recent-findings-title">Recent normalized findings</h3><p>{selectedScanSubject?.name ?? "Selected subject"} · {selectedScan ? formatScanProfileLabel(selectedScan.scan_profile_id) : "Completed audit"} · {selectedScan ? formatShortDate(selectedScan.completed_at ?? selectedScan.created_at) : "Recent"}. Open Review for evidence and triage.</p></div>
                        <button type="button" className="secondaryButton" onClick={() => setAuditPhase("review")}>Review all {filteredFindings.length} <AppIcon name="arrow" size={15} /></button>
                      </div>
                      <div className="recentFindingsTableWrap">
                        <table className="recentFindingsTable">
                          <thead><tr><th>Finding</th><th>Severity</th><th>Lifecycle</th><th>Source</th></tr></thead>
                          <tbody>
                            {filteredFindings.slice(0, 4).map((finding) => (
                              <tr key={finding.id}>
                                <td><button type="button" className="findingSelectButton" onClick={() => { setSelectedFindingId(finding.id); setAuditPhase("review"); }}>{finding.title}</button></td>
                                <td><span className={`severity severity-${finding.severity}`}>{finding.severity}</span></td>
                                <td><span className="stateBadge">{finding.lifecycle_status.replaceAll("_", " ")}</span></td>
                                <td>{finding.source_tool}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}
                </div>
              ) : null}

              {auditPhase === "authorize" ? (
                <div className="auditPhaseContent">
                  <ScanAuthorization
                    subject={selectedAuditSubject}
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
                    subject={selectedAuditSubject}
                    scanProfileId={scanProfileId}
                    canStartScan={canStartScan}
                    platformReady={scanDependenciesReady}
                    readinessMessage={scanReadinessMessage}
                    isBusy={isBusy}
                    onStartScan={startScan}
                  />
                  {renderHistoricalAuditNotice()}
                  <div className="runWorkspaceGrid">
                    {selectedScan ? <ScanProgress scan={selectedScan} targetName={selectedScanSubject?.name ?? "Historical subject"} toolRuns={toolRuns} isCancelling={isCancellingScan} onCancel={cancelSelectedScan} /> : <div className="emptyState richEmptyState"><AppIcon name="activity" size={24} /><strong>No scan selected</strong><span>Launch this audit or choose a historical scan to monitor it.</span></div>}
                    <ScanHistory scans={scanHistory} selectedScanId={selectedScanId} onSelectScan={setSelectedScanId} />
                  </div>
                  <div className="phaseFooter"><span>{currentAuditReviewReady ? "The current audit's normalized results are ready for triage." : "Review unlocks after the current audit completes or completes with warnings."}</span><button className="primaryButton" type="button" onClick={() => { if (currentAuditScan) setSelectedScanId(currentAuditScan.id); setAuditPhase("review"); }} disabled={!currentAuditReviewReady}>Review current findings <AppIcon name="arrow" size={15} /></button></div>
                </div>
              ) : null}

              {auditPhase === "review" ? (
                <div className="auditPhaseContent auditPhaseContentPriority">
                  <div className="phaseHeading reviewPhaseHeading">
                    <div><span>Completed audit</span><h2>Review the result and choose the next action</h2><p>Confirm the audit outcome, inspect the most important signals, then continue to canonical finding triage or risk intelligence.</p></div>
                  </div>
                  {renderHistoricalAuditNotice()}
                  {reviewReady && selectedScan ? (
                    <AuditReviewSummary
                      scan={selectedScan}
                      findings={displayFindings}
                      subjectName={selectedScanSubject?.name ?? "Completed audit"}
                      onOpenFindings={() => onActiveViewChange("findings")}
                      onOpenIntelligence={() => onActiveViewChange("intelligence")}
                      onOpenHistory={() => setAuditPhase("run")}
                    />
                  ) : <div className="emptyState richEmptyState"><AppIcon name="finding" size={24} /><strong>No completed audit selected</strong><span>Choose a completed scan in Run to review its normalized findings.</span><button type="button" onClick={() => setAuditPhase("run")}>Open scan history</button></div>}
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        {activeView === "findings" ? (
          <div className="findingsWorkspace productPage">
            <div className="viewToolbar">
              <div><h2>Finding triage</h2><p>Filter normalized evidence, update lifecycle state, and keep remediation decisions attached to the finding.</p></div>
              <div className="viewToolbarActions">
                <label className="searchField">
                  <AppIcon name="search" size={17} />
                  <span className="srOnly">Search loaded findings</span>
                  <input value={findingSearchQuery} onChange={(event) => setFindingSearchQuery(event.target.value)} placeholder="Search finding, tool, URL, CWE…" />
                </label>
                <button type="button" className="secondaryButton" onClick={resetFindingFilters}>Reset filters</button>
              </div>
            </div>
            {hasCompletedScan ? renderFindingsDashboard() : (
              <EvidenceFirstRunState
                onStartAudit={() => {
                  setAuditPhase("profile");
                  onActiveViewChange("scanning");
                }}
              />
            )}
            <FindingGovernancePanel
              suppressions={suppressions}
              tags={governanceTags}
              assignments={tagAssignments}
              busyActionId={governanceActionId}
              onRevokeSuppression={revokeSuppression}
              onArchiveTag={archiveTag}
              onUnassignTag={unassignTag}
            />
          </div>
        ) : null}

        {activeView === "intelligence" ? (
          <div className="intelligenceWorkspace productPage">
            <div className="viewIntro"><div><h2>Risk intelligence</h2><p>Compare security posture, generate sanitized reports, and review local guidance or explicitly request AI assistance when configured.</p></div></div>
            <RiskDashboardPanel
              overview={dashboardOverview}
              targetDashboard={targetDashboard}
              repositoryDashboard={repositoryDashboard}
              scans={scanHistory}
              selectedSubject={selectedAuditSubject}
              baselineScanId={baselineScanId}
              comparisonScanId={comparisonScanId}
              comparison={scanComparison}
              message={riskMessage}
              isComparing={isComparingScans}
              isLoading={isLoadingTargetRisk}
              onBaselineScanChange={(scanId) => {
                setBaselineScanId(scanId);
                const baselineProfile = scanHistory.find((scan) => scan.id === scanId)?.scan_profile_id;
                const comparisonProfile = scanHistory.find((scan) => scan.id === comparisonScanId)?.scan_profile_id;
                if (!baselineProfile || baselineProfile !== comparisonProfile) {
                  setComparisonScanId("");
                }
                setScanComparison(null);
                setRiskMessage(scanId ? "Choose a second completed scan from the same audit profile." : "Choose a baseline scan to begin.");
              }}
              onComparisonScanChange={(scanId) => {
                setComparisonScanId(scanId);
                setScanComparison(null);
                setRiskMessage(scanId ? "Ready to compare matching audit coverage." : "Choose a comparison scan from the same profile.");
              }}
              onCompare={loadManualComparison}
            />
            <div className="intelligenceGrid">
              <ReportsPanel
                scan={selectedScan}
                reports={reports}
                message={reportMessage}
                isGenerating={isGeneratingReports}
                pendingAction={pendingReportAction}
                onGenerate={generateReports}
                onViewReport={viewReport}
                onDownloadReport={downloadReport}
              />
              <FindingGuidancePanel explanation={displayAiExplanation} message={aiMessage} canGenerate={Boolean(selectedScan && canUseAi(selectedScan) && reviewReady)} isGenerating={isGeneratingAi} onGenerate={generateAiExplanation} />
            </div>
          </div>
        ) : null}

        {activeView === "credentials" ? (
          <div className="credentialWorkspace productPage">
            <div className="viewIntro">
              <div><h2>Credential profiles</h2><p>Manage target-application secrets used only by guarded passive requests. Secret values never return through the API.</p></div>
              <span className="safetyPill"><AppIcon name="credential" size={15} /> Encrypted locally; never returned</span>
            </div>
            <AuthProfilesPanel
              authProfiles={authProfiles}
              selectedTarget={selectedTarget}
              selectedAuthProfileId={selectedAuthProfileId}
              label={authProfileLabel}
              profileType={authProfileType}
              headerName={authProfileHeaderName}
              secret={authProfileSecret}
              rotationSecret={authProfileRotationSecret}
              message={authProfileMessage}
              isBusy={isBusy}
              onSelectAuthProfile={(authProfileId) => {
                setSelectedAuthProfileId(authProfileId);
                setAuthProfileRotationSecret("");
              }}
              onLabelChange={setAuthProfileLabel}
              onProfileTypeChange={setAuthProfileType}
              onHeaderNameChange={setAuthProfileHeaderName}
              onSecretChange={setAuthProfileSecret}
              onRotationSecretChange={setAuthProfileRotationSecret}
              onCreateProfile={createAuthProfile}
              onAttachProfile={updateSelectedTargetAuthProfile}
              onRotateProfile={rotateSelectedAuthProfile}
              onRevokeProfile={() => {
                const profile = authProfiles.find((item) => item.id === selectedAuthProfileId);
                if (profile) {
                  setConfirmActionError("");
                  setRevokeCandidate(profile);
                }
              }}
            />
          </div>
        ) : null}

        {activeView === "operations" ? (
          <div className="operationsWorkspace productPage">
            <div className="viewIntro"><div><h2>Operations & readiness</h2><p>Confirm the worker, database, artifacts, queue, and scanner dependencies, then inspect the workspace activity trail.</p></div></div>
            <OperatorSessionPanel onSessionChange={reloadAuthenticatedWorkspace} />
            <OpsHealthPanel
              health={platformHealth}
              message={opsMessage}
              isRefreshing={isCheckingPlatform}
              checkedAt={platformHealthCheckedAt}
              onRefresh={loadPlatformHealth}
              context="operations"
            />
            <section className="operationsBoundarySection" aria-labelledby="operations-boundaries-title">
              <div className="sectionHeading">
                <div><h3 id="operations-boundaries-title">Persistent safety boundaries</h3><p>These constraints remain enforced even when every local component reports healthy.</p></div>
              </div>
              <div className="operationsBoundaryList">
                <article><AppIcon name="target" /><strong>Exact target scope</strong><p>Only configured Docker services or same-machine host-gateway applications can be launched; general targets remain passive-only.</p></article>
                <article><AppIcon name="shield" /><strong>Safe persistence</strong><p>URLs and evidence are sanitized before database, report, or finding-guidance boundaries.</p></article>
                <article><AppIcon name="operations" /><strong>Local ownership</strong><p>Workspace records and generated artifacts stay isolated inside this deployment.</p></article>
              </div>
            </section>
            <AuditLogPanel
              entries={auditLogs}
              message={auditLogMessage}
              isRefreshing={isRefreshingActivity}
              checkedAt={auditLogCheckedAt}
              onRefresh={loadAuditLogs}
            />
          </div>
        ) : null}

        {activeView === "guide" ? (
          <ProductGuide
            onNavigate={(view, phase) => {
              if (phase) {
                setAuditPhase(phase);
              }
              onActiveViewChange(view);
            }}
          />
        ) : null}
      </div>

      {archiveCandidate ? (
        <ConfirmActionDialog
          eyebrow="Remove saved target"
          title={`Remove ${archiveCandidate.name}?`}
          description="The target will disappear from your active list and its attached credential and repository path will be cleared."
          note="Scan, finding, report, and audit history will be preserved."
          confirmLabel="Remove target"
          cancelLabel="Keep target"
          busyLabel="Removing…"
          icon="trash"
          isBusy={isBusy}
          error={confirmActionError}
          onCancel={() => {
            setConfirmActionError("");
            setArchiveCandidate(null);
          }}
          onConfirm={archiveTarget}
        />
      ) : null}

      {repositoryArchiveCandidate ? (
        <ConfirmActionDialog
          eyebrow="Archive repository subject"
          title={`Archive ${repositoryArchiveCandidate.name}?`}
          description="The repository will no longer be available for new scans and its launch authorization will be cleared."
          note="Historical scans, findings, reports, risk, and audit history remain available."
          confirmLabel="Archive repository"
          cancelLabel="Keep repository"
          busyLabel="Archiving…"
          icon="trash"
          isBusy={isBusy}
          error={confirmActionError}
          onCancel={() => {
            setConfirmActionError("");
            setRepositoryArchiveCandidate(null);
          }}
          onConfirm={archiveRepositoryAsset}
        />
      ) : null}

      {revokeCandidate ? (
        <ConfirmActionDialog
          eyebrow="Revoke credential profile"
          title={`Revoke ${revokeCandidate.label}?`}
          description="The encrypted secret will be erased and this profile will be detached from every target."
          note="Historical metadata and existing scan snapshots remain unchanged."
          confirmLabel="Revoke profile"
          cancelLabel="Keep profile"
          busyLabel="Revoking…"
          icon="credential"
          isBusy={isBusy}
          error={confirmActionError}
          onCancel={() => {
            setConfirmActionError("");
            setRevokeCandidate(null);
          }}
          onConfirm={revokeSelectedAuthProfile}
        />
      ) : null}
    </section>
  );
}

function WorkspaceLoadingState() {
  return (
    <div className="workspaceLoadingState" role="status" aria-live="polite">
      <span className="workspaceLoadingIcon"><AppIcon name="operations" size={20} /></span>
      <div>
        <strong>Loading the local workspace</strong>
        <p>Checking authorized targets, recent audits, normalized evidence, and platform readiness.</p>
      </div>
      <span className="workspaceLoadingPulse" aria-hidden="true" />
    </div>
  );
}

function EvidenceLoadingState() {
  return (
    <div className="evidenceLoadingState" role="status" aria-live="polite">
      <span className="evidenceLoadingIcon"><AppIcon name="activity" size={20} /></span>
      <div>
        <strong>Loading normalized evidence</strong>
        <p>Refreshing findings and triage context for the selected audit.</p>
      </div>
      <span className="workspaceLoadingPulse" aria-hidden="true" />
    </div>
  );
}

function EvidenceFirstRunState({ onStartAudit }: { onStartAudit: () => void }) {
  return (
    <div className="firstRunState">
      <span className="firstRunIcon"><AppIcon name="finding" size={22} /></span>
      <div>
        <p className="panelKicker">First completed audit</p>
        <h3>Findings will appear after evidence is normalized</h3>
        <p>Choose an audit profile, confirm authorization, and let the worker complete normalization. This page will then unlock sorting, triage, evidence detail, tags, and suppression controls.</p>
      </div>
      <button type="button" onClick={onStartAudit}>Configure an audit <AppIcon name="arrow" size={15} /></button>
    </div>
  );
}

function formatShortDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(new Date(value));
}

function hasComparableScanCoverage(scans: Scan[], subjectType: string, subjectId: string) {
  const profileCounts = new Map<string, number>();
  scans.forEach((scan) => {
    if (scan.subject_type !== subjectType || scan.subject_id !== subjectId || !["completed", "completed_with_warnings"].includes(scan.status)) {
      return;
    }
    profileCounts.set(scan.scan_profile_id, (profileCounts.get(scan.scan_profile_id) ?? 0) + 1);
  });
  return [...profileCounts.values()].some((count) => count >= 2);
}

function auditPhaseState(phase: AuditPhase, isActive: boolean, isComplete: boolean, selectedScan: Scan | null) {
  if (phase === "run" && selectedScan) {
    if (selectedScan.status === "failed") return "Failed";
    if (selectedScan.status === "cancelled") return "Cancelled";
    if (["completed", "completed_with_warnings"].includes(selectedScan.status)) return "Complete";
    if (!terminalStatuses.has(selectedScan.status)) return "Running";
  }
  if (isActive) return "In progress";
  if (isComplete) return "Complete";
  return "Pending";
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
  return [item.summary, item.why_it_matters, item.recommended_action, item.owasp_mapping, item.limitations].map(normalizeExplanationText).join("|");
}

function normalizeExplanationText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}
