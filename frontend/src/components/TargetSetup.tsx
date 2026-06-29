"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import { AiExplanationsPanel } from "@/components/dashboard/AiExplanationsPanel";
import { FindingsDashboard, severityRank } from "@/components/dashboard/FindingsDashboard";
import { ReportsPanel } from "@/components/dashboard/ReportsPanel";
import {
  ScanHistory,
  ScanLauncher,
  ScanProgress,
  canUseAi,
  canUseReports,
  formatScanModeLabel,
  mergeScan,
  terminalStatuses
} from "@/components/dashboard/ScanControls";
import { TargetForm } from "@/components/dashboard/TargetForm";
import {
  AiExplanation,
  Finding,
  ReportArtifact,
  Scan,
  Target,
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
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanMode, setScanMode] = useState("passive");
  const [activeDemoAcknowledged, setActiveDemoAcknowledged] = useState(false);
  const [ajaxShortAcknowledged, setAjaxShortAcknowledged] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<ReportArtifact[]>([]);
  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [message, setMessage] = useState("Enter an allowlisted local/demo target.");
  const [reportMessage, setReportMessage] = useState("Reports are available after a passive, Active Demo, or Repo scan completes.");
  const [aiMessage, setAiMessage] = useState("AI explanations are available after a passive or Active Demo scan completes.");
  const [bootstrapError, setBootstrapError] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  const [isGeneratingReports, setIsGeneratingReports] = useState(false);
  const selectedScanIdRef = useRef("");
  const severityFilterRef = useRef("all");

  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedScan = scanHistory.find((scan) => scan.id === selectedScanId) ?? null;
  const canCreate = useMemo(() => Boolean(validation && permissionConfirmed && !isBusy), [validation, permissionConfirmed, isBusy]);
  const canStartScan = Boolean(
    selectedTarget &&
      selectedTarget.allowed_modes.includes(scanMode) &&
      !isBusy &&
      (scanMode !== "repo" || Boolean(selectedTarget.repo_path)) &&
      (scanMode !== "active_demo" || activeDemoAcknowledged) &&
      (scanMode !== "ajax_short" || ajaxShortAcknowledged)
  );
  const filteredFindings = useMemo(() => {
    return findings
      .filter((finding) => severityFilter === "all" || finding.severity === severityFilter)
      .sort((left, right) => (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0));
  }, [findings, severityFilter]);
  const selectedFinding = filteredFindings.find((finding) => finding.id === selectedFindingId) ?? filteredFindings[0] ?? null;

  useEffect(() => {
    void loadInitialData();
  }, []);

  useEffect(() => {
    selectedScanIdRef.current = selectedScanId;
  }, [selectedScanId]);

  useEffect(() => {
    severityFilterRef.current = severityFilter;
  }, [severityFilter]);

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
  }, [selectedScanId, selectedScan?.mode]);

  async function loadInitialData() {
    setBootstrapError("");
    const results = await Promise.allSettled([loadTargets(), loadScanHistory()]);
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
          repo_path: repoPath.trim() || null
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

    setIsBusy(true);
    setMessage(`Creating ${formatScanModeLabel(scanMode)} scan...`);

    try {
      const response = await apiFetch(`${apiBaseUrl}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: selectedTarget.id,
          mode: scanMode,
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

  async function loadScanHistory(preferredScanId?: string) {
    const response = await apiFetch(`${apiBaseUrl}/scans`);
    const body = await readJson<Scan[]>(response, "Scan history load failed.");
    setScanHistory(body);
    setSelectedScanId(preferredScanId ?? selectedScanId ?? body[0]?.id ?? "");
    setBootstrapError("");
  }

  async function loadFindings(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const response = await apiFetch(`${apiBaseUrl}/scans/${scanId}/findings`);
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
        const currentSeverityFilter = severityFilterRef.current;
        const nextFindings = body.filter((finding) => currentSeverityFilter === "all" || finding.severity === currentSeverityFilter);
        return nextFindings.some((finding) => finding.id === current) ? current : nextFindings[0]?.id ?? "";
      });
    } catch {
      if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
        return;
      }
      setFindings([]);
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
        <span className="phaseBadge">Phase 12 shell</span>
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
          <ScanLauncher
            targets={targets}
            selectedTargetId={selectedTargetId}
            repoPath={repoPath}
            scanMode={scanMode}
            activeDemoAcknowledged={activeDemoAcknowledged}
            ajaxShortAcknowledged={ajaxShortAcknowledged}
            canStartScan={canStartScan}
            isBusy={isBusy}
            onSelectTarget={setSelectedTargetId}
            onSelectScanMode={setScanMode}
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

      <AiExplanationsPanel explanation={aiExplanation} message={aiMessage} />

      <div id="findings">
        <FindingsDashboard
          findings={filteredFindings}
          selectedFinding={selectedFinding}
          severityFilter={severityFilter}
          onSeverityFilter={setSeverityFilter}
          onSelectFinding={setSelectedFindingId}
        />
      </div>
    </section>
  );
}
