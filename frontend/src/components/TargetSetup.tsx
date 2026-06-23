"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

type ValidationResult = {
  allowlist_id: string;
  name: string;
  base_url: string;
  allowed_modes: string[];
  max_redirects: number;
  local_demo: boolean;
};

type Target = {
  id: string;
  allowlist_id: string;
  name: string;
  base_url: string;
  allowed_modes: string[];
  repo_path: string | null;
  auth_profile_id: string | null;
  created_at: string;
};

type Scan = {
  id: string;
  target_id: string;
  mode: string;
  status: string;
  current_step: string | null;
  status_message: string | null;
  progress_percent: number;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: string;
};

type Finding = {
  id: string;
  scan_id: string;
  title: string;
  severity: string;
  confidence: string;
  affected_url: string | null;
  affected_file: string | null;
  evidence: string | null;
  source_tool: string;
  scanner_rule_id: string | null;
  dedupe_key: string;
  owasp_category: string | null;
  cwe: string | null;
  reproduction_steps: string | null;
  remediation: string | null;
  false_positive_notes: string | null;
  redaction_applied: boolean;
  raw_artifact_ref: string | null;
  created_at: string;
};

type ReportArtifact = {
  id: string;
  scan_id: string;
  report_type: string;
  view_url: string;
  download_url: string;
  created_at: string;
};

type AiExplanationGroup = {
  label: string;
  count: number;
  finding_ids: string[];
};

type FindingExplanation = {
  finding_id: string;
  priority: number;
  summary: string;
  why_it_matters: string;
  recommended_action: string;
  owasp_mapping: string;
  limitations: string;
};

type AiExplanation = {
  scan_id: string;
  provider: string;
  fallback_used: boolean;
  provider_error: string | null;
  summary: string;
  groups: AiExplanationGroup[];
  explanations: FindingExplanation[];
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
const terminalStatuses = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);
const reportableStatuses = new Set(["completed", "completed_with_warnings"]);
const severityFilters = ["all", "info", "low", "medium", "high", "critical"];
const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function TargetSetup() {
  const [targetUrl, setTargetUrl] = useState("http://juice-shop:3000");
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [repoPath, setRepoPath] = useState("");
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanMode, setScanMode] = useState("passive");
  const [activeDemoAcknowledged, setActiveDemoAcknowledged] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<ReportArtifact[]>([]);
  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [message, setMessage] = useState<string>("Enter an allowlisted local/demo target.");
  const [reportMessage, setReportMessage] = useState<string>("Reports are available after a passive scan completes.");
  const [aiMessage, setAiMessage] = useState<string>("AI explanations are available after a passive scan completes.");
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
      (scanMode !== "active_demo" || activeDemoAcknowledged)
  );
  const filteredFindings = useMemo(() => {
    return findings
      .filter((finding) => severityFilter === "all" || finding.severity === severityFilter)
      .sort((left, right) => (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0));
  }, [findings, severityFilter]);
  const selectedFinding = filteredFindings.find((finding) => finding.id === selectedFindingId) ?? filteredFindings[0] ?? null;

  useEffect(() => {
    void loadTargets();
    void loadScanHistory();
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
    void loadReports(selectedScanId, { onlyIfSelected: true });
    void loadAiExplanation(selectedScanId, { onlyIfSelected: true });
  }, [selectedScanId]);

  async function validateTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsBusy(true);
    setValidation(null);
    setMessage("Validating target against the local allowlist...");

    try {
      const response = await fetch(`${apiBaseUrl}/targets/validate?target_url=${encodeURIComponent(targetUrl)}`);
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Target validation failed.");
      }
      setValidation(body as ValidationResult);
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
      const response = await fetch(`${apiBaseUrl}/targets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          permission_confirmed: permissionConfirmed,
          repo_path: repoPath.trim() || null
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Target creation failed.");
      }
      await loadTargets(body.id);
      setMessage("Target saved. Passive scans are available for this allowlisted target.");
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
    setMessage(`Creating ${scanMode === "active_demo" ? "Active Demo" : "passive"} scan...`);

    try {
      const response = await fetch(`${apiBaseUrl}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: selectedTarget.id,
          mode: scanMode,
          active_demo_acknowledged: activeDemoAcknowledged
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Scan creation failed.");
      }
      const scan = body as Scan;
      setSelectedScanId(scan.id);
      setFindings([]);
      setReports([]);
      setAiExplanation(null);
      setSelectedFindingId("");
      setReportMessage("Reports are available after this passive scan completes.");
      setAiMessage("AI explanations are available after this passive scan completes.");
      setMessage("Scan queued. Worker status will update below.");
      await loadScanHistory(scan.id);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function refreshScan(scanId: string) {
    try {
      const response = await fetch(`${apiBaseUrl}/scans/${scanId}`);
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Scan status refresh failed.");
      }
      const scan = body as Scan;
      setScanHistory((current) => mergeScan(current, scan));
      if (terminalStatuses.has(scan.status)) {
        await loadFindings(scan.id, { onlyIfSelected: true });
        await loadReports(scan.id, { onlyIfSelected: true });
        await loadAiExplanation(scan.id, { onlyIfSelected: true });
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan status refresh failed.");
    }
  }

  async function loadTargets(preferredTargetId?: string) {
    try {
      const response = await fetch(`${apiBaseUrl}/targets`);
      if (!response.ok) {
        return;
      }
      const body = (await response.json()) as Target[];
      setTargets(body);
      const nextTargetId = preferredTargetId ?? selectedTargetId ?? body[0]?.id ?? "";
      setSelectedTargetId(nextTargetId);
    } catch {
      // Target list is optional until the backend is running locally.
    }
  }

  async function loadScanHistory(preferredScanId?: string) {
    try {
      const response = await fetch(`${apiBaseUrl}/scans`);
      if (!response.ok) {
        return;
      }
      const body = (await response.json()) as Scan[];
      setScanHistory(body);
      const nextScanId = preferredScanId ?? selectedScanId ?? body[0]?.id ?? "";
      setSelectedScanId(nextScanId);
    } catch {
      // Scan history is optional until the backend is running locally.
    }
  }

  async function loadFindings(scanId: string, options: { onlyIfSelected?: boolean } = {}) {
    try {
      const response = await fetch(`${apiBaseUrl}/scans/${scanId}/findings`);
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
      const response = await fetch(`${apiBaseUrl}/scans/${scanId}/reports`);
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
      const response = await fetch(`${apiBaseUrl}/scans/${scanId}/ai-explanations`);
      if (!response.ok) {
        if (options.onlyIfSelected && selectedScanIdRef.current !== scanId) {
          return;
        }
        setAiExplanation(null);
        setAiMessage("AI explanations are available after this passive scan completes.");
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
      const response = await fetch(`${apiBaseUrl}/scans/${selectedScan.id}/reports`, {
        method: "POST"
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Report generation failed.");
      }
      setReports(body as ReportArtifact[]);
      setReportMessage("Reports are ready.");
    } catch (error) {
      setReportMessage(error instanceof Error ? error.message : "Report generation failed.");
    } finally {
      setIsGeneratingReports(false);
    }
  }

  return (
    <section className="dashboard" aria-labelledby="dashboard-heading">
      <div className="sectionHeader">
        <div>
          <p className="eyebrow">Phase 9B ZAP Active Demo</p>
          <h2 id="dashboard-heading">Run passive and Active Demo scans, review findings, explain risk, and generate reports</h2>
        </div>
        <span className="phaseBadge">Local demo only</span>
      </div>

      <div className="dashboardGrid">
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
            scanMode={scanMode}
            activeDemoAcknowledged={activeDemoAcknowledged}
            canStartScan={canStartScan}
            isBusy={isBusy}
            onSelectTarget={setSelectedTargetId}
            onSelectScanMode={setScanMode}
            onActiveDemoAcknowledged={setActiveDemoAcknowledged}
            onStartScan={startScan}
          />
        </div>

        <ScanHistory
          scans={scanHistory}
          selectedScanId={selectedScanId}
          onSelectScan={setSelectedScanId}
        />
      </div>

      {selectedScan ? <ScanProgress scan={selectedScan} /> : null}

      <ReportsPanel
        scan={selectedScan}
        reports={reports}
        message={reportMessage}
        isGenerating={isGeneratingReports}
        onGenerate={generateReports}
      />

      <AiExplanationsPanel explanation={aiExplanation} message={aiMessage} />

      <FindingsDashboard
        findings={filteredFindings}
        selectedFinding={selectedFinding}
        severityFilter={severityFilter}
        onSeverityFilter={setSeverityFilter}
        onSelectFinding={setSelectedFindingId}
      />
    </section>
  );
}

function ReportsPanel({
  scan,
  reports,
  message,
  isGenerating,
  onGenerate
}: {
  scan: Scan | null;
  reports: ReportArtifact[];
  message: string;
  isGenerating: boolean;
  onGenerate: () => void;
}) {
  const canGenerate = Boolean(scan && scan.mode === "passive" && reportableStatuses.has(scan.status) && !isGenerating);

  return (
    <div className="reportPanel">
      <div className="panelHeader">
        <h3>Reports</h3>
        <span className="phaseBadge">Passive</span>
      </div>

      <div className="reportActions">
        <button type="button" onClick={onGenerate} disabled={!canGenerate}>
          Generate Reports
        </button>
        <p>{scan && scan.mode !== "passive" ? "Reports remain available for passive scans in this phase." : message}</p>
      </div>

      {reports.length > 0 ? (
        <ul className="reportList">
          {reports.map((report) => (
            <li key={report.id}>
              <strong>{report.report_type}</strong>
              <span>{new Date(report.created_at).toLocaleString()}</span>
              <a href={`${apiBaseUrl}${report.view_url}`} target="_blank" rel="noreferrer">
                View
              </a>
              <a href={`${apiBaseUrl}${report.download_url}`}>
                Download
              </a>
            </li>
          ))}
        </ul>
      ) : (
        <p className="emptyState">No report artifacts yet.</p>
      )}
    </div>
  );
}

function AiExplanationsPanel({ explanation, message }: { explanation: AiExplanation | null; message: string }) {
  return (
    <div className="aiPanel">
      <div className="panelHeader">
        <h3>AI Explanations</h3>
        <span className="phaseBadge">{explanation?.provider ?? "Phase 9A"}</span>
      </div>

      {explanation ? (
        <>
          <dl className="aiMeta">
            <div>
              <dt>Provider</dt>
              <dd>{explanation.provider}</dd>
            </div>
            <div>
              <dt>Fallback</dt>
              <dd>{explanation.fallback_used ? "used" : "not used"}</dd>
            </div>
            <div>
              <dt>Groups</dt>
              <dd>{explanation.groups.length}</dd>
            </div>
          </dl>
          <p>{explanation.summary}</p>
          {explanation.provider_error ? <p className="errorText">{explanation.provider_error}</p> : null}

          {explanation.groups.length > 0 ? (
            <ul className="aiGroupList">
              {explanation.groups.map((group) => (
                <li key={group.label}>
                  <strong>{group.label}</strong>
                  <span>{group.count} finding(s)</span>
                </li>
              ))}
            </ul>
          ) : null}

          {explanation.explanations.length > 0 ? (
            <div className="aiFindingGrid">
              {explanation.explanations.map((item) => (
                <div className="aiFinding" key={item.finding_id}>
                  <div className="aiFindingHeader">
                    <strong>Priority {item.priority}</strong>
                    <small>{item.owasp_mapping}</small>
                  </div>
                  <p>{item.summary}</p>
                  <h4>Recommended action</h4>
                  <p>{item.recommended_action}</p>
                  <h4>Limitations</h4>
                  <p>{item.limitations}</p>
                </div>
              ))}
            </div>
          ) : null}
        </>
      ) : (
        <p className="emptyState">{message}</p>
      )}
    </div>
  );
}

function TargetForm({
  targetUrl,
  repoPath,
  permissionConfirmed,
  validation,
  message,
  isBusy,
  canCreate,
  onTargetUrlChange,
  onRepoPathChange,
  onPermissionChange,
  onValidate,
  onCreateTarget
}: {
  targetUrl: string;
  repoPath: string;
  permissionConfirmed: boolean;
  validation: ValidationResult | null;
  message: string;
  isBusy: boolean;
  canCreate: boolean;
  onTargetUrlChange: (value: string) => void;
  onRepoPathChange: (value: string) => void;
  onPermissionChange: (value: boolean) => void;
  onValidate: (event: FormEvent<HTMLFormElement>) => void;
  onCreateTarget: () => void;
}) {
  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Target</h3>
        <span className="phaseBadge">Allowlisted</span>
      </div>

      <form onSubmit={onValidate} className="targetForm">
        <label>
          <span>Target URL</span>
          <input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="http://juice-shop:3000" />
        </label>

        <label>
          <span>Optional local repo path</span>
          <input value={repoPath} onChange={(event) => onRepoPathChange(event.target.value)} placeholder="/repos/example" />
        </label>

        <label className="checkboxRow">
          <input
            type="checkbox"
            checked={permissionConfirmed}
            onChange={(event) => onPermissionChange(event.target.checked)}
          />
          <span>I own this app, run it locally, or am explicitly authorized to test it.</span>
        </label>

        <div className="actions">
          <button type="submit" disabled={isBusy}>
            Validate
          </button>
          <button type="button" onClick={onCreateTarget} disabled={!canCreate}>
            Save Target
          </button>
        </div>
      </form>

      <p className="formMessage" role="status">
        {message}
      </p>

      {validation ? (
        <div className="validationPanel">
          <h3>{validation.name}</h3>
          <dl>
            <div>
              <dt>Allowlist ID</dt>
              <dd>{validation.allowlist_id}</dd>
            </div>
            <div>
              <dt>Canonical URL</dt>
              <dd>{validation.base_url}</dd>
            </div>
            <div>
              <dt>Allowed Modes</dt>
              <dd>{validation.allowed_modes.join(", ")}</dd>
            </div>
            <div>
              <dt>Redirect Cap</dt>
              <dd>{validation.max_redirects}</dd>
            </div>
          </dl>
        </div>
      ) : null}
    </div>
  );
}

function ScanLauncher({
  targets,
  selectedTargetId,
  scanMode,
  activeDemoAcknowledged,
  canStartScan,
  isBusy,
  onSelectTarget,
  onSelectScanMode,
  onActiveDemoAcknowledged,
  onStartScan
}: {
  targets: Target[];
  selectedTargetId: string;
  scanMode: string;
  activeDemoAcknowledged: boolean;
  canStartScan: boolean;
  isBusy: boolean;
  onSelectTarget: (targetId: string) => void;
  onSelectScanMode: (mode: string) => void;
  onActiveDemoAcknowledged: (acknowledged: boolean) => void;
  onStartScan: () => void;
}) {
  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Scan Mode</h3>
        <span className="phaseBadge">Phase 9B</span>
      </div>

      <label className="selectLabel">
        <span>Saved target</span>
        <select value={selectedTargetId} onChange={(event) => onSelectTarget(event.target.value)}>
          <option value="">No saved targets</option>
          {targets.map((target) => (
            <option key={target.id} value={target.id}>
              {target.name} - {target.base_url}
            </option>
          ))}
        </select>
      </label>

      <div className="modeGrid" aria-label="Scan mode safety controls">
        <button
          type="button"
          className={scanMode === "passive" ? "modeCard modeCardActive" : "modeCard"}
          onClick={() => onSelectScanMode("passive")}
        >
          <strong>Passive</strong>
          <span>Custom crawl plus ZAP passive analysis</span>
        </button>
        <button
          type="button"
          className={scanMode === "active_demo" ? "modeCard modeCardActive" : "modeCard"}
          onClick={() => onSelectScanMode("active_demo")}
        >
          <strong>Active Demo</strong>
          <span>Bounded ZAP active scan for local demo targets</span>
        </button>
        <div className="modeCard">
          <strong>AJAX Short</strong>
          <span>Phase 9C gated</span>
        </div>
      </div>

      {scanMode === "active_demo" ? (
        <label className="checkboxRow activeDemoAck">
          <input
            type="checkbox"
            checked={activeDemoAcknowledged}
            onChange={(event) => onActiveDemoAcknowledged(event.target.checked)}
          />
          <span>I understand Active Demo sends bounded active test traffic only to the configured local/demo target.</span>
        </label>
      ) : null}

      <div className="actions">
        <button type="button" onClick={onStartScan} disabled={!canStartScan || isBusy}>
          {scanMode === "active_demo" ? "Start Active Demo Scan" : "Start Passive Scan"}
        </button>
      </div>
    </div>
  );
}

function ScanHistory({
  scans,
  selectedScanId,
  onSelectScan
}: {
  scans: Scan[];
  selectedScanId: string;
  onSelectScan: (scanId: string) => void;
}) {
  return (
    <div className="panel historyPanel">
      <div className="panelHeader">
        <h3>Scan History</h3>
        <span className="phaseBadge">{scans.length}</span>
      </div>

      {scans.length > 0 ? (
        <ul className="scanTimeline">
          {scans.slice(0, 10).map((scan) => (
            <li key={scan.id}>
              <button
                type="button"
                className={scan.id === selectedScanId ? "scanRow scanRowSelected" : "scanRow"}
                onClick={() => onSelectScan(scan.id)}
              >
                <span className={`statusDot status-${scan.status}`} />
                <span>
                  <strong>{scan.status}</strong>
                  <small>{scan.current_step ?? "no current step"}</small>
                </span>
                <em>{scan.progress_percent}%</em>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="emptyState">No scans yet.</p>
      )}
    </div>
  );
}

function ScanProgress({ scan }: { scan: Scan }) {
  return (
    <div className="scanPanel">
      <div className="scanHeader">
        <div>
          <h3>Selected scan</h3>
          <small>{scan.id}</small>
        </div>
        <span className={`statusPill status-${scan.status}`}>{scan.status}</span>
      </div>
      <div className="progressTrack" aria-label="Scan progress">
        <span style={{ width: `${scan.progress_percent}%` }} />
      </div>
      <dl className="scanMeta">
        <div>
          <dt>Mode</dt>
          <dd>{scan.mode}</dd>
        </div>
        <div>
          <dt>Current Step</dt>
          <dd>{scan.current_step ?? "none"}</dd>
        </div>
        <div>
          <dt>Progress</dt>
          <dd>{scan.progress_percent}%</dd>
        </div>
      </dl>
      <p>{scan.status_message}</p>
      {scan.error_detail ? <p className="errorText">{scan.error_detail}</p> : null}
    </div>
  );
}

function FindingsDashboard({
  findings,
  selectedFinding,
  severityFilter,
  onSeverityFilter,
  onSelectFinding
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  severityFilter: string;
  onSeverityFilter: (severity: string) => void;
  onSelectFinding: (findingId: string) => void;
}) {
  return (
    <div className="findingsLayout">
      <div className="panel findingsPanel">
        <div className="panelHeader">
          <h3>Findings</h3>
          <span className="phaseBadge">{findings.length}</span>
        </div>

        <div className="filterBar" role="tablist" aria-label="Severity filter">
          {severityFilters.map((severity) => (
            <button
              key={severity}
              type="button"
              className={severityFilter === severity ? "filterButton filterButtonActive" : "filterButton"}
              onClick={() => onSeverityFilter(severity)}
            >
              {severity}
            </button>
          ))}
        </div>

        {findings.length > 0 ? (
          <table className="findingsTable">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Tool</th>
                <th>Location</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} onClick={() => onSelectFinding(finding.id)}>
                  <td>
                    <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                  </td>
                  <td>{finding.title}</td>
                  <td>{finding.source_tool}</td>
                  <td>{finding.affected_url ?? finding.affected_file ?? "global"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="emptyState">No findings for this scan/filter.</p>
        )}
      </div>

      <FindingDetail finding={selectedFinding} />
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return (
      <div className="panel findingDetail">
        <div className="panelHeader">
          <h3>Finding Detail</h3>
          <span className="phaseBadge">Empty</span>
        </div>
        <p className="emptyState">Select a completed scan with findings.</p>
      </div>
    );
  }

  return (
    <div className="panel findingDetail">
      <div className="panelHeader">
        <h3>{finding.title}</h3>
        <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
      </div>

      <dl>
        <div>
          <dt>Confidence</dt>
          <dd>{finding.confidence}</dd>
        </div>
        <div>
          <dt>Rule ID</dt>
          <dd>{finding.scanner_rule_id ?? "not provided"}</dd>
        </div>
        <div>
          <dt>CWE</dt>
          <dd>{finding.cwe ?? "not mapped"}</dd>
        </div>
        <div>
          <dt>OWASP</dt>
          <dd>{finding.owasp_category ?? "not mapped"}</dd>
        </div>
        <div>
          <dt>Location</dt>
          <dd>{finding.affected_url ?? finding.affected_file ?? "global"}</dd>
        </div>
        <div>
          <dt>Redaction</dt>
          <dd>{finding.redaction_applied ? "applied" : "not needed"}</dd>
        </div>
      </dl>

      <h4>Evidence</h4>
      <pre>{finding.evidence ?? "No evidence snippet stored."}</pre>

      <h4>Remediation</h4>
      <p>{finding.remediation ?? "Remediation guidance is added in later reporting phases."}</p>
    </div>
  );
}

function mergeScan(scans: Scan[], updatedScan: Scan): Scan[] {
  const found = scans.some((scan) => scan.id === updatedScan.id);
  if (!found) {
    return [updatedScan, ...scans];
  }
  return scans.map((scan) => (scan.id === updatedScan.id ? updatedScan : scan));
}
