import type { Scan, Target } from "@/lib/securityAuditApi";

export const terminalStatuses = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);
export const reportableStatuses = new Set(["completed", "completed_with_warnings"]);
export const reportableModes = new Set(["passive", "active_demo", "repo"]);
export const aiModes = new Set(["passive", "active_demo"]);

export function formatScanModeLabel(mode: string): string {
  if (mode === "active_demo") {
    return "Active Demo";
  }
  if (mode === "ajax_short") {
    return "AJAX Short";
  }
  if (mode === "repo") {
    return "Repo";
  }
  return "Passive";
}

export function canUseReports(scan: Scan): boolean {
  return reportableModes.has(scan.mode);
}

export function canUseAi(scan: Scan): boolean {
  return aiModes.has(scan.mode);
}

export function mergeScan(scans: Scan[], updatedScan: Scan): Scan[] {
  const found = scans.some((scan) => scan.id === updatedScan.id);
  if (!found) {
    return [updatedScan, ...scans];
  }
  return scans.map((scan) => (scan.id === updatedScan.id ? updatedScan : scan));
}

export function ScanLauncher({
  targets,
  selectedTargetId,
  repoPath,
  scanMode,
  activeDemoAcknowledged,
  ajaxShortAcknowledged,
  canStartScan,
  isBusy,
  onSelectTarget,
  onSelectScanMode,
  onAttachRepoPath,
  onActiveDemoAcknowledged,
  onAjaxShortAcknowledged,
  onStartScan
}: {
  targets: Target[];
  selectedTargetId: string;
  repoPath: string;
  scanMode: string;
  activeDemoAcknowledged: boolean;
  ajaxShortAcknowledged: boolean;
  canStartScan: boolean;
  isBusy: boolean;
  onSelectTarget: (targetId: string) => void;
  onSelectScanMode: (mode: string) => void;
  onAttachRepoPath: () => void;
  onActiveDemoAcknowledged: (acknowledged: boolean) => void;
  onAjaxShortAcknowledged: (acknowledged: boolean) => void;
  onStartScan: () => void;
}) {
  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedTargetSupportsMode = selectedTarget?.allowed_modes.includes(scanMode) ?? false;
  const repoPathMissing = scanMode === "repo" && Boolean(selectedTarget) && !selectedTarget?.repo_path;
  const canAttachRepoPath = Boolean(selectedTarget && repoPath.trim() && !isBusy);

  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Scan Mode</h3>
        <span className="phaseBadge">Profiles next</span>
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
        {["passive", "active_demo", "ajax_short", "repo"].map((mode) => (
          <button
            key={mode}
            type="button"
            className={scanMode === mode ? "modeCard modeCardActive" : "modeCard"}
            onClick={() => onSelectScanMode(mode)}
          >
            <strong>{formatScanModeLabel(mode)}</strong>
            <span>{modeDescription(mode)}</span>
          </button>
        ))}
      </div>

      {scanMode === "active_demo" ? (
        <label className="checkboxRow scanModeAck">
          <input
            type="checkbox"
            checked={activeDemoAcknowledged}
            onChange={(event) => onActiveDemoAcknowledged(event.target.checked)}
          />
          <span>I understand Active Demo sends bounded active test traffic only to the configured local/demo target.</span>
        </label>
      ) : null}

      {scanMode === "ajax_short" ? (
        <label className="checkboxRow scanModeAck">
          <input
            type="checkbox"
            checked={ajaxShortAcknowledged}
            onChange={(event) => onAjaxShortAcknowledged(event.target.checked)}
          />
          <span>I understand AJAX Short drives a bounded browser crawl only against the configured local/demo target.</span>
        </label>
      ) : null}

      {scanMode === "repo" ? (
        <div className="repoPathNotice">
          <p className="formMessage">
            Repo scans use the saved local repo path for this target and do not clone, install dependencies, or execute repo code.
          </p>
          {selectedTarget ? (
            <dl>
              <div>
                <dt>Saved repo path</dt>
                <dd>{selectedTarget.repo_path ?? "None attached"}</dd>
              </div>
            </dl>
          ) : null}
          {repoPathMissing ? (
            <div className="inlineAction">
              <p>Attach the repo path from the target form before starting this repo scan.</p>
              <button type="button" onClick={onAttachRepoPath} disabled={!canAttachRepoPath}>
                Attach Repo Path
              </button>
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="actions">
        <button type="button" onClick={onStartScan} disabled={!canStartScan || isBusy}>
          Start {formatScanModeLabel(scanMode)} Scan
        </button>
      </div>
      {selectedTarget && !selectedTargetSupportsMode ? (
        <p className="formMessage">This scan mode is not allowed for the selected target.</p>
      ) : null}
    </div>
  );
}

export function ScanHistory({
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

export function ScanProgress({ scan }: { scan: Scan }) {
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

function modeDescription(mode: string): string {
  if (mode === "active_demo") {
    return "Bounded ZAP active scan for local demo targets";
  }
  if (mode === "ajax_short") {
    return "Bounded ZAP browser crawl for local demo targets";
  }
  if (mode === "repo") {
    return "Deterministic secret and dependency scanner adapters";
  }
  return "Custom crawl plus ZAP passive analysis";
}
