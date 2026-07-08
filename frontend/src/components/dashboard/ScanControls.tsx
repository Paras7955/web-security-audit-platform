"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import type { Scan, Target } from "@/lib/securityAuditApi";
import { SCAN_PROFILES } from "@/lib/contracts";

export const terminalStatuses = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);
export const reportableStatuses = new Set(["completed", "completed_with_warnings"]);
type ScanProfileMetadata = (typeof SCAN_PROFILES)[number];
const profilesById: Map<string, ScanProfileMetadata> = new Map(SCAN_PROFILES.map((profile) => [profile.id, profile]));
const profilesByMode: Map<string, ScanProfileMetadata> = new Map(SCAN_PROFILES.map((profile) => [profile.mode, profile]));

export function scanProfileForScan(scan: Scan) {
  if (!scan.scan_profile_id) {
    return profilesByMode.get(scan.mode) ?? null;
  }
  const profile = profilesById.get(scan.scan_profile_id);
  if (profile && profile.mode === scan.mode) {
    return profile;
  }
  return null;
}

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

export function formatScanProfileLabel(profileId: string, mode: string): string {
  return profilesById.get(profileId)?.label ?? formatScanModeLabel(mode);
}

export function canUseReports(scan: Scan): boolean {
  return Boolean(scanProfileForScan(scan)?.reports_enabled);
}

export function canUseAi(scan: Scan): boolean {
  return Boolean(scanProfileForScan(scan)?.ai_enabled);
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
  scanProfileId,
  activeDemoAcknowledged,
  ajaxShortAcknowledged,
  canStartScan,
  isBusy,
  onSelectTarget,
  onSelectScanProfile,
  onAttachRepoPath,
  onActiveDemoAcknowledged,
  onAjaxShortAcknowledged,
  onStartScan
}: {
  targets: Target[];
  selectedTargetId: string;
  repoPath: string;
  scanProfileId: string;
  activeDemoAcknowledged: boolean;
  ajaxShortAcknowledged: boolean;
  canStartScan: boolean;
  isBusy: boolean;
  onSelectTarget: (targetId: string) => void;
  onSelectScanProfile: (profileId: string) => void;
  onAttachRepoPath: () => void;
  onActiveDemoAcknowledged: (acknowledged: boolean) => void;
  onAjaxShortAcknowledged: (acknowledged: boolean) => void;
  onStartScan: () => void;
}) {
  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedProfile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  const selectedTargetSupportsProfile = selectedTarget?.allowed_modes.includes(selectedProfile.mode) ?? false;
  const repoPathMissing = selectedProfile.requires_repo_path && Boolean(selectedTarget) && !selectedTarget?.repo_path;
  const authProfileUnsupported = Boolean(selectedTarget?.auth_profile_id && selectedProfile.mode !== "passive");
  const canAttachRepoPath = Boolean(selectedTarget && repoPath.trim() && !isBusy);

  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Scan Profile</h3>
        <span className="phaseBadge">Profiled</span>
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

      {selectedTarget?.auth_profile_id ? (
        <p className="formMessage">Selected target has an auth profile. Authenticated scanner requests are available for Passive Web only.</p>
      ) : null}

      <div className="modeGrid" aria-label="Scan profile safety controls">
        {SCAN_PROFILES.map((profile) => (
          <button
            key={profile.id}
            type="button"
            className={scanProfileId === profile.id ? "modeCard modeCardActive" : "modeCard"}
            onClick={() => onSelectScanProfile(profile.id)}
          >
            <strong>{profile.label}</strong>
            <span>{profile.description}</span>
          </button>
        ))}
      </div>

      {selectedProfile.requires_active_demo_acknowledgement ? (
        <label className="checkboxRow scanModeAck">
          <input
            type="checkbox"
            checked={activeDemoAcknowledged}
            onChange={(event) => onActiveDemoAcknowledged(event.target.checked)}
          />
          <span>I understand Active Demo sends bounded active test traffic only to the configured local/demo target.</span>
        </label>
      ) : null}

      {selectedProfile.requires_ajax_short_acknowledgement ? (
        <label className="checkboxRow scanModeAck">
          <input
            type="checkbox"
            checked={ajaxShortAcknowledged}
            onChange={(event) => onAjaxShortAcknowledged(event.target.checked)}
          />
          <span>I understand AJAX Short drives a bounded browser crawl only against the configured local/demo target.</span>
        </label>
      ) : null}

      {selectedProfile.requires_repo_path ? (
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
          Start {selectedProfile.label} Scan
        </button>
      </div>
      {selectedTarget && !selectedTargetSupportsProfile ? (
        <p className="formMessage">This scan profile is not allowed for the selected target.</p>
      ) : null}
      {authProfileUnsupported ? (
        <p className="formMessage errorText">Auth profiles are currently supported only for passive-web scans.</p>
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

export function ScanProgress({ scan, isCancelling, onCancel }: { scan: Scan; isCancelling: boolean; onCancel: () => void }) {
  const displayedProgress = useSmoothedProgress(scan);
  const canCancel = !terminalStatuses.has(scan.status) && !scan.cancellation_requested_at;

  return (
    <div className="scanPanel">
      <div className="scanHeader">
        <div>
          <h3>Selected scan</h3>
          <small>{scan.id}</small>
        </div>
        <span className={`statusPill status-${scan.status}`}>{scan.status}</span>
      </div>
      <div className="scanActions">
        <button type="button" className="secondaryButton" onClick={onCancel} disabled={!canCancel || isCancelling}>
          {scan.cancellation_requested_at ? "Cancellation Requested" : "Cancel Scan"}
        </button>
      </div>
      <div className="progressTrack" aria-label="Scan progress">
        <span style={{ width: `${displayedProgress}%` }} />
      </div>
      <dl className="scanMeta">
        <div>
          <dt>Mode</dt>
          <dd>{scan.mode}</dd>
        </div>
        <div>
          <dt>Profile</dt>
          <dd>{formatScanProfileLabel(scan.scan_profile_id, scan.mode)}</dd>
        </div>
        <div>
          <dt>Auth</dt>
          <dd>{scan.auth_profile_id ? "Configured" : "None"}</dd>
        </div>
        <div>
          <dt>Current Step</dt>
          <dd>{scan.current_step ?? "none"}</dd>
        </div>
        <div>
          <dt>Progress</dt>
          <dd>{displayedProgress}%</dd>
        </div>
      </dl>
      <p>{scan.status_message}</p>
      {scan.cancellation_requested_at ? <p className="formMessage">Cancellation requested. Worker will stop at a safe checkpoint.</p> : null}
      {scan.error_detail ? <p className="errorText">{scan.error_detail}</p> : null}
    </div>
  );
}

function useSmoothedProgress(scan: Scan): number {
  const isTerminal = terminalStatuses.has(scan.status);
  const serverProgress = clampProgress(scan.progress_percent);
  const ceiling = useMemo(() => progressCeiling(scan), [scan.status, scan.progress_percent]);
  const [displayedProgress, setDisplayedProgress] = useState(() => (isTerminal ? serverProgress : Math.min(serverProgress, ceiling)));
  const scanIdRef = useRef(scan.id);

  useEffect(() => {
    if (scanIdRef.current !== scan.id) {
      scanIdRef.current = scan.id;
      setDisplayedProgress(isTerminal ? serverProgress : Math.min(serverProgress, ceiling));
    }
  }, [ceiling, isTerminal, scan.id, serverProgress]);

  useEffect(() => {
    if (isTerminal) {
      setDisplayedProgress(serverProgress);
      return;
    }

    const timer = window.setInterval(() => {
      setDisplayedProgress((current) => {
        if (current >= ceiling) {
          return current;
        }
        const step = serverProgress > current ? 4 : 1;
        return Math.min(current + step, ceiling);
      });
    }, 700);

    return () => window.clearInterval(timer);
  }, [ceiling, isTerminal, serverProgress]);

  return displayedProgress;
}

function progressCeiling(scan: Scan): number {
  if (terminalStatuses.has(scan.status)) {
    return clampProgress(scan.progress_percent);
  }
  if (scan.status === "queued") {
    return Math.max(clampProgress(scan.progress_percent), 12);
  }
  if (scan.status === "validating") {
    return Math.max(clampProgress(scan.progress_percent), 28);
  }
  if (scan.status === "normalizing") {
    return Math.max(clampProgress(scan.progress_percent), 96);
  }
  return Math.max(clampProgress(scan.progress_percent), 92);
}

function clampProgress(progress: number): number {
  return Math.max(0, Math.min(100, Math.round(progress)));
}
