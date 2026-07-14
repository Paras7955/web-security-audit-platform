"use client";

/* eslint-disable react-hooks/set-state-in-effect -- Displayed progress intentionally synchronizes with worker state and animation timers. */

import { useEffect, useMemo, useRef, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import type { Scan, ScannerToolRun, Target } from "@/lib/securityAuditApi";
import { ACKNOWLEDGEMENT_LABELS, SCAN_PROFILES } from "@/lib/contracts";

export const terminalStatuses = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);
export const reportableStatuses = new Set(["completed", "completed_with_warnings"]);
type ScanProfileMetadata = (typeof SCAN_PROFILES)[number];
const profilesById: Map<string, ScanProfileMetadata> = new Map(SCAN_PROFILES.map((profile) => [profile.id, profile]));

export function scanProfileForScan(scan: Scan) {
  return profilesById.get(scan.scan_profile_id) ?? null;
}

export function formatScanProfileLabel(profileId: string): string {
  if (profileId === "ajax-short") {
    return "Retired AJAX Short";
  }
  return profilesById.get(profileId)?.label ?? "Historical profile";
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
  acknowledgements,
  canStartScan,
  isBusy,
  onSelectTarget,
  onSelectScanProfile,
  onAttachRepoPath,
  onAcknowledgementChange,
  onStartScan
}: {
  targets: Target[];
  selectedTargetId: string;
  repoPath: string;
  scanProfileId: string;
  acknowledgements: string[];
  canStartScan: boolean;
  isBusy: boolean;
  onSelectTarget: (targetId: string) => void;
  onSelectScanProfile: (profileId: string) => void;
  onAttachRepoPath: () => void;
  onAcknowledgementChange: (code: string, acknowledged: boolean) => void;
  onStartScan: () => void;
}) {
  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedProfile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  const selectedTargetSupportsProfile = selectedTarget?.available_scan_profile_ids.includes(selectedProfile.id) ?? false;
  const repoPathMissing = selectedProfile.requires_repo_path && Boolean(selectedTarget) && !selectedTarget?.has_repo_path;
  const authProfileUnsupported = Boolean(selectedTarget?.auth_profile_id && selectedProfile.mode !== "passive");
  const canAttachRepoPath = Boolean(selectedTarget && repoPath.trim() && !isBusy);

  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Scan Profile</h3>
        <span className="contextBadge">Exact allowlist</span>
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

      {selectedProfile.required_acknowledgements.map((code) => (
        <label className="checkboxRow scanModeAck" key={code}>
          <input
            type="checkbox"
            checked={acknowledgements.includes(code)}
            onChange={(event) => onAcknowledgementChange(code, event.target.checked)}
          />
          <span>{ACKNOWLEDGEMENT_LABELS[code] ?? code}</span>
        </label>
      ))}

      {selectedProfile.requires_repo_path ? (
        <div className="repoPathNotice">
          <p className="formMessage">
            Repo scans use the saved local repo path for this target and do not clone, install dependencies, or execute repo code.
          </p>
          {selectedTarget ? (
            <dl>
              <div>
                <dt>Repository access</dt>
                <dd>{selectedTarget.has_repo_path ? "Configured" : "Not configured"}</dd>
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
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [profileFilter, setProfileFilter] = useState("all");
  const filteredScans = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return scans.filter((scan) => {
      const matchesStatus = statusFilter === "all" || scan.status === statusFilter;
      const matchesProfile = profileFilter === "all" || scan.scan_profile_id === profileFilter;
      const matchesQuery = !normalizedQuery || [
        scan.id,
        scan.status,
        scan.current_step,
        formatScanProfileLabel(scan.scan_profile_id)
      ].some((value) => value?.toLowerCase().includes(normalizedQuery));
      return matchesStatus && matchesProfile && matchesQuery;
    });
  }, [profileFilter, query, scans, statusFilter]);

  return (
    <div className="panel historyPanel">
      <div className="panelHeader">
        <div><p className="panelKicker">Audit trail</p><h3>Scan history</h3></div>
        <span className="contextBadge">{filteredScans.length}/{scans.length}</span>
      </div>

      <div className="historyFilters">
        <label className="searchField compactSearch">
          <AppIcon name="search" size={15} />
          <span className="srOnly">Search scans</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search scans" />
        </label>
        <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label="Filter scan history by status">
          <option value="all">All statuses</option>
          {[...new Set(scans.map((scan) => scan.status))].map((status) => <option value={status} key={status}>{status.replaceAll("_", " ")}</option>)}
        </select>
        <select value={profileFilter} onChange={(event) => setProfileFilter(event.target.value)} aria-label="Filter scan history by profile">
          <option value="all">All profiles</option>
          {[...new Set(scans.map((scan) => scan.scan_profile_id))].map((profileId) => <option value={profileId} key={profileId}>{formatScanProfileLabel(profileId)}</option>)}
        </select>
      </div>

      {filteredScans.length > 0 ? (
        <ul className="scanTimeline">
          {filteredScans.map((scan) => (
            <li key={scan.id}>
              <button
                type="button"
                className={scan.id === selectedScanId ? "scanRow scanRowSelected" : "scanRow"}
                onClick={() => onSelectScan(scan.id)}
              >
                <span className={`statusDot status-${scan.status}`} />
                <span>
                  <strong>{formatScanProfileLabel(scan.scan_profile_id)}</strong>
                  <small>{scan.status.replaceAll("_", " ")} · {formatScanDate(scan.created_at)}</small>
                </span>
                <em>{scan.progress_percent}%</em>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="emptyState">{scans.length ? "No scans match these filters." : "No scans yet."}</p>
      )}
    </div>
  );
}

function formatScanDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}

export function ScanProgress({
  scan,
  toolRuns,
  isCancelling,
  onCancel
}: {
  scan: Scan;
  toolRuns: ScannerToolRun[];
  isCancelling: boolean;
  onCancel: () => void;
}) {
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
          <dt>Profile</dt>
          <dd>{formatScanProfileLabel(scan.scan_profile_id)}</dd>
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
      {scan.failure ? <p className="errorText">{scan.failure.message} ({scan.failure.code})</p> : null}
      {toolRuns.length > 0 ? (
        <div className="toolRunPanel">
          <h4>Scanner receipts</h4>
          <ul className="opsList">
            {toolRuns.map((toolRun) => (
              <li key={toolRun.id}>
                <span className={`statusDot status-${toolRun.status}`} />
                <strong>{toolRun.tool_name}</strong>
                <em>{toolRun.status}</em>
                <small>
                  {toolRun.tool_version ?? "version unavailable"} · {toolRun.finding_count} finding(s)
                  {toolRun.warning_code ? ` · ${toolRun.warning_code}` : ""}
                </small>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function useSmoothedProgress(scan: Scan): number {
  const isTerminal = terminalStatuses.has(scan.status);
  const serverProgress = clampProgress(scan.progress_percent);
  const ceiling = useMemo(() => progressCeiling(scan), [scan]);
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
