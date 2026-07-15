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

export function ScanProfileSelector({
  targets,
  selectedTargetId,
  repoPath,
  scanProfileId,
  isBusy,
  onSelectTarget,
  onSelectScanProfile,
  onAttachRepoPath,
  onContinue
}: {
  targets: Target[];
  selectedTargetId: string;
  repoPath: string;
  scanProfileId: string;
  isBusy: boolean;
  onSelectTarget: (targetId: string) => void;
  onSelectScanProfile: (profileId: string) => void;
  onAttachRepoPath: () => void;
  onContinue: () => void;
}) {
  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const selectedProfile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  const selectedTargetSupportsProfile = selectedTarget?.available_scan_profile_ids.includes(selectedProfile.id) ?? false;
  const repoPathMissing = selectedProfile.requires_repo_path && Boolean(selectedTarget) && !selectedTarget?.has_repo_path;
  const authProfileUnsupported = Boolean(selectedTarget?.auth_profile_id && selectedProfile.mode !== "passive");
  const canAttachRepoPath = Boolean(selectedTarget && repoPath.trim() && !isBusy);

  return (
    <div className="profileWorkspace">
      <div className="profileSelectorHeader">
        <div>
          <h2>Choose how to audit this target</h2>
          <p>Each profile uses a different bounded tool path. Availability is enforced by the selected target.</p>
        </div>
        <label className="selectLabel compactSelect">
          <span>Selected target</span>
          <select value={selectedTargetId} onChange={(event) => onSelectTarget(event.target.value)}>
            <option value="">No saved targets</option>
            {targets.map((target) => (
              <option key={target.id} value={target.id}>{target.name} — {target.base_url}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="profileDecisionGrid">
        <div className="modeGrid" role="group" aria-label="Audit profile choices">
          {SCAN_PROFILES.map((profile) => {
            const isAvailable = selectedTarget?.available_scan_profile_ids.includes(profile.id) ?? false;
            const capabilities = profileCapabilities(profile);
            return (
              <button
                key={profile.id}
                type="button"
                aria-pressed={scanProfileId === profile.id}
                className={`${scanProfileId === profile.id ? "modeCard modeCardActive" : "modeCard"}${!isAvailable && selectedTarget ? " modeCardUnavailable" : ""}`}
                onClick={() => onSelectScanProfile(profile.id)}
              >
                <span className="modeCardIcon"><AppIcon name={profileIcon(profile.id)} size={28} /></span>
                <span className="modeCardTop">
                  <strong>{profile.label}</strong>
                  <em>{isAvailable ? "Available" : "Unavailable"}</em>
                </span>
                <span>{profile.description}</span>
                <span className="profileMeta">{capabilities.join(" · ")}</span>
              </button>
            );
          })}
        </div>

        <aside className="profileContext" aria-live="polite">
          <div className="profileContextHeading">
            <span className="profileContextIcon"><AppIcon name={selectedProfile.mode === "repo" ? "intelligence" : "scan"} size={20} /></span>
            <div><span>Selected profile</span><h3>{selectedProfile.label}</h3></div>
          </div>
          <ul className="profileAssuranceList">
            <li><AppIcon name="shield" size={17} /><span><strong>Guarded eligibility</strong><small>{selectedTargetSupportsProfile ? "Allowed for the selected target" : "Not allowed for the selected target"}</small></span></li>
            <li><AppIcon name="intelligence" size={17} /><span><strong>Sanitized outputs</strong><small>{selectedProfile.reports_enabled ? `Reports${selectedProfile.ai_enabled ? " and explanations" : ""} available` : "No reports or explanations"}</small></span></li>
            <li><AppIcon name="credential" size={17} /><span><strong>Credential boundary</strong><small>{selectedProfile.mode === "passive" ? "Optional guarded credential" : "Credentials are never used"}</small></span></li>
          </ul>
          {selectedProfile.requires_repo_path ? (
            <div className="repoPathNotice">
              <p>Repository scans stage bounded regular files only. ScopeHarbor never clones, builds, installs, runs hooks, or executes repository code.</p>
              <strong>{selectedTarget?.has_repo_path ? "Repository path attached" : "Repository path required"}</strong>
              {repoPathMissing ? <button type="button" onClick={onAttachRepoPath} disabled={!canAttachRepoPath}>Attach saved repo path</button> : null}
            </div>
          ) : null}
          {authProfileUnsupported ? <p className="formMessage errorText">Detach the target credential or choose Passive Web. Credentials never enter active, browser, or repository scans.</p> : null}
          <button type="button" onClick={onContinue} disabled={!selectedTargetSupportsProfile || repoPathMissing || authProfileUnsupported}>
            Continue to authorization <AppIcon name="arrow" size={15} />
          </button>
        </aside>
      </div>
    </div>
  );
}

export function ScanAuthorization({
  target,
  scanProfileId,
  acknowledgements,
  profileReady,
  onAcknowledgementChange,
  onOpenCredentials,
  onContinue
}: {
  target: Target | null;
  scanProfileId: string;
  acknowledgements: string[];
  profileReady: boolean;
  onAcknowledgementChange: (code: string, acknowledged: boolean) => void;
  onOpenCredentials: () => void;
  onContinue: () => void;
}) {
  const profile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  const allConfirmed = profile.required_acknowledgements.every((code) => acknowledgements.includes(code));
  const authProfileUnsupported = Boolean(target?.auth_profile_id && profile.mode !== "passive");

  return (
    <div className="authorizationLayout">
      <section className="authorizationChecklist">
        <div className="panelHeader">
          <div><p className="panelKicker">Explicit permission</p><h2>Confirm the audit boundary</h2></div>
          <span className="contextBadge">Required</span>
        </div>
        <p>ScopeHarbor records these confirmations with the scan request. They do not broaden the backend allowlist.</p>
        <div className="authorizationSummary">
          <span><AppIcon name="target" size={16} />{target?.name ?? "No target selected"}</span>
          <span><AppIcon name="scan" size={16} />{profile.label}</span>
        </div>
        <div className="acknowledgementList">
          {profile.required_acknowledgements.map((code) => (
            <label className="checkboxRow scanModeAck" key={code}>
              <input
                type="checkbox"
                checked={acknowledgements.includes(code)}
                onChange={(event) => onAcknowledgementChange(code, event.target.checked)}
              />
              <span>{ACKNOWLEDGEMENT_LABELS[code] ?? code}</span>
            </label>
          ))}
        </div>
        {authProfileUnsupported ? <p className="formMessage errorText">This target has a credential attached. Credentials are limited to guarded Passive Web requests, so detach it before continuing.</p> : null}
        <button type="button" onClick={onContinue} disabled={!profileReady || !allConfirmed || authProfileUnsupported}>
          Continue to launch review <AppIcon name="arrow" size={15} />
        </button>
      </section>

      <aside className="boundarySummary">
        <p className="panelKicker">What remains enforced</p>
        <h3>Permission does not replace policy</h3>
        <ul>
          <li><AppIcon name="check" size={15} /><span><strong>Exact destination</strong>Scanner traffic remains bound to the configured Docker service.</span></li>
          <li><AppIcon name="check" size={15} /><span><strong>Redirect checks</strong>Every redirect is revalidated; automatic redirects stay disabled.</span></li>
          <li><AppIcon name="check" size={15} /><span><strong>Sanitized output</strong>Queries, fragments, secrets, and raw bodies do not cross report or AI boundaries.</span></li>
        </ul>
        {profile.mode === "passive" ? (
          <div className="credentialPrompt">
            <span><AppIcon name="credential" size={18} /></span>
            <div><strong>Optional passive credential</strong><p>Attach an encrypted bearer token or static header only if this target needs guarded authenticated requests.</p></div>
            <button type="button" className="textButton" onClick={onOpenCredentials}>Manage credentials</button>
          </div>
        ) : null}
      </aside>
    </div>
  );
}

export function ScanLaunchPanel({
  target,
  scanProfileId,
  canStartScan,
  platformReady,
  isBusy,
  onStartScan
}: {
  target: Target | null;
  scanProfileId: string;
  canStartScan: boolean;
  platformReady: boolean;
  isBusy: boolean;
  onStartScan: () => void;
}) {
  const profile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  return (
    <section className="launchReview">
      <div>
        <p className="panelKicker">Launch review</p>
        <h2>{profile.label} is ready to queue</h2>
        <p>Review the exact target and profile once more. The worker will revalidate workspace, target, and policy context before any tool runs.</p>
      </div>
      <dl>
        <div><dt>Target</dt><dd>{target?.name ?? "Not selected"}</dd></div>
        <div><dt>Canonical address</dt><dd>{target?.base_url ?? "—"}</dd></div>
        <div><dt>Profile</dt><dd>{profile.label}</dd></div>
        <div><dt>Platform</dt><dd>{platformReady ? "Ready" : "Needs attention"}</dd></div>
      </dl>
      <button type="button" onClick={onStartScan} disabled={!canStartScan || isBusy}>
        {isBusy ? "Queuing audit…" : `Launch ${profile.label}`} <AppIcon name="arrow" size={15} />
      </button>
      {!platformReady ? <p className="formMessage errorText">Confirm platform readiness before launch. Refresh the Ready phase after the worker and database are healthy.</p> : null}
    </section>
  );
}

function profileCapabilities(profile: ScanProfileMetadata) {
  const capabilities = [profile.local_demo_only ? "Local demo" : "Allowlisted", profile.reports_enabled ? "Reports" : "No reports"];
  capabilities.push(profile.ai_enabled ? "AI eligible" : "No AI");
  if (profile.mode === "repo") capabilities.push("Offline DB");
  return capabilities;
}

function profileIcon(profileId: string): "target" | "operations" | "activity" | "intelligence" {
  if (profileId === "active-demo") return "operations";
  if (profileId === "modern-web-crawl") return "activity";
  if (profileId === "repo") return "intelligence";
  return "target";
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
      <div className="progressTrack" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={displayedProgress}>
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
      <p role="status">{scan.status_message}</p>
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
