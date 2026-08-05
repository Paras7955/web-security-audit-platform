"use client";

/* eslint-disable react-hooks/set-state-in-effect -- Displayed progress intentionally synchronizes with worker state and animation timers. */

import { useEffect, useMemo, useRef, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import type { AuditSubject, Scan, ScannerToolRun } from "@/lib/securityAuditApi";
import { ACKNOWLEDGEMENT_LABELS, SCAN_PROFILES } from "@/lib/contracts";

export const terminalStatuses = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);
export const reportableStatuses = new Set(["completed", "completed_with_warnings"]);
type ScanProfileMetadata = (typeof SCAN_PROFILES)[number];
const profilesById: Map<string, ScanProfileMetadata> = new Map(SCAN_PROFILES.map((profile) => [profile.id, profile]));
const receiptPreviewCount = 4;

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
  subjects,
  selectedSubjectId,
  scanProfileId,
  onSelectSubject,
  onSelectScanProfile,
  onContinue
}: {
  subjects: AuditSubject[];
  selectedSubjectId: string;
  scanProfileId: string;
  onSelectSubject: (subjectId: string) => void;
  onSelectScanProfile: (profileId: string) => void;
  onContinue: () => void;
}) {
  const selectedSubject = subjects.find((subject) => subject.id === selectedSubjectId) ?? null;
  const selectedProfile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  const selectedSubjectSupportsProfile = selectedSubject?.availableScanProfileIds.includes(selectedProfile.id) ?? false;
  const authProfileUnsupported = Boolean(selectedSubject?.target?.auth_profile_id && selectedProfile.mode !== "passive");

  return (
    <div className="profileWorkspace">
      <div className="profileSelectorHeader">
        <div>
          <h2>Choose how to audit this subject</h2>
          <p>Each profile uses a different bounded tool path. Availability is enforced by the selected web target or repository asset.</p>
        </div>
        <label className="selectLabel compactSelect">
          <span>Selected subject</span>
          <select value={selectedSubjectId} onChange={(event) => onSelectSubject(event.target.value)}>
            <option value="">No saved subjects</option>
            {subjects.map((subject) => (
              <option key={subject.id} value={subject.id}>{subject.subjectType === "repository_asset" ? "Repository: " : "Web: "}{subject.name}</option>
            ))}
          </select>
          {selectedSubject ? <small className="compactSelectMeta">{selectedSubject.detail}</small> : null}
        </label>
      </div>

      <div className="profileDecisionGrid">
        <div className="modeGrid" role="group" aria-label="Audit profile choices">
          {SCAN_PROFILES.map((profile) => {
            const isAvailable = selectedSubject?.availableScanProfileIds.includes(profile.id) ?? false;
            const isUnavailable = Boolean(selectedSubject && !isAvailable);
            const isSelected = scanProfileId === profile.id;
            const capabilities = profileCapabilities(profile);
            return (
              <button
                key={profile.id}
                type="button"
                aria-pressed={isSelected}
                aria-disabled={isUnavailable}
                disabled={isUnavailable}
                className={`modeCard${isSelected && !isUnavailable ? " modeCardActive" : ""}${isUnavailable ? " modeCardUnavailable" : ""}`}
                onClick={() => onSelectScanProfile(profile.id)}
              >
                <span className="modeCardIcon"><AppIcon name={profileIcon(profile.id)} size={28} /></span>
                <span className="modeCardTop">
                  <strong>{profile.label}</strong>
                  <em>{!selectedSubject ? "Needs subject" : isUnavailable ? "Unavailable" : isSelected ? "Selected" : "Available"}</em>
                </span>
                <span>{profileDecisionCopy(profile.id)}</span>
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
            <li><AppIcon name="shield" size={17} /><span><strong>Guarded eligibility</strong><small>{selectedSubjectSupportsProfile ? "Allowed for the selected subject" : "Not allowed for the selected subject"}</small></span></li>
            <li><AppIcon name="intelligence" size={17} /><span><strong>Sanitized outputs</strong><small>{selectedProfile.reports_enabled ? `Reports${selectedProfile.ai_enabled ? " and explanations" : ""} available` : "No reports or explanations"}</small></span></li>
            <li><AppIcon name="credential" size={17} /><span><strong>Credential boundary</strong><small>{selectedProfile.mode === "passive" ? "Optional guarded credential" : "Credentials are never used"}</small></span></li>
          </ul>
          {selectedSubject?.repositoryAsset ? (
            <div className="repoPathNotice">
              <p>Repository scans stage bounded regular files only. ScopeHarbor never clones, builds, installs, runs hooks, or executes repository code.</p>
              <strong>Confined repository identity</strong>
              <small className="repoPathValue">{selectedSubject.repositoryAsset.relative_path}</small>
            </div>
          ) : null}
          {authProfileUnsupported ? <p className="formMessage errorText">Detach the target credential or choose Passive Web. Credentials never enter active, browser, or repository scans.</p> : null}
          <button type="button" onClick={onContinue} disabled={!selectedSubjectSupportsProfile || authProfileUnsupported}>
            Continue to authorization <AppIcon name="arrow" size={15} />
          </button>
        </aside>
      </div>
    </div>
  );
}

export function ScanAuthorization({
  subject,
  scanProfileId,
  acknowledgements,
  profileReady,
  onAcknowledgementChange,
  onOpenCredentials,
  onContinue
}: {
  subject: AuditSubject | null;
  scanProfileId: string;
  acknowledgements: string[];
  profileReady: boolean;
  onAcknowledgementChange: (code: string, acknowledged: boolean) => void;
  onOpenCredentials: () => void;
  onContinue: () => void;
}) {
  const profile = profilesById.get(scanProfileId) ?? SCAN_PROFILES[0];
  const allConfirmed = profile.required_acknowledgements.every((code) => acknowledgements.includes(code));
  const authProfileUnsupported = Boolean(subject?.target?.auth_profile_id && profile.mode !== "passive");

  return (
    <div className="authorizationLayout">
      <section className="authorizationChecklist">
        <div className="panelHeader">
          <div><p className="panelKicker">Explicit permission</p><h2>Confirm the audit boundary</h2></div>
          <span className="contextBadge">Required</span>
        </div>
        <p>ScopeHarbor records these confirmations with the scan request. They do not broaden the backend allowlist.</p>
        <div className="authorizationSummary">
          <span><AppIcon name={subject?.subjectType === "repository_asset" ? "intelligence" : "target"} size={16} />{subject?.name ?? "No subject selected"}</span>
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
          <li><AppIcon name="check" size={15} /><span><strong>Exact subject</strong>{subject?.subjectType === "repository_asset" ? "Repository access remains confined below the operator root." : "Scanner traffic remains bound to the configured destination policy."}</span></li>
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
  subject,
  scanProfileId,
  canStartScan,
  platformReady,
  isBusy,
  onStartScan
}: {
  subject: AuditSubject | null;
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
        <p>Review the exact subject and profile once more. The worker will revalidate workspace and immutable launch authority before any tool runs.</p>
      </div>
      <dl>
        <div><dt>Subject</dt><dd>{subject?.name ?? "Not selected"}</dd></div>
        <div><dt>{subject?.subjectType === "repository_asset" ? "Relative path" : "Canonical address"}</dt><dd>{subject?.detail ?? "—"}</dd></div>
        <div><dt>Profile</dt><dd>{profile.label}</dd></div>
        <div><dt>Platform</dt><dd>{platformReady ? "Ready" : "Needs attention"}</dd></div>
      </dl>
      <button type="button" onClick={onStartScan} disabled={!canStartScan || isBusy}>
        {isBusy ? "Queuing audit…" : `Launch ${profile.label}`} <AppIcon name="arrow" size={15} />
      </button>
      {!platformReady ? <p className="formMessage errorText">Confirm platform readiness before launch. Run Preflight again after the worker and database are healthy.</p> : null}
    </section>
  );
}

function profileCapabilities(profile: ScanProfileMetadata) {
  const capabilities = [profile.local_demo_only ? "Local demo" : profile.mode === "repo" ? "Offline" : "Allowlisted"];
  if (profile.reports_enabled) capabilities.push(profile.ai_enabled ? "Reports + AI" : "Reports");
  else capabilities.push("No reports");
  return capabilities;
}

function profileDecisionCopy(profileId: string): string {
  if (profileId === "active-demo") return "Bounded ZAP testing for local demos.";
  if (profileId === "modern-web-crawl") return "Client Spider crawl for local demos.";
  if (profileId === "repository") return "Gitleaks and offline OSV; code is never run.";
  return "Passive checks for allowlisted targets.";
}

function profileIcon(profileId: string): "target" | "operations" | "activity" | "intelligence" {
  if (profileId === "active-demo") return "operations";
  if (profileId === "modern-web-crawl") return "activity";
  if (profileId === "repository") return "intelligence";
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
        <div><p className="panelKicker">Audit trail</p><h3>Scan history</h3><p>Filter previous audits, then select one to monitor progress or reopen its normalized results.</p></div>
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
  targetName,
  toolRuns,
  isCancelling,
  onCancel
}: {
  scan: Scan;
  targetName: string;
  toolRuns: ScannerToolRun[];
  isCancelling: boolean;
  onCancel: () => void;
}) {
  const displayedProgress = useSmoothedProgress(scan);
  const canCancel = !terminalStatuses.has(scan.status) && !scan.cancellation_requested_at;
  const visibleToolRuns = toolRuns.slice(0, receiptPreviewCount);
  const remainingToolRuns = toolRuns.slice(receiptPreviewCount);

  return (
    <div className="scanPanel">
      <div className="scanHeader">
        <div>
          <h3>Selected scan</h3>
          <p>Live status, bounded worker progress, and sanitized scanner receipts for this audit.</p>
          <small>{scan.id}</small>
        </div>
        <span className={`statusPill status-${scan.status}`}>{scan.status}</span>
      </div>
      <div className="scanActions">
        <button type="button" className="secondaryButton" onClick={onCancel} disabled={!canCancel || isCancelling}>
          {isCancelling ? "Requesting cancellation…" : scan.cancellation_requested_at ? "Cancellation requested" : "Cancel scan"}
        </button>
      </div>
      <div className="progressTrack" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={displayedProgress}>
        <span style={{ width: `${displayedProgress}%` }} />
      </div>
      <dl className="scanMeta">
        <div>
          <dt>Target</dt>
          <dd>{targetName}</dd>
        </div>
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
          <div className="toolRunHeading"><h4>Scanner receipts</h4><p>Safe execution metadata only; raw tool output is never shown here.</p></div>
          <ToolRunList toolRuns={visibleToolRuns} />
          {remainingToolRuns.length > 0 ? (
            <details className="scannerReceiptOverflow">
              <summary>Show {remainingToolRuns.length} more scanner receipt{remainingToolRuns.length === 1 ? "" : "s"}</summary>
              <ToolRunList toolRuns={remainingToolRuns} />
            </details>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function ToolRunList({ toolRuns }: { toolRuns: ScannerToolRun[] }) {
  return (
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
