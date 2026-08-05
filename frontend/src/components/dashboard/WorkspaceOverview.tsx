import { AppIcon } from "@/components/AppIcon";
import { formatScanProfileLabel } from "@/components/dashboard/ScanControls";
import type { AuditSubject, DashboardOverview, PlatformHealth, Scan } from "@/lib/securityAuditApi";

export function WorkspaceOverview({
  overview,
  health,
  selectedScan,
  selectedSubject,
  onNavigate,
  onOpenScanHistory
}: {
  overview: DashboardOverview | null;
  health: PlatformHealth | null;
  selectedScan: Scan | null;
  selectedSubject: AuditSubject | null;
  onNavigate: (view: string) => void;
  onOpenScanHistory: () => void;
}) {
  const criticalCount = overview?.severity_counts.critical ?? 0;
  const highCount = overview?.severity_counts.high ?? 0;
  const riskScore = overview?.current_posture_score?.score;

  return (
    <div className="overviewWorkspace productPage">
      <div className="viewIntro"><div><h2>Workspace overview</h2><p>See current risk, platform readiness, authorized scope, and the latest audit activity at a glance.</p></div></div>
      <section className="metricGrid" aria-label="Workspace metrics">
        <MetricCard icon="target" label="Saved subjects" value={overview ? overview.targets_count + overview.repository_assets_count : "—"} detail={`${overview?.targets_count ?? 0} web · ${overview?.repository_assets_count ?? 0} repositories`} tone="cyan" />
        <MetricCard icon="scan" label="Total scans" value={overview?.scans_count ?? "—"} detail={`${overview?.completed_scans_count ?? 0} completed`} tone="blue" />
        <MetricCard icon="finding" label="Open evidence" value={overview?.findings_count ?? "—"} detail={`${criticalCount + highCount} high priority`} tone={criticalCount ? "danger" : "accent"} />
        <MetricCard icon="activity" label="Current posture" value={riskScore ?? "—"} detail={overview?.current_posture_score?.label ?? "Awaiting completed scan"} tone="amber" />
      </section>

      <section className="overviewSplit">
        <div className="panel focusPanel">
          <div className="panelHeader">
            <div>
              <p className="panelKicker">Current focus</p>
              <h3>{selectedSubject?.name ?? "Choose an authorized subject"}</h3>
              <p>The saved web target or repository currently driving profile availability and audit actions.</p>
            </div>
            <span className={health?.status === "ok" ? "healthBadge healthBadgeOk" : "healthBadge"}>
              <span className="statusDot" /> {health?.status === "ok" ? "Systems ready" : "Check readiness"}
            </span>
          </div>

          {selectedSubject ? (
            <div className="focusTarget">
              <div className="focusTargetUrl"><AppIcon name={selectedSubject.subjectType === "repository_asset" ? "intelligence" : "target"} size={16} />{selectedSubject.detail}</div>
              <div className="focusCapabilities">
                <span><AppIcon name="shield" size={15} />Authorized</span>
                <span><AppIcon name="scan" size={15} />{selectedSubject.availableScanProfileIds.length} scan profile{selectedSubject.availableScanProfileIds.length === 1 ? "" : "s"}</span>
                <span><AppIcon name="intelligence" size={15} />{selectedSubject.subjectType === "repository_asset" ? "Offline repository tools" : "Destination policy current"}</span>
              </div>
            </div>
          ) : (
            <p className="emptyState">Save an authorized subject to unlock scan controls.</p>
          )}

          <div className="quickActions">
            <button type="button" onClick={() => onNavigate("scanning")}>
              <AppIcon name="scan" /> Configure a scan <AppIcon name="arrow" size={15} />
            </button>
            <button type="button" className="secondaryButton" onClick={() => onNavigate("findings")}>
              Review findings
            </button>
          </div>
        </div>

        <div className="panel activityPanel">
          <div className="panelHeader">
            <div>
              <p className="panelKicker">Latest activity</p>
              <h3>Scan signal</h3>
              <p>Progress and state for the selected or most recent audit.</p>
            </div>
            {selectedScan ? <span className={`statusPill status-${selectedScan.status}`}>{formatStatus(selectedScan.status)}</span> : null}
          </div>

          {selectedScan ? (
            <>
              <div className="activityProgress">
                <div>
                  <strong>{selectedScan.progress_percent}%</strong>
                  <span>{formatScanProfileLabel(selectedScan.scan_profile_id)}</span>
                </div>
                <div className="progressTrack"><span style={{ width: `${selectedScan.progress_percent}%` }} /></div>
              </div>
              <dl className="compactMeta">
                <div><dt>State</dt><dd>{selectedScan.current_step ?? formatStatus(selectedScan.status)}</dd></div>
                <div><dt>Started</dt><dd>{formatDate(selectedScan.started_at ?? selectedScan.created_at)}</dd></div>
              </dl>
            </>
          ) : (
            <p className="emptyState">Your latest scan will appear here.</p>
          )}
        </div>
      </section>

      <section className="panel recentActivityPanel">
        <div className="panelHeader">
          <div>
            <p className="panelKicker">Workspace trail</p>
            <h3>Recent scans</h3>
            <p>Use this short history to reopen monitoring or continue into result review.</p>
          </div>
          <button className="textButton" type="button" onClick={onOpenScanHistory}>View scan history <AppIcon name="arrow" size={15} /></button>
        </div>
        {overview?.recent_scans.length ? (
          <div className="activityTableWrap">
            <table className="activityTable">
              <thead><tr><th>Subject</th><th>Profile</th><th>Status</th><th>Risk</th><th>Completed</th></tr></thead>
              <tbody>
                {overview.recent_scans.slice(0, 6).map((scan) => (
                  <tr key={scan.id}>
                    <td><strong>{scan.target_name}</strong></td>
                    <td>{formatScanProfileLabel(scan.scan_profile_id)}</td>
                    <td><span className={`statusPill status-${scan.status}`}>{formatStatus(scan.status)}</span></td>
                    <td>{scan.risk_score?.score ?? "—"}</td>
                    <td>{formatDate(scan.completed_at ?? scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="emptyState">No scan activity yet.</p>}
      </section>
    </div>
  );
}

function MetricCard({ icon, label, value, detail, tone }: { icon: "target" | "scan" | "finding" | "activity"; label: string; value: string | number; detail: string; tone: string }) {
  return (
    <article className={`metricCard metricCard-${tone}`}>
      <span className="metricIcon"><AppIcon name={icon} /></span>
      <div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
    </article>
  );
}

function formatDate(value: string | null) {
  if (!value) {
    return "Not started";
  }
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}

function formatStatus(value: string) {
  return value.replaceAll("_", " ");
}
