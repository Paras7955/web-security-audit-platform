import { AppIcon } from "@/components/AppIcon";
import { formatScanProfileLabel } from "@/components/dashboard/ScanControls";
import type { DashboardOverview, PlatformHealth, Scan, Target } from "@/lib/securityAuditApi";

export function WorkspaceOverview({
  overview,
  health,
  selectedScan,
  selectedTarget,
  onNavigate
}: {
  overview: DashboardOverview | null;
  health: PlatformHealth | null;
  selectedScan: Scan | null;
  selectedTarget: Target | null;
  onNavigate: (view: string) => void;
}) {
  const criticalCount = overview?.severity_counts.critical ?? 0;
  const highCount = overview?.severity_counts.high ?? 0;
  const riskScore = overview?.latest_risk_score?.score;

  return (
    <div className="overviewWorkspace">
      <div className="viewIntro"><div><h2>Workspace overview</h2><p>See current risk, platform readiness, authorized scope, and the latest audit activity at a glance.</p></div></div>
      <section className="metricGrid" aria-label="Workspace metrics">
        <MetricCard icon="target" label="Saved targets" value={overview?.targets_count ?? "—"} detail="Exact allowlist only" tone="cyan" />
        <MetricCard icon="scan" label="Total scans" value={overview?.scans_count ?? "—"} detail={`${overview?.completed_scans_count ?? 0} completed`} tone="blue" />
        <MetricCard icon="finding" label="Open evidence" value={overview?.findings_count ?? "—"} detail={`${criticalCount + highCount} high priority`} tone={criticalCount ? "danger" : "violet"} />
        <MetricCard icon="activity" label="Latest risk" value={riskScore ?? "—"} detail={overview?.latest_risk_score?.label ?? "Awaiting completed scan"} tone="amber" />
      </section>

      <section className="overviewSplit">
        <div className="panel focusPanel">
          <div className="panelHeader">
            <div>
              <p className="panelKicker">Current focus</p>
              <h3>{selectedTarget?.name ?? "Choose an authorized target"}</h3>
            </div>
            <span className={health?.status === "ok" ? "healthBadge healthBadgeOk" : "healthBadge"}>
              <span className="statusDot" /> {health?.status === "ok" ? "Systems ready" : "Check readiness"}
            </span>
          </div>

          {selectedTarget ? (
            <div className="focusTarget">
              <div className="focusTargetUrl"><AppIcon name="target" size={16} />{selectedTarget.base_url}</div>
              <div className="focusCapabilities">
                <span><AppIcon name="shield" size={15} />Authorized</span>
                <span><AppIcon name="scan" size={15} />{selectedTarget.available_scan_profile_ids.length} scan profiles</span>
                <span className={selectedTarget.has_repo_path ? "" : "mutedCapability"}><AppIcon name="intelligence" size={15} />Repo {selectedTarget.has_repo_path ? "ready" : "not attached"}</span>
              </div>
            </div>
          ) : (
            <p className="emptyState">Save an allowlisted target to unlock scan controls.</p>
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
          </div>
          <button className="textButton" type="button" onClick={() => onNavigate("scanning")}>View scan history <AppIcon name="arrow" size={15} /></button>
        </div>
        {overview?.recent_scans.length ? (
          <div className="activityTableWrap">
            <table className="activityTable">
              <thead><tr><th>Target</th><th>Profile</th><th>Status</th><th>Risk</th><th>Completed</th></tr></thead>
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
