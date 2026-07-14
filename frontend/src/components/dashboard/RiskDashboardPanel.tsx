import type { DashboardOverview, Scan, ScanComparison, Target, TargetDashboard } from "@/lib/securityAuditApi";

const completedStatuses = new Set(["completed", "completed_with_warnings"]);
const severityOrder = ["critical", "high", "medium", "low", "info"];

export function RiskDashboardPanel({
  overview,
  targetDashboard,
  targets,
  scans,
  selectedTargetId,
  baselineScanId,
  comparisonScanId,
  comparison,
  message,
  onBaselineScanChange,
  onComparisonScanChange,
  onCompare
}: {
  overview: DashboardOverview | null;
  targetDashboard: TargetDashboard | null;
  targets: Target[];
  scans: Scan[];
  selectedTargetId: string;
  baselineScanId: string;
  comparisonScanId: string;
  comparison: ScanComparison | null;
  message: string;
  onBaselineScanChange: (scanId: string) => void;
  onComparisonScanChange: (scanId: string) => void;
  onCompare: () => void;
}) {
  const comparableScans = scans
    .filter((scan) => scan.target_id === selectedTargetId && completedStatuses.has(scan.status))
    .sort((left, right) => scanCompletionTime(right).localeCompare(scanCompletionTime(left)));
  const selectedTarget = targets.find((target) => target.id === selectedTargetId) ?? null;
  const latestScore = targetDashboard?.latest_risk_score ?? null;

  return (
    <div className="riskDashboard">
      <div className="riskMetricGrid">
        <RiskScoreCard title="Latest scan risk" score={overview?.latest_risk_score ?? null} />
        <RiskScoreCard title="Target risk" score={latestScore} />
        <MetricCard label="Targets" value={overview?.targets_count ?? 0} context="Workspace" />
        <MetricCard label="Completed scans" value={overview?.completed_scans_count ?? 0} context="Workspace" />
      </div>

      <div className="riskDashboardGrid">
        <div className="panel">
          <div className="panelHeader">
            <h3>Workspace Dashboard</h3>
            <span className="contextBadge">{overview?.findings_count ?? 0} findings</span>
          </div>
          <SeverityBars counts={overview?.severity_counts ?? {}} />
          <CompactScanTable scans={overview?.recent_scans ?? []} />
        </div>

        <div className="panel">
          <div className="panelHeader">
            <h3>Target Dashboard</h3>
            <span className="contextBadge">{selectedTarget?.name ?? "No target"}</span>
          </div>
          {targetDashboard ? (
            <>
              <dl className="scanMeta">
                <div>
                  <dt>Base URL</dt>
                  <dd>{targetDashboard.base_url}</dd>
                </div>
                <div>
                  <dt>Scans</dt>
                  <dd>{targetDashboard.completed_scan_count} completed</dd>
                </div>
                <div>
                  <dt>Score model</dt>
                  <dd>{targetDashboard.latest_risk_score?.scoring_model_version ?? "pending"}</dd>
                </div>
              </dl>
              <SeverityBars counts={targetDashboard.severity_counts} />
              <ScoreInputs dashboard={targetDashboard} />
            </>
          ) : (
            <p className="emptyState">Select a target to load target risk data.</p>
          )}
        </div>
      </div>

      <div className="panel comparisonPanel">
        <div className="panelHeader">
          <h3>Scan Comparison</h3>
          <span className="contextBadge">Same target only</span>
        </div>
        <div className="comparisonControls">
          <label className="selectLabel">
            Baseline scan
            <select value={baselineScanId} onChange={(event) => onBaselineScanChange(event.target.value)}>
              <option value="">Select baseline</option>
              {comparableScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.scan_profile_id} · {formatDate(scan.created_at)}
                </option>
              ))}
            </select>
          </label>
          <label className="selectLabel">
            Comparison scan
            <select value={comparisonScanId} onChange={(event) => onComparisonScanChange(event.target.value)}>
              <option value="">Select comparison</option>
              {comparableScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.scan_profile_id} · {formatDate(scan.created_at)}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={onCompare} disabled={!baselineScanId || !comparisonScanId || baselineScanId === comparisonScanId}>
            Compare scans
          </button>
        </div>
        <p className="formMessage">{message}</p>
        {comparison ? <ComparisonSummary comparison={comparison} /> : null}
      </div>
    </div>
  );
}

function RiskScoreCard({ title, score }: { title: string; score: DashboardOverview["latest_risk_score"] }) {
  return (
    <div className="riskScoreCard">
      <span>{title}</span>
      <strong>{score ? score.score : "-"}</strong>
      <em className={score ? `riskLabel riskLabel-${score.label.toLowerCase()}` : "riskLabel"}>{score?.label ?? "Pending"}</em>
    </div>
  );
}

function MetricCard({ label, value, context }: { label: string; value: number | string; context: string }) {
  return (
    <div className="riskScoreCard">
      <span>{label}</span>
      <strong>{value}</strong>
      <em className="riskLabel">{context}</em>
    </div>
  );
}

function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...severityOrder.map((severity) => counts[severity] ?? 0));
  return (
    <div className="severityBars">
      {severityOrder.map((severity) => {
        const count = counts[severity] ?? 0;
        return (
          <div key={severity}>
            <span>{severity}</span>
            <div className="severityTrack">
              <i style={{ width: `${Math.max(4, (count / max) * 100)}%` }} />
            </div>
            <strong>{count}</strong>
          </div>
        );
      })}
    </div>
  );
}

function CompactScanTable({ scans }: { scans: DashboardOverview["recent_scans"] }) {
  if (scans.length === 0) {
    return <p className="emptyState">No scans yet.</p>;
  }

  return (
    <table className="compactTable">
      <thead>
        <tr>
          <th>Target</th>
          <th>Profile</th>
          <th>Status</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.id}>
            <td>{scan.target_name}</td>
            <td>{scan.scan_profile_id}</td>
            <td>{scan.status}</td>
            <td>{scan.risk_score ? `${scan.risk_score.score} ${scan.risk_score.label}` : "-"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ScoreInputs({ dashboard }: { dashboard: TargetDashboard }) {
  const score = dashboard.latest_risk_score;
  if (!score) {
    return <p className="emptyState">Run a completed scan to generate risk inputs.</p>;
  }

  return (
    <dl className="scoreInputs">
      <div>
        <dt>Finding count</dt>
        <dd>{String(score.input_summary.finding_count ?? 0)}</dd>
      </div>
      <div>
        <dt>Weighted total</dt>
        <dd>{String(score.input_summary.weighted_total ?? 0)}</dd>
      </div>
      <div>
        <dt>Profile</dt>
        <dd>{String(score.input_summary.scan_profile_id ?? "unknown")}</dd>
      </div>
    </dl>
  );
}

function ComparisonSummary({ comparison }: { comparison: ScanComparison }) {
  return (
    <div className="comparisonSummary">
      <div className="riskMetricGrid riskMetricGridCompact">
        <RiskScoreCard title="Baseline" score={comparison.baseline_score} />
        <RiskScoreCard title="Comparison" score={comparison.comparison_score} />
        <MetricCard label="Score delta" value={comparison.score_delta > 0 ? `+${comparison.score_delta}` : comparison.score_delta} context="Comparison" />
        <MetricCard label="Model" value={comparison.scoring_model_version} context="Version" />
      </div>
      <div className="changeGrid">
        <ChangeList title="New" items={comparison.new_findings} />
        <ChangeList title="Resolved" items={comparison.resolved_findings} />
        <ChangeList title="Severity changed" items={comparison.severity_changed_findings} />
        <ChangeList title="Unchanged" items={comparison.unchanged_findings.slice(0, 6)} />
      </div>
    </div>
  );
}

function ChangeList({ title, items }: { title: string; items: ScanComparison["new_findings"] }) {
  return (
    <div className="changeList">
      <h4>
        {title} <span>{items.length}</span>
      </h4>
      {items.length > 0 ? (
        <ul>
          {items.map((item) => (
            <li key={`${title}-${item.dedupe_key}`}>
              <strong>{item.title}</strong>
              <small>
                {item.previous_severity ?? "-"} {"->"} {item.current_severity ?? "-"}
              </small>
            </li>
          ))}
        </ul>
      ) : (
        <p className="emptyState">None</p>
      )}
    </div>
  );
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}

function scanCompletionTime(scan: Scan) {
  return scan.completed_at ?? scan.created_at;
}
