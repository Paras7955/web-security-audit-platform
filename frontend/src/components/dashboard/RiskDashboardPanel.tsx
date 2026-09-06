"use client";

import { useState } from "react";

import { formatScanProfileLabel } from "@/components/dashboard/ScanControls";
import type { AuditSubject, DashboardOverview, RepositoryDashboard, Scan, ScanComparison, TargetDashboard } from "@/lib/securityAuditApi";

const completedStatuses = new Set(["completed", "completed_with_warnings"]);
const severityOrder = ["critical", "high", "medium", "low", "info"];
const comparisonPreviewSize = 4;

export function RiskDashboardPanel({
  overview,
  targetDashboard,
  repositoryDashboard,
  scans,
  selectedSubject,
  baselineScanId,
  comparisonScanId,
  comparison,
  message,
  isComparing,
  isLoading,
  onBaselineScanChange,
  onComparisonScanChange,
  onCompare
}: {
  overview: DashboardOverview | null;
  targetDashboard: TargetDashboard | null;
  repositoryDashboard: RepositoryDashboard | null;
  scans: Scan[];
  selectedSubject: AuditSubject | null;
  baselineScanId: string;
  comparisonScanId: string;
  comparison: ScanComparison | null;
  message: string;
  isComparing: boolean;
  isLoading: boolean;
  onBaselineScanChange: (scanId: string) => void;
  onComparisonScanChange: (scanId: string) => void;
  onCompare: () => void;
}) {
  const comparableScans = scans
    .filter((scan) => scan.subject_type === selectedSubject?.subjectType && scan.subject_id === (selectedSubject.target?.id ?? selectedSubject.repositoryAsset?.id) && completedStatuses.has(scan.status))
    .sort((left, right) => scanCompletionTime(right).localeCompare(scanCompletionTime(left)));
  const profileCounts = comparableScans.reduce<Map<string, number>>((counts, scan) => {
    counts.set(scan.scan_profile_id, (counts.get(scan.scan_profile_id) ?? 0) + 1);
    return counts;
  }, new Map());
  const eligibleProfiles = new Set(
    [...profileCounts.entries()].filter(([, count]) => count >= 2).map(([profileId]) => profileId)
  );
  const eligibleBaselineScans = comparableScans.filter((scan) => eligibleProfiles.has(scan.scan_profile_id));
  const selectedBaseline = eligibleBaselineScans.find((scan) => scan.id === baselineScanId) ?? null;
  const eligibleComparisonScans = selectedBaseline
    ? eligibleBaselineScans.filter((scan) => scan.scan_profile_id === selectedBaseline.scan_profile_id && scan.id !== selectedBaseline.id)
    : [];
  const displayedBaselineScanId = selectedBaseline?.id ?? "";
  const displayedComparisonScanId = eligibleComparisonScans.some((scan) => scan.id === comparisonScanId) ? comparisonScanId : "";
  const subjectDashboard = targetDashboard ?? repositoryDashboard;
  const currentScore = subjectDashboard?.current_posture_score ?? null;

  return (
    <div className="riskDashboard" aria-busy={isLoading}>
      <div className="riskMetricGrid" aria-label="Risk overview">
        <RiskScoreCard title="Workspace posture" score={overview?.current_posture_score ?? null} />
        <RiskScoreCard title="Subject posture" score={currentScore} />
        <MetricCard label="Subjects" value={(overview?.targets_count ?? 0) + (overview?.repository_assets_count ?? 0)} context="Web + repository" />
        <MetricCard label="Completed scans" value={overview?.completed_scans_count ?? 0} context="Workspace" />
      </div>

      <div className="riskDashboardGrid">
        <div className="panel">
          <div className="panelHeader">
            <div><h3>Workspace current posture</h3><p>Latest completed audit per subject and profile after lifecycle and active-suppression decisions.</p></div>
            <span className="contextBadge">{overview?.findings_count ?? 0} findings</span>
          </div>
          <SeverityBars counts={overview?.severity_counts ?? {}} />
          <p className="postureHistoryNote">Historical evidence: <strong>{overview?.historical_findings_count ?? 0}</strong> findings across all completed audits.</p>
          <CompactScanTable scans={overview?.recent_scans ?? []} />
        </div>

        <div className="panel">
          <div className="panelHeader">
            <div><h3>Selected subject posture</h3><p>Current risk inputs for the authorized web target or repository selected in this workspace.</p></div>
            <span className="contextBadge">{selectedSubject?.name ?? "No subject"}</span>
          </div>
          {isLoading ? (
            <p className="emptyState" role="status">Loading subject posture…</p>
          ) : subjectDashboard ? (
            <>
              <dl className="scanMeta">
                <div>
                  <dt>{repositoryDashboard ? "Relative path" : "Base URL"}</dt>
                  <dd>{repositoryDashboard?.relative_path ?? targetDashboard?.base_url}</dd>
                </div>
                <div>
                  <dt>Scans</dt>
                  <dd>{subjectDashboard.completed_scan_count} completed</dd>
                </div>
                <div>
                  <dt>Score model</dt>
                  <dd>{subjectDashboard.current_posture_score?.scoring_model_version ?? "pending"}</dd>
                </div>
              </dl>
              <SeverityBars counts={subjectDashboard.severity_counts} />
              <p className="postureHistoryNote">Historical evidence: <strong>{subjectDashboard.historical_findings_count}</strong> findings across all completed audits.</p>
              <ScoreInputs dashboard={subjectDashboard} />
            </>
          ) : (
            <p className="emptyState">{selectedSubject ? "Complete an audit to generate subject posture data." : "Select a subject to load posture data."}</p>
          )}
        </div>
      </div>

      <div className="panel comparisonPanel">
        <div className="panelHeader">
          <div><h3>Compare completed scans</h3><p>See what appeared, changed, resolved, or remained between two audits with matching coverage.</p></div>
          <span className="contextBadge">Same subject + profile</span>
        </div>
        {eligibleBaselineScans.length >= 2 ? (
          <div className="comparisonControls">
            <label className="selectLabel">
              Baseline scan
              <select value={displayedBaselineScanId} onChange={(event) => onBaselineScanChange(event.target.value)}>
                <option value="">Select baseline</option>
                {eligibleBaselineScans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {formatScanProfileLabel(scan.scan_profile_id)} · {formatDate(scanCompletionTime(scan))}
                  </option>
                ))}
              </select>
            </label>
            <label className="selectLabel">
              Comparison scan
              <select
                value={displayedComparisonScanId}
                onChange={(event) => onComparisonScanChange(event.target.value)}
                disabled={!selectedBaseline}
              >
                <option value="">{selectedBaseline ? `Select another ${formatScanProfileLabel(selectedBaseline.scan_profile_id)} audit` : "Choose a baseline first"}</option>
                {eligibleComparisonScans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {formatScanProfileLabel(scan.scan_profile_id)} · {formatDate(scanCompletionTime(scan))}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" onClick={onCompare} disabled={isComparing || !displayedBaselineScanId || !displayedComparisonScanId}>
              {isComparing ? "Comparing…" : "Compare scans"}
            </button>
          </div>
        ) : (
          <p className="emptyState">Complete at least two audits with the same profile for this subject to unlock a coverage-equivalent comparison.</p>
        )}
        {eligibleBaselineScans.length >= 2 ? <p className="formMessage" role="status" aria-live="polite">{message}</p> : null}
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
              <i style={{ width: count === 0 ? "0%" : `${(count / max) * 100}%` }} />
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
          <th>Subject</th>
          <th>Profile</th>
          <th>Status</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.id}>
            <td>{scan.target_name}</td>
            <td>{formatScanProfileLabel(scan.scan_profile_id)}</td>
            <td>{formatStatus(scan.status)}</td>
            <td>{scan.risk_score ? `${scan.risk_score.score} ${scan.risk_score.label}` : "-"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ScoreInputs({ dashboard }: { dashboard: TargetDashboard | RepositoryDashboard }) {
  const score = dashboard.current_posture_score;
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
        <dt>Raw weighted sum</dt>
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
        <ChangeList key={`${comparison.baseline_scan_id}:${comparison.comparison_scan_id}:new`} title="New" items={comparison.new_findings} />
        <ChangeList key={`${comparison.baseline_scan_id}:${comparison.comparison_scan_id}:resolved`} title="Resolved" items={comparison.resolved_findings} />
        <ChangeList key={`${comparison.baseline_scan_id}:${comparison.comparison_scan_id}:severity`} title="Severity changed" items={comparison.severity_changed_findings} />
        <ChangeList key={`${comparison.baseline_scan_id}:${comparison.comparison_scan_id}:unchanged`} title="Unchanged" items={comparison.unchanged_findings} />
      </div>
    </div>
  );
}

function ChangeList({ title, items }: { title: string; items: ScanComparison["new_findings"] }) {
  const [expanded, setExpanded] = useState(false);
  const visibleItems = expanded ? items : items.slice(0, comparisonPreviewSize);
  const remainingCount = Math.max(0, items.length - visibleItems.length);
  const listId = `comparison-${title.toLowerCase().replaceAll(" ", "-")}-findings`;

  return (
    <div className="changeList">
      <h4>
        {title} <span>{items.length}</span>
      </h4>
      {items.length > 0 ? (
        <>
          <ul id={listId}>
            {visibleItems.map((item) => (
              <li key={`${title}-${item.dedupe_key}`}>
                <strong>{item.title}</strong>
                <small>
                  {item.previous_severity ?? "none"} {"→"} {item.current_severity ?? "none"}
                </small>
              </li>
            ))}
          </ul>
          {items.length > comparisonPreviewSize ? (
            <button
              type="button"
              className="secondaryButton changeListDisclosure"
              aria-controls={listId}
              aria-expanded={expanded}
              onClick={() => setExpanded((currentValue) => !currentValue)}
            >
              {expanded ? "Show fewer" : `Show ${remainingCount} more`}
            </button>
          ) : null}
        </>
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

function formatStatus(value: string) {
  return value.replaceAll("_", " ");
}
