import type { Finding } from "@/lib/securityAuditApi";

const severityFilters = ["all", "info", "low", "medium", "high", "critical"];
const lifecycleStatuses = ["open", "confirmed", "in_progress", "resolved", "suppressed", "false_positive"];

export const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function FindingsDashboard({
  findings,
  selectedFinding,
  severityFilter,
  lifecycleFilter,
  suppressionFilter,
  suppressionReason,
  onSeverityFilter,
  onLifecycleFilter,
  onSuppressionFilter,
  onSelectFinding,
  onUpdateLifecycle,
  onSuppressionReasonChange,
  onSuppressFinding
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  severityFilter: string;
  lifecycleFilter: string;
  suppressionFilter: string;
  suppressionReason: string;
  onSeverityFilter: (severity: string) => void;
  onLifecycleFilter: (status: string) => void;
  onSuppressionFilter: (status: string) => void;
  onSelectFinding: (findingId: string) => void;
  onUpdateLifecycle: (findingId: string, lifecycleStatus: string) => void;
  onSuppressionReasonChange: (reason: string) => void;
  onSuppressFinding: (finding: Finding) => void;
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

        <div className="filterBar" role="tablist" aria-label="Finding management filter">
          <select value={lifecycleFilter} onChange={(event) => onLifecycleFilter(event.target.value)} aria-label="Lifecycle filter">
            <option value="all">all states</option>
            {lifecycleStatuses.map((item) => (
              <option value={item} key={item}>
                {formatStatus(item)}
              </option>
            ))}
          </select>
          <select value={suppressionFilter} onChange={(event) => onSuppressionFilter(event.target.value)} aria-label="Suppression filter">
            <option value="all">all suppression</option>
            <option value="active">suppressed</option>
            <option value="not_suppressed">not suppressed</option>
          </select>
        </div>

        {findings.length > 0 ? (
          <table className="findingsTable">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Status</th>
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
                  <td>
                    <span className={finding.suppressed ? "stateBadge stateBadgeSuppressed" : "stateBadge"}>
                      {formatStatus(finding.lifecycle_status)}
                    </span>
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

      <FindingDetail
        finding={selectedFinding}
        suppressionReason={suppressionReason}
        onUpdateLifecycle={onUpdateLifecycle}
        onSuppressionReasonChange={onSuppressionReasonChange}
        onSuppressFinding={onSuppressFinding}
      />
    </div>
  );
}

function FindingDetail({
  finding,
  suppressionReason,
  onUpdateLifecycle,
  onSuppressionReasonChange,
  onSuppressFinding
}: {
  finding: Finding | null;
  suppressionReason: string;
  onUpdateLifecycle: (findingId: string, lifecycleStatus: string) => void;
  onSuppressionReasonChange: (reason: string) => void;
  onSuppressFinding: (finding: Finding) => void;
}) {
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

      <div className="findingActions">
        <label>
          Lifecycle
          <select value={finding.lifecycle_status} onChange={(event) => onUpdateLifecycle(finding.id, event.target.value)}>
            {lifecycleStatuses.map((item) => (
              <option value={item} key={item}>
                {formatStatus(item)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Suppression reason
          <textarea value={suppressionReason} onChange={(event) => onSuppressionReasonChange(event.target.value)} rows={2} />
        </label>
        <button type="button" onClick={() => onSuppressFinding(finding)} disabled={finding.suppressed || !suppressionReason.trim()}>
          Suppress
        </button>
      </div>

      <dl>
        <div>
          <dt>Status</dt>
          <dd>{formatStatus(finding.lifecycle_status)}</dd>
        </div>
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
        <div>
          <dt>Tags</dt>
          <dd>{finding.tags.length > 0 ? finding.tags.join(", ") : "none"}</dd>
        </div>
      </dl>

      <h4>Evidence</h4>
      <pre>{finding.evidence ?? "No evidence snippet stored."}</pre>

      <h4>Remediation</h4>
      <p>{finding.remediation ?? "Remediation guidance is added in later reporting phases."}</p>
    </div>
  );
}

function formatStatus(value: string) {
  return value.replaceAll("_", " ");
}
