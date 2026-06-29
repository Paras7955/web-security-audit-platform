import type { Finding } from "@/lib/securityAuditApi";

const severityFilters = ["all", "info", "low", "medium", "high", "critical"];

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
  onSeverityFilter,
  onSelectFinding
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  severityFilter: string;
  onSeverityFilter: (severity: string) => void;
  onSelectFinding: (findingId: string) => void;
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

        {findings.length > 0 ? (
          <table className="findingsTable">
            <thead>
              <tr>
                <th>Severity</th>
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

      <FindingDetail finding={selectedFinding} />
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding | null }) {
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

      <dl>
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
      </dl>

      <h4>Evidence</h4>
      <pre>{finding.evidence ?? "No evidence snippet stored."}</pre>

      <h4>Remediation</h4>
      <p>{finding.remediation ?? "Remediation guidance is added in later reporting phases."}</p>
    </div>
  );
}
