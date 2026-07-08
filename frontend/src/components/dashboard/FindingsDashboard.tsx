import type { Finding, Tag, Target } from "@/lib/securityAuditApi";

const severityFilters = ["all", "info", "low", "medium", "high", "critical"];
const lifecycleStatuses = ["open", "confirmed", "in_progress", "resolved", "suppressed", "false_positive"];
const confidenceFilters = ["all", "confirmed", "high", "medium", "low"];

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
  confidenceFilter,
  scannerFilter,
  owaspFilter,
  cweFilter,
  tagFilter,
  dateAfterFilter,
  dateBeforeFilter,
  riskMinFilter,
  riskMaxFilter,
  findingScope,
  targetFilter,
  profileFilter,
  targets,
  scanProfiles,
  tags,
  tagLabel,
  tagResourceType,
  suppressionReason,
  onSeverityFilter,
  onLifecycleFilter,
  onSuppressionFilter,
  onConfidenceFilter,
  onScannerFilter,
  onOwaspFilter,
  onCweFilter,
  onTagFilter,
  onDateAfterFilter,
  onDateBeforeFilter,
  onRiskMinFilter,
  onRiskMaxFilter,
  onFindingScope,
  onTargetFilter,
  onProfileFilter,
  onTagLabelChange,
  onTagResourceTypeChange,
  onCreateTag,
  onAssignTag,
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
  confidenceFilter: string;
  scannerFilter: string;
  owaspFilter: string;
  cweFilter: string;
  tagFilter: string;
  dateAfterFilter: string;
  dateBeforeFilter: string;
  riskMinFilter: string;
  riskMaxFilter: string;
  findingScope: string;
  targetFilter: string;
  profileFilter: string;
  targets: Target[];
  scanProfiles: readonly { id: string; label: string }[];
  tags: Tag[];
  tagLabel: string;
  tagResourceType: string;
  suppressionReason: string;
  onSeverityFilter: (severity: string) => void;
  onLifecycleFilter: (status: string) => void;
  onSuppressionFilter: (status: string) => void;
  onConfidenceFilter: (confidence: string) => void;
  onScannerFilter: (scanner: string) => void;
  onOwaspFilter: (owasp: string) => void;
  onCweFilter: (cwe: string) => void;
  onTagFilter: (tagId: string) => void;
  onDateAfterFilter: (date: string) => void;
  onDateBeforeFilter: (date: string) => void;
  onRiskMinFilter: (value: string) => void;
  onRiskMaxFilter: (value: string) => void;
  onFindingScope: (scope: string) => void;
  onTargetFilter: (targetId: string) => void;
  onProfileFilter: (profileId: string) => void;
  onTagLabelChange: (label: string) => void;
  onTagResourceTypeChange: (resourceType: string) => void;
  onCreateTag: () => void;
  onAssignTag: () => void;
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

        <div className="filterBar" aria-label="Finding scope filter">
          <select value={findingScope} onChange={(event) => onFindingScope(event.target.value)} aria-label="Finding scope">
            <option value="scan">current scan</option>
            <option value="workspace">workspace</option>
          </select>
          <select value={targetFilter} onChange={(event) => onTargetFilter(event.target.value)} aria-label="Target filter" disabled={findingScope !== "workspace"}>
            <option value="">all targets</option>
            {targets.map((target) => (
              <option value={target.id} key={target.id}>
                {target.name}
              </option>
            ))}
          </select>
          <select value={profileFilter} onChange={(event) => onProfileFilter(event.target.value)} aria-label="Scan profile filter" disabled={findingScope !== "workspace"}>
            <option value="">all profiles</option>
            {scanProfiles.map((profile) => (
              <option value={profile.id} key={profile.id}>
                {profile.label}
              </option>
            ))}
          </select>
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
          <select value={confidenceFilter} onChange={(event) => onConfidenceFilter(event.target.value)} aria-label="Confidence filter">
            {confidenceFilters.map((item) => (
              <option value={item} key={item}>
                {item === "all" ? "all confidence" : item}
              </option>
            ))}
          </select>
          <select value={suppressionFilter} onChange={(event) => onSuppressionFilter(event.target.value)} aria-label="Suppression filter">
            <option value="all">all suppression</option>
            <option value="active">suppressed</option>
            <option value="not_suppressed">not suppressed</option>
          </select>
          <select value={tagFilter} onChange={(event) => onTagFilter(event.target.value)} aria-label="Tag filter">
            <option value="">all tags</option>
            {tags.map((tag) => (
              <option value={tag.id} key={tag.id}>
                {tag.label}
              </option>
            ))}
          </select>
        </div>

        <div className="filterGrid" aria-label="Advanced finding filters">
          <label>
            Scanner
            <input value={scannerFilter} onChange={(event) => onScannerFilter(event.target.value)} />
          </label>
          <label>
            OWASP
            <input value={owaspFilter} onChange={(event) => onOwaspFilter(event.target.value)} />
          </label>
          <label>
            CWE
            <input value={cweFilter} onChange={(event) => onCweFilter(event.target.value)} />
          </label>
          <label>
            From
            <input type="datetime-local" value={dateAfterFilter} onChange={(event) => onDateAfterFilter(event.target.value)} />
          </label>
          <label>
            To
            <input type="datetime-local" value={dateBeforeFilter} onChange={(event) => onDateBeforeFilter(event.target.value)} />
          </label>
          <label>
            Risk min
            <input type="number" min="0" max="100" value={riskMinFilter} onChange={(event) => onRiskMinFilter(event.target.value)} />
          </label>
          <label>
            Risk max
            <input type="number" min="0" max="100" value={riskMaxFilter} onChange={(event) => onRiskMaxFilter(event.target.value)} />
          </label>
        </div>

        <div className="tagManagement">
          <input value={tagLabel} onChange={(event) => onTagLabelChange(event.target.value)} placeholder="Tag label" />
          <button type="button" onClick={onCreateTag} disabled={!tagLabel.trim()}>
            Create Tag
          </button>
          <select value={tagResourceType} onChange={(event) => onTagResourceTypeChange(event.target.value)} aria-label="Tag resource type">
            <option value="target">target</option>
            <option value="scan">scan</option>
          </select>
          <button type="button" onClick={onAssignTag} disabled={!tagFilter || !selectedFinding}>
            Assign Tag
          </button>
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
