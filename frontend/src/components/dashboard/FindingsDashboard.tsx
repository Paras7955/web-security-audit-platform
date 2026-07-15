"use client";

import { useMemo, useState } from "react";

import type { Finding, Tag, Target } from "@/lib/securityAuditApi";

const severityFilters = ["all", "info", "low", "medium", "high", "critical"];
const lifecycleStatuses = ["open", "confirmed", "in_progress", "resolved", "suppressed", "false_positive"];
const confidenceFilters = ["all", "confirmed", "high", "medium", "low"];
const pageSizes = [5, 10, 20];

type FindingSort = "severity-desc" | "severity-asc" | "newest" | "title" | "status";

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
  const [sortBy, setSortBy] = useState<FindingSort>("severity-desc");
  const [pageSize, setPageSize] = useState(5);
  const [requestedPage, setRequestedPage] = useState(1);
  const sortedFindings = useMemo(() => sortFindings(findings, sortBy), [findings, sortBy]);
  const pageCount = Math.max(1, Math.ceil(sortedFindings.length / pageSize));
  const currentPage = Math.min(requestedPage, pageCount);
  const pageStart = (currentPage - 1) * pageSize;
  const visibleFindings = sortedFindings.slice(pageStart, pageStart + pageSize);
  const resultStart = sortedFindings.length > 0 ? pageStart + 1 : 0;
  const resultEnd = Math.min(pageStart + pageSize, sortedFindings.length);
  const secondaryFilterCount = [
    findingScope !== "scan",
    targetFilter,
    profileFilter,
    lifecycleFilter !== "all",
    confidenceFilter !== "all",
    suppressionFilter !== "all",
    tagFilter,
    scannerFilter,
    owaspFilter,
    cweFilter,
    dateAfterFilter,
    dateBeforeFilter,
    riskMinFilter,
    riskMaxFilter
  ].filter(Boolean).length;

  function selectPage(nextPage: number) {
    const safePage = Math.max(1, Math.min(nextPage, pageCount));
    setRequestedPage(safePage);
    const firstFinding = sortedFindings[(safePage - 1) * pageSize];
    if (firstFinding) onSelectFinding(firstFinding.id);
  }

  function changeSort(nextSort: FindingSort) {
    const nextFindings = sortFindings(findings, nextSort);
    setSortBy(nextSort);
    setRequestedPage(1);
    if (nextFindings[0]) onSelectFinding(nextFindings[0].id);
  }

  function changePageSize(nextPageSize: number) {
    setPageSize(nextPageSize);
    setRequestedPage(1);
    if (sortedFindings[0]) onSelectFinding(sortedFindings[0].id);
  }

  return (
    <div className="findingsLayout">
      <div className="panel findingsPanel">
        <div className="panelHeader">
          <h3>Findings</h3>
          <span className="contextBadge">{findings.length}</span>
        </div>

        <div className="filterBar" role="group" aria-label="Severity filter">
          {severityFilters.map((severity) => (
            <button
              key={severity}
              type="button"
              aria-pressed={severityFilter === severity}
              className={severityFilter === severity ? "filterButton filterButtonActive" : "filterButton"}
              onClick={() => onSeverityFilter(severity)}
            >
              {severity}
            </button>
          ))}
        </div>

        <div className="resultsToolbar">
          <p aria-live="polite">Showing <strong>{resultStart}–{resultEnd}</strong> of <strong>{sortedFindings.length}</strong></p>
          <div>
            <label>
              Sort
              <select value={sortBy} onChange={(event) => changeSort(event.target.value as FindingSort)}>
                <option value="severity-desc">Severity: highest first</option>
                <option value="severity-asc">Severity: lowest first</option>
                <option value="newest">Newest first</option>
                <option value="title">Finding title</option>
                <option value="status">Lifecycle status</option>
              </select>
            </label>
            <label>
              Rows
              <select value={pageSize} onChange={(event) => changePageSize(Number(event.target.value))}>
                {pageSizes.map((size) => <option value={size} key={size}>{size}</option>)}
              </select>
            </label>
          </div>
        </div>

        <details className="advancedFindingControls">
          <summary><span>Filters &amp; tags</span>{secondaryFilterCount > 0 ? <span className="activeFilterCount">{secondaryFilterCount} active</span> : <span className="filterSummaryHint">Scope, status, confidence, and more</span>}</summary>
          <div className="findingFilterSection">
            <h4>Scope and management</h4>
            <div className="filterGrid filterGridPrimary" aria-label="Finding scope and management filters">
              <label>Scope<select value={findingScope} onChange={(event) => onFindingScope(event.target.value)}><option value="scan">Current scan</option><option value="workspace">Workspace</option></select></label>
              <label>Target<select value={targetFilter} onChange={(event) => onTargetFilter(event.target.value)} disabled={findingScope !== "workspace"}><option value="">All targets</option>{targets.map((target) => <option value={target.id} key={target.id}>{target.name}</option>)}</select></label>
              <label>Profile<select value={profileFilter} onChange={(event) => onProfileFilter(event.target.value)} disabled={findingScope !== "workspace"}><option value="">All profiles</option>{scanProfiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.label}</option>)}</select></label>
              <label>Lifecycle<select value={lifecycleFilter} onChange={(event) => onLifecycleFilter(event.target.value)}><option value="all">All states</option>{lifecycleStatuses.map((item) => <option value={item} key={item}>{formatStatus(item)}</option>)}</select></label>
              <label>Confidence<select value={confidenceFilter} onChange={(event) => onConfidenceFilter(event.target.value)}>{confidenceFilters.map((item) => <option value={item} key={item}>{item === "all" ? "All confidence" : item}</option>)}</select></label>
              <label>Suppression<select value={suppressionFilter} onChange={(event) => onSuppressionFilter(event.target.value)}><option value="all">All suppression</option><option value="active">Suppressed</option><option value="not_suppressed">Not suppressed</option></select></label>
              <label>Tag<select value={tagFilter} onChange={(event) => onTagFilter(event.target.value)}><option value="">All tags</option>{tags.map((tag) => <option value={tag.id} key={tag.id}>{tag.label}</option>)}</select></label>
            </div>
          </div>
          <div className="findingFilterSection">
            <h4>Evidence detail</h4>
            <div className="filterGrid" aria-label="Advanced finding filters">
              <label>Scanner<input value={scannerFilter} onChange={(event) => onScannerFilter(event.target.value)} /></label>
              <label>OWASP<input value={owaspFilter} onChange={(event) => onOwaspFilter(event.target.value)} /></label>
              <label>CWE<input value={cweFilter} onChange={(event) => onCweFilter(event.target.value)} /></label>
              <label>From<input type="datetime-local" value={dateAfterFilter} onChange={(event) => onDateAfterFilter(event.target.value)} /></label>
              <label>To<input type="datetime-local" value={dateBeforeFilter} onChange={(event) => onDateBeforeFilter(event.target.value)} /></label>
              <label>Risk min<input type="number" min="0" max="100" value={riskMinFilter} onChange={(event) => onRiskMinFilter(event.target.value)} /></label>
              <label>Risk max<input type="number" min="0" max="100" value={riskMaxFilter} onChange={(event) => onRiskMaxFilter(event.target.value)} /></label>
            </div>
            <div className="tagManagement">
              <label className="tagLabelInput"><span className="srOnly">New tag label</span><input value={tagLabel} onChange={(event) => onTagLabelChange(event.target.value)} placeholder="Tag label" /></label>
              <button type="button" onClick={onCreateTag} disabled={!tagLabel.trim()}>Create tag</button>
              <select value={tagResourceType} onChange={(event) => onTagResourceTypeChange(event.target.value)} aria-label="Tag resource type"><option value="target">Target</option><option value="scan">Scan</option></select>
              <button type="button" onClick={onAssignTag} disabled={!tagFilter || !selectedFinding}>Assign tag</button>
            </div>
          </div>
        </details>

        {sortedFindings.length > 0 ? (
          <>
            <div className="findingsTableViewport">
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
                  {visibleFindings.map((finding) => (
                    <tr key={finding.id} className={finding.id === selectedFinding?.id ? "findingRowSelected" : undefined}>
                      <td>
                        <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                      </td>
                      <td>
                        <span className={finding.suppressed ? "stateBadge stateBadgeSuppressed" : "stateBadge"}>
                          {formatStatus(finding.lifecycle_status)}
                        </span>
                      </td>
                      <td><button type="button" className="findingSelectButton" aria-current={finding.id === selectedFinding?.id ? "true" : undefined} onClick={() => onSelectFinding(finding.id)}>{finding.title}</button></td>
                      <td>{finding.source_tool}</td>
                      <td>{finding.affected_url ?? finding.affected_file ?? "global"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <nav className="resultsPagination" aria-label="Finding result pages">
              <button type="button" className="secondaryButton" onClick={() => selectPage(currentPage - 1)} disabled={currentPage === 1}>Previous</button>
              <span>Page <strong>{currentPage}</strong> of <strong>{pageCount}</strong></span>
              <button type="button" className="secondaryButton" onClick={() => selectPage(currentPage + 1)} disabled={currentPage === pageCount}>Next</button>
            </nav>
          </>
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
          <span className="contextBadge">Empty</span>
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
          <dt>Evidence boundary</dt>
          <dd>Normalized and redacted</dd>
        </div>
        <div>
          <dt>Tags</dt>
          <dd>{finding.tags.length > 0 ? finding.tags.join(", ") : "none"}</dd>
        </div>
      </dl>

      <h4>Evidence</h4>
      <pre>{finding.evidence ?? "No evidence snippet stored."}</pre>

      <h4>Reproduction</h4>
      <p>{finding.reproduction_steps ?? "No safe reproduction steps were provided by this scanner."}</p>

      <h4>Remediation</h4>
      <p>{finding.remediation ?? "No remediation guidance was provided for this finding."}</p>

      <h4>False-positive notes</h4>
      <p>{finding.false_positive_notes ?? "No false-positive guidance was provided. Validate the affected behavior before changing lifecycle state."}</p>
    </div>
  );
}

function formatStatus(value: string) {
  return value.replaceAll("_", " ");
}

function sortFindings(findings: Finding[], sortBy: FindingSort) {
  return [...findings].sort((left, right) => {
    if (sortBy === "severity-asc") return (severityRank[left.severity] ?? 0) - (severityRank[right.severity] ?? 0);
    if (sortBy === "newest") return Date.parse(right.created_at) - Date.parse(left.created_at);
    if (sortBy === "title") return left.title.localeCompare(right.title);
    if (sortBy === "status") return left.lifecycle_status.localeCompare(right.lifecycle_status) || (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0);
    return (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0);
  });
}
