import type { ReportArtifact, Scan } from "@/lib/securityAuditApi";

import { canUseReports, reportableStatuses } from "./ScanControls";

const visibleReportCount = 4;

export function ReportsPanel({
  scan,
  reports,
  message,
  isGenerating,
  onGenerate,
  onViewReport,
  onDownloadReport
}: {
  scan: Scan | null;
  reports: ReportArtifact[];
  message: string;
  isGenerating: boolean;
  onGenerate: () => void;
  onViewReport: (report: ReportArtifact) => void;
  onDownloadReport: (report: ReportArtifact) => void;
}) {
  const canGenerate = Boolean(scan && canUseReports(scan) && reportableStatuses.has(scan.status) && !isGenerating);
  const visibleReports = reports.slice(0, visibleReportCount);
  const remainingReports = reports.slice(visibleReportCount);

  return (
    <div className="reportPanel">
      <div className="panelHeader">
        <h3>Reports</h3>
        <span className="contextBadge">Normalized findings only</span>
      </div>

      <div className="reportActions">
        <button type="button" onClick={onGenerate} disabled={!canGenerate}>
          Generate Reports
        </button>
        <p>{scan && !canUseReports(scan) ? "Reports remain available for passive, Active Demo, and Repo scans." : message}</p>
      </div>

      {reports.length > 0 ? (
        <div className="reportHistory">
          <ReportList reports={visibleReports} onViewReport={onViewReport} onDownloadReport={onDownloadReport} />
          {remainingReports.length > 0 ? (
            <details className="reportOverflowDetails">
              <summary>Show {remainingReports.length} older report{remainingReports.length === 1 ? "" : "s"}</summary>
              <ReportList reports={remainingReports} onViewReport={onViewReport} onDownloadReport={onDownloadReport} />
            </details>
          ) : null}
        </div>
      ) : (
        <p className="emptyState">No report artifacts yet.</p>
      )}
    </div>
  );
}

function ReportList({
  reports,
  onViewReport,
  onDownloadReport
}: {
  reports: ReportArtifact[];
  onViewReport: (report: ReportArtifact) => void;
  onDownloadReport: (report: ReportArtifact) => void;
}) {
  return (
    <ul className="reportList">
      {reports.map((report) => (
        <li key={report.id}>
          <strong>{report.report_type}</strong>
          <span>{new Date(report.created_at).toLocaleString()}</span>
          <button type="button" onClick={() => onViewReport(report)}>
            View
          </button>
          <button type="button" onClick={() => onDownloadReport(report)}>
            Download
          </button>
        </li>
      ))}
    </ul>
  );
}
