import type { ReportArtifact, Scan } from "@/lib/securityAuditApi";

import { canUseReports, reportableStatuses } from "./ScanControls";

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
      ) : (
        <p className="emptyState">No report artifacts yet.</p>
      )}
    </div>
  );
}
