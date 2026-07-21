import type { ReportArtifact, Scan } from "@/lib/securityAuditApi";

import { canUseReports, reportableStatuses } from "./ScanControls";

const visibleReportCount = 4;
type PendingReportAction = { reportId: string; action: "view" | "download" } | null;

export function ReportsPanel({
  scan,
  reports,
  message,
  isGenerating,
  pendingAction,
  onGenerate,
  onViewReport,
  onDownloadReport
}: {
  scan: Scan | null;
  reports: ReportArtifact[];
  message: string;
  isGenerating: boolean;
  pendingAction: PendingReportAction;
  onGenerate: () => void;
  onViewReport: (report: ReportArtifact) => void;
  onDownloadReport: (report: ReportArtifact) => void;
}) {
  const canGenerate = Boolean(scan && canUseReports(scan) && reportableStatuses.has(scan.status) && !isGenerating && !pendingAction);
  const visibleReports = reports.slice(0, visibleReportCount);
  const remainingReports = reports.slice(visibleReportCount);

  return (
    <div className="reportPanel">
      <div className="panelHeader">
        <div><h3>Reports</h3><p>Generate sanitized Markdown and HTML artifacts from normalized findings for the selected scan.</p></div>
        <span className="contextBadge">Normalized findings only</span>
      </div>

      <div className="reportActions">
        <button type="button" onClick={onGenerate} disabled={!canGenerate}>
          {isGenerating ? "Generating…" : "Generate reports"}
        </button>
        <p role="status" aria-live="polite">{scan && !canUseReports(scan) ? "Reports remain available for passive, Active Demo, and Repo scans." : message}</p>
      </div>

      {reports.length > 0 ? (
        <div className="reportHistory">
          <ReportList reports={visibleReports} pendingAction={pendingAction} onViewReport={onViewReport} onDownloadReport={onDownloadReport} />
          {remainingReports.length > 0 ? (
            <details className="reportOverflowDetails">
              <summary>Show {remainingReports.length} older report{remainingReports.length === 1 ? "" : "s"}</summary>
              <ReportList reports={remainingReports} pendingAction={pendingAction} onViewReport={onViewReport} onDownloadReport={onDownloadReport} />
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
  pendingAction,
  onViewReport,
  onDownloadReport
}: {
  reports: ReportArtifact[];
  pendingAction: PendingReportAction;
  onViewReport: (report: ReportArtifact) => void;
  onDownloadReport: (report: ReportArtifact) => void;
}) {
  return (
    <ul className="reportList">
      {reports.map((report) => {
        const isViewing = pendingAction?.reportId === report.id && pendingAction.action === "view";
        const isDownloading = pendingAction?.reportId === report.id && pendingAction.action === "download";
        return (
          <li key={report.id}>
            <strong>{report.report_type}</strong>
            <span>{new Date(report.created_at).toLocaleString()}</span>
            <button className="secondaryButton" type="button" onClick={() => onViewReport(report)} disabled={Boolean(pendingAction)}>
              {isViewing ? "Opening…" : "View"}
            </button>
            <button className="secondaryButton" type="button" onClick={() => onDownloadReport(report)} disabled={Boolean(pendingAction)}>
              {isDownloading ? "Preparing…" : "Download"}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
