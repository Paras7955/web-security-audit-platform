import type { ReportArtifact, Scan } from "@/lib/securityAuditApi";

import { canUseReports, reportableStatuses } from "./ScanControls";
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
  const htmlReport = reports.find((report) => report.report_type === "html") ?? null;
  const markdownReport = reports.find((report) => report.report_type === "markdown") ?? null;

  return (
    <div className="reportPanel">
      <div className="panelHeader">
        <div><h3>Reports</h3><p>Generate sanitized Markdown and HTML artifacts from normalized findings for the selected scan.</p></div>
        <span className="contextBadge">Normalized findings only</span>
      </div>

      <div className="reportActions">
        <button className="primaryButton" type="button" onClick={onGenerate} disabled={!canGenerate}>
          {isGenerating ? "Generating…" : "Generate reports"}
        </button>
        <p role="status" aria-live="polite">{scan && !canUseReports(scan) ? "Reports remain available for Passive Web, Active Demo, and Repository scans." : message}</p>
      </div>

      {reports.length > 0 ? (
        <div className="reportArtifactActions">
          <div className="reportPrimaryAction">
            <div>
              <strong>Formatted audit report</strong>
              <span>{htmlReport ? `Updated ${new Date(htmlReport.created_at).toLocaleString()}` : "HTML artifact unavailable"}</span>
            </div>
            <button className="secondaryButton" type="button" onClick={() => htmlReport && onViewReport(htmlReport)} disabled={!htmlReport || Boolean(pendingAction)}>
              {htmlReport && pendingAction?.reportId === htmlReport.id && pendingAction.action === "view" ? "Opening…" : "Open formatted report"}
            </button>
          </div>
          <div className="reportDownloads" aria-label="Report downloads">
            <span>Download a portable copy</span>
            <button className="textButton" type="button" onClick={() => htmlReport && onDownloadReport(htmlReport)} disabled={!htmlReport || Boolean(pendingAction)}>
              {htmlReport && pendingAction?.reportId === htmlReport.id && pendingAction.action === "download" ? "Preparing HTML…" : "HTML"}
            </button>
            <button className="textButton" type="button" onClick={() => markdownReport && onDownloadReport(markdownReport)} disabled={!markdownReport || Boolean(pendingAction)}>
              {markdownReport && pendingAction?.reportId === markdownReport.id && pendingAction.action === "download" ? "Preparing Markdown…" : "Markdown"}
            </button>
          </div>
        </div>
      ) : (
        <p className="emptyState">No report artifacts yet.</p>
      )}
    </div>
  );
}
