import { AppIcon } from "@/components/AppIcon";
import type { Finding, Scan } from "@/lib/securityAuditApi";

import { canUseAi, canUseReports, formatScanProfileLabel } from "./ScanControls";

const severityOrder = ["critical", "high", "medium", "low", "info"] as const;
const severityRank: Record<string, number> = Object.fromEntries(severityOrder.map((severity, index) => [severity, index]));

export function AuditReviewSummary({
  scan,
  findings,
  subjectName,
  onOpenFindings,
  onOpenIntelligence,
  onOpenScanHistory
}: {
  scan: Scan;
  findings: Finding[];
  subjectName: string;
  onOpenFindings: () => void;
  onOpenIntelligence: () => void;
  onOpenScanHistory: () => void;
}) {
  const counts = Object.fromEntries(severityOrder.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length]));
  const topFindings = [...findings]
    .sort((left, right) => (severityRank[left.severity] ?? severityOrder.length) - (severityRank[right.severity] ?? severityOrder.length))
    .slice(0, 3);
  const intelligenceLabel = canUseReports(scan)
    ? canUseAi(scan) ? "Open reports and guidance" : "Open reports"
    : "Open risk intelligence";

  return (
    <section className="auditReviewSummary" aria-labelledby="audit-review-summary-title">
      <div className="auditReviewOutcome">
        <div>
          <span className="contextBadge">{scan.status.replaceAll("_", " ")}</span>
          <h3 id="audit-review-summary-title">{subjectName}</h3>
          <p>{formatScanProfileLabel(scan.scan_profile_id)} completed {formatCompletion(scan.completed_at ?? scan.created_at)} with {findings.length} normalized finding{findings.length === 1 ? "" : "s"}.</p>
        </div>
        <dl className="auditReviewMeta">
          <div><dt>Audit ID</dt><dd>{scan.id}</dd></div>
          <div><dt>Profile</dt><dd>{formatScanProfileLabel(scan.scan_profile_id)}</dd></div>
        </dl>
      </div>

      <div className="auditReviewSeverity" aria-label="Severity distribution">
        {severityOrder.map((severity) => (
          <div key={severity}><strong>{counts[severity]}</strong><span>{severity}</span></div>
        ))}
      </div>

      <section className="auditReviewTopFindings" aria-labelledby="audit-review-top-findings-title">
        <div className="sectionHeading"><div><h4 id="audit-review-top-findings-title">Highest-priority signals</h4><p>Open Findings for evidence, lifecycle, suppression, and tag decisions.</p></div></div>
        {topFindings.length ? (
          <ol>
            {topFindings.map((finding) => (
              <li key={finding.id}><span className={`severity severity-${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong><small>{finding.source_tool}</small></li>
            ))}
          </ol>
        ) : <p className="emptyState">No normalized findings were recorded. This does not guarantee the subject is secure.</p>}
      </section>

      <div className="auditReviewHandoffs" aria-label="Review next actions">
        <button className="primaryButton" type="button" onClick={onOpenFindings}><AppIcon name="finding" size={16} />Triage findings</button>
        <button className="secondaryButton" type="button" onClick={onOpenIntelligence}><AppIcon name="intelligence" size={16} />{intelligenceLabel}</button>
        <button className="textButton" type="button" onClick={onOpenScanHistory}>Open scan history</button>
      </div>
    </section>
  );
}

function formatCompletion(value: string) {
  return new Date(value).toLocaleString();
}
