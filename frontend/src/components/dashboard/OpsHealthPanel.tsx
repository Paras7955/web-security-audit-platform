import type { PlatformHealth } from "@/lib/securityAuditApi";

type OpsHealthContext = "audit" | "operations";

const componentPurpose: Record<string, string> = {
  Database: "Stores workspace and audit state",
  Worker: "Runs bounded audit jobs",
  ZAP: "Supports approved local demo profiles",
  Artifacts: "Stores sanitized reports and receipts"
};

export function OpsHealthPanel({
  health,
  message,
  onRefresh,
  context = "operations"
}: {
  health: PlatformHealth | null;
  message: string;
  onRefresh: () => void;
  context?: OpsHealthContext;
}) {
  const components: Array<[string, { status: string; detail: string | null }]> = health
    ? [
        ["Database", health.database],
        ["Worker", health.worker],
        ["ZAP", health.zap],
        ["Artifacts", health.artifact_root]
      ]
    : [];
  const healthyComponents = components.filter(([, component]) => component.status === "ok").length;
  const isAuditContext = context === "audit";

  return (
    <div className={`opsPanel opsPanel-${context}`}>
      <div className="panelHeader">
        <div>
          <h3>{isAuditContext ? "Audit preflight results" : "Platform health"}</h3>
          <p>{isAuditContext ? "These checks confirm the local platform can start and preserve an audit safely." : "Live state for the local services that support this workspace."}</p>
        </div>
        <button type="button" className="secondaryButton" onClick={onRefresh}>
          {health ? "Run checks again" : "Run readiness checks"}
        </button>
      </div>
      {health ? (
        <>
          <dl className="opsSummary">
            <div>
              <dt>{isAuditContext ? "Preflight result" : "Overall status"}</dt>
              <dd className={`health-${health.status}`}>{health.status === "ok" ? (isAuditContext ? "Ready to audit" : "All systems ready") : "Needs attention"}</dd>
              <small>{healthyComponents} of {components.length} required services healthy</small>
            </div>
            <div>
              <dt>Waiting audits</dt>
              <dd>{health.queue_depth}</dd>
              <small>{health.queue_depth === 0 ? "The worker queue is clear" : "Audit jobs are waiting for the worker"}</small>
            </div>
          </dl>
          <ul className="opsList">
            {components.map(([label, component]) => (
              <li key={label}>
                <span className={`statusDot status-${component.status}`} />
                <strong>{label}</strong>
                <em>{component.status}</em>
                <small>{componentPurpose[label]}{component.detail ? ` · ${component.detail}` : ""}</small>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <div className="emptyState richEmptyState">
          <strong>No readiness result yet</strong>
          <span>{message}</span>
        </div>
      )}
    </div>
  );
}
