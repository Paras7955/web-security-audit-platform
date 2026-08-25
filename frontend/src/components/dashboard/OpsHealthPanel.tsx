import { AppIcon } from "@/components/AppIcon";
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
  isRefreshing,
  checkedAt,
  onRefresh,
  context = "operations"
}: {
  health: PlatformHealth | null;
  message: string;
  isRefreshing: boolean;
  checkedAt: string;
  onRefresh: () => Promise<void>;
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
  const coreComponents = components.filter(([label]) => label !== "ZAP");
  const healthyCoreComponents = coreComponents.filter(([, component]) => component.status === "ok").length;
  const isAuditContext = context === "audit";

  return (
    <div className={`opsPanel opsPanel-${context}`}>
      <div className="panelHeader">
        <div>
          <h3>{isAuditContext ? "Audit preflight results" : "Platform health"}</h3>
          <p>{isAuditContext ? "These checks confirm the local platform can start and preserve an audit safely." : "Live state for the local services that support this workspace."}</p>
        </div>
        <button type="button" className="secondaryButton" onClick={() => void onRefresh()} disabled={isRefreshing}>
          <AppIcon name="refresh" size={15} />
          {isRefreshing ? "Checking…" : health ? "Run checks again" : "Run readiness checks"}
        </button>
      </div>
      <p className="panelActionStatus" role="status" aria-live="polite">
        {message}{checkedAt ? ` · Last checked ${formatCheckedAt(checkedAt)}` : ""}
      </p>
      {health ? (
        <>
          <dl className="opsSummary">
            <div>
              <dt>{isAuditContext ? "Preflight result" : "Overall status"}</dt>
              <dd className={`health-${health.status}`}>{health.status === "ok" ? (isAuditContext ? "Ready to audit" : "All systems ready") : "Needs attention"}</dd>
              <small>{healthyCoreComponents} of {coreComponents.length} core services healthy · ZAP {health.zap.status}</small>
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
          <AppIcon name="operations" size={22} />
          <strong>No readiness result yet</strong>
          <span>Run the local checks to confirm the services required for a safe audit.</span>
        </div>
      )}
    </div>
  );
}

function formatCheckedAt(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}
