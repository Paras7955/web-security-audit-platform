import type { PlatformHealth } from "@/lib/securityAuditApi";

export function OpsHealthPanel({ health, message, onRefresh }: { health: PlatformHealth | null; message: string; onRefresh: () => void }) {
  const components: Array<[string, { status: string; detail: string | null }]> = health
    ? [
        ["Database", health.database],
        ["Worker", health.worker],
        ["ZAP", health.zap],
        ["Artifacts", health.artifact_root]
      ]
    : [];

  return (
    <div className="opsPanel">
      <div className="panelHeader">
        <h3>Platform Ops</h3>
        <button type="button" className="secondaryButton" onClick={onRefresh}>
          Refresh
        </button>
      </div>
      {health ? (
        <>
          <dl className="opsMeta">
            <div>
              <dt>Status</dt>
              <dd className={`health-${health.status}`}>{health.status}</dd>
            </div>
            <div>
              <dt>Queue</dt>
              <dd>{health.queue_depth}</dd>
            </div>
          </dl>
          <ul className="opsList">
            {components.map(([label, component]) => (
              <li key={label}>
                <span className={`statusDot status-${component.status}`} />
                <strong>{label}</strong>
                <em>{component.status}</em>
                <small>{component.detail ?? "No detail"}</small>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="emptyState">{message}</p>
      )}
    </div>
  );
}
