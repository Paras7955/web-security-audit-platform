import { TargetSetup } from "@/components/TargetSetup";
import { SCAN_PROFILES, SCAN_STATUSES } from "@/lib/contracts";

const safetyRules = [
  "Allowlisted targets only",
  "Workspace-owned records",
  "Redacted evidence",
  "Template AI by default"
];

export function AppShell() {
  return (
    <main className="appShell">
      <header className="appTopbar">
        <div>
          <p className="eyebrow">ScopeHarbor — Local AppSec Audit Platform</p>
          <h1>Authorized security reviews, kept inside your environment</h1>
        </div>
        <div className="workspaceBadge" aria-label="Workspace data model">
          <span>Data model</span>
          <strong>Workspace-owned</strong>
        </div>
      </header>

      <section id="overview" className="overviewBand" aria-label="Workspace overview">
        <div className="metricStrip">
          <div>
            <span>Scan profiles</span>
            <strong>{SCAN_PROFILES.length}</strong>
          </div>
          <div>
            <span>Status states</span>
            <strong>{SCAN_STATUSES.length}</strong>
          </div>
          <div>
            <span>API surface</span>
            <strong>/api/v1</strong>
          </div>
          <div>
            <span>Target scope</span>
            <strong>Allowlist</strong>
          </div>
        </div>

        <ul className="safetyStrip">
          {safetyRules.map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ul>
      </section>

      <section id="workspace-console" className="workspaceConsole">
        <TargetSetup />
      </section>
    </main>
  );
}
