import { TargetSetup } from "@/components/TargetSetup";
import { SCAN_MODES, SCAN_STATUSES } from "@/lib/contracts";

const navItems = ["Overview", "Targets", "Scans", "Findings", "Reports"];
const safetyRules = [
  "Allowlisted targets only",
  "Workspace-scoped data",
  "Redacted evidence",
  "Template AI by default"
];

export function AppShell() {
  return (
    <main className="appShell">
      <header className="appTopbar">
        <div>
          <p className="eyebrow">Defensive Web App Security Audit</p>
          <h1>Workspace Security Console</h1>
        </div>
        <div className="workspaceBadge" aria-label="Current workspace">
          <span>Workspace</span>
          <strong>Local Dev</strong>
        </div>
      </header>

      <nav className="appNav" aria-label="Workspace navigation">
        {navItems.map((item) => (
          <a href={item === "Overview" ? "#overview" : "#workspace-console"} key={item}>
            {item}
          </a>
        ))}
      </nav>

      <section id="overview" className="overviewBand" aria-label="Workspace overview">
        <div className="metricStrip">
          <div>
            <span>Scan modes</span>
            <strong>{SCAN_MODES.length}</strong>
          </div>
          <div>
            <span>Status states</span>
            <strong>{SCAN_STATUSES.length}</strong>
          </div>
          <div>
            <span>Auth mode</span>
            <strong>Bearer</strong>
          </div>
          <div>
            <span>Scope</span>
            <strong>Local</strong>
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
