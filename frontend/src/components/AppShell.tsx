import { TargetSetup } from "@/components/TargetSetup";
import { SCAN_MODES, SCAN_STATUSES } from "@/lib/contracts";

const navItems = [
  { label: "Overview", href: "#overview" },
  { label: "Targets", href: "#targets" },
  { label: "Scans", href: "#scans" },
  { label: "Reports", href: "#reports" },
  { label: "Findings", href: "#findings" }
];
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
        <div className="workspaceBadge" aria-label="Workspace data boundary">
          <span>Data access</span>
          <strong>Workspace-scoped</strong>
        </div>
      </header>

      <nav className="appNav" aria-label="Workspace navigation">
        {navItems.map((item) => (
          <a href={item.href} key={item.href}>
            {item.label}
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
            <span>API boundary</span>
            <strong>Protected routes</strong>
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
