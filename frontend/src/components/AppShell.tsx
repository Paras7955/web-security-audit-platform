import { TargetSetup } from "@/components/TargetSetup";
import { SCAN_PROFILES, SCAN_STATUSES } from "@/lib/contracts";

const navItems = [
  { label: "Overview", href: "#overview" },
  { label: "Targets", href: "#targets" },
  { label: "Scans", href: "#scans" },
  { label: "Reports", href: "#reports" },
  { label: "Findings", href: "#findings" }
];
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
          <p className="eyebrow">Defensive Web App Security Audit</p>
          <h1>Workspace Security Console</h1>
        </div>
        <div className="workspaceBadge" aria-label="Workspace data model">
          <span>Data model</span>
          <strong>Workspace-owned</strong>
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
            <span>Scan profiles</span>
            <strong>{SCAN_PROFILES.length}</strong>
          </div>
          <div>
            <span>Status states</span>
            <strong>{SCAN_STATUSES.length}</strong>
          </div>
          <div>
            <span>API surface</span>
            <strong>Protected endpoints</strong>
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
