"use client";

import { AppIcon } from "@/components/AppIcon";
import { ScopeHarborMark } from "@/components/ScopeHarborMark";
import { TargetSetup } from "@/components/TargetSetup";
import { WebGLScopeField } from "@/components/WebGLScopeField";

const safetyRules = ["Exact allowlist", "Workspace isolated", "Evidence redacted"];

export function AppShell() {
  function toggleTheme() {
    const root = document.documentElement;
    const nextTheme = root.dataset.theme === "light" ? "dark" : "light";
    root.dataset.theme = nextTheme;
    root.style.colorScheme = nextTheme;
    window.localStorage.setItem("scopeharbor-theme", nextTheme);
  }

  return (
    <main className="appShell">
      <header className="appTopbar">
        <a className="brandLockup" href="#workspace-console" aria-label="ScopeHarbor workspace home">
          <ScopeHarborMark />
          <span>
            <strong>ScopeHarbor</strong>
            <small>Local AppSec Audit Platform</small>
          </span>
        </a>

        <div className="topbarActions">
          <div className="localOnlyBadge">
            <span className="liveDot" />
            Local workspace
          </div>
          <button className="iconButton themeToggle" type="button" onClick={toggleTheme} aria-label="Toggle light and dark mode">
            <span className="themeIcon themeIconSun"><AppIcon name="sun" /></span>
            <span className="themeIcon themeIconMoon"><AppIcon name="moon" /></span>
          </button>
        </div>
      </header>

      <section className="commandHero" aria-labelledby="workspace-title">
        <div className="commandHeroCopy">
          <p className="eyebrow"><AppIcon name="shield" size={15} /> Defensive security workspace</p>
          <h1 id="workspace-title">See the attack surface.<br /><span>Keep control of the scope.</span></h1>
          <p className="heroSummary">
            Launch authorized scans, triage normalized findings, and turn evidence into clear remediation decisions—without sending raw artifacts outside your environment.
          </p>
          <ul className="safetyStrip" aria-label="Safety boundaries">
            {safetyRules.map((rule) => (
              <li key={rule}><AppIcon name="check" size={14} />{rule}</li>
            ))}
          </ul>
        </div>
        <WebGLScopeField />
      </section>

      <section id="workspace-console" className="workspaceConsole">
        <TargetSetup />
      </section>
    </main>
  );
}
