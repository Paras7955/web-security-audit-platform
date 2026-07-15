"use client";

import { AppIcon } from "@/components/AppIcon";
import { ScopeHarborMark } from "@/components/ScopeHarborMark";
import { TargetSetup } from "@/components/TargetSetup";
import { WebGLScopeField } from "@/components/WebGLScopeField";

const safetyRules = ["Exact allowlist", "Local-first", "Evidence redacted"];

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
          <p className="eyebrow"><AppIcon name="shield" size={15} /> Authorized security workspace</p>
          <h1 id="workspace-title">Find the risks.<br /><span>Keep the path clear.</span></h1>
          <p className="heroSummary">
            Move from an approved local target to clear, normalized findings through a guided audit path that keeps scope, evidence, and decisions under your control.
          </p>
          <div className="heroActions">
            <a className="primaryAction" href="#workspace-console">Start an audit <AppIcon name="arrow" size={16} /></a>
            <span className="heroReady"><span className="liveDot" /> Platform readiness is visible before launch</span>
          </div>
          <ul className="safetyStrip" aria-label="Safety boundaries">
            {safetyRules.map((rule) => (
              <li key={rule}><AppIcon name="check" size={14} />{rule}</li>
            ))}
          </ul>
        </div>
        <WebGLScopeField activeProfile="passive-web" status="ready" />
      </section>

      <section id="workspace-console" className="workspaceConsole">
        <TargetSetup />
      </section>
    </main>
  );
}
