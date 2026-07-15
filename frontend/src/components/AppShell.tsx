"use client";

import { useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import { ScopeHarborMark } from "@/components/ScopeHarborMark";
import { TargetSetup, workspaceViews, type WorkspaceView } from "@/components/TargetSetup";
import { WebGLScopeField } from "@/components/WebGLScopeField";

const safetyRules = ["Exact allowlist", "Local-first", "Evidence redacted"];

export function AppShell() {
  const [activeView, setActiveView] = useState<WorkspaceView>("overview");
  const [heroState, setHeroState] = useState({ activeProfile: "passive-web", currentStep: null as string | null, status: "ready" });

  function toggleTheme() {
    const root = document.documentElement;
    const nextTheme = root.dataset.theme === "light" ? "dark" : "light";
    root.dataset.theme = nextTheme;
    root.style.colorScheme = nextTheme;
    window.localStorage.setItem("scopeharbor-theme", nextTheme);
  }

  function navigateTo(view: WorkspaceView) {
    setActiveView(view);
    window.requestAnimationFrame(() => document.getElementById("workspace-console")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  return (
    <main className="appShell">
      <header className="appTopbar">
        <a className="brandLockup" href="#workspace-console" aria-label="ScopeHarbor workspace home" onClick={(event) => { event.preventDefault(); navigateTo("overview"); }}>
          <ScopeHarborMark />
          <span>
            <strong>ScopeHarbor</strong>
            <small>Local AppSec Audit Platform</small>
          </span>
        </a>

        <nav className="primaryNavigation" aria-label="Primary workspace navigation">
          {workspaceViews.map((view) => (
            <button
              key={view.id}
              type="button"
              className={activeView === view.id ? "primaryNavItem primaryNavItemActive" : "primaryNavItem"}
              aria-current={activeView === view.id ? "page" : undefined}
              onClick={() => navigateTo(view.id)}
            >
              {view.label}
            </button>
          ))}
        </nav>

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
            <button className="primaryAction" type="button" onClick={() => navigateTo("scanning")}>Start an audit <AppIcon name="arrow" size={16} /></button>
            <span className="heroReady"><span className="liveDot" /> Platform readiness is visible before launch</span>
          </div>
          <ul className="safetyStrip" aria-label="Safety boundaries">
            {safetyRules.map((rule) => (
              <li key={rule}><AppIcon name="check" size={14} />{rule}</li>
            ))}
          </ul>
        </div>
        <WebGLScopeField {...heroState} />
      </section>

      <section id="workspace-console" className="workspaceConsole">
        <TargetSetup activeView={activeView} onActiveViewChange={navigateTo} onHeroStateChange={setHeroState} />
      </section>
    </main>
  );
}
