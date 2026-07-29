"use client";

import { useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import { ScopeHarborMark } from "@/components/ScopeHarborMark";
import { TargetSetup, workspaceViews, type WorkspaceView } from "@/components/TargetSetup";
import { WebGLScopeField } from "@/components/WebGLScopeField";

const safetyRules = [
  { icon: "shield" as const, label: "Your scope stays explicit" },
  { icon: "credential" as const, label: "Sensitive evidence stays local" },
  { icon: "check" as const, label: "Findings lead to clear action" }
];

export function AppShell() {
  const [activeView, setActiveView] = useState<WorkspaceView>("scanning");
  const [heroState, setHeroState] = useState({ activeProfile: "passive-web", currentStep: null as string | null, status: "validating" });

  function toggleTheme() {
    const root = document.documentElement;
    const nextTheme = root.dataset.theme === "light" ? "dark" : "light";
    root.dataset.theme = nextTheme;
    root.style.colorScheme = nextTheme;
    window.localStorage.setItem("scopeharbor-theme", nextTheme);
  }

  function navigateTo(view: WorkspaceView) {
    setActiveView(view);
    window.requestAnimationFrame(() => document.getElementById("workspace-console")?.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start"
    }));
  }

  return (
    <main className="appShell">
      <header className="appTopbar">
        <a className="brandLockup" href="#workspace-console" aria-label="ScopeHarbor workspace home" onClick={(event) => { event.preventDefault(); navigateTo("overview"); }}>
          <ScopeHarborMark />
          <strong>ScopeHarbor</strong>
          <span className="brandContext">Local workspace</span>
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
            <span className={heroState.status === "ready" || heroState.status === "completed" ? "liveDot" : "liveDot liveDotChecking"} />
            {heroState.status === "ready" || heroState.status === "completed" ? "Platform ready" : "Platform check"}
          </div>
          <button className="iconButton themeToggle" type="button" onClick={toggleTheme} aria-label="Toggle light and dark mode">
            <span className="themeIcon themeIconSun"><AppIcon name="sun" /></span>
            <span className="themeIcon themeIconMoon"><AppIcon name="moon" /></span>
          </button>
        </div>
      </header>

      <section className="commandHero" aria-labelledby="workspace-title">
        <div className="commandHeroCopy">
          <h1 id="workspace-title">ScopeHarbor</h1>
          <p className="heroSummary">Local-first application security audits</p>
          <ul className="safetyStrip" aria-label="Product promises">
            {safetyRules.map((rule) => (
              <li key={rule.label}><AppIcon name={rule.icon} size={17} />{rule.label}</li>
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
