"use client";

import { useEffect, useRef, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import { ScopeHarborMark } from "@/components/ScopeHarborMark";
import { TargetSetup, workspaceViews, type WorkspaceView } from "@/components/TargetSetup";

export function AppShell() {
  const [activeView, setActiveView] = useState<WorkspaceView>("overview");
  const [platformStatus, setPlatformStatus] = useState("validating");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const topbarRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      setTheme(document.documentElement.dataset.theme === "light" ? "light" : "dark");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    const topbar = topbarRef.current;
    if (!topbar) return;
    const updateOffset = () => document.documentElement.style.setProperty("--app-topbar-height", `${topbar.offsetHeight}px`);
    updateOffset();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(updateOffset);
    observer.observe(topbar);
    return () => observer.disconnect();
  }, []);

  function toggleTheme() {
    const root = document.documentElement;
    const nextTheme = root.dataset.theme === "light" ? "dark" : "light";
    root.dataset.theme = nextTheme;
    root.style.colorScheme = nextTheme;
    window.localStorage.setItem("scopeharbor-theme", nextTheme);
    setTheme(nextTheme);
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
      <a className="skipLink" href="#workspace-console">Skip to workspace</a>
      <h1 className="srOnly">ScopeHarbor local application security workspace</h1>
      <header ref={topbarRef} className="appTopbar">
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
          <button className="localOnlyBadge" type="button" onClick={() => navigateTo("operations")} aria-label="Open platform readiness">
            <span className={platformStatus === "ready" || platformStatus === "completed" ? "liveDot" : "liveDot liveDotChecking"} />
            <span aria-live="polite">{platformStatus === "ready" || platformStatus === "completed" ? "Platform ready" : "Check platform"}</span>
          </button>
          <button
            className="iconButton themeToggle"
            type="button"
            onClick={toggleTheme}
            aria-pressed={theme === "light"}
            aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
            title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
          >
            <span className="themeIcon themeIconSun"><AppIcon name="sun" /></span>
            <span className="themeIcon themeIconMoon"><AppIcon name="moon" /></span>
          </button>
        </div>
      </header>

      <section id="workspace-console" className="workspaceConsole">
        <TargetSetup activeView={activeView} onActiveViewChange={navigateTo} onPlatformStatusChange={setPlatformStatus} />
      </section>
    </main>
  );
}
