"use client";

import { AppIcon } from "@/components/AppIcon";

type GuideView = "overview" | "scanning" | "findings" | "intelligence" | "credentials" | "operations";
type GuideAuditPhase = "ready" | "scope" | "profile" | "authorize" | "run" | "review";

const workflowSteps: Array<{
  number: string;
  title: string;
  description: string;
  action: string;
  view: GuideView;
  phase?: GuideAuditPhase;
}> = [
  {
    number: "01",
    title: "Confirm local readiness",
    description: "Check the database, worker, approved scanner support, artifact storage, and queue before any target is contacted.",
    action: "Open Preflight",
    view: "scanning",
    phase: "ready"
  },
  {
    number: "02",
    title: "Define exact authorized scope",
    description: "Choose a saved allowlisted web target or attach an approved local repository path. ScopeHarbor denies destinations outside configured policy.",
    action: "Open Scope",
    view: "scanning",
    phase: "scope"
  },
  {
    number: "03",
    title: "Choose the right audit profile",
    description: "Select Passive Web, a local-demo profile, or Repository based on the evidence you need and the boundaries the target supports.",
    action: "Choose a profile",
    view: "scanning",
    phase: "profile"
  },
  {
    number: "04",
    title: "Confirm authorization and launch",
    description: "Review the exact target, profile, and required acknowledgements. The worker revalidates workspace and policy context before tools run.",
    action: "Open authorization",
    view: "scanning",
    phase: "authorize"
  },
  {
    number: "05",
    title: "Review normalized findings",
    description: "Sort and filter scanner-neutral findings, inspect sanitized evidence, update lifecycle state, add tags, and record suppression decisions.",
    action: "Review findings",
    view: "findings"
  },
  {
    number: "06",
    title: "Explain impact and track posture",
    description: "Use risk summaries, scan comparisons, sanitized reports, and bounded explanations to turn evidence into remediation work.",
    action: "Open Intelligence",
    view: "intelligence"
  }
];

const profiles = [
  {
    name: "Passive Web",
    use: "A quick high-level review of an exact allowlisted HTTP service.",
    boundary: "Optional guarded target credential; reports and explanations supported."
  },
  {
    name: "Active Demo",
    use: "Bounded ZAP active testing against a configured local demo only.",
    boundary: "Never uses saved credentials; reports and explanations supported."
  },
  {
    name: "Modern Web Crawl",
    use: "A short ZAP Client Spider crawl for a configured local demo.",
    boundary: "Browser-style crawl only; no credentials, reports, or explanations."
  },
  {
    name: "Repository",
    use: "Pinned Gitleaks and offline OSV checks for an approved local path.",
    boundary: "Never clones, fetches, builds, installs, runs hooks, or executes repository code."
  }
];

export function ProductGuide({
  onNavigate
}: {
  onNavigate: (view: GuideView, phase?: GuideAuditPhase) => void;
}) {
  return (
    <div className="guideWorkspace productPage">
      <div className="viewIntro guideIntro">
        <div>
          <h2>How to use ScopeHarbor</h2>
          <p>A practical guide to running authorized local audits, reviewing normalized evidence, and producing useful remediation outputs.</p>
        </div>
        <button type="button" onClick={() => onNavigate("scanning", "profile")}>
          <AppIcon name="scan" size={16} /> Start an audit
        </button>
      </div>

      <div className="guideLayout">
        <aside className="guideContents" aria-label="Guide contents">
          <p className="panelKicker">In this guide</p>
          <nav>
            <a href="#guide-overview">What ScopeHarbor does</a>
            <a href="#guide-workflow">Audit workflow</a>
            <a href="#guide-profiles">Audit profiles</a>
            <a href="#guide-results">Findings and outputs</a>
            <a href="#guide-safety">Safety boundaries</a>
          </nav>
          <button type="button" className="secondaryButton" onClick={() => onNavigate("operations")}>
            Check platform health
          </button>
        </aside>

        <div className="guideContent">
          <section id="guide-overview" className="guideSection">
            <div className="guideSectionHeading">
              <span>Overview</span>
              <div>
                <h3>Defensive AppSec work without an expert-only interface</h3>
                <p>ScopeHarbor is a local-first audit workspace for security-minded developers and small teams. It keeps authorization, scope, scan progress, normalized evidence, remediation decisions, and reports in one repeatable workflow.</p>
              </div>
            </div>
            <div className="guidePrinciples">
              <div><AppIcon name="target" size={18} /><strong>Exact scope</strong><p>Launches are limited to configured targets or approved local repository paths.</p></div>
              <div><AppIcon name="shield" size={18} /><strong>Safe evidence</strong><p>Raw bodies, secrets, unsafe paths, and unredacted scanner output stay outside reports and AI boundaries.</p></div>
              <div><AppIcon name="finding" size={18} /><strong>Actionable results</strong><p>Scanner output is normalized so triage and remediation remain consistent across profiles.</p></div>
            </div>
          </section>

          <section id="guide-workflow" className="guideSection">
            <div className="guideSectionHeading">
              <span>Workflow</span>
              <div>
                <h3>From readiness check to remediation</h3>
                <p>Follow the sequence below for a repeatable audit. Every action opens the relevant page or audit phase.</p>
              </div>
            </div>
            <ol className="guideWorkflow">
              {workflowSteps.map((step) => (
                <li key={step.number}>
                  <span>{step.number}</span>
                  <div><h4>{step.title}</h4><p>{step.description}</p></div>
                  <button type="button" className="secondaryButton" onClick={() => onNavigate(step.view, step.phase)}>
                    {step.action} <AppIcon name="arrow" size={14} />
                  </button>
                </li>
              ))}
            </ol>
          </section>

          <section id="guide-profiles" className="guideSection">
            <div className="guideSectionHeading">
              <span>Profiles</span>
              <div>
                <h3>Choose based on coverage—not intensity</h3>
                <p>Profiles gather different kinds of evidence. Availability is enforced by the selected target and does not broaden the allowlist.</p>
              </div>
            </div>
            <div className="guideProfileList">
              {profiles.map((profile) => (
                <article key={profile.name}>
                  <h4>{profile.name}</h4>
                  <p>{profile.use}</p>
                  <small>{profile.boundary}</small>
                </article>
              ))}
            </div>
            <div className="guideSectionAction">
              <button type="button" onClick={() => onNavigate("scanning", "profile")}>Compare audit profiles</button>
            </div>
          </section>

          <section id="guide-results" className="guideSection guideSplitSection">
            <div>
              <div className="guideSectionHeading">
                <span>Evidence</span>
                <div><h3>Findings and triage</h3><p>Use severity, lifecycle, confidence, tags, scanner, OWASP, CWE, dates, and risk filters to focus the result set. Finding detail keeps sanitized evidence, reproduction guidance, remediation, and false-positive notes together.</p></div>
              </div>
              <button type="button" className="secondaryButton" onClick={() => onNavigate("findings")}>Open Findings</button>
            </div>
            <div>
              <div className="guideSectionHeading">
                <span>Outputs</span>
                <div><h3>Risk, reports, and explanations</h3><p>Intelligence summarizes posture and can compare completed scans of the same target. Reports use normalized findings, while explanations remain bounded by profile and data-handling policy.</p></div>
              </div>
              <button type="button" className="secondaryButton" onClick={() => onNavigate("intelligence")}>Open Intelligence</button>
            </div>
          </section>

          <section id="guide-safety" className="guideSection">
            <div className="guideSectionHeading">
              <span>Boundaries</span>
              <div>
                <h3>What the platform will not do</h3>
                <p>These constraints are enforced by backend policy and worker validation, not only by interface copy.</p>
              </div>
            </div>
            <ul className="guideBoundaryList">
              <li><AppIcon name="check" size={15} /><span><strong>No arbitrary public scanning.</strong> Web targets must match the exact configured allowlist.</span></li>
              <li><AppIcon name="check" size={15} /><span><strong>No repository execution.</strong> Repository scans stage bounded regular files and use pinned/offline tooling.</span></li>
              <li><AppIcon name="check" size={15} /><span><strong>No secret projection.</strong> Target credentials never enter findings, reports, AI, scanner receipts, or audit logs.</span></li>
              <li><AppIcon name="check" size={15} /><span><strong>No hidden redirect trust.</strong> Redirects and outbound destinations are revalidated against SSRF and scope controls.</span></li>
            </ul>
            <div className="guideSectionAction guideSectionActionSplit">
              <button type="button" className="secondaryButton" onClick={() => onNavigate("credentials")}><AppIcon name="credential" size={15} /> Manage Credentials</button>
              <button type="button" className="secondaryButton" onClick={() => onNavigate("operations")}><AppIcon name="operations" size={15} /> Review Operations</button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
