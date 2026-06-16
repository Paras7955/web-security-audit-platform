import { DEFAULT_LIMITS, SCAN_MODES, SCAN_STATUSES, SCAN_STEPS } from "@/lib/contracts";
import { TargetSetup } from "@/components/TargetSetup";

const safetyRules = [
  "Only scan apps you own, run locally, or are explicitly authorized to test.",
  "Active Demo scans are restricted to configured local/demo targets.",
  "No credential attacks, destructive testing, stealth scanning, or mass scanning.",
  "AI receives only normalized, redacted findings."
];

export default function Home() {
  return (
    <main className="shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Defensive Web App Security Audit</p>
          <h1>Local-first security evidence, normalized findings, and clear reports.</h1>
        </div>
        <div className="statusPanel" aria-label="Phase 2 target validation status">
          <span>Phase 3</span>
          <strong>Scan lifecycle ready</strong>
          <small>Create allowlisted targets and run passive lifecycle jobs. Real scanner checks start in later phases.</small>
        </div>
      </section>

      <section className="grid">
        <article>
          <h2>Scan Modes</h2>
          <ul>
            {SCAN_MODES.map((mode) => (
              <li key={mode}>{mode}</li>
            ))}
          </ul>
        </article>

        <article>
          <h2>Status Contract</h2>
          <ul>
            {SCAN_STATUSES.map((status) => (
              <li key={status}>{status}</li>
            ))}
          </ul>
        </article>

        <article>
          <h2>Current Steps</h2>
          <ul>
            {SCAN_STEPS.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ul>
        </article>

        <article>
          <h2>Default Limits</h2>
          <dl>
            {Object.entries(DEFAULT_LIMITS).map(([key, value]) => (
              <div key={key}>
                <dt>{key}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </article>
      </section>

      <section className="safety">
        <h2>Responsible Use</h2>
        <ul>
          {safetyRules.map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ul>
      </section>

      <TargetSetup />
    </main>
  );
}
