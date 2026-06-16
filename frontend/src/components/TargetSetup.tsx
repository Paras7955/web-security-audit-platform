"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type ValidationResult = {
  allowlist_id: string;
  name: string;
  base_url: string;
  allowed_modes: string[];
  max_redirects: number;
  local_demo: boolean;
};

type CreatedTarget = {
  id: string;
  allowlist_id: string;
  name: string;
  base_url: string;
  allowed_modes: string[];
};

type Scan = {
  id: string;
  target_id: string;
  mode: string;
  status: string;
  current_step: string | null;
  status_message: string | null;
  progress_percent: number;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
const terminalStatuses = new Set(["completed", "completed_with_warnings", "failed", "cancelled"]);

export function TargetSetup() {
  const [targetUrl, setTargetUrl] = useState("http://juice-shop:3000");
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [repoPath, setRepoPath] = useState("");
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [createdTarget, setCreatedTarget] = useState<CreatedTarget | null>(null);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [message, setMessage] = useState<string>("Enter an allowlisted local/demo target.");
  const [isBusy, setIsBusy] = useState(false);

  const canCreate = useMemo(() => Boolean(validation && permissionConfirmed && !isBusy), [validation, permissionConfirmed, isBusy]);
  const canStartScan = Boolean(createdTarget && !isBusy);

  useEffect(() => {
    void loadScanHistory();
  }, []);

  useEffect(() => {
    if (!activeScan || terminalStatuses.has(activeScan.status)) {
      return;
    }

    const timer = window.setInterval(() => {
      void refreshScan(activeScan.id);
    }, 1500);
    return () => window.clearInterval(timer);
  }, [activeScan]);

  async function validateTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsBusy(true);
    setCreatedTarget(null);
    setValidation(null);
    setMessage("Validating target against the local allowlist...");

    try {
      const response = await fetch(`${apiBaseUrl}/targets/validate?target_url=${encodeURIComponent(targetUrl)}`);
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Target validation failed.");
      }
      setValidation(body as ValidationResult);
      setMessage("Target is allowlisted. Confirm authorization before saving it.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target validation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function createTarget() {
    setIsBusy(true);
    setMessage("Saving target...");

    try {
      const response = await fetch(`${apiBaseUrl}/targets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          permission_confirmed: permissionConfirmed,
          repo_path: repoPath.trim() || null
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Target creation failed.");
      }
      setCreatedTarget(body as CreatedTarget);
      setMessage("Target saved. Scan execution is enabled in Phase 3.");
      await loadScanHistory();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function startScan() {
    if (!createdTarget) {
      return;
    }

    setIsBusy(true);
    setMessage("Creating passive lifecycle scan...");

    try {
      const response = await fetch(`${apiBaseUrl}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: createdTarget.id,
          mode: "passive"
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Scan creation failed.");
      }
      setActiveScan(body as Scan);
      setMessage("Scan queued. Worker status will update below.");
      await loadScanHistory();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan creation failed.");
    } finally {
      setIsBusy(false);
    }
  }

  async function refreshScan(scanId: string) {
    try {
      const response = await fetch(`${apiBaseUrl}/scans/${scanId}`);
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? "Scan status refresh failed.");
      }
      setActiveScan(body as Scan);
      await loadScanHistory();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan status refresh failed.");
    }
  }

  async function loadScanHistory() {
    try {
      const response = await fetch(`${apiBaseUrl}/scans`);
      if (!response.ok) {
        return;
      }
      const body = await response.json();
      setScanHistory(body as Scan[]);
    } catch {
      // Scan history is optional for the target creation flow.
    }
  }

  return (
    <section className="targetSetup" aria-labelledby="target-setup-heading">
      <div className="sectionHeader">
        <div>
          <p className="eyebrow">Target Setup</p>
          <h2 id="target-setup-heading">Create an authorized scan target</h2>
        </div>
        <span className="phaseBadge">Phase 2</span>
      </div>

      <form onSubmit={validateTarget} className="targetForm">
        <label>
          <span>Target URL</span>
          <input value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://juice-shop:3000" />
        </label>

        <label>
          <span>Optional local repo path</span>
          <input value={repoPath} onChange={(event) => setRepoPath(event.target.value)} placeholder="/repos/example" />
        </label>

        <label className="checkboxRow">
          <input
            type="checkbox"
            checked={permissionConfirmed}
            onChange={(event) => setPermissionConfirmed(event.target.checked)}
          />
          <span>I own this app, run it locally, or am explicitly authorized to test it.</span>
        </label>

        <div className="actions">
          <button type="submit" disabled={isBusy}>
            Validate
          </button>
          <button type="button" onClick={createTarget} disabled={!canCreate}>
            Save Target
          </button>
          <button type="button" onClick={startScan} disabled={!canStartScan} title="Create a Phase 3 passive lifecycle scan">
            Start Scan
          </button>
        </div>
      </form>

      <p className="formMessage" role="status">
        {message}
      </p>

      {validation ? (
        <div className="validationPanel">
          <h3>{validation.name}</h3>
          <dl>
            <div>
              <dt>Allowlist ID</dt>
              <dd>{validation.allowlist_id}</dd>
            </div>
            <div>
              <dt>Canonical URL</dt>
              <dd>{validation.base_url}</dd>
            </div>
            <div>
              <dt>Allowed Modes</dt>
              <dd>{validation.allowed_modes.join(", ")}</dd>
            </div>
            <div>
              <dt>Redirect Cap</dt>
              <dd>{validation.max_redirects}</dd>
            </div>
          </dl>
        </div>
      ) : null}

      {createdTarget ? (
        <div className="validationPanel successPanel">
          <h3>Saved target</h3>
          <p>{createdTarget.base_url}</p>
          <small>Target ID: {createdTarget.id}</small>
        </div>
      ) : null}

      {activeScan ? (
        <div className="scanPanel">
          <div className="scanHeader">
            <div>
              <h3>Active scan</h3>
              <small>{activeScan.id}</small>
            </div>
            <span className={`statusPill status-${activeScan.status}`}>{activeScan.status}</span>
          </div>
          <div className="progressTrack" aria-label="Scan progress">
            <span style={{ width: `${activeScan.progress_percent}%` }} />
          </div>
          <dl>
            <div>
              <dt>Current Step</dt>
              <dd>{activeScan.current_step ?? "none"}</dd>
            </div>
            <div>
              <dt>Progress</dt>
              <dd>{activeScan.progress_percent}%</dd>
            </div>
          </dl>
          <p>{activeScan.status_message}</p>
        </div>
      ) : null}

      {scanHistory.length > 0 ? (
        <div className="scanPanel">
          <div className="scanHeader">
            <h3>Recent scans</h3>
            <span className="phaseBadge">{scanHistory.length}</span>
          </div>
          <ul className="scanList">
            {scanHistory.slice(0, 5).map((scan) => (
              <li key={scan.id}>
                <span>{scan.mode}</span>
                <strong>{scan.status}</strong>
                <small>{scan.current_step ?? "no current step"}</small>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
