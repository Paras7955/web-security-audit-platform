"use client";

import { FormEvent, useMemo, useState } from "react";

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

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export function TargetSetup() {
  const [targetUrl, setTargetUrl] = useState("http://juice-shop:3000");
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [repoPath, setRepoPath] = useState("");
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [createdTarget, setCreatedTarget] = useState<CreatedTarget | null>(null);
  const [message, setMessage] = useState<string>("Enter an allowlisted local/demo target.");
  const [isBusy, setIsBusy] = useState(false);

  const canCreate = useMemo(() => Boolean(validation && permissionConfirmed && !isBusy), [validation, permissionConfirmed, isBusy]);

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
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Target creation failed.");
    } finally {
      setIsBusy(false);
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
          <button type="button" disabled title="Scan execution starts in Phase 3">
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
    </section>
  );
}

