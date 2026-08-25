import { FormEvent } from "react";

import type { ValidationResult } from "@/lib/securityAuditApi";

export function TargetForm({
  targetUrl,
  permissionConfirmed,
  validation,
  message,
  isBusy,
  canCreate,
  onTargetUrlChange,
  onPermissionChange,
  onValidate,
  onCreateTarget
}: {
  targetUrl: string;
  permissionConfirmed: boolean;
  validation: ValidationResult | null;
  message: string;
  isBusy: boolean;
  canCreate: boolean;
  onTargetUrlChange: (value: string) => void;
  onPermissionChange: (value: boolean) => void;
  onValidate: (event: FormEvent<HTMLFormElement>) => void;
  onCreateTarget: () => void;
}) {
  return (
    <div className="panel">
      <div className="panelHeader">
        <div><h3>Validate a web target</h3><p>Confirm the exact destination policy and truthful profile eligibility before saving scope.</p></div>
        <span className="contextBadge">Allowlisted</span>
      </div>

      <form onSubmit={onValidate} className="targetForm">
        <label>
          <span>Target URL</span>
          <input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="http://juice-shop:3000" />
        </label>

        <label className="checkboxRow">
          <input
            type="checkbox"
            checked={permissionConfirmed}
            onChange={(event) => onPermissionChange(event.target.checked)}
          />
          <span>I own this app, run it locally, or am explicitly authorized to test it.</span>
        </label>

        <div className="actions">
          <button type="submit" disabled={isBusy}>
            Validate
          </button>
          <button type="button" onClick={onCreateTarget} disabled={!canCreate}>
            Save Target
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
              <dt>Eligible profiles</dt>
              <dd>{validation.available_scan_profile_ids.join(", ")}</dd>
            </div>
            <div>
              <dt>Redirect Cap</dt>
              <dd>{validation.max_redirects}</dd>
            </div>
            <div>
              <dt>Connection</dt>
              <dd>{validation.connection_class.replaceAll("_", " ")}</dd>
            </div>
            <div>
              <dt>Scope path</dt>
              <dd>{validation.scope_path}</dd>
            </div>
            <div>
              <dt>TLS trust</dt>
              <dd>{validation.tls_trust.replaceAll("_", " ")}</dd>
            </div>
            <div>
              <dt>Target class</dt>
              <dd>{validation.local_demo ? "Disposable local demo" : "General local target"}</dd>
            </div>
          </dl>
        </div>
      ) : null}
    </div>
  );
}
