import { FormEvent } from "react";

import type { ValidationResult } from "@/lib/securityAuditApi";

export function TargetForm({
  targetUrl,
  repoPath,
  permissionConfirmed,
  validation,
  message,
  isBusy,
  canCreate,
  onTargetUrlChange,
  onRepoPathChange,
  onPermissionChange,
  onValidate,
  onCreateTarget
}: {
  targetUrl: string;
  repoPath: string;
  permissionConfirmed: boolean;
  validation: ValidationResult | null;
  message: string;
  isBusy: boolean;
  canCreate: boolean;
  onTargetUrlChange: (value: string) => void;
  onRepoPathChange: (value: string) => void;
  onPermissionChange: (value: boolean) => void;
  onValidate: (event: FormEvent<HTMLFormElement>) => void;
  onCreateTarget: () => void;
}) {
  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Target</h3>
        <span className="contextBadge">Allowlisted</span>
      </div>

      <form onSubmit={onValidate} className="targetForm">
        <label>
          <span>Target URL</span>
          <input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="http://juice-shop:3000" />
        </label>

        <label>
          <span>Optional local repo path</span>
          <input value={repoPath} onChange={(event) => onRepoPathChange(event.target.value)} placeholder="/app/repositories/security-project" />
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
              <dt>Available Profiles</dt>
              <dd>{validation.available_scan_profile_ids.join(", ")}</dd>
            </div>
            <div>
              <dt>Redirect Cap</dt>
              <dd>{validation.max_redirects}</dd>
            </div>
          </dl>
        </div>
      ) : null}
    </div>
  );
}
