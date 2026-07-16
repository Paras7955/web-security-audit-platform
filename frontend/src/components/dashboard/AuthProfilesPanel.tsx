import { AppIcon } from "@/components/AppIcon";
import type { AuthProfile, Target } from "@/lib/securityAuditApi";

export function AuthProfilesPanel({
  authProfiles,
  selectedTarget,
  selectedAuthProfileId,
  label,
  profileType,
  headerName,
  secret,
  rotationSecret,
  message,
  isBusy,
  onSelectAuthProfile,
  onLabelChange,
  onProfileTypeChange,
  onHeaderNameChange,
  onSecretChange,
  onRotationSecretChange,
  onCreateProfile,
  onAttachProfile,
  onRotateProfile,
  onRevokeProfile
}: {
  authProfiles: AuthProfile[];
  selectedTarget: Target | null;
  selectedAuthProfileId: string;
  label: string;
  profileType: string;
  headerName: string;
  secret: string;
  rotationSecret: string;
  message: string;
  isBusy: boolean;
  onSelectAuthProfile: (authProfileId: string) => void;
  onLabelChange: (value: string) => void;
  onProfileTypeChange: (value: string) => void;
  onHeaderNameChange: (value: string) => void;
  onSecretChange: (value: string) => void;
  onRotationSecretChange: (value: string) => void;
  onCreateProfile: () => void;
  onAttachProfile: () => void;
  onRotateProfile: () => void;
  onRevokeProfile: () => void;
}) {
  const selectedProfile = authProfiles.find((profile) => profile.id === selectedAuthProfileId) ?? null;
  const canCreate = Boolean(label.trim() && secret.trim() && (profileType === "bearer_token" || headerName.trim()) && !isBusy);
  const canAttach = Boolean(selectedTarget && !isBusy && (!selectedProfile || selectedProfile.status === "active"));
  const canRotate = Boolean(selectedProfile?.status === "active" && rotationSecret.trim() && !isBusy);
  const canRevoke = Boolean(selectedProfile?.status === "active" && !isBusy);

  return (
    <div className="panel credentialPanel">
      <div className="panelHeader">
        <div>
          <h3>Guarded target credentials</h3>
          <p>Create encrypted credentials, then explicitly attach one to the currently selected target.</p>
        </div>
        <span className="contextBadge">Encrypted secrets</span>
      </div>

      <div className="credentialSafetyNote">
        <AppIcon name="shield" size={18} />
        <p><strong>Passive requests only.</strong> Secret values never appear in findings, reports, AI explanations, logs, ZAP scans, or browser workflows.</p>
      </div>

      <div className="authProfileGrid">
        <section className="authProfileCreate" aria-labelledby="create-credential-title">
          <div className="authSectionHeader">
            <span>01</span>
            <div><h4 id="create-credential-title">Create a credential profile</h4><p>Give the secret a recognizable label. The value is encrypted and is never returned after saving.</p></div>
          </div>

          <div className="targetForm">
            <label>
              <span>Profile label</span>
              <input value={label} onChange={(event) => onLabelChange(event.target.value)} placeholder="Demo bearer token" />
            </label>

            <label>
              <span>Profile type</span>
              <select value={profileType} onChange={(event) => onProfileTypeChange(event.target.value)}>
                <option value="bearer_token">Bearer token</option>
                <option value="custom_header">Custom header</option>
              </select>
            </label>

            {profileType === "custom_header" ? (
              <label>
                <span>Header name</span>
                <input value={headerName} onChange={(event) => onHeaderNameChange(event.target.value)} placeholder="X-API-Key" />
              </label>
            ) : null}

            <label>
              <span>Secret value</span>
              <input type="password" value={secret} onChange={(event) => onSecretChange(event.target.value)} placeholder="Stored encrypted; never returned" />
            </label>

            <div className="actions">
              <button type="button" onClick={onCreateProfile} disabled={!canCreate}>
                Save credential profile
              </button>
            </div>
          </div>
        </section>

        <section className="authProfileManage" aria-labelledby="manage-credential-title">
          <div className="authSectionHeader">
            <span>02</span>
            <div><h4 id="manage-credential-title">Attach and manage</h4><p>Choose one saved profile for the selected target, or detach credentials before running an incompatible profile.</p></div>
          </div>

          <div className="authProfileAttach">
            <label className="selectLabel">
              <span>Saved profile</span>
              <select value={selectedAuthProfileId} onChange={(event) => onSelectAuthProfile(event.target.value)}>
                <option value="">None</option>
                {authProfiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.label} - {profile.profile_type} ({profile.status})
                  </option>
                ))}
              </select>
            </label>

            <dl>
              <div>
                <dt>Selected target</dt>
                <dd>{selectedTarget ? selectedTarget.name : "None"}</dd>
              </div>
              <div>
                <dt>Attached profile</dt>
                <dd>{selectedTarget?.auth_profile_id ? profileLabel(authProfiles, selectedTarget.auth_profile_id) : "None"}</dd>
              </div>
              <div>
                <dt>Selected secret hint</dt>
                <dd>{selectedProfile?.secret_hint ?? "None"}</dd>
              </div>
              <div>
                <dt>Profile status</dt>
                <dd>{selectedProfile?.status ?? "None"}</dd>
              </div>
              <div>
                <dt>Rotations</dt>
                <dd>{selectedProfile?.rotation_count ?? 0}</dd>
              </div>
            </dl>

            <label className="selectLabel rotationSecretField">
              <span>Replacement secret</span>
              <input type="password" value={rotationSecret} onChange={(event) => onRotationSecretChange(event.target.value)} placeholder="Used only when rotating this profile" />
              <small>Rotation affects future passive scans only. Existing scan snapshots remain unchanged.</small>
            </label>

            <div className="actions">
              <button type="button" onClick={onAttachProfile} disabled={!canAttach}>
                {selectedAuthProfileId ? "Attach to target" : "Detach from target"}
              </button>
              <button type="button" className="secondaryButton" onClick={onRotateProfile} disabled={!canRotate}>
                Rotate secret
              </button>
              <button type="button" className="dangerButton" onClick={onRevokeProfile} disabled={!canRevoke}>
                Revoke profile
              </button>
            </div>
          </div>
        </section>
      </div>

      <p className="formMessage" role="status">
        {message}
      </p>
    </div>
  );
}

export function profileLabel(authProfiles: AuthProfile[], authProfileId: string): string {
  return authProfiles.find((profile) => profile.id === authProfileId)?.label ?? "Configured";
}
