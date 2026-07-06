import type { AuthProfile, Target } from "@/lib/securityAuditApi";

export function AuthProfilesPanel({
  authProfiles,
  selectedTarget,
  selectedAuthProfileId,
  label,
  profileType,
  headerName,
  secret,
  message,
  isBusy,
  onSelectAuthProfile,
  onLabelChange,
  onProfileTypeChange,
  onHeaderNameChange,
  onSecretChange,
  onCreateProfile,
  onAttachProfile
}: {
  authProfiles: AuthProfile[];
  selectedTarget: Target | null;
  selectedAuthProfileId: string;
  label: string;
  profileType: string;
  headerName: string;
  secret: string;
  message: string;
  isBusy: boolean;
  onSelectAuthProfile: (authProfileId: string) => void;
  onLabelChange: (value: string) => void;
  onProfileTypeChange: (value: string) => void;
  onHeaderNameChange: (value: string) => void;
  onSecretChange: (value: string) => void;
  onCreateProfile: () => void;
  onAttachProfile: () => void;
}) {
  const selectedProfile = authProfiles.find((profile) => profile.id === selectedAuthProfileId) ?? null;
  const canCreate = Boolean(label.trim() && secret.trim() && (profileType === "bearer_token" || headerName.trim()) && !isBusy);
  const canAttach = Boolean(selectedTarget && !isBusy);

  return (
    <div className="panel">
      <div className="panelHeader">
        <h3>Target Auth</h3>
        <span className="phaseBadge">Phase 14</span>
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
          <span>Secret</span>
          <input type="password" value={secret} onChange={(event) => onSecretChange(event.target.value)} placeholder="Stored encrypted; never returned" />
        </label>

        <div className="actions">
          <button type="button" onClick={onCreateProfile} disabled={!canCreate}>
            Save Auth Profile
          </button>
        </div>
      </div>

      <div className="authProfileAttach">
        <label className="selectLabel">
          <span>Saved profile</span>
          <select value={selectedAuthProfileId} onChange={(event) => onSelectAuthProfile(event.target.value)}>
            <option value="">None</option>
            {authProfiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.label} - {profile.profile_type}
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
        </dl>

        <div className="actions">
          <button type="button" onClick={onAttachProfile} disabled={!canAttach}>
            {selectedAuthProfileId ? "Attach To Target" : "Detach From Target"}
          </button>
        </div>
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
