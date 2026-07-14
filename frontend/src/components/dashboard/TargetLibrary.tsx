"use client";

import { useMemo, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import type { Target } from "@/lib/securityAuditApi";

export function TargetLibrary({
  targets,
  selectedTargetId,
  isBusy,
  onSelectTarget,
  onRequestArchive
}: {
  targets: Target[];
  selectedTargetId: string;
  isBusy: boolean;
  onSelectTarget: (targetId: string) => void;
  onRequestArchive: (target: Target) => void;
}) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const filteredTargets = useMemo(() => {
    if (!normalizedQuery) {
      return targets;
    }
    return targets.filter((target) =>
      [target.name, target.base_url, target.allowlist_id].some((value) => value.toLowerCase().includes(normalizedQuery))
    );
  }, [normalizedQuery, targets]);

  return (
    <div className="panel targetLibrary">
      <div className="panelHeader">
        <div>
          <p className="panelKicker">Authorized inventory</p>
          <h3>Saved targets</h3>
        </div>
        <span className="contextBadge">{targets.length}</span>
      </div>

      <label className="searchField compactSearch">
        <AppIcon name="search" size={16} />
        <span className="srOnly">Search saved targets</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search targets" />
      </label>

      {filteredTargets.length > 0 ? (
        <ul className="targetList">
          {filteredTargets.map((target) => (
            <li key={target.id} className={target.id === selectedTargetId ? "targetListItem targetListItemSelected" : "targetListItem"}>
              <button className="targetSelect" type="button" onClick={() => onSelectTarget(target.id)}>
                <span className="targetGlyph"><AppIcon name="target" size={18} /></span>
                <span className="targetIdentity">
                  <strong>{target.name}</strong>
                  <small>{target.base_url}</small>
                  <span className="targetCapabilities">
                    {target.has_repo_path ? <em>Repository</em> : null}
                    {target.auth_profile_id ? <em>Credential</em> : null}
                    <em>{target.available_scan_profile_ids.length} profiles</em>
                  </span>
                </span>
                {target.id === selectedTargetId ? <span className="selectedTick"><AppIcon name="check" size={14} /></span> : null}
              </button>
              <button
                type="button"
                className="quietDangerButton"
                onClick={() => onRequestArchive(target)}
                disabled={isBusy}
                aria-label={`Remove ${target.name} from saved targets`}
                title="Remove saved target"
              >
                <AppIcon name="trash" size={16} />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <div className="emptyState richEmptyState">
          <AppIcon name="target" size={24} />
          <strong>{targets.length ? "No targets match your search" : "No saved targets yet"}</strong>
          <span>{targets.length ? "Try a different name or URL." : "Validate an allowlisted target to begin."}</span>
        </div>
      )}
    </div>
  );
}
