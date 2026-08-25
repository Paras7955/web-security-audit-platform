"use client";

import { FormEvent, useMemo, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import type { RepositoryAsset } from "@/lib/securityAuditApi";

export function RepositoryAssetsPanel({
  assets,
  selectedAssetId,
  name,
  path,
  permissionConfirmed,
  message,
  isBusy,
  onSelectAsset,
  onNameChange,
  onPathChange,
  onPermissionChange,
  onCreateAsset,
  onRequestArchive
}: {
  assets: RepositoryAsset[];
  selectedAssetId: string;
  name: string;
  path: string;
  permissionConfirmed: boolean;
  message: string;
  isBusy: boolean;
  onSelectAsset: (assetId: string) => void;
  onNameChange: (value: string) => void;
  onPathChange: (value: string) => void;
  onPermissionChange: (value: boolean) => void;
  onCreateAsset: (event: FormEvent<HTMLFormElement>) => void;
  onRequestArchive: (asset: RepositoryAsset) => void;
}) {
  const [query, setQuery] = useState("");
  const filteredAssets = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return assets;
    return assets.filter((asset) => [asset.name, asset.relative_path].some((value) => value.toLowerCase().includes(normalized)));
  }, [assets, query]);

  return (
    <section className="repositoryAssetsPanel" aria-labelledby="repository-assets-title">
      <div className="sectionHeading">
        <div>
          <p className="panelKicker">Repository subjects</p>
          <h3 id="repository-assets-title">Authorized repositories</h3>
          <p>Create a first-class repository identity. The API returns only its confined relative path.</p>
        </div>
        <span className="contextBadge">{assets.length}</span>
      </div>

      <div className="repositoryAssetsLayout">
        <form className="repositoryAssetForm" onSubmit={onCreateAsset}>
          <div className="authSectionHeader">
            <span><AppIcon name="intelligence" size={18} /></span>
            <div><h4>Add repository</h4><p>ScopeHarbor will not clone, fetch, install, build, run hooks, or execute its code.</p></div>
          </div>
          <label>
            <span>Display name</span>
            <input value={name} onChange={(event) => onNameChange(event.target.value)} placeholder="ScopeHarbor" maxLength={200} />
          </label>
          <label>
            <span>Operator-approved local path</span>
            <input value={path} onChange={(event) => onPathChange(event.target.value)} placeholder="/app/repositories/security-project" maxLength={2048} />
          </label>
          <label className="checkboxRow">
            <input type="checkbox" checked={permissionConfirmed} onChange={(event) => onPermissionChange(event.target.checked)} />
            <span>I am authorized to inspect this local repository.</span>
          </label>
          <button type="submit" disabled={isBusy || !name.trim() || !path.trim() || !permissionConfirmed}>
            {isBusy ? "Saving repository…" : "Save repository"}
          </button>
          <p className="formMessage" role="status" aria-live="polite">{message}</p>
        </form>

        <div className="repositoryAssetLibrary">
          <label className="searchField compactSearch">
            <AppIcon name="search" size={16} />
            <span className="srOnly">Search repository assets</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search repositories" />
          </label>
          {filteredAssets.length ? (
            <ul className="repositoryAssetList">
              {filteredAssets.map((asset) => (
                <li key={asset.id} className={asset.id === selectedAssetId ? "repositoryAssetRow repositoryAssetRowSelected" : "repositoryAssetRow"}>
                  <button type="button" className="repositoryAssetSelect" onClick={() => onSelectAsset(asset.id)}>
                    <span className="targetGlyph"><AppIcon name="intelligence" size={18} /></span>
                    <span>
                      <strong>{asset.name}</strong>
                      <small>{asset.relative_path}</small>
                      <em>Repository profile · offline tools</em>
                    </span>
                    {asset.id === selectedAssetId ? <span className="selectedTick"><AppIcon name="check" size={14} /></span> : null}
                  </button>
                  <button
                    type="button"
                    className="quietDangerButton"
                    onClick={() => onRequestArchive(asset)}
                    disabled={isBusy}
                    aria-label={`Archive ${asset.name}`}
                    title="Archive repository"
                  >
                    <AppIcon name="trash" size={16} />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="emptyState richEmptyState">
              <AppIcon name="intelligence" size={24} />
              <strong>{assets.length ? "No repositories match your search" : "No repository assets yet"}</strong>
              <span>{assets.length ? "Try another name or relative path." : "Authorize a confined local path to enable repository audits."}</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
