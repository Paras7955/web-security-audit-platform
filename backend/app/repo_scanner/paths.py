from pathlib import Path


class RepoPathError(ValueError):
    pass


def validate_repo_path(repo_path: str | None, *, repo_scan_root: str | Path) -> Path:
    if repo_path is None or not repo_path.strip():
        raise RepoPathError("Repo scans require a configured local repo path.")

    root = Path(repo_scan_root).resolve()
    candidate_path = Path(repo_path.strip())
    if not candidate_path.is_absolute():
        raise RepoPathError("Repo path must be absolute.")

    candidate = candidate_path.resolve()
    if root != candidate and root not in candidate.parents:
        raise RepoPathError("Repo path must stay within the configured repo scan root.")
    if candidate_path.is_symlink() or candidate.is_symlink():
        raise RepoPathError("Repo path must not be a symlink.")
    if not candidate.exists() or not candidate.is_dir():
        raise RepoPathError("Repo path must be an existing directory.")
    return candidate
