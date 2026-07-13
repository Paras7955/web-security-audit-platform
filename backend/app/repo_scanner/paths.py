from pathlib import Path


class RepoPathError(ValueError):
    pass


def validate_repo_path(repo_path: str | None, *, repo_scan_root: str | Path) -> Path:
    if repo_path is None or not repo_path.strip():
        raise RepoPathError("Repo scans require a configured local repo path.")

    root_path = Path(repo_scan_root)
    if root_path.is_symlink():
        raise RepoPathError("Repo scan root must not be a symlink.")
    root = root_path.resolve()
    candidate_path = Path(repo_path.strip())
    if not candidate_path.is_absolute():
        raise RepoPathError("Repo path must be absolute.")

    candidate = candidate_path.resolve()
    if root != candidate and root not in candidate.parents:
        raise RepoPathError("Repo path must stay within the configured repo scan root.")
    reject_symlink_components_under_root(candidate_path, root_path, root)
    if candidate_path.is_symlink() or candidate.is_symlink():
        raise RepoPathError("Repo path must not be a symlink.")
    if not candidate.exists() or not candidate.is_dir():
        raise RepoPathError("Repo path must be an existing directory.")
    return candidate


def repo_path_for_storage(repo_path: str | None, *, repo_scan_root: str | Path) -> str:
    candidate = validate_repo_path(repo_path, repo_scan_root=repo_scan_root)
    root = Path(repo_scan_root).resolve()
    relative = candidate.relative_to(root)
    return relative.as_posix() or "."


def resolve_stored_repo_path(repo_path: str | None, *, repo_scan_root: str | Path) -> Path:
    if repo_path is None or not repo_path.strip():
        raise RepoPathError("Repo scans require a configured local repo path.")
    relative = Path(repo_path.strip())
    if relative.is_absolute() or ".." in relative.parts:
        raise RepoPathError("Stored repo path is invalid; reconfigure the target repository path.")
    root = Path(repo_scan_root).resolve()
    return validate_repo_path(str(root / relative), repo_scan_root=root)


def reject_symlink_components_under_root(path: Path, root_path: Path, root: Path) -> None:
    try:
        parts = path.relative_to(root_path).parts
        current = root_path
    except ValueError:
        parts = path.resolve().relative_to(root).parts
        current = root

    for part in parts:
        current = current / part
        if current.is_symlink():
            raise RepoPathError("Repo path must not contain symlink components.")
