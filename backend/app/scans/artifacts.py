from pathlib import Path


class ArtifactPathError(ValueError):
    pass


def scan_artifact_dir(artifact_root: str | Path, scan_id: str) -> Path:
    root = Path(artifact_root).resolve()
    scans_root = root / "scans"
    if scans_root.is_symlink():
        raise ArtifactPathError("scan artifact root must not be a symlink")

    scans_root_resolved = scans_root.resolve()
    if root != scans_root_resolved and root not in scans_root_resolved.parents:
        raise ArtifactPathError("scan artifact root escaped artifact root")

    scan_dir = scans_root / scan_id
    if scan_dir.is_symlink():
        raise ArtifactPathError("scan artifact path must not be a symlink")

    candidate = scan_dir.resolve()
    if scans_root_resolved != candidate and scans_root_resolved not in candidate.parents:
        raise ArtifactPathError("scan artifact path escaped artifact root")
    return candidate


def ensure_scan_artifact_dir(artifact_root: str | Path, scan_id: str) -> Path:
    path = scan_artifact_dir(artifact_root, scan_id)
    path.mkdir(parents=True, exist_ok=True)
    return path
