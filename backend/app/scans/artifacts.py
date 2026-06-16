from pathlib import Path


class ArtifactPathError(ValueError):
    pass


def scan_artifact_dir(artifact_root: str | Path, scan_id: str) -> Path:
    root = Path(artifact_root).resolve()
    scans_root = (root / "scans").resolve()
    candidate = (scans_root / scan_id).resolve()
    if scans_root != candidate and scans_root not in candidate.parents:
        raise ArtifactPathError("scan artifact path escaped artifact root")
    return candidate


def ensure_scan_artifact_dir(artifact_root: str | Path, scan_id: str) -> Path:
    path = scan_artifact_dir(artifact_root, scan_id)
    path.mkdir(parents=True, exist_ok=True)
    return path
