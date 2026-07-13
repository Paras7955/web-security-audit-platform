from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".mypy_cache",
    ".next",
    ".npm",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "bower_components",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
UNTRUSTED_SCANNER_CONFIGS = {
    ".gitleaks.toml",
    ".gitleaksignore",
    "osv-scanner.toml",
    "osv-scanner.json",
}


class RepositoryStagingError(ValueError):
    code = "repo_staging_failed"


class RepositoryLimitError(RepositoryStagingError):
    code = "repo_limit_exceeded"


@dataclass(frozen=True)
class StagingLimits:
    max_files: int
    max_file_bytes: int
    max_total_bytes: int


@dataclass(frozen=True)
class StagingReceipt:
    root: Path
    files_copied: int
    bytes_copied: int
    files_skipped: int


class StagedRepository:
    def __init__(self, source: Path, staging_parent: Path, limits: StagingLimits) -> None:
        self.source = source
        self.staging_parent = staging_parent
        self.limits = limits
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.receipt: StagingReceipt | None = None

    def __enter__(self) -> StagingReceipt:
        self.staging_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.staging_parent.chmod(0o700)
        self._temporary = tempfile.TemporaryDirectory(prefix="scan-", dir=self.staging_parent)
        root = Path(self._temporary.name)
        root.chmod(0o700)
        try:
            copied, total, skipped = _copy_tree(self.source, root, self.limits)
        except Exception:
            self._temporary.cleanup()
            self._temporary = None
            raise
        self.receipt = StagingReceipt(root=root, files_copied=copied, bytes_copied=total, files_skipped=skipped)
        return self.receipt

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()


def _copy_tree(source: Path, destination: Path, limits: StagingLimits) -> tuple[int, int, int]:
    copied = 0
    total = 0
    skipped = 0
    pending: list[tuple[Path, Path]] = [(source, destination)]
    while pending:
        source_dir, destination_dir = pending.pop()
        try:
            entries = sorted(os.scandir(source_dir), key=lambda entry: entry.name)
        except OSError as exc:
            raise RepositoryStagingError("Repository directory could not be read safely.") from exc
        for entry in entries:
            source_path = Path(entry.path)
            destination_path = destination_dir / entry.name
            try:
                if entry.is_symlink():
                    skipped += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIPPED_DIRECTORIES:
                        skipped += 1
                        continue
                    destination_path.mkdir(mode=0o700)
                    pending.append((source_path, destination_path))
                    continue
                if not entry.is_file(follow_symlinks=False) or entry.name in UNTRUSTED_SCANNER_CONFIGS:
                    skipped += 1
                    continue
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RepositoryStagingError("Repository entry changed during staging.") from exc
            if not stat.S_ISREG(metadata.st_mode):
                skipped += 1
                continue
            if metadata.st_size > limits.max_file_bytes:
                raise RepositoryLimitError("A repository file exceeds the configured per-file limit.")
            if copied + 1 > limits.max_files or total + metadata.st_size > limits.max_total_bytes:
                raise RepositoryLimitError("The repository exceeds configured staging limits.")
            _copy_regular_file(source_path, destination_path, metadata)
            copied += 1
            total += metadata.st_size
    return copied, total, skipped


def _copy_regular_file(source: Path, destination: Path, expected: os.stat_result) -> None:
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, source_flags)
        destination_fd = os.open(destination, destination_flags, 0o600)
        with os.fdopen(source_fd, "rb") as source_handle, os.fdopen(destination_fd, "wb") as destination_handle:
            opened = os.fstat(source_handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise RepositoryStagingError("Repository entry changed during staging.")
            shutil.copyfileobj(source_handle, destination_handle, length=1024 * 1024)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            final = os.fstat(source_handle.fileno())
            if (final.st_size, final.st_mtime_ns) != (expected.st_size, expected.st_mtime_ns):
                raise RepositoryStagingError("Repository entry changed during staging.")
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise RepositoryStagingError("Repository file could not be staged safely.") from exc
