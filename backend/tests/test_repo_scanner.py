import tempfile
import unittest
from pathlib import Path

from app.repo_scanner.paths import RepoPathError, validate_repo_path
from app.repo_scanner.stubs import run_repo_stub_scan


class RepoScannerTests(unittest.TestCase):
    def test_validate_repo_path_requires_absolute_path_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            repo_root = Path(temp_dir)
            repo_path = repo_root / "repo"
            repo_path.mkdir()

            self.assertEqual(validate_repo_path(str(repo_path), repo_scan_root=repo_root), repo_path.resolve())

            with self.assertRaises(RepoPathError):
                validate_repo_path("relative/repo", repo_scan_root=repo_root)

            with self.assertRaises(RepoPathError):
                validate_repo_path(outside_dir, repo_scan_root=repo_root)

    def test_validate_repo_path_rejects_symlinked_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            repo_root = Path(temp_dir)
            repo_link = repo_root / "repo-link"
            repo_link.symlink_to(outside_dir, target_is_directory=True)

            with self.assertRaises(RepoPathError):
                validate_repo_path(str(repo_link), repo_scan_root=repo_root)

    def test_stub_scan_returns_redacted_normalized_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "package-lock.json").write_text("{}", encoding="utf-8")
            (repo_path / ".env.example").write_text("API_KEY=example", encoding="utf-8")

            result = run_repo_stub_scan(repo_path=repo_path)

        self.assertEqual(result.errors, ())
        self.assertEqual({finding.source_tool for finding in result.findings}, {"gitleaks-stub", "dependency-stub"})
        self.assertTrue(all(finding.redaction_applied for finding in result.findings))
        self.assertTrue(all("example" not in (finding.evidence or "") for finding in result.findings))


if __name__ == "__main__":
    unittest.main()
