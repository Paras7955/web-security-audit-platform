import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.config import Settings
from app.repo_scanner.adapters import RepoToolOutputError, _load_json, _osv_findings, run_gitleaks
from app.repo_scanner.paths import RepoPathError, validate_repo_path
from app.repo_scanner.staging import RepositoryLimitError, StagedRepository, StagingLimits


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

    def test_validate_repo_path_rejects_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            real_parent = repo_root / "real-parent"
            repo_path = real_parent / "repo"
            repo_path.mkdir(parents=True)
            parent_link = repo_root / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaises(RepoPathError):
                validate_repo_path(str(parent_link / "repo"), repo_scan_root=repo_root)

    def test_validate_repo_path_rejects_nested_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            real_parent = repo_root / "real-parent"
            repo_path = real_parent / "repo"
            repo_path.mkdir(parents=True)
            nested_dir = repo_root / "nested"
            nested_dir.mkdir()
            parent_link = nested_dir / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaises(RepoPathError):
                validate_repo_path(str(parent_link / "repo"), repo_scan_root=repo_root)

    def test_validate_repo_path_rejects_symlinked_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            real_root = Path(temp_dir) / "real-root"
            repo_path = real_root / "repo"
            repo_path.mkdir(parents=True)
            root_link = Path(temp_dir) / "root-link"
            root_link.symlink_to(real_root, target_is_directory=True)

            with self.assertRaises(RepoPathError):
                validate_repo_path(str(repo_path), repo_scan_root=root_link)

    def test_staging_copies_only_regular_bounded_files_and_ignores_scanner_config(self) -> None:
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as staging_dir:
            source = Path(source_dir)
            (source / "src").mkdir()
            (source / "src" / "app.py").write_text("print('not executed')", encoding="utf-8")
            (source / ".gitleaks.toml").write_text("malicious", encoding="utf-8")
            (source / "osv-scanner.toml").write_text("malicious", encoding="utf-8")
            (source / "node_modules").mkdir()
            (source / "node_modules" / "hook.js").write_text("malicious", encoding="utf-8")
            (source / "link").symlink_to(source / "src" / "app.py")
            os.mkfifo(source / "pipe")

            with StagedRepository(source, Path(staging_dir), StagingLimits(20, 1024, 4096)) as staged:
                self.assertEqual((staged.root / "src" / "app.py").read_text(encoding="utf-8"), "print('not executed')")
                self.assertFalse((staged.root / ".gitleaks.toml").exists())
                self.assertFalse((staged.root / "osv-scanner.toml").exists())
                self.assertFalse((staged.root / "node_modules").exists())
                self.assertFalse((staged.root / "link").exists())
                self.assertFalse((staged.root / "pipe").exists())

    def test_staging_fails_closed_when_repository_limit_is_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as staging_dir:
            source = Path(source_dir)
            (source / "large").write_bytes(b"x" * 11)
            with self.assertRaises(RepositoryLimitError):
                with StagedRepository(source, Path(staging_dir), StagingLimits(10, 10, 100)):
                    pass

    def test_gitleaks_adapter_never_persists_reported_secret(self) -> None:
        canary = "scopeharbor-canary-secret"
        report = [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "src/settings.py",
                "StartLine": 12,
                "Secret": canary,
                "Match": f"API_KEY={canary}",
            }
        ]

        def fake_run(command, **_kwargs):
            report_path = Path(command[command.index("--report-path") + 1])
            report_path.write_text(json.dumps(report), encoding="utf-8")
            return 1

        with tempfile.TemporaryDirectory() as staged_dir, tempfile.TemporaryDirectory() as config_dir:
            config_path = Path(config_dir) / "gitleaks.toml"
            config_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            config = Settings(
                _env_file=None,
                gitleaks_config_path=str(config_path),
                repo_tool_max_findings=10,
            )
            with patch("app.repo_scanner.adapters._verify_version", return_value="8.30.1"), patch(
                "app.repo_scanner.adapters._run_tool", side_effect=fake_run
            ):
                result = run_gitleaks(Path(staged_dir), config)

        self.assertEqual(len(result.findings), 1)
        self.assertNotIn(canary, str(result.findings[0].model_dump()))
        self.assertEqual(result.receipt.tool_version, "8.30.1")

    def test_osv_parser_keeps_only_safe_package_and_advisory_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as staged_dir:
            root = Path(staged_dir)
            lockfile = root / "package-lock.json"
            lockfile.write_text("{}", encoding="utf-8")
            payload = {
                "results": [
                    {
                        "source": {"path": str(lockfile), "type": "lockfile"},
                        "packages": [
                            {
                                "package": {"name": "demo", "version": "1.0.0", "ecosystem": "npm"},
                                "vulnerabilities": [{"id": "GHSA-test", "summary": "Demo advisory", "details": "ignored raw body"}],
                            }
                        ],
                    }
                ]
            }
            findings = _osv_findings(payload, root, 10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].affected_file, "package-lock.json")
        self.assertEqual(findings[0].scanner_rule_id, "GHSA-test")
        self.assertNotIn("ignored raw body", str(findings[0].model_dump()))

    def test_json_loader_rejects_malformed_and_oversized_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "result.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(RepoToolOutputError):
                _load_json(path, 100)
            path.write_text("[]" * 100, encoding="utf-8")
            with self.assertRaises(RepoToolOutputError):
                _load_json(path, 10)

    @unittest.skipUnless(os.environ.get("SCOPEHARBOR_REAL_SCANNER_TESTS") == "1", "real scanner binaries not requested")
    def test_real_gitleaks_binary_redacts_secret_and_never_executes_package_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as staged_dir:
            root = Path(staged_dir)
            canary = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
            (root / "settings.env").write_text(f"GITHUB_TOKEN={canary}\n", encoding="utf-8")
            marker = root / "script-executed"
            (root / "package.json").write_text(
                json.dumps({"scripts": {"postinstall": f"touch {marker}"}}),
                encoding="utf-8",
            )
            result = run_gitleaks(root)
            self.assertGreaterEqual(len(result.findings), 1)
            self.assertNotIn(canary, str(result))
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
