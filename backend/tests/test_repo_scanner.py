import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from app.core.config import Settings
from app.findings.schemas import NormalizedFindingInput
from app.repo_scanner.adapters import (
    AdapterResult,
    RepoToolError,
    RepoToolOutputError,
    RepoToolTimeoutError,
    RepoToolUnavailableError,
    ToolReceipt,
    _limit_process,
    _load_json,
    _optional_version,
    _osv_findings,
    _osv_severity,
    _relative_scanner_path,
    _run_tool,
    _safe_positive_int,
    _terminate_process_group,
    _validate_osv_database,
    _verify_version,
    run_gitleaks,
    run_osv_scanner,
    run_repository_scan,
    verify_repo_tools,
)
from app.repo_scanner.paths import RepoPathError, repo_path_for_storage, resolve_stored_repo_path, validate_repo_path
from app.repo_scanner.staging import (
    RepositoryLimitError,
    RepositoryStagingError,
    StagedRepository,
    StagingLimits,
    _copy_regular_file,
    _copy_tree,
)


class RepoScannerTests(unittest.TestCase):
    def test_validate_repo_path_requires_absolute_path_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            repo_root = Path(temp_dir)
            repo_path = repo_root / "repo"
            repo_path.mkdir()

            self.assertEqual(validate_repo_path(str(repo_path), repo_scan_root=repo_root), repo_path.resolve())
            self.assertEqual(repo_path_for_storage(str(repo_path), repo_scan_root=repo_root), "repo")
            self.assertEqual(resolve_stored_repo_path("repo", repo_scan_root=repo_root), repo_path.resolve())

            with self.assertRaises(RepoPathError):
                validate_repo_path("relative/repo", repo_scan_root=repo_root)
            with self.assertRaises(RepoPathError):
                resolve_stored_repo_path(str(repo_path), repo_scan_root=repo_root)

            with self.assertRaises(RepoPathError):
                validate_repo_path(outside_dir, repo_scan_root=repo_root)

            for missing in (None, "   "):
                with self.assertRaises(RepoPathError):
                    validate_repo_path(missing, repo_scan_root=repo_root)
            file_path = repo_root / "not-a-directory"
            file_path.touch()
            with self.assertRaises(RepoPathError):
                validate_repo_path(str(file_path), repo_scan_root=repo_root)
            with self.assertRaises(RepoPathError):
                validate_repo_path(str(repo_root / "missing"), repo_scan_root=repo_root)

            relative_root = Path(os.path.relpath(repo_root, Path.cwd()))
            self.assertEqual(validate_repo_path(str(repo_path), repo_scan_root=relative_root), repo_path.resolve())

    def test_validate_repo_path_keeps_direct_symlink_check_as_defense_in_depth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            real_repo = repo_root / "real"
            real_repo.mkdir()
            repo_link = repo_root / "repo-link"
            repo_link.symlink_to(real_repo, target_is_directory=True)
            with patch("app.repo_scanner.paths.reject_symlink_components_under_root"):
                with self.assertRaisesRegex(RepoPathError, "must not be a symlink"):
                    validate_repo_path(str(repo_link), repo_scan_root=repo_root)

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

            (source / "large").write_bytes(b"x")
            with self.assertRaises(RepositoryLimitError):
                with StagedRepository(source, Path(staging_dir), StagingLimits(0, 10, 100)):
                    pass

    def test_staging_fails_closed_on_directory_and_entry_races(self) -> None:
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as staging_dir:
            source = Path(source_dir)
            destination = Path(staging_dir) / "destination"
            destination.mkdir()
            limits = StagingLimits(10, 1024, 4096)

            with patch("app.repo_scanner.staging.os.scandir", side_effect=OSError("private read detail")), self.assertRaisesRegex(
                RepositoryStagingError, "could not be read safely"
            ):
                _copy_tree(source, destination, limits)

            changed = MagicMock()
            changed.name = "changed.py"
            changed.path = str(source / changed.name)
            changed.is_symlink.return_value = False
            changed.is_dir.return_value = False
            changed.is_file.return_value = True
            changed.stat.side_effect = OSError("private stat detail")
            with patch("app.repo_scanner.staging.os.scandir", return_value=[changed]), self.assertRaisesRegex(
                RepositoryStagingError, "entry changed"
            ):
                _copy_tree(source, destination, limits)

            special = MagicMock()
            special.name = "special"
            special.path = str(source / special.name)
            special.is_symlink.return_value = False
            special.is_dir.return_value = False
            special.is_file.return_value = True
            special.stat.return_value = SimpleNamespace(st_mode=stat.S_IFIFO)
            with patch("app.repo_scanner.staging.os.scandir", return_value=[special]):
                self.assertEqual(_copy_tree(source, destination, limits), (0, 0, 1))

            never_entered = StagedRepository(source, Path(staging_dir), limits)
            never_entered.__exit__(None, None, None)

    def test_regular_file_copy_detects_replacement_and_io_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.py"
            source.write_text("safe", encoding="utf-8")
            expected = source.stat()

            replaced = SimpleNamespace(st_mode=expected.st_mode, st_dev=expected.st_dev, st_ino=expected.st_ino + 1)
            with patch("app.repo_scanner.staging.os.fstat", return_value=replaced), self.assertRaisesRegex(
                RepositoryStagingError, "changed during staging"
            ):
                _copy_regular_file(source, root / "replaced.py", expected)

            changed_size = SimpleNamespace(st_size=expected.st_size + 1, st_mtime_ns=expected.st_mtime_ns)
            with patch("app.repo_scanner.staging.os.fstat", side_effect=[expected, changed_size]), self.assertRaisesRegex(
                RepositoryStagingError, "changed during staging"
            ):
                _copy_regular_file(source, root / "changed.py", expected)

            destination = root / "io-error.py"
            with patch("app.repo_scanner.staging.os.open", side_effect=OSError("private io detail")), self.assertRaisesRegex(
                RepositoryStagingError, "could not be staged safely"
            ):
                _copy_regular_file(source, destination, expected)
            self.assertFalse(destination.exists())

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
        self.assertEqual(result.findings[0].affected_file, "src/settings.py")
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
            with self.assertRaises(RepoToolOutputError):
                _load_json(Path(temp_dir) / "missing.json", 100)

    def test_repository_scan_makes_osv_failure_an_explicit_warning(self) -> None:
        now = datetime.now(UTC)
        finding = NormalizedFindingInput(
            title="Secret",
            severity="high",
            confidence="confirmed",
            affected_file="app.py",
            evidence="[REDACTED]",
            source_tool="gitleaks",
            scanner_rule_id="rule",
        )
        gitleaks = AdapterResult((finding,), ToolReceipt("gitleaks", "8.30.1", "completed", None, 1, now, now))
        with patch("app.repo_scanner.adapters.run_gitleaks", return_value=gitleaks), patch(
            "app.repo_scanner.adapters.run_osv_scanner", side_effect=RepoToolUnavailableError("missing")
        ), patch("app.repo_scanner.adapters._optional_version", return_value=None):
            result = run_repository_scan(Path("/staged"), Settings(_env_file=None))
        self.assertEqual(result.findings, (finding,))
        self.assertEqual(result.receipts[1].status, "skipped")
        self.assertEqual(result.warning_codes, ("repo_tool_unavailable",))

        osv = AdapterResult((), ToolReceipt("osv-scanner", "2.5.0", "completed", None, 0, now, now))
        with patch("app.repo_scanner.adapters.run_gitleaks", return_value=gitleaks), patch(
            "app.repo_scanner.adapters.run_osv_scanner", return_value=osv
        ):
            successful = run_repository_scan(Path("/staged"), Settings(_env_file=None))
        self.assertEqual(successful.warning_codes, ())

    def test_tool_version_verification_is_exact_and_safe(self) -> None:
        with patch("app.repo_scanner.adapters.shutil.which", return_value=None):
            with self.assertRaises(RepoToolUnavailableError):
                _verify_version("gitleaks", "8.30.1")

        completed = SimpleNamespace(returncode=0, stdout="gitleaks 8.30.1", stderr="")
        with patch("app.repo_scanner.adapters.shutil.which", return_value="/trusted/gitleaks"), patch(
            "app.repo_scanner.adapters.subprocess.run", return_value=completed
        ):
            self.assertEqual(_verify_version("gitleaks", "8.30.1"), "8.30.1")
        with patch("app.repo_scanner.adapters._verify_version", side_effect=lambda _binary, expected: expected):
            self.assertEqual(verify_repo_tools(Settings(_env_file=None)), {"gitleaks": "8.30.1", "osv-scanner": "2.5.0"})

        for result in (
            SimpleNamespace(returncode=1, stdout="8.30.1", stderr=""),
            SimpleNamespace(returncode=0, stdout="8.30.10", stderr=""),
        ):
            with patch("app.repo_scanner.adapters.shutil.which", return_value="/trusted/tool"), patch(
                "app.repo_scanner.adapters.subprocess.run", return_value=result
            ), self.assertRaises(RepoToolUnavailableError):
                _verify_version("tool", "8.30.1")
        with patch("app.repo_scanner.adapters.shutil.which", return_value="/trusted/tool"), patch(
            "app.repo_scanner.adapters.subprocess.run", side_effect=subprocess.TimeoutExpired("tool", 5)
        ), self.assertRaises(RepoToolUnavailableError):
            _verify_version("tool", "1.0")
        with patch("app.repo_scanner.adapters._verify_version", side_effect=RepoToolUnavailableError("missing")):
            self.assertIsNone(_optional_version("tool", "1.0"))

    def test_child_limits_are_applied_to_the_scanner_process(self) -> None:
        with patch("app.repo_scanner.adapters.resource.prlimit", create=True) as set_limit:
            _limit_process(123, 1024, 7)

        self.assertEqual(set_limit.call_count, 2)
        self.assertTrue(all(call_args.args[0] == 123 for call_args in set_limit.call_args_list))

    def test_tool_runner_maps_failures_and_bounds_output(self) -> None:
        config = Settings(_env_file=None, repo_tool_output_bytes=32, repo_tool_timeout_seconds=2)
        with tempfile.TemporaryDirectory() as output_dir:
            output = Path(output_dir)
            completed_process = MagicMock(pid=123)
            completed_process.wait.return_value = 7
            completed_process.poll.return_value = 7
            with patch("app.repo_scanner.adapters.subprocess.Popen", return_value=completed_process) as popen:
                with patch("app.repo_scanner.adapters._limit_process"):
                    self.assertEqual(_run_tool(["trusted", "--fixed"], output_dir=output, config=config), 7)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertEqual(popen.call_args.kwargs["umask"], 0o077)

            for exception, error_type in (
                (FileNotFoundError(), RepoToolUnavailableError),
                (subprocess.TimeoutExpired("trusted", 2), RepoToolTimeoutError),
                (OSError("private OS detail"), RepoToolError),
            ):
                with patch("app.repo_scanner.adapters.subprocess.Popen", side_effect=exception), self.assertRaises(error_type):
                    _run_tool(["trusted"], output_dir=output, config=config)

            def oversized_run(_command, **kwargs):
                kwargs["stdout"].write(b"x" * 33)
                kwargs["stdout"].flush()
                process = MagicMock(pid=124)
                process.wait.return_value = 0
                process.poll.return_value = 0
                return process

            with patch("app.repo_scanner.adapters.subprocess.Popen", side_effect=oversized_run), patch(
                "app.repo_scanner.adapters._limit_process"
            ), self.assertRaises(RepoToolOutputError):
                _run_tool(["trusted"], output_dir=output, config=config)

    def test_tool_runner_terminates_process_group_when_checkpoint_aborts(self) -> None:
        class ExecutionStopped(Exception):
            pass

        config = Settings(_env_file=None, repo_tool_timeout_seconds=2)
        process = MagicMock(pid=321)
        process.poll.return_value = None
        checkpoint = MagicMock(side_effect=[None, ExecutionStopped()])
        with tempfile.TemporaryDirectory() as output_dir, patch(
            "app.repo_scanner.adapters.subprocess.Popen",
            return_value=process,
        ) as popen, patch("app.repo_scanner.adapters._limit_process"), patch(
            "app.repo_scanner.adapters._terminate_process_group"
        ) as terminate:
            with self.assertRaises(ExecutionStopped):
                _run_tool(
                    ["trusted"],
                    output_dir=Path(output_dir),
                    config=config,
                    checkpoint=checkpoint,
                )

        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        terminate.assert_called_once_with(process)

    def test_process_group_cleanup_escalates_to_kill(self) -> None:
        process = MagicMock(pid=321)
        process.wait.side_effect = [subprocess.TimeoutExpired("trusted", 1), 0]
        with patch("app.repo_scanner.adapters.os.killpg") as kill_group:
            _terminate_process_group(process)

        self.assertEqual(
            kill_group.call_args_list,
            [call(321, signal.SIGTERM), call(321, signal.SIGKILL)],
        )

    def test_osv_adapter_handles_bounded_exit_codes_and_output(self) -> None:
        payload = {"results": []}
        captured_command: list[str] = []
        captured_environment: dict[str, str] = {}

        def fake_run(command, **kwargs):
            captured_command.extend(command)
            captured_environment.update(kwargs["extra_environment"])
            Path(command[command.index("--output-file") + 1]).write_text(json.dumps(payload), encoding="utf-8")
            return 1

        with tempfile.TemporaryDirectory() as staged_dir, patch(
            "app.repo_scanner.adapters._verify_version", return_value="2.5.0"
        ), patch("app.repo_scanner.adapters._validate_osv_database"), patch(
            "app.repo_scanner.adapters._run_tool", side_effect=fake_run
        ):
            result = run_osv_scanner(Path(staged_dir), Settings(_env_file=None))
        self.assertEqual(result.receipt.status, "completed")
        self.assertIn("--offline", captured_command)
        self.assertNotIn("--offline-vulnerabilities", captured_command)
        self.assertIn("--no-resolve", captured_command)
        self.assertEqual(captured_environment, {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/var/lib/osv-scanner"})

        with tempfile.TemporaryDirectory() as staged_dir, patch(
            "app.repo_scanner.adapters._verify_version", return_value="2.5.0"
        ), patch("app.repo_scanner.adapters._validate_osv_database"), patch(
            "app.repo_scanner.adapters._run_tool", return_value=4
        ), self.assertRaises(RepoToolError):
            run_osv_scanner(Path(staged_dir), Settings(_env_file=None))

        with tempfile.TemporaryDirectory() as staged_dir, patch(
            "app.repo_scanner.adapters._verify_version", return_value="8.30.1"
        ), patch("app.repo_scanner.adapters._run_tool", return_value=7), self.assertRaises(RepoToolError):
            run_gitleaks(Path(staged_dir), Settings(_env_file=None))

        def malformed_gitleaks(command, **_kwargs):
            Path(command[command.index("--report-path") + 1]).write_text("{}", encoding="utf-8")
            return 0

        with tempfile.TemporaryDirectory() as staged_dir, patch(
            "app.repo_scanner.adapters._verify_version", return_value="8.30.1"
        ), patch("app.repo_scanner.adapters._run_tool", side_effect=malformed_gitleaks), self.assertRaises(RepoToolOutputError):
            run_gitleaks(Path(staged_dir), Settings(_env_file=None))

    def test_osv_parser_rejects_shape_and_bounds_findings(self) -> None:
        with self.assertRaises(RepoToolOutputError):
            _osv_findings([], Path("/tmp/staged"), 10)
        with self.assertRaises(RepoToolOutputError):
            _osv_findings({"results": {}}, Path("/tmp/staged"), 10)

        payload = {
            "results": [
                None,
                {
                    "source": "malformed",
                    "packages": [
                        None,
                        {
                            "package": None,
                            "vulnerabilities": [
                                None,
                                {"id": "OSV-1", "summary": "First", "database_specific": {"severity": "critical"}},
                                {"id": "OSV-1", "summary": "duplicate"},
                                {"id": "OSV-2", "summary": "Second", "severity": [{"score": "CVSS:3.1/AV:N/C:H"}]},
                            ],
                        },
                    ],
                },
            ]
        }
        findings = _osv_findings(payload, Path("/tmp/staged"), 2)
        self.assertEqual([finding.scanner_rule_id for finding in findings], ["OSV-1", "OSV-2"])
        self.assertEqual([finding.severity for finding in findings], ["critical", "high"])
        self.assertEqual(_osv_severity({"database_specific": {"severity": "unknown"}, "severity": [None, {"score": "n/a"}]}), "medium")

    def test_relative_paths_numbers_and_osv_database_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as staged_dir, tempfile.TemporaryDirectory() as outside_dir:
            staged = Path(staged_dir)
            inside = staged / "src" / "app.py"
            inside.parent.mkdir()
            inside.touch()
            outside = Path(outside_dir) / "private.py"
            outside.touch()
            self.assertEqual(_relative_scanner_path(inside.as_posix(), staged), "src/app.py")
            self.assertEqual(_relative_scanner_path(outside.as_posix(), staged), "private.py")
            self.assertEqual(_relative_scanner_path(None, staged), "unknown")

        for value, expected in (("12", 12), ("invalid", None), (0, None), (-1, None), (10_000_000, None), ({}, None)):
            self.assertEqual(_safe_positive_int(value), expected)

        with tempfile.TemporaryDirectory() as database_dir:
            config = Settings(_env_file=None, osv_database_path=database_dir, osv_database_max_age_days=1)
            with self.assertRaisesRegex(RepoToolUnavailableError, "unavailable") as missing:
                _validate_osv_database(config)
            self.assertEqual(missing.exception.code, "osv_database_missing")
            archive = Path(database_dir) / "osv-scalibr" / "npm" / "all.zip"
            archive.parent.mkdir(parents=True)
            archive.touch()
            old = (datetime.now(UTC) - timedelta(days=2)).timestamp()
            os.utime(archive, (old, old))
            with self.assertRaisesRegex(RepoToolUnavailableError, "stale") as stale:
                _validate_osv_database(config)
            self.assertEqual(stale.exception.code, "osv_database_stale")
            archive.touch()
            _validate_osv_database(config)

        with tempfile.TemporaryDirectory() as database_dir, patch.object(Path, "glob", side_effect=OSError("private glob detail")):
            with self.assertRaisesRegex(RepoToolUnavailableError, "unavailable"):
                _validate_osv_database(Settings(_env_file=None, osv_database_path=database_dir))

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

    @unittest.skipUnless(os.environ.get("SCOPEHARBOR_REAL_SCANNER_TESTS") == "1", "real scanner binaries not requested")
    def test_real_osv_binary_uses_offline_database_and_never_executes_package_scripts(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "osv-vulnerable"
        with tempfile.TemporaryDirectory() as staged_dir:
            root = Path(staged_dir)
            shutil.copytree(fixture, root, dirs_exist_ok=True)
            marker = root / "script-executed"
            result = run_osv_scanner(root)

            self.assertGreaterEqual(len(result.findings), 1)
            self.assertTrue(all(finding.source_tool == "osv-scanner" for finding in result.findings))
            self.assertTrue(all(finding.affected_file == "package-lock.json" for finding in result.findings))
            self.assertNotIn(str(root), str(result))
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
