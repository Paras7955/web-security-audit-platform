import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_IMAGE = (
    "python:3.12.13-slim-bookworm@"
    "sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b"
)


class PublicSetupTests(unittest.TestCase):
    def test_setup_wrappers_share_pinned_isolated_bootstrap(self) -> None:
        bash = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")

        for script in (bash, powershell):
            self.assertIn(BOOTSTRAP_IMAGE, script)
            self.assertIn("--network", script)
            self.assertIn("none", script)
            self.assertIn("--read-only", script)
            self.assertIn("--cap-drop", script)
            self.assertIn("ALL", script)
            self.assertIn("no-new-privileges:true", script)
            self.assertIn("scripts/bootstrap_env.py", script)
            self.assertIn("--detach", script)
            self.assertIn("--wait", script)
            self.assertIn("osv-db-update", script)
            self.assertIn("/workspace:ro", script)
            self.assertIn("/output", script)
            self.assertIn("--project-name", script)

        self.assertNotIn('$REPO_ROOT:/workspace"', bash)
        self.assertNotIn('${RepoRoot}:/workspace"', powershell)

    def test_setup_wrappers_keep_environment_path_inside_repository(self) -> None:
        bash = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")

        self.assertIn(r"^\.env(\.[A-Za-z0-9][A-Za-z0-9._-]*)?$", bash)
        self.assertIn("-L \"$ENV_FILE\"", bash)
        self.assertIn("EnvironmentFilePattern", powershell)
        self.assertIn("GetFileName($EnvFile)", powershell)
        self.assertIn("EnvironmentPath.StartsWith($RootPrefix", powershell)
        self.assertIn("OrdinalIgnoreCase", powershell)

        for invalid_name in (".", "..", "settings", "nested/.env"):
            result = subprocess.run(  # noqa: S603 - fixed test script and arguments
                ["/bin/bash", str(ROOT / "scripts" / "setup.sh"), "--bootstrap-only", "--env-file", invalid_name],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_setup_wrappers_propagate_custom_environment_file_to_compose(self) -> None:
        bash = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")

        self.assertGreaterEqual(bash.count('SCOPEHARBOR_ENV_FILE="$ENV_FILE" docker compose'), 2)
        self.assertIn('SetEnvironmentVariable("SCOPEHARBOR_ENV_FILE", $EnvFile, "Process")', powershell)
        self.assertIn("$PreviousScopeHarborEnvFile", powershell)

    def test_bash_custom_environment_reaches_every_runtime_compose_call(self) -> None:
        env_name = ".env.public-setup-test"
        env_path = ROOT / env_name
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_docker = Path(temp_dir) / "docker"
            log_path = Path(temp_dir) / "docker.log"
            fake_docker.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s\\n' "${SCOPEHARBOR_ENV_FILE:-}" "$*" >> "$FAKE_DOCKER_LOG"
if [[ "${1:-}" == "run" ]]; then
  previous=""
  for argument in "$@"; do
    if [[ "$previous" == "--volume" && "$argument" == *:/output ]]; then
      cp "$PWD/.env.example" "${argument%:/output}/environment"
      exit 0
    fi
    previous="$argument"
  done
fi
if [[ "$*" == *" port frontend 3000" ]]; then printf '127.0.0.1:3101\\n'; fi
if [[ "$*" == *" port backend 8000" ]]; then printf '127.0.0.1:8100\\n'; fi
if [[ "$*" == *" port juice-shop 3000" ]]; then printf '127.0.0.1:3100\\n'; fi
""",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{temp_dir}:{environment['PATH']}"
            environment["FAKE_DOCKER_LOG"] = str(log_path)
            try:
                result = subprocess.run(  # noqa: S603 - fixed test script and arguments
                    ["/bin/bash", str(ROOT / "scripts" / "setup.sh"), "--env-file", env_name],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                runtime_calls = [line for line in log_path.read_text(encoding="utf-8").splitlines() if "--project-name" in line]
                self.assertGreaterEqual(len(runtime_calls), 5)
                self.assertTrue(all(line.startswith(f"{env_name}|") for line in runtime_calls), runtime_calls)
                self.assertTrue(all(f"--env-file {env_name}" in line for line in runtime_calls), runtime_calls)
                self.assertIn("http://127.0.0.1:3101", result.stdout)
                self.assertIn("http://127.0.0.1:8100/docs", result.stdout)
                self.assertIn("http://127.0.0.1:3100", result.stdout)
            finally:
                env_path.unlink(missing_ok=True)

    def test_supported_environment_files_are_excluded_from_build_context(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        workflow = (ROOT / ".github" / "workflows" / "container-build.yml").read_text(encoding="utf-8")

        self.assertIn(".env", dockerignore)
        self.assertIn(".env.*", dockerignore)
        self.assertIn("!.env.example", dockerignore)
        self.assertIn(".env.scopeharbor-ci", workflow)
        self.assertNotIn(".scopeharbor-ci.env", workflow)

    def test_setup_summaries_derive_published_urls_from_compose(self) -> None:
        bash = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")

        for script in (bash, powershell):
            self.assertIn("port", script)
            self.assertIn("frontend", script)
            self.assertIn("backend", script)
            self.assertIn("juice-shop", script)
            self.assertNotIn("UI:           http://localhost:3001", script)

    def test_setup_wrappers_validate_isolated_compose_project_names(self) -> None:
        bash = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")

        expected_pattern = "^[a-z0-9][a-z0-9_-]*$"
        self.assertIn(expected_pattern, bash)
        self.assertIn(expected_pattern, powershell)
        self.assertIn('PROJECT_NAME="scopeharbor"', bash)
        self.assertIn('[string]$ProjectName = "scopeharbor"', powershell)

    def test_compose_errors_use_platform_neutral_setup_guidance(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertNotIn("python3 scripts/bootstrap_env.py", compose)
        self.assertIn("setup script documented in README.md", compose)


if __name__ == "__main__":
    unittest.main()
