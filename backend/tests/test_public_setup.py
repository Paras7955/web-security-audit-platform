import re
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

    def test_setup_wrappers_keep_environment_path_inside_repository(self) -> None:
        bash = (ROOT / "scripts" / "setup.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")

        self.assertRegex(bash, re.compile(r'""\|\*/\*'))
        self.assertIn("GetFileName($EnvFile)", powershell)
        self.assertIn("EnvironmentPath.StartsWith($RootPrefix", powershell)
        self.assertIn("OrdinalIgnoreCase", powershell)

    def test_compose_errors_use_platform_neutral_setup_guidance(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertNotIn("python3 scripts/bootstrap_env.py", compose)
        self.assertIn("setup script documented in README.md", compose)


if __name__ == "__main__":
    unittest.main()
