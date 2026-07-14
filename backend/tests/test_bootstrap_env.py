import tempfile
import unittest
from pathlib import Path

from scripts.bootstrap_env import bootstrap


class BootstrapEnvironmentTests(unittest.TestCase):
    def test_bootstrap_generates_missing_values_and_preserves_fernet_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            template = root / ".env.example"
            destination = root / ".env"
            template.write_text(
                "POSTGRES_PASSWORD=\nDEV_AUTH_TOKEN=\nAUTH_PROFILE_SECRET_KEY=\nZAP_API_KEY=\n"
                "NEXT_PUBLIC_DEV_AUTH_TOKEN=\n",
                encoding="utf-8",
            )
            existing_key = "existing-user-managed-fernet-key="
            destination.write_text(f"AUTH_PROFILE_SECRET_KEY={existing_key}\nZAP_API_KEY=\n", encoding="utf-8")

            generated, preserved = bootstrap(destination, template)
            content = destination.read_text(encoding="utf-8")

            self.assertIn(f"AUTH_PROFILE_SECRET_KEY={existing_key}", content)
            self.assertIn("AUTH_PROFILE_SECRET_KEY", preserved)
            self.assertIn("ZAP_API_KEY", generated)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
