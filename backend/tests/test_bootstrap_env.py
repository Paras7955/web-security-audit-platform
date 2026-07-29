import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

from scripts.bootstrap_env import bootstrap


class BootstrapEnvironmentTests(unittest.TestCase):
    def test_bootstrap_generates_missing_values_and_preserves_fernet_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            template = root / ".env.example"
            destination = root / ".env"
            template.write_text(
                "POSTGRES_PASSWORD=\nDEV_AUTH_TOKEN=\nAUTH_PROFILE_SECRET_KEY=\nZAP_API_KEY=\n"
                "SCAN_RELAY_SECRET=\nNEXT_PUBLIC_DEV_AUTH_TOKEN=\nNEW_LIMIT=25\nDATABASE_URL=\n",
                encoding="utf-8",
            )
            existing_key = "existing-user-managed-fernet-key="
            destination.write_text(
                f"AUTH_PROFILE_SECRET_KEY={existing_key}\nPOSTGRES_PASSWORD=p@ss word\nZAP_API_KEY=\n",
                encoding="utf-8",
            )

            generated, preserved = bootstrap(destination, template)
            content = destination.read_text(encoding="utf-8")

            self.assertIn(f"AUTH_PROFILE_SECRET_KEY={existing_key}", content)
            self.assertIn("AUTH_PROFILE_SECRET_KEY", preserved)
            self.assertIn("ZAP_API_KEY", generated)
            self.assertIn("SCAN_RELAY_SECRET", generated)
            self.assertIn("NEW_LIMIT=25", content)
            self.assertIn(
                f"DATABASE_URL=postgresql+psycopg://security_audit:{quote('p@ss word', safe='')}@postgres:5432/security_audit",
                content,
            )
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_bootstrap_preserves_external_database_url_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            template = root / ".env.example"
            destination = root / ".env"
            template.write_text(
                "POSTGRES_PASSWORD=\nDEV_AUTH_TOKEN=\nAUTH_PROFILE_SECRET_KEY=\nZAP_API_KEY=\n"
                "SCAN_RELAY_SECRET=\nNEXT_PUBLIC_DEV_AUTH_TOKEN=\nDATABASE_URL=\n",
                encoding="utf-8",
            )
            external_url = "postgresql+psycopg://operator:secret@database.example:5432/scopeharbor"
            destination.write_text(
                "AUTH_PROFILE_SECRET_KEY=not-replaced-even-if-invalid\n"
                f"DATABASE_URL={external_url}\n",
                encoding="utf-8",
            )

            bootstrap(destination, template)
            first = destination.read_text(encoding="utf-8")
            bootstrap(destination, template)
            second = destination.read_text(encoding="utf-8")

            self.assertEqual(first, second)
            self.assertIn(f"DATABASE_URL={external_url}", second)
            self.assertEqual(second.count("SCAN_RELAY_SECRET="), 1)


if __name__ == "__main__":
    unittest.main()
