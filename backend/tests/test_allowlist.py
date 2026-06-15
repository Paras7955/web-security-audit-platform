import tempfile
import unittest
from pathlib import Path

import yaml

from app.security.allowlist import AllowlistError, load_allowlist


VALID_CONFIG = {
    "targets": [
        {
            "id": "juice-shop",
            "name": "OWASP Juice Shop",
            "base_url": "http://juice-shop:3000",
            "schemes": ["http"],
            "hosts": ["juice-shop"],
            "ports": [3000],
            "allowed_modes": ["passive", "active_demo", "ajax_short"],
            "max_redirects": 5,
            "local_demo": True,
            "notes": "Local Docker Compose demo target",
        }
    ]
}


class AllowlistTests(unittest.TestCase):
    def write_config(self, config: dict) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "scan-allowlist.yml"
        path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return path

    def test_valid_juice_shop_allowlist_loads(self) -> None:
        allowlist = load_allowlist(self.write_config(VALID_CONFIG))

        target = allowlist.get_target("juice-shop")
        self.assertIsNotNone(target)
        self.assertEqual(target.base_url, "http://juice-shop:3000")

    def test_invalid_scheme_is_rejected(self) -> None:
        config = dict(VALID_CONFIG)
        config["targets"] = [dict(VALID_CONFIG["targets"][0], schemes=["ftp"])]

        with self.assertRaises(AllowlistError):
            load_allowlist(self.write_config(config))

    def test_wildcard_host_is_rejected(self) -> None:
        config = dict(VALID_CONFIG)
        config["targets"] = [dict(VALID_CONFIG["targets"][0], hosts=["*.example.com"])]

        with self.assertRaises(AllowlistError):
            load_allowlist(self.write_config(config))

    def test_duplicate_target_id_is_rejected(self) -> None:
        config = {"targets": [VALID_CONFIG["targets"][0], VALID_CONFIG["targets"][0]]}

        with self.assertRaises(AllowlistError):
            load_allowlist(self.write_config(config))

    def test_malformed_port_is_rejected(self) -> None:
        config = dict(VALID_CONFIG)
        config["targets"] = [dict(VALID_CONFIG["targets"][0], ports=[70000])]

        with self.assertRaises(AllowlistError):
            load_allowlist(self.write_config(config))

    def test_multiple_schemes_hosts_or_ports_are_rejected(self) -> None:
        cases = [
            {"schemes": ["http", "https"]},
            {"hosts": ["juice-shop", "localhost"]},
            {"ports": [3000, 3001]},
        ]

        for override in cases:
            with self.subTest(override=override):
                config = dict(VALID_CONFIG)
                config["targets"] = [dict(VALID_CONFIG["targets"][0], **override)]

                with self.assertRaises(AllowlistError):
                    load_allowlist(self.write_config(config))

    def test_duplicate_endpoint_is_rejected(self) -> None:
        second_target = dict(
            VALID_CONFIG["targets"][0],
            id="juice-shop-copy",
            allowed_modes=["passive"],
            max_redirects=1,
        )
        config = {"targets": [VALID_CONFIG["targets"][0], second_target]}

        with self.assertRaises(AllowlistError):
            load_allowlist(self.write_config(config))


if __name__ == "__main__":
    unittest.main()
