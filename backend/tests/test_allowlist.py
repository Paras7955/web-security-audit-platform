import tempfile
import unittest
from pathlib import Path

import yaml
from app.security.allowlist import AllowlistError, ScanAllowlist, load_allowlist
from pydantic import ValidationError

VALID_CONFIG = {
    "targets": [
        {
            "id": "juice-shop",
            "name": "OWASP Juice Shop",
            "base_url": "http://juice-shop:3000",
            "schemes": ["http"],
            "hosts": ["juice-shop"],
            "ports": [3000],
            "allowed_modes": ["passive", "active_demo", "ajax_short", "repo"],
            "max_redirects": 5,
            "local_demo": True,
            "notes": "Local Docker Compose demo target",
        }
    ]
}
V2_TARGET = {
    "id": "local-app",
    "name": "Local App",
    "base_url": "http://local-app:8080/app",
    "connection": {"kind": "compose_service", "host": "local-app", "port": 8080},
    "profile_engines": {"passive-web": ["scopeharbor-passive"]},
    "disposable_demo": False,
    "tls": {"trust": "system"},
    "max_redirects": 2,
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

    def test_v2_policy_exposes_legacy_compatibility_properties(self) -> None:
        allowlist = ScanAllowlist.model_validate({"version": 2, "targets": [V2_TARGET]})
        target = allowlist.targets[0]

        self.assertEqual(target.schemes, ["http"])
        self.assertEqual(target.hosts, ["local-app"])
        self.assertEqual(target.ports, [8080])
        self.assertEqual([mode.value for mode in target.allowed_modes], ["passive"])
        self.assertFalse(target.local_demo)
        self.assertEqual([engine.value for engine in target.engines_for_profile("passive-web")], ["scopeharbor-passive"])

    def test_policy_fingerprint_is_canonical_and_excludes_display_copy(self) -> None:
        first = ScanAllowlist.model_validate({"version": 2, "targets": [V2_TARGET]}).targets[0]
        changed_copy = dict(V2_TARGET, name="Renamed App", notes="Operator-only copy")
        second = ScanAllowlist.model_validate({"version": 2, "targets": [changed_copy]}).targets[0]

        self.assertEqual(first.policy_fingerprint, second.policy_fingerprint)
        self.assertEqual(len(first.policy_fingerprint), 64)

    def test_overlapping_base_paths_are_rejected_but_siblings_are_allowed(self) -> None:
        overlapping = dict(V2_TARGET, id="admin-app", base_url="http://local-app:8080/app/admin")
        with self.assertRaises(ValidationError):
            ScanAllowlist.model_validate({"version": 2, "targets": [V2_TARGET, overlapping]})

        sibling = dict(V2_TARGET, id="other-app", base_url="http://local-app:8080/other")
        allowlist = ScanAllowlist.model_validate({"version": 2, "targets": [V2_TARGET, sibling]})
        self.assertEqual(len(allowlist.targets), 2)

    def test_ambiguous_base_paths_and_public_host_gateway_addresses_are_rejected(self) -> None:
        for base_url in (
            "http://local-app:8080/app/../admin",
            "http://local-app:8080/app//admin",
            "http://local-app:8080/app/%2e%2e/admin",
            "http://local-app:8080/app/%2fadmin",
        ):
            with self.subTest(base_url=base_url), self.assertRaises(ValidationError):
                ScanAllowlist.model_validate({"version": 2, "targets": [dict(V2_TARGET, base_url=base_url)]})

        host_gateway = dict(
            V2_TARGET,
            base_url="https://localhost:8443/",
            connection={
                "kind": "host_gateway",
                "host": "scopeharbor-host",
                "port": 8443,
                "expected_ips": ["8.8.8.8"],
            },
        )
        with self.assertRaises(ValidationError):
            ScanAllowlist.model_validate({"version": 2, "targets": [host_gateway]})

    def test_all_zap_engines_require_disposable_demo(self) -> None:
        for profile_engines in (
            {"passive-web": ["scopeharbor-passive", "zap-passive"]},
            {"active-demo": ["scopeharbor-passive", "zap-passive", "zap-active"]},
            {"modern-web-crawl": ["scopeharbor-passive", "zap-passive", "zap-client-spider"]},
        ):
            with self.subTest(profile_engines=profile_engines), self.assertRaises(ValidationError):
                ScanAllowlist.model_validate({
                    "version": 2,
                    "targets": [dict(V2_TARGET, profile_engines=profile_engines)],
                })

    def test_legacy_non_demo_passive_policy_drops_zap_compatibility(self) -> None:
        legacy_target = dict(
            VALID_CONFIG["targets"][0],
            allowed_modes=["passive"],
            local_demo=False,
        )

        target = ScanAllowlist.model_validate({"targets": [legacy_target]}).targets[0]

        self.assertEqual(
            [engine.value for engine in target.engines_for_profile("passive-web")],
            ["scopeharbor-passive"],
        )

    def test_tls_policy_has_no_insecure_mode_and_custom_ca_is_https_only(self) -> None:
        for tls in (
            {"trust": "custom_ca"},
            {"trust": "system", "ca_bundle_path": "/tmp/ca.pem"},
            {"trust": "insecure"},
        ):
            with self.subTest(tls=tls), self.assertRaises(ValidationError):
                ScanAllowlist.model_validate({"version": 2, "targets": [dict(V2_TARGET, tls=tls)]})

        https_target = dict(
            V2_TARGET,
            base_url="https://local-app:8443/",
            connection={"kind": "compose_service", "host": "local-app", "port": 8443},
            tls={"trust": "custom_ca", "ca_bundle_path": "/app/config/ca/local-app.pem"},
        )
        target = ScanAllowlist.model_validate({"version": 2, "targets": [https_target]}).targets[0]
        self.assertEqual(target.tls.trust, "custom_ca")


if __name__ == "__main__":
    unittest.main()
