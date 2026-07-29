import unittest
from copy import deepcopy

from scripts.check_compose_hardening import ComposeHardeningError, validate_compose


def safe_compose() -> dict[str, object]:
    networks = {
        "data": {"internal": True},
        "scanner-control": {"internal": True},
        "scan-target": {"internal": True},
        "host-access": {},
        "operator-access": {},
        "updater": {},
    }
    expected = {
        "postgres": ["data", "operator-access"],
        "migrate": ["data"],
        "backend": ["data", "operator-access"],
        "worker": ["data", "scanner-control"],
        "relay": ["scanner-control", "scan-target", "host-access"],
        "zap": ["scanner-control", "scan-target"],
        "juice-shop": ["scan-target", "operator-access"],
        "osv-db-update": ["updater"],
        "frontend": ["operator-access"],
    }
    services: dict[str, object] = {}
    for name, service_networks in expected.items():
        services[name] = {
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "networks": {network: None for network in service_networks},
            "read_only": name not in {"postgres", "juice-shop"},
        }
    return {"services": services, "networks": networks}


class ComposeHardeningTests(unittest.TestCase):
    def test_accepts_expected_boundaries(self) -> None:
        validate_compose(safe_compose())

    def test_rejects_worker_host_access_and_relay_credentials(self) -> None:
        worker_escape = deepcopy(safe_compose())
        worker_escape["services"]["worker"]["networks"]["host-access"] = None  # type: ignore[index]
        with self.assertRaises(ComposeHardeningError):
            validate_compose(worker_escape)

        relay_secret_exposure = deepcopy(safe_compose())
        relay_secret_exposure["services"]["relay"]["environment"] = {"DATABASE_URL": "secret"}  # type: ignore[index]
        with self.assertRaises(ComposeHardeningError):
            validate_compose(relay_secret_exposure)


if __name__ == "__main__":
    unittest.main()
