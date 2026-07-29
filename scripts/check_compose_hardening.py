#!/usr/bin/env python3
"""Fail when the rendered Compose topology regresses security boundaries."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Mapping


class ComposeHardeningError(ValueError):
    pass


EXPECTED_NETWORKS = {
    "postgres": {"data", "operator-access"},
    "migrate": {"data"},
    "backend": {"data", "operator-access"},
    "worker": {"data", "scanner-control"},
    "relay": {"scanner-control", "scan-target", "host-access"},
    "zap": {"scanner-control", "scan-target"},
    "juice-shop": {"scan-target", "operator-access"},
    "osv-db-update": {"updater"},
    "frontend": {"operator-access"},
}


def _network_names(service: Mapping[str, object]) -> set[str]:
    networks = service.get("networks", {})
    if isinstance(networks, Mapping):
        return {str(name) for name in networks}
    if isinstance(networks, list):
        return {str(name) for name in networks}
    return set()


def validate_compose(payload: Mapping[str, object]) -> None:
    services = payload.get("services")
    networks = payload.get("networks")
    if not isinstance(services, Mapping) or not isinstance(networks, Mapping):
        raise ComposeHardeningError("Rendered Compose configuration is missing services or networks.")

    for name, expected_networks in EXPECTED_NETWORKS.items():
        raw_service = services.get(name)
        if not isinstance(raw_service, Mapping):
            raise ComposeHardeningError(f"Required service is missing: {name}.")
        if set(raw_service.get("cap_drop", [])) != {"ALL"}:
            raise ComposeHardeningError(f"{name} must drop all Linux capabilities.")
        if "no-new-privileges:true" not in set(raw_service.get("security_opt", [])):
            raise ComposeHardeningError(f"{name} must enable no-new-privileges.")
        actual_networks = _network_names(raw_service)
        if actual_networks != expected_networks:
            raise ComposeHardeningError(
                f"{name} network boundary changed: expected {sorted(expected_networks)}, got {sorted(actual_networks)}."
            )

    for name in ("migrate", "backend", "worker", "relay", "zap", "osv-db-update", "frontend"):
        service = services[name]
        if isinstance(service, Mapping) and service.get("read_only") is not True:
            raise ComposeHardeningError(f"{name} must use a read-only root filesystem.")

    migrate = services["migrate"]
    if isinstance(migrate, Mapping) and migrate.get("volumes"):
        raise ComposeHardeningError("The migration service must not receive repository, artifact, or scanner mounts.")

    worker = services["worker"]
    if isinstance(worker, Mapping) and worker.get("extra_hosts"):
        raise ComposeHardeningError("The worker must not receive host-gateway resolution.")

    relay = services["relay"]
    if isinstance(relay, Mapping):
        relay_environment = relay.get("environment", {})
        forbidden = {"DATABASE_URL", "ZAP_API_KEY", "OPENAI_API_KEY", "AUTH_PROFILE_SECRET_KEY"}
        if isinstance(relay_environment, Mapping) and forbidden.intersection(relay_environment):
            raise ComposeHardeningError("The relay received a forbidden credential or database setting.")

    for network_name in ("data", "scanner-control", "scan-target"):
        network = networks.get(network_name)
        if not isinstance(network, Mapping) or network.get("internal") is not True:
            raise ComposeHardeningError(f"{network_name} must remain an internal network.")


def main() -> int:
    docker_binary = shutil.which("docker")
    if not docker_binary:
        print("Compose hardening check failed: docker is unavailable.", file=sys.stderr)
        return 1
    completed = subprocess.run(  # noqa: S603 - fixed arguments passed to the resolved local Docker CLI
        [docker_binary, "compose", "--profile", "maintenance", "config", "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        print("Compose rendering failed.", file=sys.stderr)
        return completed.returncode
    try:
        payload = json.loads(completed.stdout)
        if not isinstance(payload, Mapping):
            raise ComposeHardeningError("Rendered Compose configuration is not an object.")
        validate_compose(payload)
    except (json.JSONDecodeError, ComposeHardeningError) as exc:
        print(f"Compose hardening check failed: {exc}", file=sys.stderr)
        return 1
    print("Compose hardening boundaries verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
