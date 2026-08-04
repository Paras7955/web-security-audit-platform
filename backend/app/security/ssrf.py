from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass

from app.security.allowlist import (
    AllowlistTarget,
    HostGatewayConnection,
    is_private_target_address,
    path_is_within_scope,
)
from app.security.target_url import NormalizedTargetUrl


class SsrfGuardError(ValueError):
    pass


Resolver = Callable[[str, int], list[str]]
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class DestinationValidation:
    host: str
    port: int
    connection_host: str
    connection_port: int
    resolved_ips: tuple[str, ...]

    @property
    def connection_ip(self) -> str:
        return self.resolved_ips[0]


METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
}
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
UNIQUE_LOCAL_IPV6 = ipaddress.ip_network("fc00::/7")


def resolve_host(host: str, port: int) -> list[str]:
    try:
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SsrfGuardError("target host could not be resolved") from exc

    ips = sorted({str(item[4][0]) for item in addrinfo})
    if not ips:
        raise SsrfGuardError("target host resolved to no addresses")
    return ips


def validate_destination(
    normalized_url: NormalizedTargetUrl,
    allowlist_target: AllowlistTarget,
    resolver: Resolver = resolve_host,
) -> DestinationValidation:
    if normalized_url.scheme not in allowlist_target.schemes:
        raise SsrfGuardError("target scheme is not allowlisted")
    if normalized_url.host not in allowlist_target.hosts:
        raise SsrfGuardError("target host is not allowlisted")
    if normalized_url.port not in allowlist_target.ports:
        raise SsrfGuardError("target port is not allowlisted")
    if not path_is_within_scope(normalized_url.path.split("?", 1)[0], allowlist_target.base_path):
        raise SsrfGuardError("target path is outside the allowlisted base path")

    connection = allowlist_target.connection
    resolved_ips = resolver(connection.host, connection.port)
    if not resolved_ips:
        raise SsrfGuardError("target host resolved to no addresses")

    normalized_ips: list[str] = []
    for raw_ip in resolved_ips:
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise SsrfGuardError("target host resolved to an invalid address") from exc
        validate_ip_for_target(ip, normalized_url.host, allowlist_target)
        normalized_ips.append(ip.compressed)

    return DestinationValidation(
        host=normalized_url.host,
        port=normalized_url.port,
        connection_host=connection.host,
        connection_port=connection.port,
        resolved_ips=tuple(sorted(set(normalized_ips))),
    )


def validate_ip_for_target(ip: IpAddress, host: str, allowlist_target: AllowlistTarget) -> None:
    if host != allowlist_target.hosts[0]:
        raise SsrfGuardError("target host is not allowlisted")
    if ip in METADATA_IPS:
        raise SsrfGuardError("cloud metadata destinations are blocked")

    if is_never_allowed_internal_address(ip):
        raise SsrfGuardError("loopback, link-local, reserved, multicast, and unspecified destinations are blocked")

    if not is_private_target_address(ip):
        raise SsrfGuardError("public and non-target network destinations are blocked")

    connection = allowlist_target.connection
    if isinstance(connection, HostGatewayConnection):
        expected_ips = {ipaddress.ip_address(raw_ip) for raw_ip in connection.expected_ips}
        if ip not in expected_ips:
            raise SsrfGuardError("host gateway resolved outside its exact configured addresses")
        return

    if not is_local_demo_network_address(ip):
        raise SsrfGuardError("Compose service targets must resolve only to RFC1918 or unique-local addresses")


def is_internal_address(ip: IpAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_never_allowed_internal_address(ip: IpAddress) -> bool:
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_local_demo_network_address(ip: IpAddress) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in network for network in RFC1918_NETWORKS)
    return ip in UNIQUE_LOCAL_IPV6
