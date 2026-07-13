from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass

from app.security.allowlist import AllowlistTarget
from app.security.target_url import NormalizedTargetUrl


class SsrfGuardError(ValueError):
    pass


Resolver = Callable[[str, int], list[str]]
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class DestinationValidation:
    host: str
    port: int
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

    resolved_ips = resolver(normalized_url.host, normalized_url.port)
    if not resolved_ips:
        raise SsrfGuardError("target host resolved to no addresses")

    for raw_ip in resolved_ips:
        ip = ipaddress.ip_address(raw_ip)
        validate_ip_for_target(ip, normalized_url.host, allowlist_target)

    return DestinationValidation(
        host=normalized_url.host,
        port=normalized_url.port,
        resolved_ips=tuple(resolved_ips),
    )


def validate_ip_for_target(ip: IpAddress, host: str, allowlist_target: AllowlistTarget) -> None:
    if ip in METADATA_IPS:
        raise SsrfGuardError("cloud metadata destinations are blocked")

    if is_never_allowed_internal_address(ip):
        raise SsrfGuardError("loopback, link-local, reserved, multicast, and unspecified destinations are blocked")

    if is_local_demo_network_address(ip):
        if allowlist_target.local_demo and host == allowlist_target.hosts[0]:
            return
        raise SsrfGuardError("private, loopback, link-local, and internal destinations are blocked")

    if is_internal_address(ip):
        raise SsrfGuardError("private, loopback, link-local, and internal destinations are blocked")

    if allowlist_target.local_demo:
        raise SsrfGuardError("local Docker service targets must resolve only to an RFC1918 container address")


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
