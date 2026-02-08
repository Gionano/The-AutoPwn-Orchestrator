from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Iterable, Optional

from .config import ConfigError, ScanConfig, TargetConfig
from .fingerprint import HTTP_PORTS, fingerprint


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Target:
    host: str
    ip: str


@dataclass(frozen=True)
class PortScan:
    port: int
    service: str
    banner: str
    details: dict


@dataclass(frozen=True)
class HostScan:
    target: Target
    open_ports: list[PortScan]


def expand_targets(targets: TargetConfig, resolve_dns: bool) -> list[Target]:
    allowlist = _parse_allowlist(targets.allowlist)
    results: list[Target] = []
    seen: set[str] = set()

    for item in targets.include:
        if _is_ip_address(item):
            _add_target(item, item, allowlist, results, seen)
        else:
            if not resolve_dns:
                raise ConfigError(f"DNS resolution disabled but hostname provided: {item}")
            resolved = _resolve_hostname(item)
            if not resolved:
                raise ConfigError(f"Unable to resolve hostname: {item}")
            for ip in resolved:
                _add_target(item, ip, allowlist, results, seen)

    for cidr in targets.cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            if len(results) >= targets.max_hosts:
                raise ConfigError("Target count exceeded targets.max_hosts")
            _add_target(str(ip), str(ip), allowlist, results, seen)

    if not results:
        raise ConfigError("No targets remain after allowlist filtering")
    return results


async def scan_targets(targets: list[Target], scan: ScanConfig) -> list[HostScan]:
    semaphore = asyncio.Semaphore(scan.concurrency)
    tasks = [
        scan_host(target, scan.ports, scan.timeout_seconds, scan.banner_bytes, semaphore)
        for target in targets
    ]
    results = await asyncio.gather(*tasks)
    return results


async def scan_host(
    target: Target,
    ports: list[int],
    timeout_seconds: float,
    banner_bytes: int,
    semaphore: asyncio.Semaphore,
) -> HostScan:
    port_tasks = [
        scan_port(target, port, timeout_seconds, banner_bytes, semaphore)
        for port in ports
    ]
    port_results = await asyncio.gather(*port_tasks)
    open_ports = [result for result in port_results if result is not None]
    return HostScan(target=target, open_ports=open_ports)


async def scan_port(
    target: Target,
    port: int,
    timeout_seconds: float,
    banner_bytes: int,
    semaphore: asyncio.Semaphore,
) -> Optional[PortScan]:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.ip, port), timeout=timeout_seconds
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        banner = b""
        try:
            if port in HTTP_PORTS:
                request = f"HEAD / HTTP/1.0\r\nHost: {target.host}\r\n\r\n"
                writer.write(request.encode("ascii", errors="ignore"))
                await writer.drain()
            if banner_bytes > 0:
                banner = await asyncio.wait_for(reader.read(banner_bytes), timeout=timeout_seconds)
        except (asyncio.TimeoutError, OSError):
            banner = b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        fp = fingerprint(port, banner)
        logger.debug("Open port %s:%s (%s)", target.ip, port, fp["service"])
        return PortScan(
            port=port,
            service=fp["service"],
            banner=fp["banner"],
            details=fp["details"],
        )


def _parse_allowlist(allowlist: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for item in allowlist:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ConfigError(f"Invalid allowlist entry: {item}") from exc
    if not networks:
        raise ConfigError("Allowlist is empty")
    return networks


def _add_target(
    host: str,
    ip: str,
    allowlist: list[ipaddress._BaseNetwork],
    results: list[Target],
    seen: set[str],
) -> None:
    if not _ip_in_allowlist(ip, allowlist):
        raise ConfigError(f"Target {ip} is not in allowlist")
    if ip in seen:
        return
    results.append(Target(host=host, ip=ip))
    seen.add(ip)


def _ip_in_allowlist(ip: str, allowlist: list[ipaddress._BaseNetwork]) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in allowlist)


def _resolve_hostname(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except socket.gaierror:
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
