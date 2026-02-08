from __future__ import annotations

import logging
import shutil
from typing import Any

try:
    import nmap
except ImportError:
    nmap = None

logger = logging.getLogger(__name__)


class NmapScanner:
    def __init__(self, arguments: str = "-sV -O", sudo: bool = False):
        self.arguments = arguments
        self.sudo = sudo
        self.nm = nmap.PortScanner() if nmap else None

    def is_available(self) -> bool:
        return self.nm is not None and shutil.which("nmap") is not None

    def scan(self, hosts: list[str], ports: list[int]) -> dict[str, Any]:
        if not self.is_available():
            logger.warning("Nmap not available or not installed.")
            return {}

        hosts_str = " ".join(hosts)
        ports_str = ",".join(map(str, ports))
        
        logger.info(f"Starting Nmap scan on {len(hosts)} hosts...")
        try:
            self.nm.scan(hosts=hosts_str, ports=ports_str, arguments=self.arguments, sudo=self.sudo)
            return self.nm.scaninfo()
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {}

    def get_results(self) -> dict[str, Any]:
        if not self.nm:
            return {}
        return {host: self.nm[host] for host in self.nm.all_hosts()}
