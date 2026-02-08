from __future__ import annotations

from typing import Optional


SERVICE_BY_PORT = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    27017: "mongodb",
}

HTTP_PORTS = {80, 8080, 8000, 8888, 5000, 8008}


def guess_service(port: int) -> str:
    return SERVICE_BY_PORT.get(port, "unknown")


def sanitize_banner(data: bytes) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    return "".join(ch if 32 <= ord(ch) <= 126 else " " for ch in text).strip()


def extract_http_server(banner: str) -> Optional[str]:
    for line in banner.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


def fingerprint(port: int, banner_bytes: bytes) -> dict:
    banner = sanitize_banner(banner_bytes)
    service = guess_service(port)
    details: dict[str, str] = {}
    if service == "http":
        server = extract_http_server(banner)
        if server:
            details["server"] = server
    return {
        "service": service,
        "banner": banner,
        "details": details,
    }
