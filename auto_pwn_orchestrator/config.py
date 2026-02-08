from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for Python < 3.11
    import tomli as tomllib

from .metasploit import MetasploitConfig


DEFAULT_PORTS = [
    22,
    23,
    80,
    443,
    445,
    3389,
    3306,
    5432,
    6379,
    27017,
]


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class TargetConfig:
    allowlist: list[str]
    include: list[str]
    cidrs: list[str]
    max_hosts: int


@dataclass(frozen=True)
class ScanConfig:
    ports: list[int]
    timeout_seconds: float
    concurrency: int
    banner_bytes: int
    resolve_dns: bool


@dataclass(frozen=True)
class OutputConfig:
    directory: Path
    inventory_file: str
    report_file: str
    report_text_file: str
    report_csv_file: str
    summary_csv_file: str
    timestamped: bool


@dataclass(frozen=True)
class InferenceConfig:
    rules_file: Path


@dataclass(frozen=True)
class NmapConfig:
    enabled: bool
    arguments: str
    sudo: bool


@dataclass(frozen=True)
class WebConfig:
    host: str
    port: int
    enabled: bool


@dataclass(frozen=True)
class Config:
    targets: TargetConfig
    scan: ScanConfig
    output: OutputConfig
    inference: InferenceConfig
    metasploit: MetasploitConfig
    nmap: NmapConfig
    web: WebConfig


def load_config(path: Path) -> Config:
    data = _load_toml(path)
    targets_data = data.get("targets", {})
    scan_data = data.get("scan", {})
    output_data = data.get("output", {})
    inference_data = data.get("inference", {})
    metasploit_data = data.get("metasploit", {})
    nmap_data = data.get("nmap", {})
    web_data = data.get("web", {})

    targets = TargetConfig(
        allowlist=_coerce_list(targets_data.get("allowlist", [])),
        include=_coerce_list(targets_data.get("include", [])),
        cidrs=_coerce_list(targets_data.get("cidrs", [])),
        max_hosts=_coerce_int(targets_data.get("max_hosts", 1024), "targets.max_hosts"),
    )
    scan = ScanConfig(
        ports=_coerce_ports(scan_data.get("ports", DEFAULT_PORTS)),
        timeout_seconds=_coerce_float(scan_data.get("timeout_seconds", 1.0), "scan.timeout_seconds"),
        concurrency=_coerce_int(scan_data.get("concurrency", 200), "scan.concurrency"),
        banner_bytes=_coerce_nonnegative_int(scan_data.get("banner_bytes", 256), "scan.banner_bytes"),
        resolve_dns=bool(scan_data.get("resolve_dns", True)),
    )
    output = OutputConfig(
        directory=_resolve_output_dir(path.parent, output_data.get("directory", "output")),
        inventory_file=str(output_data.get("inventory_file", "inventory.json")),
        report_file=str(output_data.get("report_file", "report.json")),
        report_text_file=str(output_data.get("report_text_file", "report.txt")),
        report_csv_file=str(output_data.get("report_csv_file", "report.csv")),
        summary_csv_file=str(output_data.get("summary_csv_file", "summary.csv")),
        timestamped=bool(output_data.get("timestamped", True)),
    )
    inference = InferenceConfig(
        rules_file=_resolve_output_dir(path.parent, inference_data.get("rules_file", "data/rules.json")),
    )
    metasploit = MetasploitConfig(
        host=str(metasploit_data.get("host", "127.0.0.1")),
        port=_coerce_int(metasploit_data.get("port", 55553), "metasploit.port"),
        username=str(metasploit_data.get("username", "msf")),
        password=str(metasploit_data.get("password", "msf")),
        ssl=bool(metasploit_data.get("ssl", True)),
        enabled=bool(metasploit_data.get("enabled", False)),
        allowlist_modules=_coerce_list(metasploit_data.get("allowlist_modules", [])),
        dry_run=bool(metasploit_data.get("dry_run", True)),
    )
    nmap = NmapConfig(
        enabled=bool(nmap_data.get("enabled", False)),
        arguments=str(nmap_data.get("arguments", "-sV -O")),
        sudo=bool(nmap_data.get("sudo", False)),
    )
    web = WebConfig(
        host=str(web_data.get("host", "127.0.0.1")),
        port=_coerce_int(web_data.get("port", 8000), "web.port"),
        enabled=bool(web_data.get("enabled", False)),
    )

    _validate_config(targets, scan, output, inference)
    return Config(
        targets=targets,
        scan=scan,
        output=output,
        inference=inference,
        metasploit=metasploit,
        nmap=nmap,
        web=web,
    )


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc


def _coerce_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ConfigError(f"Expected list or string, got {type(value).__name__}")


def _coerce_ports(value: Any) -> list[int]:
    ports = _coerce_list(value)
    if not ports:
        raise ConfigError("scan.ports must contain at least one port")
    parsed: list[int] = []
    for port in ports:
        parsed.append(_coerce_port(port))
    return parsed


def _coerce_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid port value: {value}") from exc
    if port < 1 or port > 65535:
        raise ConfigError(f"Port out of range: {port}")
    return port


def _coerce_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid integer for {name}: {value}") from exc
    if parsed < 1:
        raise ConfigError(f"{name} must be >= 1")
    return parsed


def _coerce_nonnegative_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid integer for {name}: {value}") from exc
    if parsed < 0:
        raise ConfigError(f"{name} must be >= 0")
    return parsed


def _coerce_float(value: Any, name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid float for {name}: {value}") from exc
    if parsed <= 0:
        raise ConfigError(f"{name} must be > 0")
    return parsed


def _resolve_output_dir(base_dir: Path, value: Any) -> Path:
    if isinstance(value, Path):
        directory = value
    else:
        directory = Path(str(value))
    if not directory.is_absolute():
        return base_dir / directory
    return directory


def _validate_config(
    targets: TargetConfig,
    scan: ScanConfig,
    output: OutputConfig,
    inference: InferenceConfig,
) -> None:
    if not targets.allowlist:
        raise ConfigError("targets.allowlist is required to prevent accidental scanning")
    if not targets.include and not targets.cidrs:
        raise ConfigError("targets.include or targets.cidrs must be set")
    if scan.concurrency < 1:
        raise ConfigError("scan.concurrency must be >= 1")
    if scan.banner_bytes < 0:
        raise ConfigError("scan.banner_bytes must be >= 0")
    if not output.inventory_file:
        raise ConfigError("output.inventory_file is required")
    if not output.report_file:
        raise ConfigError("output.report_file is required")
    if not output.report_text_file:
        raise ConfigError("output.report_text_file is required")
    if not output.report_csv_file:
        raise ConfigError("output.report_csv_file is required")
    if not output.summary_csv_file:
        raise ConfigError("output.summary_csv_file is required")
    if not inference.rules_file:
        raise ConfigError("inference.rules_file is required")
