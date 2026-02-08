from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable


def build_report(inventory: dict, findings: list[dict]) -> dict:
    targets = inventory.get("targets", [])
    open_ports = sum(len(target.get("open_ports", [])) for target in targets)
    return {
        "generated_at": inventory.get("generated_at"),
        "summary": {
            "targets": len(targets),
            "open_ports": open_ports,
            "findings": len(findings),
        },
        "findings": findings,
    }


def write_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)


def severity_rank(value: str) -> int:
    mapping = {
        "unknown": 0,
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    if not value:
        return 0
    return mapping.get(value.lower(), 0)


def summarize_findings(findings: Iterable[dict]) -> dict:
    counts = Counter()
    for finding in findings:
        severity = str(finding.get("severity", "unknown")).lower()
        counts[severity] += 1
    summary = {}
    for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
        summary[severity] = counts.get(severity, 0)
    return summary


def write_text_report(report: dict, path: Path) -> None:
    text = build_text_report(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_text_report(report: dict) -> str:
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    severity_counts = summarize_findings(findings)

    lines: list[str] = []
    lines.append("Auto-Pwn Orchestrator Report")
    lines.append(f"Generated at: {report.get('generated_at', 'unknown')}")
    lines.append("")
    lines.append("Summary")
    lines.append(f"Targets: {summary.get('targets', 0)}")
    lines.append(f"Open ports: {summary.get('open_ports', 0)}")
    lines.append(f"Findings: {summary.get('findings', 0)}")
    lines.append("")
    lines.append("Findings by severity")
    for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
        lines.append(f"- {severity}: {severity_counts.get(severity, 0)}")

    if not findings:
        lines.append("")
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("")
    lines.append("Findings")
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            -severity_rank(str(item.get("severity", ""))),
            str(item.get("target", {}).get("ip", "")),
            int(item.get("target", {}).get("port", 0)),
        ),
    )
    for finding in sorted_findings:
        target = finding.get("target", {})
        evidence = finding.get("evidence", {})
        severity = str(finding.get("severity", "unknown")).upper()
        lines.append(f"[{severity}] {finding.get('title', '')} ({finding.get('id', '')})")
        lines.append(
            "Target: {host} ({ip}) port {port} service {service}".format(
                host=target.get("host", ""),
                ip=target.get("ip", ""),
                port=target.get("port", ""),
                service=target.get("service", ""),
            )
        )
        lines.append(f"Confidence: {finding.get('confidence', 'unknown')}")
        banner = evidence.get("banner", "")
        if banner:
            lines.append(f"Banner: {banner}")
        description = finding.get("description", "")
        if description:
            lines.append(f"Description: {description}")
        remediation = finding.get("remediation", "")
        if remediation:
            lines.append(f"Remediation: {remediation}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_findings_csv(findings: Iterable[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "id",
        "title",
        "severity",
        "confidence",
        "host",
        "ip",
        "port",
        "service",
        "description",
        "remediation",
        "banner",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            target = finding.get("target", {})
            evidence = finding.get("evidence", {})
            writer.writerow(
                {
                    "id": finding.get("id", ""),
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", ""),
                    "confidence": finding.get("confidence", ""),
                    "host": target.get("host", ""),
                    "ip": target.get("ip", ""),
                    "port": target.get("port", ""),
                    "service": target.get("service", ""),
                    "description": finding.get("description", ""),
                    "remediation": finding.get("remediation", ""),
                    "banner": evidence.get("banner", ""),
                }
            )


def write_summary_csv(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = report.get("summary", {})
    severity_counts = summarize_findings(report.get("findings", []))
    fieldnames = [
        "generated_at",
        "targets",
        "open_ports",
        "findings",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "unknown",
    ]
    row = {
        "generated_at": report.get("generated_at", ""),
        "targets": summary.get("targets", 0),
        "open_ports": summary.get("open_ports", 0),
        "findings": summary.get("findings", 0),
        **severity_counts,
    }
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)
