from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .scanner import HostScan, PortScan


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    remediation: str
    match: dict[str, Any]


def load_rules(path: Path) -> list[Rule]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Rules file must contain a list of rules")
    rules: list[Rule] = []
    for entry in data:
        rules.append(
            Rule(
                rule_id=str(entry.get("id", "")),
                title=str(entry.get("title", "")),
                severity=str(entry.get("severity", "unknown")),
                confidence=str(entry.get("confidence", "unknown")),
                description=str(entry.get("description", "")),
                remediation=str(entry.get("remediation", "")),
                match=dict(entry.get("match", {})),
            )
        )
    return rules


def infer_findings(scans: Iterable[HostScan], rules: Iterable[Rule]) -> list[dict]:
    findings: list[dict] = []
    for scan in scans:
        for port in scan.open_ports:
            for rule in rules:
                if _rule_matches(rule, port):
                    findings.append(_build_finding(scan, port, rule))
    return findings


def _rule_matches(rule: Rule, port: PortScan) -> bool:
    match = rule.match
    if not match:
        return False
    if "port" in match and int(match["port"]) != port.port:
        return False
    if "service" in match and str(match["service"]).lower() != port.service.lower():
        return False
    if "banner_contains" in match:
        needles = match["banner_contains"]
        if isinstance(needles, str):
            needles = [needles]
        banner_lower = port.banner.lower()
        if not any(str(needle).lower() in banner_lower for needle in needles):
            return False
    return True


def _build_finding(scan: HostScan, port: PortScan, rule: Rule) -> dict:
    return {
        "id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "description": rule.description,
        "remediation": rule.remediation,
        "target": {
            "host": scan.target.host,
            "ip": scan.target.ip,
            "port": port.port,
            "service": port.service,
        },
        "evidence": {
            "banner": port.banner,
        },
    }
