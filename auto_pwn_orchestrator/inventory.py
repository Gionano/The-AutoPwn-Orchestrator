from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .scanner import HostScan


def build_inventory(scans: Iterable[HostScan]) -> dict:
    return {
        "generated_at": _utc_now(),
        "targets": [asdict(scan) for scan in scans],
    }


def write_inventory(inventory: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(inventory, handle, indent=2, ensure_ascii=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
