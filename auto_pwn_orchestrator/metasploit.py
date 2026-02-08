from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    MsfRpcClient = None

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MetasploitConfig:
    host: str
    port: int
    username: str
    password: str
    ssl: bool
    enabled: bool
    allowlist_modules: list[str]
    dry_run: bool


class MetasploitIntegration:
    def __init__(self, config: MetasploitConfig):
        self.config = config
        self.client: Optional[MsfRpcClient] = None

    def connect(self) -> bool:
        if not self.config.enabled:
            logger.info("Metasploit integration is disabled.")
            return False

        if MsfRpcClient is None:
            logger.error("pymetasploit3 is not installed. Cannot connect to Metasploit.")
            return False

        try:
            logger.info(f"Connecting to Metasploit RPC at {self.config.host}:{self.config.port}...")
            self.client = MsfRpcClient(
                self.config.password,
                username=self.config.username,
                server=self.config.host,
                port=self.config.port,
                ssl=self.config.ssl
            )
            logger.info("Successfully connected to Metasploit RPC.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Metasploit RPC: {e}")
            return False

    def list_modules(self, module_type: str = "exploit") -> list[str]:
        if not self.client:
            logger.warning("Not connected to Metasploit. Cannot list modules.")
            return []
        
        try:
            return self.client.modules.modules(module_type)
        except Exception as e:
            logger.error(f"Failed to list modules: {e}")
            return []

    def execute_module(self, module_type: str, module_name: str, options: dict[str, Any]) -> dict[str, Any]:
        if not self.client:
            return {"status": "error", "message": "Not connected"}

        if module_name not in self.config.allowlist_modules:
            logger.warning(f"Module {module_name} is not in the allowlist. Skipping execution.")
            return {"status": "skipped", "message": "Module not allowed"}

        if self.config.dry_run:
            logger.info(f"[DRY-RUN] Would execute {module_type}/{module_name} with options: {options}")
            return {"status": "dry-run", "options": options}

        try:
            logger.info(f"Executing {module_type}/{module_name} with options: {options}")
            module = self.client.modules.use(module_type, module_name)
            result = module.execute(payload=options.get("payload"), **options)
            return {"status": "executed", "result": result}
        except Exception as e:
            logger.error(f"Failed to execute module {module_name}: {e}")
            return {"status": "error", "message": str(e)}

    def list_sessions(self) -> dict[str, Any]:
        if not self.client:
            return {}
        return self.client.sessions.list

    def run_on_session(self, session_id: str, command: str) -> str:
        if not self.client:
            return "Not connected"
        
        try:
            shell = self.client.sessions.session(session_id)
            shell.write(command)
            return shell.read()
        except Exception as e:
            logger.error(f"Failed to run command on session {session_id}: {e}")
            return str(e)

    def run_bruteforce(self, service: str, rhosts: str, user_file: str, pass_file: str) -> dict[str, Any]:
        module_map = {
            "ssh": "scanner/ssh/ssh_login",
            "ftp": "scanner/ftp/ftp_login",
            "smb": "scanner/smb/smb_login",
            "http": "scanner/http/http_login",
        }
        
        module_name = module_map.get(service)
        if not module_name:
            return {"status": "error", "message": f"No brute force module for {service}"}

        options = {
            "RHOSTS": rhosts,
            "USER_FILE": user_file,
            "PASS_FILE": pass_file,
            "STOP_ON_SUCCESS": True,
        }
        
        return self.execute_module("auxiliary", module_name, options)
