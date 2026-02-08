from __future__ import annotations

import logging
import subprocess
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_payload(
    payload: str,
    lhost: str,
    lport: int,
    format: str,
    output_file: Path,
    platform: str | None = None,
    arch: str | None = None,
    bad_chars: str | None = None,
    encoder: str | None = None,
    iterations: int = 0,
) -> bool:
    """
    Wraps msfvenom to generate a payload.
    """
    if not shutil.which("msfvenom"):
        logger.error("msfvenom not found in PATH. Please install Metasploit Framework.")
        return False

    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", format,
        "-o", str(output_file),
    ]

    if platform:
        cmd.extend(["--platform", platform])
    if arch:
        cmd.extend(["-a", arch])
    if bad_chars:
        cmd.extend(["-b", bad_chars])
    if encoder:
        cmd.extend(["-e", encoder])
    if iterations > 0:
        cmd.extend(["-i", str(iterations)])

    logger.info(f"Running command: {' '.join(cmd)}")
    
    try:
        # Run msfvenom
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logger.info(f"Payload generated successfully: {output_file}")
        if result.stderr:
            logger.debug(f"msfvenom stderr: {result.stderr}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate payload. Exit code: {e.returncode}")
        logger.error(f"Error output: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return False
