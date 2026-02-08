import asyncio
import unittest

from auto_pwn_orchestrator.config import ConfigError, TargetConfig
from auto_pwn_orchestrator.scanner import Target, expand_targets, scan_port


class ScannerTests(unittest.TestCase):
    def test_expand_targets_allowlist(self) -> None:
        targets = TargetConfig(
            allowlist=["127.0.0.1/32"],
            include=["127.0.0.1"],
            cidrs=[],
            max_hosts=10,
        )
        results = expand_targets(targets, resolve_dns=False)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ip, "127.0.0.1")

    def test_expand_targets_rejects_outside_allowlist(self) -> None:
        targets = TargetConfig(
            allowlist=["192.168.1.0/24"],
            include=["127.0.0.1"],
            cidrs=[],
            max_hosts=10,
        )
        with self.assertRaises(ConfigError):
            expand_targets(targets, resolve_dns=False)

    def test_scan_port_finds_open_port(self) -> None:
        async def run_scan() -> bool:
            async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                writer.write(b"HELLO")
                await writer.drain()
                writer.close()

            server = await asyncio.start_server(handle_client, host="127.0.0.1", port=0)
            sock = server.sockets[0]
            port = sock.getsockname()[1]
            try:
                target = Target(host="127.0.0.1", ip="127.0.0.1")
                result = await scan_port(
                    target=target,
                    port=port,
                    timeout_seconds=1.0,
                    banner_bytes=64,
                    semaphore=asyncio.Semaphore(1),
                )
                return result is not None and result.port == port
            finally:
                server.close()
                await server.wait_closed()

        found = asyncio.run(run_scan())
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
