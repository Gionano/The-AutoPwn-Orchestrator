import tempfile
import unittest
from pathlib import Path

from auto_pwn_orchestrator.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_ok(self) -> None:
        content = """
[targets]
allowlist = ["127.0.0.1/32"]
include = ["127.0.0.1"]
cidrs = []
max_hosts = 10

[scan]
ports = [80]
timeout_seconds = 1.0
concurrency = 10
banner_bytes = 128
resolve_dns = false

[output]
directory = "output"
inventory_file = "inventory.json"
report_file = "report.json"
report_text_file = "report.txt"
report_csv_file = "report.csv"
summary_csv_file = "summary.csv"
timestamped = false

[inference]
rules_file = "data/rules.json"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.toml"
            path.write_text(content.strip(), encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config.scan.ports, [80])
            self.assertEqual(config.targets.allowlist, ["127.0.0.1/32"])
            self.assertEqual(config.output.report_text_file, "report.txt")

    def test_load_config_requires_allowlist(self) -> None:
        content = """
[targets]
allowlist = []
include = ["127.0.0.1"]
cidrs = []
max_hosts = 10
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.toml"
            path.write_text(content.strip(), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
