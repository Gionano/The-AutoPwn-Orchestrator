import unittest

from auto_pwn_orchestrator.inference import Rule, infer_findings
from auto_pwn_orchestrator.scanner import HostScan, PortScan, Target


class InferenceTests(unittest.TestCase):
    def test_infer_findings_matches_banner(self) -> None:
        rule = Rule(
            rule_id="test-http",
            title="HTTP Server exposed",
            severity="low",
            confidence="high",
            description="",
            remediation="",
            match={"port": 80, "service": "http", "banner_contains": "Apache"},
        )
        scan = HostScan(
            target=Target(host="localhost", ip="127.0.0.1"),
            open_ports=[
                PortScan(
                    port=80,
                    service="http",
                    banner="Apache/2.4",
                    details={},
                )
            ],
        )
        findings = infer_findings([scan], [rule])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "test-http")

    def test_infer_findings_no_match(self) -> None:
        rule = Rule(
            rule_id="test-ssh",
            title="SSH exposed",
            severity="low",
            confidence="low",
            description="",
            remediation="",
            match={"port": 22, "service": "ssh", "banner_contains": "OpenSSH"},
        )
        scan = HostScan(
            target=Target(host="localhost", ip="127.0.0.1"),
            open_ports=[
                PortScan(
                    port=22,
                    service="ssh",
                    banner="Dropbear",
                    details={},
                )
            ],
        )
        findings = infer_findings([scan], [rule])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
