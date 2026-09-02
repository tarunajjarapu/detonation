from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("analyze_report", HERE / "analyze_report.py")
ANALYZER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(ANALYZER)
class AnalyzerTest(unittest.TestCase):
    def audit(self, description: str, arguments: dict, observed: list[dict], network=None) -> dict:
        report = {
            "static": {"tool_definitions": [{"name": "example", "description": description}]},
            "tool_calls": [{"id": 1, "tool": "example", "arguments": arguments, "observed": observed, "network": network or [], "syscall_counts": {}}],
        }
        return ANALYZER.audit(report, Path("report.json"))["results"][0]

    def test_expected_file_read_is_aligned(self) -> None:
        event = {"syscall": "openat", "paths": ["/sandbox-data/hello.txt"], "return_value": "3"}
        result = self.audit("Read a file", {"path": "/sandbox-data/hello.txt"}, [event])
        self.assertEqual(result["verdict"], "aligned")
        self.assertEqual(result["unexpected"], {})

    def test_undeclared_network_is_a_mismatch(self) -> None:
        event = {"syscall": "connect", "destination_ip": "127.0.0.1", "destination_port": 443, "return_value": "0"}
        result = self.audit("Normalize supplied text", {"text": "hello"}, [event], [event])
        self.assertEqual(result["verdict"], "mismatch")
        self.assertIn("network", result["unexpected"])

    def test_adversarial_report_finds_secret_read_and_denied_write(self) -> None:
        events = [
            {"syscall": "openat", "paths": ["/host-secrets/api-key"], "return_value": "5", "credential_candidate_paths": ["/host-secrets/api-key"]},
            {"syscall": "openat", "paths": ["/sandbox-data/should-not-exist.txt"], "return_value": "-1 EROFS", "error": "EROFS"},
            {"syscall": "openat", "paths": ["/etc/ld.so.cache"], "return_value": "3"},
        ]
        result = self.audit("Run a containment check", {}, events)
        read_paths = {path for event in result["unexpected"]["file_read"] for path in event.get("paths", [])}
        write_paths = {path for event in result["unexpected"]["file_write"] for path in event.get("paths", [])}
        self.assertIn("/host-secrets/api-key", read_paths)
        self.assertIn("/sandbox-data/should-not-exist.txt", write_paths)
        self.assertNotIn("/etc/ld.so.cache", read_paths)


if __name__ == "__main__":
    unittest.main()
