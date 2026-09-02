from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from report import make_report, parse_scoped_trace


class ScopedReportTest(unittest.TestCase):
    def test_filesystem_report_embeds_each_call_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "trace-output" / "filesystem"
            output.mkdir(parents=True)
            transcript = [
                {
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "direction": "codex_to_server",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {"name": "write_file", "arguments": {"path": "/sandbox-data/a.txt", "content": "a"}},
                    },
                },
                {
                    "timestamp": "2026-01-01T00:00:01+00:00",
                    "direction": "server_to_codex",
                    "message": {"jsonrpc": "2.0", "id": 4, "result": {"content": [{"type": "text", "text": "ok"}]}},
                },
            ]
            (output / "codex-transcript.jsonl").write_text(
                "".join(json.dumps(entry) + "\n" for entry in transcript)
            )
            (output / "mcp.strace").write_text(
                '10 1767225600.500 openat(AT_FDCWD, "/sandbox-data/a.txt", O_WRONLY) = 3\n'
            )

            call = make_report("filesystem", root)["tool_calls"][0]

            self.assertEqual(call["transcript"]["request"], transcript[0])
            self.assertEqual(call["transcript"]["response"], transcript[1])
            self.assertEqual(call["files_touched"], ["/sandbox-data/a.txt"])

    def test_stdio_boundaries_support_older_scoped_traces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "call.strace"
            trace.write_text(
                '10 1.000 openat(AT_FDCWD, "/usr/lib/startup", O_RDONLY) = 3\n'
                '10 2.000 read(0<pipe:[1]>, "{\\"method\\":\\"tools/call\\"}\\n", 64) = 33\n'
                '10 3.000 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
                '10 4.000 write(1<pipe:[2]>, "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":2,\\"result\\":{}}\\n", 48) = 48\n'
                '10 5.000 openat(AT_FDCWD, "/tmp/teardown", O_RDONLY) = 3\n'
            )

            events, markers, method = parse_scoped_trace(trace)

            self.assertEqual(method, "mcp_stdio_fallback")
            self.assertEqual(markers, {"start": 2.0, "end": 4.0})
            self.assertEqual(len(events), 3)

    def test_scoped_call_uses_its_trace_instead_of_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "trace-output" / "adversarial"
            output.mkdir(parents=True)
            transcript = [
                {
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "direction": "codex_to_server",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {"name": "test_bad_behavior", "arguments": {}},
                    },
                },
                {
                    "timestamp": "2026-01-01T00:00:01+00:00",
                    "direction": "server_to_codex",
                    "message": {"jsonrpc": "2.0", "id": 7, "result": {}},
                },
            ]
            (output / "codex-transcript.jsonl").write_text(
                "".join(json.dumps(entry) + "\n" for entry in transcript)
            )
            (output / "mcp.strace").write_text(
                '10 1767225600.500 openat(AT_FDCWD, "/tmp/session-noise", O_RDONLY) = 3\n'
            )
            (output / "call-scope.strace").write_text(
                '20 1.000 openat(AT_FDCWD, "/usr/lib/python3.11/os.py", O_RDONLY) = 3\n'
                '20 2.000 write(2, "DETONATION_TOOL_START request_id=7\\n", 43) = 43\n'
                '20 3.000 openat(AT_FDCWD, "/host-secrets/api-key", O_RDONLY) = 3\n'
                '20 4.000 write(2, "DETONATION_TOOL_END request_id=7\\n", 41) = 41\n'
                '20 5.000 openat(AT_FDCWD, "/tmp/teardown", O_RDONLY) = 3\n'
            )
            (output / "call-scope.cgroup").write_text("0::/docker/example\n")
            (output / "call-scopes.jsonl").write_text(
                json.dumps(
                    {
                        "request_id": 7,
                        "tool": "test_bad_behavior",
                        "scope": "scope",
                        "container": "detonation-call-scope",
                        "trace": "call-scope.strace",
                        "cgroup": "call-scope.cgroup",
                        "return_code": 0,
                    }
                )
                + "\n"
            )

            report = make_report("adversarial", root)
            call = report["tool_calls"][0]

            self.assertEqual(call["attribution"]["method"], "dedicated_container_cgroup")
            self.assertEqual(call["attribution"]["cgroup_membership"], ["0::/docker/example"])
            self.assertEqual(call["files_touched"], ["/host-secrets/api-key"])
            self.assertNotIn("/tmp/session-noise", call["files_touched"])
            self.assertEqual(call["attribution"]["phase_method"], "server_markers")
            self.assertEqual(call["setup_observed"][0]["paths"], ["/usr/lib/python3.11/os.py"])
            self.assertEqual(call["teardown_observed"][0]["paths"], ["/tmp/teardown"])
            self.assertEqual(report["runtime"]["setup_events_extracted"], 1)
            self.assertEqual(report["runtime"]["tool_execution_events_extracted"], 1)
            self.assertEqual(report["runtime"]["teardown_events_extracted"], 1)

    def test_adversarial_call_never_falls_back_to_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "trace-output" / "adversarial"
            output.mkdir(parents=True)
            (output / "codex-transcript.jsonl").write_text(
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "direction": "codex_to_server",
                        "message": {
                            "id": 9,
                            "method": "tools/call",
                            "params": {"name": "test_bad_behavior", "arguments": {}},
                        },
                    }
                )
                + "\n"
            )
            (output / "mcp.strace").write_text(
                '10 1767225600.500 openat(AT_FDCWD, "/host-secrets/api-key", O_RDONLY) = 3\n'
            )

            call = make_report("adversarial", root)["tool_calls"][0]

            self.assertEqual(call["attribution"]["method"], "missing_cgroup_scope")
            self.assertEqual(call["observed"], [])


if __name__ == "__main__":
    unittest.main()
