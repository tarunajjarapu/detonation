from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class ServerTest(unittest.TestCase):
    def test_echo_mcp_call(self) -> None:
        server_path = Path(__file__).with_name("server.py")
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "test value"}},
            },
        ]
        input_text = "".join(json.dumps(message) + "\n" for message in messages)
        completed = subprocess.run(
            [sys.executable, str(server_path)],
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines()]

        self.assertEqual([response["id"] for response in responses], [1, 2, 3])
        self.assertEqual(
            responses[2]["result"]["content"][0]["text"], "test value"
        )


if __name__ == "__main__":
    unittest.main()
