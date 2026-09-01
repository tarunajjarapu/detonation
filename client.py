#!/usr/bin/env python3
"""Run one MCP handshake and echo tool call against the traced server."""

from __future__ import annotations

import json
import subprocess


server = subprocess.Popen(
    [
        "strace",
        "-f",
        "-tt",
        "-s",
        "512",
        "-e",
        "trace=%file,%process,%network,read,write",
        "-o",
        "/trace-output/mcp.strace",
        "python3",
        "/app/server.py",
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True,
)


def send(message: dict, expect_response: bool = True) -> dict | None:
    assert server.stdin is not None and server.stdout is not None
    server.stdin.write(json.dumps(message) + "\n")
    server.stdin.flush()
    if not expect_response:
        return None
    response = json.loads(server.stdout.readline())
    print(json.dumps(response, indent=2))
    return response


send(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "strace-client", "version": "0.1.0"},
        },
    }
)
send({"jsonrpc": "2.0", "method": "notifications/initialized"}, False)
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
result = send(
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "hello from the sandbox"}},
    }
)
assert result is not None
assert result["result"]["content"][0]["text"] == "hello from the sandbox"

assert server.stdin is not None
server.stdin.close()
if server.wait(timeout=5) != 0:
    raise SystemExit("traced MCP server failed")
