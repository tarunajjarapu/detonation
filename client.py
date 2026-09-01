#!/usr/bin/env python3
"""Drive a real filesystem MCP server while recording its syscalls."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


OUTPUT = Path("/trace-output")
events: list[dict] = []
stderr_log = (OUTPUT / "server.stderr.log").open("w")


server = subprocess.Popen(
    [
        "strace",
        "-f",
        "-ttt",
        "-s",
        "512",
        "-e",
        "trace=%file,%process,%network,read,write",
        "-o",
        "/trace-output/mcp.strace",
        "mcp-server-filesystem",
        "/sandbox-data",
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=stderr_log,
    text=True,
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def send(phase: str, message: dict, expect_response: bool = True) -> dict | None:
    assert server.stdin is not None and server.stdout is not None
    event = {"phase": phase, "request_started": now(), "request": message}
    server.stdin.write(json.dumps(message) + "\n")
    server.stdin.flush()
    if not expect_response:
        event["request_finished"] = now()
        events.append(event)
        return None
    response = json.loads(server.stdout.readline())
    event["request_finished"] = now()
    event["response"] = response
    events.append(event)
    print(json.dumps(response, indent=2))
    return response


send(
    "initialize",
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
send(
    "initialized_notification",
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    False,
)
tools = send(
    "tools_list", {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
)
assert tools is not None
assert "read_text_file" in {tool["name"] for tool in tools["result"]["tools"]}
result = send(
    "tool_read_text_file",
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "read_text_file",
            "arguments": {"path": "/sandbox-data/hello.txt"},
        },
    }
)
assert result is not None
assert "real MCP server" in result["result"]["content"][0]["text"]

assert server.stdin is not None
server.stdin.close()
if server.wait(timeout=5) != 0:
    raise SystemExit("traced MCP server failed")
stderr_log.close()
(OUTPUT / "events.json").write_text(json.dumps(events, indent=2) + "\n")
