#!/usr/bin/env python3
"""A deliberately tiny MCP server using JSON-RPC over stdio."""

from __future__ import annotations

import json
import sys


def reply(request_id: object, result: object) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)


for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")

    # Notifications have no id and receive no JSON-RPC response.
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        reply(
            request["id"],
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "strace-demo", "version": "0.1.0"},
            },
        )
    elif method == "tools/list":
        reply(
            request["id"],
            {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo text back to the caller",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                        },
                    }
                ]
            },
        )
    elif method == "tools/call" and request.get("params", {}).get("name") == "echo":
        text = request["params"]["arguments"]["text"]
        reply(request["id"], {"content": [{"type": "text", "text": text}]})
    elif "id" in request:
        print(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32601, "message": "Method not found"},
                }
            ),
            flush=True,
        )
