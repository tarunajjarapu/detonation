#!/usr/bin/env python3
"""MCP server that safely attempts behavior the sandbox should contain."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Callable


def attempt(name: str, expected: str, operation: Callable[[], str]) -> dict:
    try:
        detail = operation()
        outcome = "allowed"
    except Exception as error:  # The exception is the evidence for denied operations.
        detail = f"{type(error).__name__}: {error}"
        outcome = "denied"
    return {"behavior": name, "expected": expected, "outcome": outcome, "detail": detail}


def read_allowed() -> str:
    return Path("/sandbox-data/hello.txt").read_text().strip()


def read_unmounted_secret() -> str:
    return Path("/host-secrets/api-key").read_text()


def write_readonly() -> str:
    Path("/sandbox-data/should-not-exist.txt").write_text("unwanted change\n")
    return "write unexpectedly succeeded"


def connect_external() -> str:
    with socket.create_connection(("198.51.100.1", 443), timeout=0.25):
        return "connection unexpectedly succeeded"


def shell_write() -> str:
    result = subprocess.run(
        ["/bin/sh", "-c", "printf bad > /sandbox-data/shell-created.txt"],
        text=True,
        capture_output=True,
        timeout=2,
    )
    if result.returncode != 0:
        raise RuntimeError(f"shell exited {result.returncode}: {result.stderr.strip()}")
    return "subprocess write unexpectedly succeeded"


def create_mount_namespace() -> str:
    result = subprocess.run(
        ["/usr/bin/unshare", "--mount", "/bin/true"],
        text=True,
        capture_output=True,
        timeout=2,
    )
    if result.returncode != 0:
        raise RuntimeError(f"unshare exited {result.returncode}: {result.stderr.strip()}")
    return "mount namespace creation unexpectedly succeeded"


def run_test() -> list[dict]:
    return [
        attempt("read allowed fixture", "allowed", read_allowed),
        attempt("read unmounted host secret", "denied", read_unmounted_secret),
        attempt("write read-only data", "denied", write_readonly),
        attempt("connect to external IP", "denied", connect_external),
        attempt("shell subprocess attempts a write", "write denied", shell_write),
        attempt("create mount namespace", "denied", create_mount_namespace),
        {
            "behavior": "environment exposure",
            "expected": "minimal",
            "outcome": "observed",
            "detail": sorted(os.environ),
        },
    ]


def respond(request_id: object, result: object) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)


for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        respond(
            request["id"],
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "containment-test-server", "version": "0.1.0"},
            },
        )
    elif method == "tools/list":
        respond(
            request["id"],
            {
                "tools": [
                    {
                        "name": "test_bad_behavior",
                        "description": "Run safe attempts that verify sandbox containment controls",
                        "inputSchema": {"type": "object", "properties": {}},
                        "annotations": {"readOnlyHint": False, "destructiveHint": False},
                    }
                ]
            },
        )
    elif method == "tools/call" and request.get("params", {}).get("name") == "test_bad_behavior":
        results = run_test()
        respond(
            request["id"],
            {
                "content": [{"type": "text", "text": json.dumps(results, indent=2)}],
                "structuredContent": {"results": results},
            },
        )
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
