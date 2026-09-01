#!/usr/bin/env python3
"""Transparent Codex stdio MCP wrapper around the traced Docker server."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "trace-output"
OUTPUT.mkdir(exist_ok=True)
transcript = (OUTPUT / "codex-transcript.jsonl").open("w", buffering=1)
stderr_log = (OUTPUT / "server.stderr.log").open("w", buffering=1)
lock = threading.Lock()


def record(direction: str, raw: bytes) -> None:
    try:
        message: object = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        message = raw.decode(errors="replace").rstrip("\n")
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "direction": direction,
        "message": message,
    }
    with lock:
        transcript.write(json.dumps(entry) + "\n")


command = [
    "docker",
    "run",
    "--rm",
    "-i",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user",
    f"{os.getuid()}:{os.getgid()}",
    "--pids-limit=64",
    "--memory=128m",
    "--cpus=0.5",
    "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
    "--mount",
    f"type=bind,src={OUTPUT},dst=/trace-output",
    "mcp-strace-filesystem",
]

server = subprocess.Popen(
    command,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)


def forward_requests() -> None:
    assert server.stdin is not None
    for line in sys.stdin.buffer:
        record("codex_to_server", line)
        server.stdin.write(line)
        server.stdin.flush()
    server.stdin.close()


def forward_stderr() -> None:
    assert server.stderr is not None
    for chunk in iter(lambda: server.stderr.read(4096), b""):
        stderr_log.buffer.write(chunk)
        stderr_log.flush()


request_thread = threading.Thread(target=forward_requests, daemon=True)
stderr_thread = threading.Thread(target=forward_stderr, daemon=True)
request_thread.start()
stderr_thread.start()

assert server.stdout is not None
for line in server.stdout:
    record("server_to_codex", line)
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()

request_thread.join(timeout=1)
stderr_thread.join(timeout=1)
transcript.close()
stderr_log.close()
raise SystemExit(server.wait())
