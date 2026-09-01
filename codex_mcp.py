#!/usr/bin/env python3
"""Transparent Codex stdio MCP wrapper around the traced Docker server."""

from __future__ import annotations

import json
import os
import argparse
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=("filesystem", "adversarial"), default="filesystem")
parser.add_argument("--allow-network", action="store_true")
args = parser.parse_args()

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "trace-output" / args.mode
OUTPUT.mkdir(parents=True, exist_ok=True)
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
    "--network=bridge" if args.allow_network else "--network=none",
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

if args.mode == "adversarial":
    command.extend(
        [
            "strace",
            "-f",
            "-ttt",
            "-yy",
            "-s",
            "512",
            "-e",
            "trace=%file,%process,%network,read,write,poll,ppoll,select,pselect6,getsockopt,mount,umount2,unshare,setns,ptrace,bpf",
            "-o",
            "/trace-output/mcp.strace",
            "python3",
            "/app/adversarial_server.py",
        ]
    )

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
