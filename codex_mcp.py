#!/usr/bin/env python3
"""Transparent Codex stdio MCP wrapper around the traced Docker server."""

from __future__ import annotations

import json
import os
import argparse
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=("filesystem", "adversarial", "adversarial_network"), default="filesystem")
parser.add_argument("--allow-network", action="store_true")
args = parser.parse_args()

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "trace-output" / args.mode
OUTPUT.mkdir(parents=True, exist_ok=True)
SANDBOX_DATA = OUTPUT / "sandbox-data"
if args.mode == "filesystem":
    SANDBOX_DATA.mkdir(exist_ok=True)
    fixture = SANDBOX_DATA / "hello.txt"
    if not fixture.exists():
        fixture.write_text("hello from a real MCP server\n")
transcript = (OUTPUT / "codex-transcript.jsonl").open("w", buffering=1)
stderr_log = (OUTPUT / "server.stderr.log").open("w", buffering=1)
lock = threading.Lock()
stdout_lock = threading.Lock()
scope_manifest = OUTPUT / "call-scopes.jsonl"
if args.mode in {"adversarial", "adversarial_network"}:
    scope_manifest.write_text("")


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


docker_options = [
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
]
if args.mode == "filesystem":
    docker_options.extend(
        ["--mount", f"type=bind,src={SANDBOX_DATA},dst=/sandbox-data"]
    )
command = [
    "docker",
    "run",
    *docker_options,
    "mcp-strace-filesystem",
]


def container_options() -> list[str]:
    """Containment options shared by the session and per-call containers."""
    return docker_options.copy()


def emit(raw: bytes) -> None:
    record("server_to_codex", raw)
    with stdout_lock:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()


def run_scoped_call(raw: bytes, message: dict) -> None:
    """Execute one adversarial tools/call in its own Docker cgroup."""
    request_id = message.get("id")
    scope = uuid.uuid4().hex
    trace_name = f"call-{scope}.strace"
    cgroup_name = f"call-{scope}.cgroup"
    call_command = [
        "docker",
        "run",
        "--cgroupns=host",
        *container_options(),
        "--name",
        f"detonation-call-{scope}",
        "mcp-strace-filesystem",
        "python3",
        "/app/call_runner.py",
        "--trace",
        f"/trace-output/{trace_name}",
        "--cgroup",
        f"/trace-output/{cgroup_name}",
    ]
    init = {
        "jsonrpc": "2.0",
        "id": f"scope-init-{scope}",
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    payload = b"".join(
        json.dumps(item).encode() + b"\n" for item in (init, initialized)
    ) + raw
    completed = subprocess.run(call_command, input=payload, capture_output=True)
    stderr_log.buffer.write(completed.stderr)
    stderr_log.flush()
    responses = [line + b"\n" for line in completed.stdout.splitlines()]
    response = next(
        (
            line
            for line in responses
            if json.loads(line).get("id") == request_id
        ),
        None,
    )
    scope_entry = {
        "request_id": request_id,
        "tool": message.get("params", {}).get("name"),
        "scope": scope,
        "container": f"detonation-call-{scope}",
        "trace": trace_name,
        "cgroup": cgroup_name,
        "return_code": completed.returncode,
    }
    with lock:
        with scope_manifest.open("a") as manifest:
            manifest.write(json.dumps(scope_entry) + "\n")
    if response is None:
        response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"isolated tool container exited {completed.returncode}",
                },
            }
        ).encode() + b"\n"
    emit(response)

if args.mode in {"adversarial", "adversarial_network"}:
    command.extend(
        [
            "strace",
            "-f",
            "-ttt",
            "-yy",
            "-s",
            "512",
            "-e",
            "trace=%file,%process,%network,read,write,getdents64,poll,ppoll,select,pselect6,getsockopt,mount,umount2,unshare,setns,ptrace,bpf",
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
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            message = {}
        if (
            args.mode in {"adversarial", "adversarial_network"}
            and message.get("method") == "tools/call"
        ):
            run_scoped_call(line, message)
            continue
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
    emit(line)

request_thread.join(timeout=1)
stderr_thread.join(timeout=1)
transcript.close()
stderr_log.close()
return_code = server.wait()
if return_code == 0:
    subprocess.run(
        [sys.executable, str(ROOT / "report.py"), "--mode", args.mode],
        cwd=ROOT,
        check=True,
        stdout=sys.stderr,
    )
raise SystemExit(return_code)
