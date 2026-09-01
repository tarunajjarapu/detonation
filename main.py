#!/usr/bin/env python3
"""Build and run the minimal MCP strace sandbox."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
IMAGE = "mcp-strace-demo"


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    output = ROOT / "trace-output"
    output.mkdir(exist_ok=True)
    if not args.skip_build:
        run(["docker", "build", "-t", IMAGE, "."])

    run(
        [
            "docker",
            "run",
            "--rm",
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
            f"type=bind,src={output},dst=/trace-output",
            IMAGE,
        ]
    )
    print(f"\nTrace written to {output / 'mcp.strace'}")


if __name__ == "__main__":
    main()
