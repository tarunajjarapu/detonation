#!/usr/bin/env python3
"""Record this container's cgroup membership, then exec the traced MCP server."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--trace", required=True)
parser.add_argument("--cgroup", required=True)
args = parser.parse_args()

Path(args.cgroup).write_text(Path("/proc/self/cgroup").read_text())
os.execvp(
    "strace",
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
        args.trace,
        "python3",
        "/app/adversarial_server.py",
    ],
)
