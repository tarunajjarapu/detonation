#!/usr/bin/env python3
"""Turn a captured MCP transcript and strace into a small evidence report."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path


LINE = re.compile(r"^\s*(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)$")
PATH = re.compile(r'"([^"\n]+)"')
ERROR = re.compile(r"= -1 ([A-Z]+)")
IP = re.compile(r'inet_addr\("([0-9.]+)"\)')
PORT = re.compile(r"sin_port=htons\((\d+)\)")
COUNT = re.compile(r"\) = (\d+)$")
CREDENTIAL_PATH = re.compile(r"(?i)(?:secret|token|api[-_]?key|credential|password|auth)")
AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token)\b")


def epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def parse_trace(path: Path) -> list[dict]:
    events = []
    for raw in path.read_text(errors="replace").splitlines():
        match = LINE.match(raw)
        if not match:
            continue
        pid, timestamp, syscall, body = match.groups()
        event = {"pid": int(pid), "timestamp": float(timestamp), "syscall": syscall}
        paths = PATH.findall(body)
        if paths:
            event["paths"] = paths
        ip = IP.search(body)
        port = PORT.search(body)
        count = COUNT.search(raw)
        if ip:
            event["destination_ip"] = ip.group(1)
        if port:
            event["destination_port"] = int(port.group(1))
        if count and syscall in {"read", "pread64", "recv", "recvfrom", "recvmsg", "write", "pwrite64", "send", "sendto", "sendmsg"}:
            event["bytes"] = int(count.group(1))
        auth_headers = sorted(set(AUTH_HEADER.findall(raw))) if syscall in {"send", "sendto", "sendmsg", "write"} else []
        if auth_headers:
            event["authorization_indicators"] = auth_headers
        credential_paths = [path for path in paths if CREDENTIAL_PATH.search(path)]
        if credential_paths:
            event["credential_candidate_paths"] = credential_paths
        error = ERROR.search(raw)
        if error:
            event["error"] = error.group(1)
        if syscall in {"open", "openat", "openat2", "readlink", "readlinkat", "stat", "statx", "unlink", "rename", "mkdir"}:
            events.append(event)
        elif syscall in {"execve", "clone", "clone3", "fork", "vfork", "socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "unshare", "setns", "mount", "ptrace", "bpf"}:
            events.append(event)
    return events


def load_transcript(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def make_report(mode: str, root: Path) -> dict:
    directory = root / "trace-output" / mode
    transcript = load_transcript(directory / "codex-transcript.jsonl")
    trace = parse_trace(directory / "mcp.strace")
    calls = []
    tools = []
    for entry in transcript:
        message = entry.get("message", {})
        if entry.get("direction") == "server_to_codex" and message.get("id") is not None:
            result = message.get("result", {})
            tools.extend(tool.get("name") for tool in result.get("tools", []))
        if entry.get("direction") == "codex_to_server" and message.get("method") == "tools/call":
            calls.append({
                "id": message.get("id"),
                "tool": message.get("params", {}).get("name"),
                "arguments": message.get("params", {}).get("arguments", {}),
                "timestamp": epoch(entry["timestamp"]),
            })
    for call in calls:
        window = [event for event in trace if event["timestamp"] >= call["timestamp"]]
        # A call's response is the next matching server response timestamp.
        response_times = [epoch(e["timestamp"]) for e in transcript if e.get("direction") == "server_to_codex" and e.get("message", {}).get("id") == call["id"]]
        if response_times:
            window = [event for event in window if event["timestamp"] <= response_times[0] + 1.0]
        call["observed"] = window
        call["network"] = [
            event for event in window
            if event["syscall"] in {"socket", "connect", "bind", "listen", "accept", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg"}
        ]
        credential_reads = [
            event for event in window
            if event.get("credential_candidate_paths")
        ]
        call["credential_network_correlations"] = []
        for network in call["network"]:
            if network["syscall"] not in {"connect", "send", "sendto", "sendmsg"}:
                continue
            prior = [event for event in credential_reads if event["timestamp"] <= network["timestamp"]]
            if prior:
                credential = prior[-1]
                call["credential_network_correlations"].append({
                    "credential_paths": credential.get("credential_candidate_paths", []),
                    "network_syscall": network["syscall"],
                    "destination_ip": network.get("destination_ip"),
                    "destination_port": network.get("destination_port"),
                    "process_match": credential["pid"] == network["pid"],
                    "relationship": "prior_read_same_process" if credential["pid"] == network["pid"] else "prior_read_different_process",
                    "confidence": "medium" if credential["pid"] == network["pid"] else "low",
                    "payload_contains_canary": False,
                })
    return {
        "mode": mode,
        "static": {
            "server": "@modelcontextprotocol/server-filesystem@2026.7.10" if mode == "filesystem" else "detonation containment-test-server",
            "tools_advertised": sorted(set(filter(None, tools))),
        },
        "tool_calls": calls,
        "runtime": {
            "trace_events_extracted": len(trace),
            "pids": sorted({event["pid"] for event in trace}),
            "errors": sorted({event["error"] for event in trace if "error" in event}),
            "network_attempts": sum(event["syscall"] in {"connect", "send", "sendto", "sendmsg"} for event in trace),
            "honeytoken_accesses": [event for event in trace if any("/host-secrets/api-key" in path for path in event.get("paths", []))],
            "credential_candidate_reads": [event for event in trace if event.get("credential_candidate_paths")],
        },
        "findings": [{
            "severity": "high",
            "type": "honeytoken_access",
            "message": "MCP accessed synthetic credential canary /host-secrets/api-key",
        }] if any("/host-secrets/api-key" in path for event in trace for path in event.get("paths", [])) else [],
    }


def write_markdown(report: dict, destination: Path) -> None:
    lines = [f"# MCP detonation report ({report['mode']})", "", f"Server: `{report['static']['server']}`", "", "## Advertised tools", ""]
    if report["static"]["tools_advertised"]:
        lines.extend(f"- `{tool}`" for tool in report["static"]["tools_advertised"])
    else:
        lines.append("- none captured")
    lines += ["", "## Tool-call observations", ""]
    for call in report["tool_calls"]:
        lines += [f"### `{call['tool']}` (request id `{call['id']}`)", "", f"Arguments: `{json.dumps(call['arguments'], separators=(',', ':'))}`", "", "Observed syscalls:"]
        for event in call["observed"]:
            suffix = f" [{event['error']}]" if "error" in event else ""
            paths = " " + " ".join(event.get("paths", [])) if event.get("paths") else ""
            lines.append(f"- `{event['syscall']}`{paths}{suffix}")
        if call["network"]:
            lines += ["", "Network activity:"]
            for event in call["network"]:
                target = ""
                if event.get("destination_ip"):
                    target = f" → {event['destination_ip']}:{event.get('destination_port', '?')}"
                count = f", {event['bytes']} bytes" if "bytes" in event else ""
                suffix = f" [{event['error']}]" if "error" in event else ""
                lines.append(f"- `{event['syscall']}`{target}{count}{suffix}")
                if event.get("authorization_indicators"):
                    lines.append(f"  - authorization indicators: `{', '.join(event['authorization_indicators'])}`")
        if call["credential_network_correlations"]:
            lines += ["", "Credential-to-network correlations (reverse attribution):"]
            for relation in call["credential_network_correlations"]:
                target = f"{relation.get('destination_ip')}:{relation.get('destination_port', '?')}"
                lines.append(
                    f"- `{', '.join(relation['credential_paths'])}` → `{target}` "
                    f"({relation['relationship']}, confidence `{relation['confidence']}`)"
                )
        lines.append("")
    lines += ["## Runtime summary", "", f"Extracted events: `{report['runtime']['trace_events_extracted']}`", f"PIDs: `{report['runtime']['pids']}`", f"Observed error codes: `{report['runtime']['errors']}`", ""]
    if report["findings"]:
        lines += ["## Findings", ""]
        lines.extend(f"- **{finding['severity']}**: {finding['message']}" for finding in report["findings"])
        lines.append("")
    destination.write_text("\n".join(lines))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("filesystem", "adversarial"), default="filesystem")
    args = parser.parse_args()
    project = Path(__file__).resolve().parent
    report = make_report(args.mode, project)
    directory = project / "trace-output" / args.mode
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    write_markdown(report, directory / "report.md")
    print(f"Wrote {directory / 'report.json'}")
    print(f"Wrote {directory / 'report.md'}")
