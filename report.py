#!/usr/bin/env python3
"""Turn a captured MCP transcript and strace into a small evidence report."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


LINE = re.compile(r"^\s*(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)$")
PATH = re.compile(r'"([^"\n]+)"')
ERROR = re.compile(r"= -1 ([A-Z]+)")
IP = re.compile(r'inet_addr\("([0-9.]+)"\)')
PORT = re.compile(r"sin_port=htons\((\d+)\)")
COUNT = re.compile(r"\) = (\d+)$")
RESULT = re.compile(r"\) = (.+)$")
CREDENTIAL_PATH = re.compile(r"(?i)(?:secret|token|api[-_]?key|credential|password|auth)")
AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token)\b")
TOOL_MARKER = re.compile(r"DETONATION_TOOL_(START|END) request_id=([^\\\"]+)")


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
        result = RESULT.search(raw)
        if result:
            event["return_value"] = result.group(1)
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
        if syscall in {
            "open", "openat", "openat2", "readlink", "readlinkat", "stat", "statx",
            "access", "faccessat", "faccessat2", "getdents64", "unlink", "unlinkat",
            "rename", "renameat", "renameat2", "mkdir", "mkdirat",
        }:
            events.append(event)
        elif syscall in {"execve", "clone", "clone3", "fork", "vfork", "socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "unshare", "setns", "mount", "ptrace", "bpf"}:
            events.append(event)
    return events


def parse_scoped_trace(path: Path) -> tuple[list[dict], dict[str, float], str]:
    """Parse reportable events and tool-boundary markers from one call trace."""
    markers: dict[str, float] = {}
    stdio_start: float | None = None
    stdio_end: float | None = None
    for raw in path.read_text(errors="replace").splitlines():
        line = LINE.match(raw)
        marker = TOOL_MARKER.search(raw)
        if line and marker:
            markers[marker.group(1).lower()] = float(line.group(2))
        if line and "tools/call" in raw and "read(0" in raw:
            stdio_start = float(line.group(2))
        if line and stdio_start is not None and "write(1" in raw and "result" in raw:
            stdio_end = float(line.group(2))
    if "start" in markers and "end" in markers:
        method = "server_markers"
    elif stdio_start is not None and stdio_end is not None:
        markers = {"start": stdio_start, "end": stdio_end}
        method = "mcp_stdio_fallback"
    else:
        method = "markers_missing_all_events_attributed"
    return parse_trace(path), markers, method


def load_transcript(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def load_scopes(path: Path) -> dict[object, dict]:
    if not path.exists():
        return {}
    scopes = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return {scope["request_id"]: scope for scope in scopes}


def make_report(mode: str, root: Path) -> dict:
    directory = root / "trace-output" / mode
    transcript = load_transcript(directory / "codex-transcript.jsonl")
    session_trace = directory / "mcp.strace"
    trace = parse_trace(session_trace) if session_trace.exists() else []
    scopes = load_scopes(directory / "call-scopes.jsonl")
    attributed_trace = [] if mode in {"adversarial", "adversarial_network"} else list(trace)
    setup_trace = []
    execution_trace = [] if mode in {"adversarial", "adversarial_network"} else list(trace)
    teardown_trace = []
    calls = []
    tools = []
    tool_definitions = []
    for entry in transcript:
        message = entry.get("message", {})
        if entry.get("direction") == "server_to_codex" and message.get("id") is not None:
            result = message.get("result", {})
            listed_tools = result.get("tools", [])
            tools.extend(tool.get("name") for tool in listed_tools)
            tool_definitions.extend(
                {
                    "name": tool.get("name"),
                    "description": tool.get("description", ""),
                    "inputSchema": tool.get("inputSchema", {}),
                    "annotations": tool.get("annotations", {}),
                }
                for tool in listed_tools
                if tool.get("name")
            )
        if entry.get("direction") == "codex_to_server" and message.get("method") == "tools/call":
            calls.append({
                "id": message.get("id"),
                "tool": message.get("params", {}).get("name"),
                "arguments": message.get("params", {}).get("arguments", {}),
                "timestamp": epoch(entry["timestamp"]),
                "request_entry": entry,
            })
    for call in calls:
        responses = [
            entry
            for entry in transcript
            if entry.get("direction") == "server_to_codex"
            and entry.get("message", {}).get("id") == call["id"]
        ]
        call["transcript"] = {
            "request": call.pop("request_entry"),
            "response": responses[0] if responses else None,
        }
        scope = scopes.get(call["id"])
        if scope:
            trace_path = directory / scope["trace"]
            scoped_events, markers, phase_method = parse_scoped_trace(trace_path)
            start = markers.get("start")
            end = markers.get("end")
            if start is not None and end is not None:
                setup = [event for event in scoped_events if event["timestamp"] < start]
                window = [event for event in scoped_events if start <= event["timestamp"] <= end]
                teardown = [event for event in scoped_events if event["timestamp"] > end]
            else:
                setup = []
                window = scoped_events
                teardown = []
            attributed_trace.extend(scoped_events)
            setup_trace.extend(setup)
            execution_trace.extend(window)
            teardown_trace.extend(teardown)
            cgroup_path = directory / scope["cgroup"]
            call["attribution"] = {
                "method": "dedicated_container_cgroup",
                "scope": scope["scope"],
                "container": scope["container"],
                "cgroup_membership": cgroup_path.read_text().splitlines() if cgroup_path.exists() else [],
                "trace": scope["trace"],
                "phase_method": phase_method,
                "markers": markers,
            }
        elif mode == "filesystem":
            window = [event for event in trace if event["timestamp"] >= call["timestamp"]]
            response_times = [epoch(e["timestamp"]) for e in responses]
            if response_times:
                window = [event for event in window if event["timestamp"] <= response_times[0]]
            call["attribution"] = {"method": "timestamp_window"}
        else:
            window = []
            setup = []
            teardown = []
            call["attribution"] = {
                "method": "missing_cgroup_scope",
                "error": "No request-to-cgroup mapping was captured; no syscalls attributed",
            }
        if not scope:
            setup = []
            teardown = []
        call["observed"] = window
        call["setup_observed"] = setup
        call["teardown_observed"] = teardown
        call["setup_syscall_counts"] = dict(Counter(event["syscall"] for event in setup))
        call["teardown_syscall_counts"] = dict(Counter(event["syscall"] for event in teardown))
        call["syscall_counts"] = dict(Counter(event["syscall"] for event in window))
        call["files_touched"] = sorted({path for event in window for path in event.get("paths", []) if path.startswith(("/sandbox-data", "/host-secrets", "/workspace", "/tmp"))})
        call["network"] = [
            event for event in window
            if event["syscall"] in {"socket", "connect", "bind", "listen", "accept", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg"}
        ]
        call["setup_network"] = [
            event for event in setup
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
                })
    return {
        "mode": mode,
        "static": {
            "server": "@modelcontextprotocol/server-filesystem@2026.7.10" if mode == "filesystem" else "detonation containment-test-server",
            "tools_advertised": sorted(set(filter(None, tools))),
            "tool_definitions": list({tool["name"]: tool for tool in tool_definitions}.values()),
        },
        "tool_calls": calls,
        "runtime": {
            "trace_events_extracted": len(attributed_trace),
            "setup_events_extracted": len(setup_trace),
            "tool_execution_events_extracted": len(execution_trace),
            "teardown_events_extracted": len(teardown_trace),
            "pids": sorted({event["pid"] for event in attributed_trace}),
            "errors": sorted({event["error"] for event in attributed_trace if "error" in event}),
            "network_attempts": sum(event["syscall"] in {"connect", "send", "sendto", "sendmsg"} for event in execution_trace),
            "network_observations": [event for event in execution_trace if event["syscall"] in {"socket", "connect", "bind", "listen", "accept", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg"}],
            "setup_network_observations": [event for event in setup_trace if event["syscall"] in {"socket", "connect", "bind", "listen", "accept", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg"}],
            "trace_scope": "Adversarial calls use one Docker container/cgroup and trace per request; filesystem calls retain timestamp correlation",
        },
        "findings": [],
    }


def write_markdown(report: dict, destination: Path) -> None:
    lines = [f"# MCP detonation report ({report['mode']})", "", f"Server: `{report['static']['server']}`", "", "## Executive summary", ""]
    lines += [f"- Tool calls: `{len(report['tool_calls'])}`", f"- Extracted runtime events: `{report['runtime']['trace_events_extracted']}`", f"- Direct tool-execution events: `{report['runtime']['tool_execution_events_extracted']}`", f"- Supporting setup/context events: `{report['runtime']['setup_events_extracted']}`", f"- Direct tool-execution network connect/send attempts: `{report['runtime']['network_attempts']}`", ""]
    if report["tool_calls"]:
        lines += ["| Tool | Request ID | Syscalls | Network events | Files of interest |", "|---|---:|---:|---:|---|"]
        for call in report["tool_calls"]:
            lines.append(f"| `{call['tool']}` | `{call['id']}` | `{sum(call['syscall_counts'].values())}` | `{len(call['network'])}` | `{', '.join(call['files_touched']) or 'none'}` |")
        lines.append("")
    lines += ["## Advertised tools", ""]
    if report["static"]["tools_advertised"]:
        lines.extend(f"- `{tool}`" for tool in report["static"]["tools_advertised"])
    else:
        lines.append("- none captured")
    lines += ["", "## Network observations", ""]
    network = report["runtime"]["network_observations"]
    if network:
        lines += ["| PID | Syscall | Destination | Bytes | Result |", "|---:|---|---|---:|---|"]
        for event in network:
            target = ""
            if event.get("destination_ip"):
                target = f"{event['destination_ip']}:{event.get('destination_port', '?')}"
            elif event.get("paths"):
                target = " ".join(event["paths"])
            lines.append(f"| {event['pid']} | `{event['syscall']}` | `{target}` | {event.get('bytes', '')} | `{event.get('return_value', '')}` |")
    else:
        lines.append("No network syscalls captured.")
    setup_network = report["runtime"].get("setup_network_observations", [])
    if setup_network:
        lines += ["", "### Supporting server setup/context", "", "These events are not direct tool actions, but are retained because they can establish infrastructure used by the tool (for example, a listener that the tool later connects to).", "", "| PID | Syscall | Destination | Result |", "|---:|---|---|---|"]
        for event in setup_network:
            target = ""
            if event.get("destination_ip"):
                target = f"{event['destination_ip']}:{event.get('destination_port', '?')}"
            elif event.get("paths"):
                target = " ".join(event["paths"])
            lines.append(f"| {event['pid']} | `{event['syscall']}` | `{target}` | `{event.get('return_value', '')}` |")
    lines += ["", "## Tool-call observations", ""]
    for call in report["tool_calls"]:
        response = call.get("transcript", {}).get("response")
        response_message = response.get("message") if response else None
        lines += [
            f"### `{call['tool']}` (request id `{call['id']}`)",
            "",
            "MCP transcript:",
            f"- request: `{json.dumps(call.get('transcript', {}).get('request', {}).get('message'), separators=(',', ':'))}`",
            f"- response: `{json.dumps(response_message, separators=(',', ':'))}`" if response_message is not None else "- response: `not captured`",
            "",
            "Observed syscalls:",
        ]
        attribution = call.get("attribution", {})
        lines.append(f"- attribution: `{attribution.get('method', 'unknown')}`")
        if attribution.get("scope"):
            lines.append(f"- call scope: `{attribution['scope']}`")
            lines.append(f"- cgroup membership: `{json.dumps(attribution.get('cgroup_membership', []))}`")
            lines.append(f"- trace: `{attribution['trace']}`")
            lines.append(f"- phase boundary: `{attribution.get('phase_method', 'unknown')}`")
        if call["setup_observed"]:
            lines.append(f"- supporting setup/context syscalls (not counted as direct tool actions): `{json.dumps(call['setup_syscall_counts'], sort_keys=True)}`")
        lines.append(f"- direct tool-execution syscall counts: `{json.dumps(call['syscall_counts'], sort_keys=True)}`")
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
        if call["setup_network"] or call["network"]:
            lines += ["", "Combined network evidence:", "", "| Phase | PID | Syscall | Destination | Result |", "|---|---:|---|---|---|"]
            for phase, events in (("supporting setup/context", call["setup_network"]), ("direct tool execution", call["network"])):
                for event in events:
                    target = ""
                    if event.get("destination_ip"):
                        target = f"{event['destination_ip']}:{event.get('destination_port', '?')}"
                    elif event.get("paths"):
                        target = " ".join(event["paths"])
                    lines.append(f"| {phase} | {event['pid']} | `{event['syscall']}` | `{target}` | `{event.get('return_value', '')}` |")
        if call["credential_network_correlations"]:
            lines += ["", "Credential-to-network correlations (reverse attribution):"]
            for relation in call["credential_network_correlations"]:
                target = f"{relation.get('destination_ip')}:{relation.get('destination_port', '?')}"
                lines.append(
                    f"- `{', '.join(relation['credential_paths'])}` → `{target}` "
                    f"({relation['relationship']}, confidence `{relation['confidence']}`)"
                )
        if call["teardown_observed"]:
            lines += ["", f"Teardown syscalls (excluded from tool behavior): `{json.dumps(call['teardown_syscall_counts'], sort_keys=True)}`"]
        lines.append("")
    lines += ["## Runtime summary", "", f"Extracted events: `{report['runtime']['trace_events_extracted']}`", f"PIDs: `{report['runtime']['pids']}`", f"Observed error codes: `{report['runtime']['errors']}`", ""]
    if report["findings"]:
        lines += ["## Findings", ""]
        lines.extend(f"- **{finding['severity']}**: {finding['message']}" for finding in report["findings"])
        lines.append("")
    destination.write_text("\n".join(lines))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("filesystem", "adversarial", "adversarial_network"), default="filesystem")
    args = parser.parse_args()
    project = Path(__file__).resolve().parent
    report = make_report(args.mode, project)
    directory = project / "trace-output" / args.mode
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    write_markdown(report, directory / "report.md")
    print(f"Wrote {directory / 'report.json'}")
    print(f"Wrote {directory / 'report.md'}")
