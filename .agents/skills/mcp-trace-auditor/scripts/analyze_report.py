#!/usr/bin/env python3
"""Conservative first-pass contract/syscall comparison for detonation reports."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


CAPABILITIES = {
    "network": re.compile(r"\b(network|http|https|url|web|download|upload|api|remote|fetch|telemetry)\b", re.I),
    "process": re.compile(r"\b(command|shell|subprocess|execute|exec|program|script)\b", re.I),
    "privileged": re.compile(r"\b(mount|namespace|trace|kernel|bpf|privilege)\b", re.I),
    "file_read": re.compile(r"\b(read|load|inspect|file|directory|search|metadata|stat)\b", re.I),
    "file_write": re.compile(r"\b(write|edit|create|delete|remove|rename|move|modify|save)\b", re.I),
}
PROCESS = {"execve", "fork", "vfork", "clone", "clone3"}
PRIVILEGED = {"mount", "umount2", "unshare", "setns", "ptrace", "bpf"}
NETWORK_MATERIAL = {"connect", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg", "bind", "listen", "accept", "accept4"}
FILE_READ = {"open", "openat", "openat2", "stat", "statx", "lstat", "access", "faccessat", "readlink", "readlinkat"}
FILE_MUTATION = {"write", "pwrite", "pwrite64", "pwritev", "pwritev2", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat"}
RUNTIME_PATH_PREFIXES = ("/etc/", "/lib/", "/usr/")


def definitions(report: dict) -> dict[str, dict]:
    raw = report.get("static", {}).get("tool_definitions", [])
    if isinstance(raw, dict):
        return raw
    return {item.get("name"): item for item in raw if isinstance(item, dict) and item.get("name")}


def expected_capabilities(definition: dict) -> set[str]:
    description = definition.get("description", "")
    return {name for name, pattern in CAPABILITIES.items() if pattern.search(description)}


def event_syscalls(call: dict) -> set[str]:
    result = set((call.get("syscall_counts") or {}).keys())
    result.update(e.get("syscall", "") for e in call.get("observed", []) if isinstance(e, dict))
    return result


def argument_paths(value) -> set[str]:
    if isinstance(value, dict):
        return {path for child in value.values() for path in argument_paths(child)}
    if isinstance(value, list):
        return {path for child in value for path in argument_paths(child)}
    return {value} if isinstance(value, str) and value.startswith("/") else set()


def path_is_scoped(path: str, allowed: set[str]) -> bool:
    normalized = path.rstrip("/") or "/"
    candidates = (item.rstrip("/") or "/" for item in allowed)
    return any(normalized == candidate or candidate.startswith(normalized + "/") for candidate in candidates)


def file_events(call: dict, syscalls: set[str], include_runtime: bool = False) -> list[dict]:
    allowed = argument_paths(call.get("arguments") or {})
    result = []
    for event in call.get("observed", []):
        if not isinstance(event, dict) or event.get("syscall") not in syscalls:
            continue
        if syscalls is FILE_READ and event.get("error") == "EROFS":
            continue
        paths = [path for path in event.get("paths", []) if isinstance(path, str) and path.startswith("/")]
        if not paths:
            continue
        credential_related = bool(event.get("credential_candidate_paths"))
        if not include_runtime and not credential_related and all(path.startswith(RUNTIME_PATH_PREFIXES) for path in paths):
            continue
        item = dict(event)
        item["outside_argument_scope"] = bool(allowed) and any(not path_is_scoped(path, allowed) for path in paths)
        result.append(item)
    return result


def writable_open_attempts(call: dict) -> list[dict]:
    """Recover denied writable opens when the report did not retain open flags."""
    result = []
    for event in call.get("observed", []):
        if not isinstance(event, dict) or event.get("syscall") not in {"open", "openat", "openat2"}:
            continue
        if event.get("error") not in {"EROFS"}:
            continue
        paths = [path for path in event.get("paths", []) if isinstance(path, str) and path.startswith("/")]
        if paths:
            result.append({**event, "outside_argument_scope": bool(argument_paths(call.get("arguments") or {})) and any(not path_is_scoped(path, argument_paths(call.get("arguments") or {})) for path in paths)})
    return result


def observed_capabilities(call: dict) -> dict[str, list[dict]]:
    observed = [e for e in call.get("observed", []) if isinstance(e, dict)]
    syscalls = event_syscalls(call)
    network = [e for e in call.get("network", []) if e.get("syscall") in NETWORK_MATERIAL]
    return {
        "network": network,
        "process": [e for e in observed if e.get("syscall") in PROCESS] or ([{}] if syscalls & PROCESS else []),
        "privileged": [e for e in observed if e.get("syscall") in PRIVILEGED] or ([{}] if syscalls & PRIVILEGED else []),
        "file_read": file_events(call, FILE_READ),
        "file_write": file_events(call, FILE_MUTATION) + writable_open_attempts(call),
    }


def summarize(events: list[dict]) -> list[dict]:
    keys = ("syscall", "pid", "timestamp", "paths", "destination_ip", "destination_port", "bytes", "return_value", "error", "outside_argument_scope")
    return [{key: event[key] for key in keys if key in event} for event in events[:8]]


def audit(report: dict, source: Path) -> dict:
    defs = definitions(report)
    results = []
    for call in report.get("tool_calls", []):
        name = call.get("tool")
        definition = defs.get(name)
        if not definition:
            results.append({"tool": name, "request_id": call.get("id"), "verdict": "needs-review", "severity": "unknown", "confidence": "low", "reason": "Tool description/schema is absent, so the advertised contract cannot be established from this report."})
            continue
        expected = expected_capabilities(definition)
        observed = observed_capabilities(call)
        unexpected = {}
        for capability, events in observed.items():
            if not events:
                continue
            if capability not in expected:
                unexpected[capability] = events
            elif capability in {"file_read", "file_write"}:
                outside_scope = [event for event in events if event.get("outside_argument_scope")]
                if outside_scope:
                    unexpected[capability] = outside_scope
        credential_links = call.get("credential_network_correlations", [])
        severity = "high" if "network" in unexpected and credential_links else "medium" if unexpected else "none"
        results.append({
            "tool": name,
            "request_id": call.get("id"),
            "description": definition.get("description", ""),
            "arguments": call.get("arguments", {}),
            "expected_capabilities": sorted(expected),
            "verdict": "mismatch" if unexpected else "aligned",
            "severity": severity,
            "confidence": "high" if unexpected else "medium",
            "unexpected": {cap: summarize(events) for cap, events in unexpected.items()},
            "credential_network_correlations": credential_links,
        })
    return {
        "source": str(source),
        "trace_scope": report.get("runtime", {}).get("trace_scope"),
        "results": results,
        "caveats": ["Failed syscalls show attempted behavior, not successful sandbox escape.", "Temporal call windows do not by themselves prove causal attribution.", "This triage output requires agent review of the underlying events."],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(audit(json.loads(args.report.read_text()), args.report), indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
