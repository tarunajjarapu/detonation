---
name: mcp-trace-auditor
description: Audit MCP tool-call traces by comparing each tool's advertised description, schema, and annotations with correlated file, network, process, and privilege-related system calls. Use for report.json files produced from sandbox or strace captures and for detecting undeclared MCP behavior.
---

# MCP Trace Auditor

Evaluate the behavioral contract advertised to the agent, not whether the tool returned a plausible result.

## Input

The normal input is exactly one `report.json`. Read it as a self-contained evidence bundle: use `static.tool_definitions` for the advertised contract and each `tool_calls` entry for arguments, attribution, observed events, files, network activity, syscall counts, and credential correlations. Do not inspect the implementation or execute the MCP tool merely to fill gaps.

If the user does not name a report, use `report.json` when present; otherwise ask them to select one from `trace-output/*/report.json` when there is more than one. If `static.tool_definitions` is absent, classify affected calls as `needs-review`. An adjacent transcript may improve the review, but its absence must not prevent a useful account of what is and is not knowable from the JSON.

Run the deterministic first pass when available:

```sh
python3 .agents/skills/mcp-trace-auditor/scripts/analyze_report.py REPORT_JSON
```

The script writes its result to stdout unless `--output` is supplied. It is a deterministic evidence index, not the final explanation. Review the relevant source-report entries yourself before presenting conclusions.

## Contract comparison

For every `tool_calls` entry:

1. Quote or tightly paraphrase the tool description and relevant annotations. Note missing contract evidence explicitly.
2. Derive only capabilities reasonably implied by that interface: file read, file mutation, network client/server activity, subprocess execution, or privileged/kernel operations. `readOnlyHint: false` means only that a tool may have side effects; it does not advertise file mutation by itself. Arguments narrow advertised access to supplied paths and targets. Reading a supplied file may include metadata checks of that path and its parents, but not unrelated paths.
3. Compare those expectations with `observed`, `files_touched`, `network`, `syscall_counts`, and credential/network correlations.
4. Classify the call as `aligned`, `mismatch`, or `needs-review`. Use `needs-review` when evidence or the advertised definition is insufficient or ambiguous.

Treat `connect`, `send*`, externally meaningful `recv*`, `bind`, `listen`, and `accept` as network behavior. A failed syscall still proves an attempt; distinguish an unexpected attempt from a successful sandbox escape. Treat `execve`, `fork`, `vfork`, `clone`, and `clone3` as process behavior when correlated to the call. Treat `mount`, `unshare`, `setns`, `ptrace`, and `bpf` as privileged behavior. File mutations include `write`/`pwrite*` when attributable to a file, plus `unlink*`, `rename*`, `mkdir*`, and writable opens when flags are available.

Ignore ordinary runtime/library loading and MCP stdio transport unless it is material to the tool call. Be cautious with `socket` alone, loopback traffic, background threads, broad time windows, and events lacking process/file-descriptor attribution. They may still be findings, but state the attribution limit.

Raise severity for credential-like paths or authorization indicators followed by network transmission. Do not claim exfiltration from temporal proximity alone; report process match, destination, payload evidence, and confidence.

## Output

Lead with a per-call verdict table containing tool, verdict, severity, advertised behavior, unexpected observation, and confidence. Then answer plainly whether each call did something wrong, what it attempted versus what succeeded, and why that behavior was or was not advertised. Give concise evidence with syscall, PID, timestamp, path/destination, return/error, and end with trace limitations and recommended contract, implementation, or sandbox changes. Do not dump the whole JSON or require the user to understand syscall terminology.

Never execute the MCP tool while auditing unless the user separately authorizes a new run. Do not infer that blocked behavior is harmless: it can be a contract mismatch even when containment worked.
