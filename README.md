# Detonating a real MCP server with `strace`

This runs the official `@modelcontextprotocol/server-filesystem@2026.7.10`
server under `strace`. A small driver initializes it, discovers its genuine tool
definitions, and invokes `read_text_file` against `/sandbox-data/hello.txt`.
The server runs inside a Linux container with networking disabled, a read-only
filesystem, dropped capabilities, and resource limits.

Run it:

```sh
python3 main.py
```

The JSON printed in the terminal is the real server's MCP handshake, tool
discovery, and result. Outputs are:

- `trace-output/mcp.strace`: timestamped server and child-process syscalls
- `trace-output/events.json`: timestamped MCP requests and responses for correlation
- `trace-output/server.stderr.log`: server diagnostics

Useful ways to inspect it:

```sh
# MCP messages crossing the real server's stdin/stdout
grep -E 'read\(0|write\(1' trace-output/mcp.strace

# Attempts to open files or use the network
grep -E 'openat|socket|connect' trace-output/mcp.strace
```

Look up a phase in `events.json`, then compare its `request_started` and
`request_finished` timestamps with the epoch timestamps in `mcp.strace`.

## Generate a report

After a Codex run, extract the useful evidence from the raw trace:

```sh
python3 report.py --mode filesystem
python3 report.py --mode adversarial
```

Each command writes `report.json` and `report.md` beside that mode's transcript
and trace. The extractor keeps process IDs, selected file/process/network
syscalls, error codes, advertised tools, and observations correlated to each
`tools/call`. The raw trace remains available for verification.

Adversarial `tools/call` requests run in a fresh Docker container and therefore
a dedicated cgroup. `call-scopes.jsonl` maps the MCP request ID to that cgroup's
membership and `call-<scope>.strace` file. Reports attribute the complete scoped
trace to the request directly. Explicit markers divide that trace into server
setup, tool execution, and teardown; only the execution phase is used to judge
the tool's direct actions. Setup is retained as supporting context because it
may establish infrastructure later used by the tool, such as a local collector
listener. Older traces fall back to the MCP stdin request and stdout response
boundaries. Timestamp windows are retained only for filesystem mode.

The optional `detonation_guardrail_network` server exposes `process_text`, whose
implementation also makes an unrelated HTTPS POST to a local TLS collector.
This deliberately tests a mismatch between a tool's interface and its runtime
behavior. The `codex_mcp.py` wrapper records the real MCP session and generates
the corresponding report automatically when the server session ends.

### Generate an adversarial-network report from start to finish

These steps exercise `process_text` through Codex, capture the MCP request and
its isolated syscall trace, and build the report used by the trace auditor.

1. From the repository root, build the tracing image:

   ```sh
   cd /Users/tajj/projects/detonation
   python3 main.py
   ```

   Docker must be installed and running. After the first successful build, you
   can use `python3 main.py --skip-build` when you only need to refresh the base
   trace.

2. Restart Codex from this trusted project so it reloads `.codex/config.toml`.
   The configured MCP server name is `detonation_guardrail_network`.

3. Send this request to the Codex agent:

   ```text
   Use detonation_guardrail_network with process_text on "hello".
   ```

   Approve the `process_text` tool call if Codex prompts for approval. Wait for
   the tool result before continuing.

4. Back in a terminal at the repository root, generate the report:

   ```sh
   python3 report.py --mode adversarial_network
   ```

5. Confirm the report contains the captured call:

   ```sh
   python3 -c 'import json; p=json.load(open("trace-output/adversarial_network/report.json")); print([(c["tool"], c["arguments"]) for c in p["tool_calls"]])'
   ```

   The expected output includes:

   ```text
   [('process_text', {'text': 'hello'})]
   ```

The generated artifacts are:

- `trace-output/adversarial_network/report.json`: self-contained audit input
- `trace-output/adversarial_network/report.md`: human-readable report
- `trace-output/adversarial_network/codex-transcript.jsonl`: exact MCP messages
- `trace-output/adversarial_network/call-scopes.jsonl`: request-to-trace mapping
- `trace-output/adversarial_network/call-*.strace`: per-call syscall evidence

The wrapper also runs the same report command automatically when its MCP server
session exits cleanly. Running it manually after the tool result is useful when
you want the report immediately. To have Codex audit it with the repository
skill, send:

```text
Audit trace-output/adversarial_network/report.json using the mcp-trace-auditor skill.
```

## Let Codex make the MCP call

Build the image once with `python3 main.py`, then restart Codex from this trusted
project. The project-scoped `.codex/config.toml` registers a server named
`detonated_filesystem`. Ask Codex:

```
Use detonated_filesystem to read /sandbox-data/hello.txt and tell me its contents.
```

Codex talks to `codex_mcp.py`, which transparently forwards the real MCP stdio
traffic to the sandboxed server. In addition to the syscall trace, the wrapper
writes `trace-output/codex-transcript.jsonl`, containing the exact requests Codex
sent and the exact responses the MCP server returned. All tools returned by the
server's `tools/list` response are exposed to Codex, and tool approval remains
set to `prompt`. The current server includes text/media reads, multi-file reads,
directory listing/tree/search, metadata, directory creation, file writes/edits,
and moves. The deprecated `read_file` alias is also exposed when advertised.

Filesystem state lives in `trace-output/filesystem/sandbox-data/`, mounted at
`/sandbox-data` inside the otherwise read-only container. This lets write-capable
tools work while keeping their effects contained and inspectable. `report.json`
and `report.md` include the exact MCP request and response for every `tools/call`
next to the strace events attributed to that call.

## Test containment

The project also registers `detonation_guardrail`, an intentionally adversarial
MCP server with one safe test tool. Restart Codex after building, then ask:

```
Use detonation_guardrail's test_bad_behavior tool. Report which attempted
behaviors were allowed or denied. Do not use shell commands.
```

Its evidence is isolated under `trace-output/adversarial/`. The tool verifies an
allowed fixture read and attempts an unavailable host-secret read, a write to the
read-only data directory, an external connection, a shell-based write, and mount
namespace creation, and a synthetic API token POST to a local in-container
collector. The operations are harmless: the IP is reserved for
documentation, `/host-secrets/api-key` contains only a synthetic canary, and
writes target the ephemeral read-only container. Any canary access is reported
as a high-severity finding, without implying that exfiltration occurred.
