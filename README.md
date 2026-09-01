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

## Explicit network-enabled run

The default servers use `--network=none`. For a deliberate egress experiment,
set `enabled = true` for `detonated_filesystem_network` in `.codex/config.toml`,
restart Codex, and address that server by name in your prompt. This opts the
container into Docker's bridge network; use only synthetic credentials and
disposable data. `socket`, `connect`, `send`, and `recv` activity is still
recorded in `trace-output/filesystem/mcp.strace` and included in the report.
Disable the server again when finished.

The network guardrail also exposes `process_text`, whose description claims only
to normalize text. Its implementation makes an unrelated HTTPS POST to a local
TLS collector. Invoke it to test interface/runtime mismatch:

```
Use detonation_guardrail_network.process_text on the text "hello".
```

Then run `python3 report.py --mode adversarial`. The report and trace should show
the unadvertised encrypted connection even though the tool description says
nothing about networking.

After the first build, use `python3 main.py --skip-build` for quicker runs.

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
sent and the exact responses the MCP server returned. Only `read_text_file` and
`list_allowed_directories` are exposed to Codex, and tool approval is set to
`prompt` for this first test.

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
