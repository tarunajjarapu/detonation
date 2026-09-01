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
