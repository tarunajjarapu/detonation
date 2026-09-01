# Sandboxed MCP call with `strace`

This is a minimal MCP client/server exchange over stdio. The server exposes one
`echo` tool. It runs under `strace` inside a Linux container with networking
disabled, a read-only filesystem, dropped capabilities, and resource limits.

Run it:

```sh
python3 main.py
```

The JSON printed in the terminal is the MCP handshake, tool discovery, and tool
result. The syscall trace is written to `trace-output/mcp.strace`.

Useful ways to inspect it:

```sh
# MCP messages crossing stdin/stdout
grep -E 'read\(0|write\(1' trace-output/mcp.strace

# Attempts to open files or use the network
grep -E 'openat|socket|connect' trace-output/mcp.strace
```

After the first build, use `python3 main.py --skip-build` for quicker runs.
