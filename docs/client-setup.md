# Client Setup

Linux Debug MCP runs as a stdio MCP server. Client examples should use an
absolute repository path so the client can start the server reliably from any
workspace.

The examples below assume the repository is checked out at:

```text
/home/dave/src/linux-debug-mcp
```

Replace that path with your local checkout path.

## Claude Code

Add the server to the current project. Project scope is the recommended default
because this server exposes local build, libvirt, SSH, and gdb-related tools:

```bash
claude mcp add --transport stdio --scope project linux-debug-mcp -- \
  uv --directory /home/dave/src/linux-debug-mcp run linux-debug-mcp
```

Add the server to your user configuration only when you intentionally want it
available across Claude Code projects:

```bash
claude mcp add --transport stdio --scope user linux-debug-mcp -- \
  uv --directory /home/dave/src/linux-debug-mcp run linux-debug-mcp
```

Verify the registration from the shell:

```bash
claude mcp list
```

Inside Claude Code, inspect connected MCP servers with:

```text
/mcp
```

## Codex CLI

Add the server through the Codex MCP CLI:

```bash
codex mcp add linux-debug-mcp -- \
  uv --directory /home/dave/src/linux-debug-mcp run linux-debug-mcp
```

Verify the registration:

```bash
codex mcp list
codex mcp get linux-debug-mcp
```

## Codex TOML Configuration

You can also configure the server directly in `~/.codex/config.toml`:

```toml
[mcp_servers.linux-debug-mcp]
command = "uv"
args = ["--directory", "/home/dave/src/linux-debug-mcp", "run", "linux-debug-mcp"]
enabled = true
```

## Path Choices

Use an absolute repository path in client configuration. Absolute paths avoid
startup failures when a client launches from a different working directory.

If `linux-debug-mcp` is installed into a stable environment, you may set
`command` to the absolute path of the `linux-debug-mcp` console script instead
of running it through `uv`.

## Safety Notes

This MCP server exposes constrained tools that can run local build, libvirt,
SSH, and gdb-related commands. Connect it only in workspaces where you intend to
make those workflows available to the agent.

Prefer project-scoped client registration unless the broader exposure of a
user-scoped registration is intentional.
