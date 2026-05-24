# Linux Development MCP Server

Linux Debug MCP is a Python MCP server for local Linux kernel build, boot,
smoke-test, artifact, and QEMU gdbstub debug workflows.

## What Works Today

- local host prerequisite checks
- local x86_64 kernel builds from a prepared Linux source tree
- local libvirt/QEMU direct kernel boot for a dedicated managed domain
- SSH smoke tests against a prepared rootfs profile
- artifact manifest and bundle indexing
- local QEMU gdbstub debug sessions with constrained `debug.*` tools
- discoverable future-provider stubs for remote, provisioning, hardware,
  console, and real-boot workflows

## Quick Start

```bash
git clone git@github.com:randomparity/linux-debug-mcp.git linux-debug-mcp
cd linux-debug-mcp
just setup
uv run python -m pytest
```

See [Installation](docs/installation.md) for direct `uv`, minimal `pip`, host
check, and server smoke-check commands.

## Connect A Client

The server runs over stdio. See [Client Setup](docs/client-setup.md) for Claude
Code and Codex configuration.

## Local Workflow

Use `providers.list` and `host.check_prerequisites` before selecting a workflow.
The implemented end-to-end local examples are documented in
[Tool Reference](docs/tool-reference.md). Host preparation for libvirt/QEMU is
documented in [Fedora Libvirt User Guide](docs/fedora-libvirt-user-guide.md).

## Development

```bash
just test
just lint
```
