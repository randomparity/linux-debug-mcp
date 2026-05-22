# Linux Development MCP Server

An MCP server foundation for Linux kernel development workflows in agentic
development environments.

## Sprint 0 Scope

Sprint 0 provides a runnable Python MCP skeleton and local foundation services:

- host prerequisite checks
- durable run workspace creation
- manifest readback
- provider capability listing
- structured `not_implemented` responses for later build, boot, test, artifact,
  workflow, and debug tools

Sprint 0 does not build kernels, modify libvirt domains, boot guests, run SSH or
serial commands, attach gdb, or collect real VM artifacts.

## Install

For a new development checkout, install `uv` and run:

```bash
just setup
```

The setup target verifies that `uv` is available, installs editable Python
development dependencies, runs the Sprint 0 host prerequisite checks, generates
the secrets baseline, installs pre-commit hooks, and runs the hooks once across
the repository.

For a minimal editable install without hooks:

```bash
python -m pip install -e '.[test]'
```

## Test

```bash
python -m pytest
```

The unit tests do not require libvirt, QEMU, a Linux checkout, or gdb.

## Start The Server

```bash
linux-debug-mcp
```

The console script starts the MCP server using the Python MCP SDK.

## Foundational Tools

`host.check_prerequisites` checks local Python, host tools, artifact root
writability, optional Linux source tree markers, and optional non-destructive
libvirt visibility.

`kernel.create_run` creates a run directory under the artifact root and writes a
durable `manifest.json`.

`artifacts.get_manifest` returns a redacted manifest view.

`providers.list` returns Sprint 0 provider capability declarations.

Later-sprint tools return structured `not_implemented` responses.

## Artifact Layout

Each run is stored under:

```text
<artifact-root>/<run-id>/
  manifest.json
  inputs/
  logs/
  build/
  target/
  tests/
  debug/
  summaries/
  sensitive/
```

The manifest records schema version, writer version, immutable run inputs,
planned steps, step results, and cleanup state.

## Interpreting Prerequisite Failures

Each prerequisite result includes a stable `check_id`, status, message, optional
details, and suggested fix. Sprint 0 never installs packages or modifies the
host; apply fixes manually and rerun `host.check_prerequisites`.
