# Linux Development MCP Server

An MCP server foundation for Linux kernel development workflows in agentic
development environments.

## Current Scope

Sprint 1 provides:

- host prerequisite checks
- durable run workspace creation
- local x86_64 `kernel.build` for prepared Linux source checkouts
- per-run build output under `<artifact-root>/<run-id>/build`
- build log capture at `<artifact-root>/<run-id>/logs/build.log`
- build summary capture at `<artifact-root>/<run-id>/summaries/build-summary.json`
- manifest readback
- provider capability listing
- structured `not_implemented` responses for boot, test, artifact collection,
  workflow, and debug tools

Sprint 1 does not boot kernels, create root filesystems, run SSH or serial
commands, attach gdb, use remote builders, generate kernel configs, or apply
config fragments automatically.

## Local Kernel Builds

`kernel.build` builds a developer-prepared local Linux checkout. The source tree
must contain `Kconfig` and `Makefile`, and the developer must provide a kernel
configuration either at `<source>/.config` or by pre-populating
`<artifact-root>/<run-id>/build/.config`.

The default Sprint 1 command shape is:

```bash
make -C <source> O=<artifact-root>/<run-id>/build ARCH=x86_64 bzImage
```

The provider does not run `defconfig`, `olddefconfig`, `menuconfig`,
`localmodconfig`, or config fragment application. If the per-run build config is
missing and `<source>/.config` exists, the source config is copied into the
per-run build directory before `make` starts.

On success, artifacts include the build log, `.config`, `arch/x86/boot/bzImage`,
optional `vmlinux`, and `summaries/build-summary.json`.

## Install

For a new development checkout, install `uv` and run:

```bash
just setup
```

The setup target verifies that `uv` is available, installs editable Python
development dependencies, runs the host prerequisite checks, generates
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

`providers.list` returns provider capability declarations.

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
details, and suggested fix. The server never installs packages or modifies the
host; apply fixes manually and rerun `host.check_prerequisites`.
