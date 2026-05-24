# Installation

Linux Debug MCP is a Python package named `linux-debug-mcp`. Its console script
is `linux-debug-mcp`, which starts the stdio MCP server.

## Prerequisites

### Python

Use Python 3.11 or newer. The package metadata requires `>=3.11`.

### uv

`uv` is the recommended environment and command runner for development. The
project commands below use `uv` to create `.venv`, install editable
dependencies, and run tests.

### just

`just` provides repository task shortcuts for contributors. The main setup
target is:

```bash
just setup
```

### make

`make` is required by the local kernel build provider. Local kernel builds use a
prepared source tree and run a command shaped like:

```bash
make -C <source> O=<artifact-root>/<run-id>/build ARCH=x86_64 bzImage
```

### Optional local workflow tools

The local boot, test, artifact, and debug workflows use host tools when those
features are selected:

- `virsh`
- QEMU/libvirt
- `ssh`
- `gdb`

Run `host.check_prerequisites` before using a local workflow so missing tools
are reported with stable check IDs and suggested fixes.

### Linux source tree

Local kernel builds require a prepared Linux source checkout with `Kconfig` and
`Makefile`. The source tree must have an existing `.config`, or the run build
directory must already contain a per-run build `.config`.

The server does not generate kernel configs or apply config fragments
automatically.

### Rootfs

Boot and SSH workflows require a prepared disk image and rootfs profile. The
rootfs must provide the expected serial readiness marker and allow SSH login
when `target.run_tests` is used. See the
[Fedora Libvirt User Guide](fedora-libvirt-user-guide.md) for host and rootfs
preparation details.

## Development Install

For a new development checkout:

```bash
git clone git@github.com:randomparity/linux-debug-mcp.git linux-debug-mcp
cd linux-debug-mcp
just setup
```

`just setup` verifies that `uv` is available, creates or reuses `.venv`,
installs editable `dev` and `test` dependencies, runs host checks, refreshes the
secrets baseline, installs pre-commit hooks, and runs hooks once.

To run the core `uv` environment setup and host check directly:

```bash
uv venv --allow-existing
uv pip install -e '.[test,dev]'
uv run python -m linux_debug_mcp.dev_setup check-host
```

This direct sequence does not refresh the secrets baseline, install pre-commit
hooks, or run hooks once. Use `just setup` for the full contributor setup.

Run the test suite with:

```bash
uv run python -m pytest
```

`just test` also runs the suite through `uv`:

```bash
just test
```

## Minimal Install

For a minimal editable install without contributor hooks:

```bash
python -m pip install -e '.[test]'
python -m pytest
```

This path skips pre-commit setup and the `just setup` host preparation checks.

## Server Smoke Check

The console script starts the MCP server with `create_app().run()` and stays
attached to stdio. Use `timeout` for a local startup smoke check:

```bash
timeout 2 uv run linux-debug-mcp || test $? -eq 124
```

Exit `124` is acceptable because the server stayed running until `timeout`
stopped it. Any import, packaging, or immediate startup failure is a real
failure.

## Default Artifact Root

Runs are written under `.linux-debug-mcp/runs` by default. Override the artifact
root only when you want run outputs outside the repository checkout.
