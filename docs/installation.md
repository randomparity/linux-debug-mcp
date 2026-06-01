# Installation

KDIVE is a Python package named `kdive`. Its console script
is `kdive`, which starts the stdio MCP server.

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
git clone git@github.com:randomparity/kdive.git kdive
cd kdive
just setup
```

`just setup` verifies that `uv` is available, creates or reuses `.venv`,
installs editable `dev` and `test` dependencies, runs host checks, installs
pre-commit hooks, and runs hooks once against the checked-in secrets baseline.

To run the core `uv` environment setup and host check directly:

```bash
uv venv --allow-existing
uv pip install -e '.[test,dev]'
uv run python -m kdive.prereqs.dev_setup check-host
```

This direct sequence does not install pre-commit hooks or run hooks once. Use
`just setup` for the full contributor setup.

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

The console script starts the MCP server with `create_app(load_server_config()).run()`
and stays attached to stdio. Use `timeout` for a local startup smoke check:

```bash
timeout 2 uv run kdive || test $? -eq 124
```

Exit `124` is acceptable because the server stayed running until `timeout`
stopped it. Any import, packaging, or immediate startup failure is a real
failure.

## Default Artifact Root

Runs are written under `.kdive/runs` by default. Override the artifact
root only when you want run outputs outside the repository checkout.

## Operator Configuration

Set `KDIVE_CONFIG` to the path of a JSON `ServerConfig` file to enforce
operator-configured sensitive paths. When set, a `rootfs_source` override (passed
to `kernel.create_run` or `target.boot`) that resolves inside any configured
`sensitive_paths` entry is rejected with a configuration error. When the variable
is unset, only the built-in path-safety guards apply.

```json
{
  "artifact_root": "/var/lib/kdive/runs",
  "sensitive_paths": ["/etc", "/var/lib/secrets"]
}
```

An unreadable or invalid config file fails server startup with an actionable
error rather than silently falling back.
