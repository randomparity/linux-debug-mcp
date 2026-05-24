# Linux Development MCP Server

An MCP server foundation for Linux kernel development workflows in agentic
development environments.

## Current Scope

The current implementation provides:

- host prerequisite checks
- durable run workspace creation
- local x86_64 `kernel.build` for prepared Linux source checkouts
- per-run build output under `<artifact-root>/<run-id>/build`
- build log capture at `<artifact-root>/<run-id>/logs/build.log`
- build summary capture at `<artifact-root>/<run-id>/summaries/build-summary.json`
- manifest readback
- provider capability listing
- a narrow local libvirt/QEMU `target.boot` pilot path
- SSH-first `target.run_tests` smoke execution
- artifact bundle indexing with `artifacts.collect`
- `workflow.build_boot_test` orchestration
- local QEMU gdbstub debug attach and constrained `debug.*` tools
- `workflow.build_boot_debug` orchestration

The pilot paths do not create root filesystems, install SSH packages or keys,
discover guest addresses, use remote builders, generate kernel configs, or
apply config fragments automatically.

## Provider Extensibility Status

Sprint 5 adds a contract-first provider discovery surface for future remote,
provisioning, hardware-control, console, and real-boot workflows. The local
x86_64 path remains the only implemented end-to-end workflow.

Future providers are discoverable as safe stubs. They advertise planned
operations, architectures, transports, limitations, and documentation paths, but
valid requests return `not_implemented` until a later sprint adds real provider
implementations.

Provider implementation states are:

- `implemented`: the provider has executable local behavior.
- `stub`: the provider is discoverable for planning and contract validation
  only; it must not create run workspaces or contact external systems.
- `external_reserved`: the provider name or capability is reserved for a future
  external integration.

Use `providers.list` as the primary discovery tool before selecting a provider.
It reports implemented local providers and Sprint 5 stubs with their operation
capabilities and implementation states.

ppc64le may appear in stub provider metadata and future-facing request
contracts, but it is not executable in Sprint 5. See
[`docs/ppc64le-provider-spike.md`](docs/ppc64le-provider-spike.md) for the
current ppc64le design notes and boundaries.

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

## Pilot Libvirt Boot Host

`target.boot` supports a narrow pilot path for a dedicated local libvirt/QEMU
domain. It boots an x86_64 kernel with direct kernel boot, attaches a disk-image
rootfs as `/dev/vda`, captures serial console output, and waits for a configured
readiness marker on `ttyS0`.

For full Fedora host setup, libvirt authentication options, rootfs expectations,
and the opt-in integration command, see
[`docs/fedora-libvirt-user-guide.md`](docs/fedora-libvirt-user-guide.md).

At a high level, a real-host run needs:

- Fedora host packages for kernel builds, QEMU, and libvirt.
- A working libvirt URI such as `qemu:///session` or `qemu:///system`.
- A dedicated managed domain whose name starts with `mcp-linux-debug-`.
- A Linux source tree with a built `arch/x86/boot/bzImage`.
- A disk-image rootfs that prints the configured readiness marker on `ttyS0`.

The pilot boot path does not create root filesystems, use remote builders,
generate kernel configs, or apply config fragments automatically.

## Live Kernel Debug

Sprint 4 adds a local QEMU gdbstub debug workflow for dedicated libvirt/QEMU
domains. The host must provide `virsh`, QEMU/libvirt, `gdb`, a built Linux
source tree with matching `arch/x86/boot/bzImage` and `vmlinux`, and the same
Sprint 2 rootfs readiness behavior described in the Fedora guide.

`workflow.build_boot_debug` creates or reuses a run, builds the kernel, boots
the target with a localhost-only QEMU gdbstub, waits for serial readiness, and
attaches a managed gdb session. It does not run `target.run_tests`; run SSH
smoke tests separately when needed.

Example debug workflow call:

```json
{
  "tool": "workflow.build_boot_debug",
  "arguments": {
    "source_path": "/home/dave/src/linux",
    "build_profile": "x86_64-default",
    "target_profile": "local-qemu-debug",
    "rootfs_profile": "minimal",
    "debug_profile": "qemu-gdbstub-default"
  }
}
```

After a session is attached, use the constrained `debug.*` tools for inspection.
`debug.read_memory` is capped at 4096 bytes per call. Raw gdb transcripts are
artifact-only; response snippets and manifest views are redacted.

### Run SSH Smoke Tests

Sprint 3 expects the selected rootfs profile to already allow SSH login from
the MCP server. The tool does not install packages, create users, copy SSH keys,
discover guest addresses, or mutate the rootfs to enable login.

The default suite is `smoke-basic`:

- `uname -a`
- `test -r /proc/version`
- `cat /proc/cmdline`

After `kernel.build` and `target.boot` succeed:

```json
{
  "tool": "target.run_tests",
  "arguments": {
    "run_id": "run-abc123",
    "test_suite": "smoke-basic"
  }
}
```

Ad hoc commands are argv lists and run after the named suite:

```json
{
  "tool": "target.run_tests",
  "arguments": {
    "run_id": "run-abc123",
    "commands": [["sh", "-lc", "cat /proc/cmdline | tr ' ' '\\n'"]]
  }
}
```

Collect the artifact bundle:

```json
{
  "tool": "artifacts.collect",
  "arguments": {
    "run_id": "run-abc123"
  }
}
```

Run the full pilot workflow:

```json
{
  "tool": "workflow.build_boot_test",
  "arguments": {
    "source_path": "/home/dave/src/linux",
    "build_profile": "x86_64-default",
    "target_profile": "local-qemu",
    "rootfs_profile": "minimal",
    "test_suite": "smoke-basic"
  }
}
```

Smoke output is written under
`.linux-debug-mcp/runs/<run-id>/tests/attempt-NNN/`, dmesg under the same
attempt directory, serial console logs under `logs/`, and the bundle index at
`summaries/artifact-bundle.json`.

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
The libvirt boot and live gdbstub integration tests are opt-in and skipped by
default.

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

`providers.list` returns provider capability declarations, including provider
family, implementation state, advertised operations, operation-level metadata,
limitations, and documentation paths when available. Treat `stub` providers as
non-executable planning metadata.

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
