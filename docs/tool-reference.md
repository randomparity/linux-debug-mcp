# Tool Reference

KDIVE exposes local kernel build, boot, smoke-test, artifact, transport, live
debug, introspection, postmortem, and future-provider planning tools over stdio
MCP. The default artifact root is `.kdive/runs`.

Use `providers.list` and `host.check_prerequisites` before choosing a workflow.
Client setup is covered in [Client Setup](client-setup.md), and Fedora
libvirt/QEMU host preparation is covered in the
[Fedora Libvirt User Guide](fedora-libvirt-user-guide.md).

## Registered MCP Tool Inventory

This list is checked against `create_app()` in tests so the reference changes
with the runtime MCP surface.

- `artifacts.collect`
- `artifacts.get_manifest`
- `console.open_session`
- `console.read`
- `console.write`
- `debug.backtrace`
- `debug.clear_breakpoint`
- `debug.clear_watchpoint`
- `debug.continue`
- `debug.end_session`
- `debug.evaluate`
- `debug.finish`
- `debug.interrupt`
- `debug.introspect.check_prerequisites`
- `debug.introspect.from_vmcore`
- `debug.introspect.from_vmcore_helper`
- `debug.introspect.helper`
- `debug.introspect.run`
- `debug.list_breakpoints`
- `debug.list_variables`
- `debug.load_module_symbols`
- `debug.next`
- `debug.postmortem.check_prereqs`
- `debug.postmortem.crash`
- `debug.postmortem.fetch`
- `debug.postmortem.list_dumps`
- `debug.postmortem.triage`
- `debug.read_memory`
- `debug.read_registers`
- `debug.read_symbol`
- `debug.set_breakpoint`
- `debug.set_watchpoint`
- `debug.start_session`
- `debug.step`
- `hardware.boot_kernel`
- `hardware.power_control`
- `host.check_prerequisites`
- `kernel.build`
- `kernel.create_run`
- `providers.list`
- `provision.prepare_target`
- `remote.build_kernel`
- `remote.sync_artifacts`
- `reservation.release_host`
- `reservation.request_host`
- `target.boot`
- `target.run_tests`
- `transport.close`
- `transport.inject_break`
- `transport.open`
- `workflow.build_boot_debug`
- `workflow.build_boot_test`
- `workflow.reserve_provision_boot`

## Discovery Tools

### `providers.list`

Returns provider capability declarations for implemented local providers and
future-provider stubs. Use it to check provider families, implementation state,
advertised operations, limitations, and documentation paths.

### `host.check_prerequisites`

Checks local Python, host tools, artifact root writability, optional Linux
source markers, and optional non-destructive libvirt visibility. When you pass
the build/target/rootfs profile names you intend to use, it also runs a
run-readiness preflight that names the roundtrip-blocking gaps up front, each
with a concrete `suggested_fix`:

- `kernel.config` — the kernel `.config` is present in the source tree or
  derivable from the build profile's `base_config`.
- `rootfs.image` — the rootfs profile resolves to an existing disk image
  (a missing builder image points you at `just rootfs`).
- `gdbstub.port` — for a `debug_gdbstub` target, the `gdbstub_endpoint` port is
  free to bind. This is a point-in-time advisory, not a reservation: the port can
  be taken before `target.boot` binds it.

Omitting a profile name leaves its readiness check `skipped`. An unsupported or
typo'd profile name is reported as a `failed` check, not a hard error, so the
remaining checks still run.

```json
{
  "tool": "host.check_prerequisites",
  "arguments": {
    "artifact_root": ".kdive/runs",
    "source_path": "/home/dave/src/linux",
    "enable_libvirt_check": true,
    "build_profile": "x86_64-debug",
    "target_profile": "local-qemu-debug",
    "rootfs_profile": "minimal"
  }
}
```

### `artifacts.get_manifest`

Returns the redacted manifest for an existing run. Use it to inspect run inputs,
step results, artifacts, cleanup state, and suggested next actions.

```json
{
  "tool": "artifacts.get_manifest",
  "arguments": {
    "run_id": "run-abc123"
  }
}
```

## Local Build, Boot, And Test Tools

The implemented local workflow expects:

- a Linux source tree with `Kconfig`, `Makefile`, and a usable `.config`
- `make` for x86_64 kernel builds
- a prepared rootfs profile for local libvirt/QEMU boot
- SSH access from the MCP server when running guest smoke tests

Implemented tools:

- `kernel.create_run`
- `kernel.build`
- `target.boot`
- `target.run_tests`
- `artifacts.collect`
- `workflow.build_boot_test`

Run the local build, boot, SSH smoke-test, and artifact workflow with:

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

The default `smoke-basic` suite runs:

- `uname -a`
- `test -r /proc/version`
- `cat /proc/cmdline`

The local providers do not create root filesystems, install SSH packages or
keys, discover guest addresses, generate kernel configs, or apply config
fragments automatically.

`kernel.create_run` accepts either named profiles (`build_profile`,
`target_profile`, `rootfs_profile`) or inline specs under `profile_specs`
(`build`, `target`, `rootfs`) — exactly one per kind. An inline spec is
validated by the same model as the named profile and frozen into the run
manifest; an inline `rootfs_source` is subject to the same path-safety guards as
a `boot_overrides.rootfs_source` override.

Per-run build changes are supplied with `build_overrides` (`make_variables`,
`config_lines`, `base_config`). Per-run boot changes are supplied with
`boot_overrides` (`kernel_args`, `rootfs_source`, `rootfs`). Rootfs field
overrides besides `source` live under `boot_overrides.rootfs`: `mutability`,
`access_method`, `readiness_marker`, `ssh_host`, `ssh_port`, `ssh_user`,
`ssh_key_ref`, and `ssh_options`. Each is validated like the corresponding
`RootfsProfile` field and replaces that field on the resolved profile at boot.
Because `target.boot` can define, update, start, stop, or destroy MCP-owned
libvirt domains, booting or rebooting requires `acknowledged_permissions` to
include the destructive permissions advertised by `providers.list`.

## Local Debug Tools

The implemented debug path attaches local `gdb` to a localhost-only QEMU
gdbstub for a dedicated libvirt/QEMU domain. It requires a built kernel image
and matching unstripped `vmlinux`.

Implemented debug tools:

- `workflow.build_boot_debug`
- `debug.start_session`
- `debug.interrupt`
- `debug.continue`
- `debug.step`
- `debug.next`
- `debug.finish`
- `debug.set_breakpoint`
- `debug.set_watchpoint`
- `debug.clear_breakpoint`
- `debug.clear_watchpoint`
- `debug.list_breakpoints`
- `debug.backtrace`
- `debug.list_variables`
- `debug.load_module_symbols`
- `debug.read_registers`
- `debug.read_symbol`
- `debug.read_memory`
- `debug.evaluate`
- `debug.end_session`

Run the local build, boot, and debug attach workflow with:

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

After the session is attached, use the constrained `debug.*` tools for
inspection. `debug.read_memory` is capped at 4096 bytes per call. Raw gdb
transcripts are artifact-only; response snippets and manifest views are
redacted.

`workflow.build_boot_debug` does not run `target.run_tests`. Run SSH smoke tests
separately when guest command coverage is needed.

## Introspection, Transport, And Postmortem Tools

Live drgn introspection tools (`debug.introspect.run`,
`debug.introspect.helper`, and `debug.introspect.check_prerequisites`) execute
against a booted target and share the same run/profile checks as the debug
workflow. Offline drgn introspection (`debug.introspect.from_vmcore` and
`debug.introspect.from_vmcore_helper`) reads a fetched vmcore plus matching
`vmlinux` and optional modules.

Transport tools (`transport.open`, `transport.close`, and
`transport.inject_break`) expose the low-level session boundary used by the
debug tier. Most callers should prefer `debug.start_session` and
`debug.end_session`; transport tools are for explicit recovery and integration
workflows.

Postmortem tools (`debug.postmortem.check_prereqs`,
`debug.postmortem.list_dumps`, `debug.postmortem.fetch`,
`debug.postmortem.crash`, and `debug.postmortem.triage`) cover kdump readiness,
vmcore discovery/fetch, crash utility batches, and composite triage. See
[Debug Postmortem](debug-postmortem.md) for request and artifact details.

## Artifact Layout

Each run is stored under `<artifact-root>/<run-id>/`. With the default artifact
root, that is `.kdive/runs/<run-id>/`.

Important paths include:

- build logs under `<artifact-root>/<run-id>/logs/build.log`
- build summaries under
  `<artifact-root>/<run-id>/summaries/build-summary.json`
- serial and boot logs under `<artifact-root>/<run-id>/logs/`
- smoke output under `<artifact-root>/<run-id>/tests/attempt-NNN/`
- debug artifacts under `<artifact-root>/<run-id>/debug/`
- bundle index under
  `<artifact-root>/<run-id>/summaries/artifact-bundle.json`

Use `artifacts.collect` after a run to refresh the artifact bundle index:

```json
{
  "tool": "artifacts.collect",
  "arguments": {
    "run_id": "run-abc123"
  }
}
```

## Future-Provider Stubs

Future-provider tools are discoverable for planning and contract validation
only:

- `remote.build_kernel`
- `remote.sync_artifacts`
- `reservation.request_host`
- `reservation.release_host`
- `provision.prepare_target`
- `hardware.power_control`
- `hardware.boot_kernel`
- `console.open_session`
- `console.read`
- `console.write`
- `workflow.reserve_provision_boot`

Valid future-provider requests return `not_implemented`. Malformed requests
return `configuration_error`. These stubs do not contact remote hosts, open
consoles, provision targets, control hardware, or create real-boot side
effects.

ppc64le appears only in future-provider metadata and contracts today. See the
[ppc64le Provider Spike](ppc64le-provider-spike.md) for design notes and
current boundaries.
