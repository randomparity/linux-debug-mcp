# Linux Debug MCP Architecture Design

Date: 2026-05-22

## Purpose

Build an MCP server that helps agentic coding environments such as Claude Code
and Codex perform Linux kernel development workflows with less manual setup and
less repeated host-specific knowledge.

The initial rollout is a pilot-oriented Python MCP server for an x86_64
build-boot-debug loop on the local host. The architecture must support later
extension to ppc64le, remote build systems, external lab reservation services,
real hardware provisioning, PXE/NIM workflows, HMC/IPMI/serial access, device
passthrough, crash dump analysis, and broader test orchestration.

## Initial Scope

The first end-to-end workflow should:

1. Register or discover a local Linux kernel checkout.
2. Build an x86_64 kernel with a named build profile.
3. Provision or reuse a minimal root filesystem and libvirt domain.
4. Boot the built kernel under QEMU/libvirt with console capture.
5. Optionally enable a QEMU gdbstub for live kernel debugging.
6. Wait for target readiness through a serial marker and/or SSH.
7. Run smoke scripts inside the VM.
8. Collect build logs, VM console logs, dmesg, test output, kernel config,
   vmlinux, generated metadata, and a pass/fail summary.
9. Expose initial live debug operations: set/list/clear breakpoints,
   continue/interrupt, read registers, inspect symbols, read memory, and
   evaluate constrained kernel expressions or predefined inspectors.

Deferred but designed-for capabilities include ppc64le, remote build hosts,
host reservation, PXE/NIM provisioning, physical host boot, HMC/IPMI/serial
access, PCI passthrough, vmcore/crash dump workflows, and large-scale test
orchestration.

## Architecture

The server should use a small stable core with provider implementations behind
it. The first providers are local and concrete, but the contracts should be
capability-based so future providers can wrap remote services and real lab
hardware without changing the MCP tool surface.

### Core Modules

**MCP Tool Layer**

Exposes agent-facing tools for workflow and expert operations, including kernel
builds, target boots, test execution, artifact collection, and live debug
sessions.

**Workflow Orchestrator**

Coordinates common flows such as `build_boot_test` and `build_boot_debug`.
Tracks run IDs, step state, logs, provider decisions, timeouts, and artifact
paths.

**Provider Registry**

Loads named providers from configuration. Providers advertise capabilities and
dependencies. The first registry can be static, but the interface should allow
entry-point or module-based plugin loading later.

**Domain Model**

Defines typed objects for:

- `KernelSource`
- `BuildProfile`
- `BuildArtifact`
- `RootfsProfile`
- `TargetProfile`
- `BootSession`
- `DebugSession`
- `TestSuite`
- `ArtifactBundle`

**Artifact Store**

Creates durable per-run directories containing inputs, generated config, logs,
binaries, VM metadata, test results, debug transcripts, and summaries.

**Policy And Safety Layer**

Validates host paths, provider permissions, dangerous operations, command
templates, timeout limits, cleanup settings, and physical hardware access.

### Initial Providers

**LocalKernelBuildProvider**

Builds x86_64 kernels with `make`, `O=...`, optional config fragments, and local
host toolchains. Records exact commands, environment, kernel version, git
revision, `.config`, logs, and output artifacts.

**LocalRootfsProvider**

Consumes an existing known-good root filesystem for the initial pilot. Later
iterations can add rootfs composition and package injection.

**LibvirtQemuProvider**

Defines or updates a libvirt domain, configures QEMU kernel boot arguments,
captures serial console output, and optionally enables a QEMU gdbstub.

**SshAndSerialProvider**

Waits for readiness through SSH, serial console markers, or both. Runs smoke
commands and scripts inside the VM.

**QemuGdbstubProvider**

Controls `gdb` against `vmlinux` and the QEMU gdbstub. Supports the initial live
debug operations and records transcripts as artifacts.

**LocalArtifactProvider**

Collects logs, binaries, kernel config, VM metadata, dmesg, test outputs, debug
transcripts, and generated summaries into an artifact bundle.

## MCP Tool Surface

The tool surface should be workflow-oriented first, with lower-level escape
hatches for expert use.

### Workflow And Target Tools

- `kernel.create_run`: create a run workspace from source path, build profile,
  target profile, rootfs profile, and optional debug/test settings.
- `kernel.build`: build the kernel for a run and return artifact paths plus a
  concise build summary.
- `target.boot`: boot or reboot the target with the built kernel and return
  console/readiness status.
- `target.run_tests`: run named smoke scripts or ad hoc commands and record
  output.
- `artifacts.collect`: collect logs and generated files into an artifact bundle.
- `workflow.build_boot_test`: build, boot, run smoke tests, and collect
  artifacts.
- `workflow.build_boot_debug`: build, boot with gdbstub enabled, wait for
  readiness, and open a debug session.

### Debug Tools

- `debug.start_session`
- `debug.interrupt`
- `debug.continue`
- `debug.set_breakpoint`
- `debug.clear_breakpoint`
- `debug.list_breakpoints`
- `debug.read_registers`
- `debug.read_symbol`
- `debug.read_memory`
- `debug.evaluate`
- `debug.end_session`

`debug.evaluate` must be constrained. The initial implementation may support
predefined inspectors and a limited expression mode rather than arbitrary
interactive gdb control.

## Data Flow

The normal flow is:

```text
config profiles
  -> run workspace
  -> build artifacts
  -> target boot session
  -> access/test session
  -> optional debug session
  -> artifact bundle
  -> agent-readable summary
```

Each tool returns structured JSON with `run_id`, status, artifact paths,
concise summaries, and suggested next MCP calls. Long logs remain on disk. Tool
responses should include relevant snippets, offsets, and artifact references
instead of dumping full logs into the agent context.

## Safety And Error Handling

Every workflow step should have explicit timeouts, cancellation behavior, and
cleanup policy.

Provider errors should normalize into stable categories:

- configuration error
- missing dependency
- build failure
- boot timeout
- readiness failure
- test failure
- debug attach failure
- infrastructure failure

Destructive or host-sensitive operations require explicit profile settings,
including deleting VM disks, redefining domains, writing host devices, PCI
passthrough, changing boot services, or accessing real hardware control planes.

Commands should run through provider-owned templates and allowlists where
practical. Artifact metadata must preserve enough context to reproduce failures:
exact command lines, environment, config fragments, libvirt XML, kernel version,
git revision, and tool versions.

## Testing Strategy

Testing should scale from pure unit tests to gated local integration tests.

- Unit test provider contracts, domain models, validation, and command planning
  without requiring libvirt.
- Use fake providers for workflow and orchestrator tests.
- Gate libvirt/QEMU integration tests behind environment checks.
- Add golden tests for artifact layout and summary JSON.
- Test debug-provider command planning and gdb transcript parsing before live
  gdbstub integration tests.
- Keep demo workflows reproducible with sample configs and documented host
  prerequisites.

## Sprint Plan

### Sprint 0: Project Foundation

- Create the Python package and MCP server skeleton.
- Define configuration models and domain models.
- Implement provider registry basics.
- Create run workspace and artifact layout.
- Add structured logging and initial docs.

### Sprint 1: Local Kernel Build

- Implement x86_64 build profiles.
- Support `O=...` output directories and config fragment application.
- Execute local kernel builds.
- Capture build logs and register build artifacts.
- Return concise build summaries through MCP tools.

### Sprint 2: Libvirt Boot

- Define rootfs and target profiles.
- Generate or update libvirt domain configuration.
- Boot QEMU/libvirt with kernel command-line support.
- Capture serial console output.
- Implement boot timeout and readiness detection.

### Sprint 3: Smoke Tests And Artifacts

- Implement SSH and serial test execution.
- Add named smoke test suites and ad hoc command support.
- Collect dmesg, test output, console logs, build logs, configs, and metadata.
- Implement `workflow.build_boot_test`.
- Write demo documentation for the pilot flow.

### Sprint 4: Live Kernel Debug MVP

- Enable QEMU gdbstub through the target provider.
- Discover and validate `vmlinux`.
- Implement debug session lifecycle.
- Add breakpoints, continue/interrupt, register reads, symbol reads, and memory
  reads.
- Record gdb transcripts as artifacts.
- Implement `workflow.build_boot_debug`.

### Sprint 5: Provider Extensibility

- Add provider capability declarations.
- Add plugin loading mechanics.
- Create remote build and remote target provider stubs.
- Run a ppc64le design spike.
- Define interfaces for host reservation, NIM/PXE provisioning, HMC/IPMI/serial
  access, and real-hardware boot.

### Sprint 6: Pilot Hardening

- Add dependency checks and clearer error messages.
- Improve recovery and cleanup paths.
- Provide sample configs and scripts.
- Create a management-facing productivity demo scenario.
- Document current limits and next integration opportunities.

## Open Follow-Up Decisions

These are intentionally deferred until implementation planning:

- Exact MCP SDK package and server transport.
- Configuration file format and default paths.
- Minimal rootfs source for the pilot.
- Exact libvirt domain XML strategy.
- Whether the first gdb integration shells out to `gdb` or uses a Python MI
  wrapper.
- CI environment for non-libvirt tests.
