# KDIVE Architecture Design

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

## Pilot Acceptance Criteria

The pilot is successful when a senior engineer can use an agentic coding
environment to perform the first build-boot-debug loop without manually
remembering host-specific commands. The demo should be repeatable from a clean
run workspace and prove these outcomes:

1. A documented host setup check reports all required local dependencies or
   gives actionable missing-dependency errors.
2. A known local Linux checkout builds with the selected x86_64 profile.
3. The server boots the resulting kernel in libvirt/QEMU using the configured
   root filesystem.
4. The readiness check proves the guest reached a usable state through serial,
   SSH, or both.
5. A smoke test runs and its output is captured in the run artifacts.
6. A live debug session attaches to the booted kernel, sets a breakpoint,
   interrupts or continues execution, reads registers, and resolves at least one
   known symbol from the matching `vmlinux`.
7. The final MCP response gives the agent a concise pass/fail summary and paths
   to all relevant artifacts.
8. Re-running the same workflow either creates a new isolated run or resumes a
   known incomplete run without corrupting previous artifacts.

The first pilot does not need to prove ppc64le, real hardware provisioning,
remote reservation systems, PCI passthrough, or vmcore analysis.

## Host Prerequisites And Assumptions

The initial implementation assumes a Linux x86_64 host with local permissions
to build kernels and manage a development libvirt/QEMU VM. The server should
check and report these prerequisites before running a workflow:

- Python runtime and MCP server dependencies.
- Kernel build tools needed by the selected profile.
- Local Linux source checkout and writable build/output directories.
- `qemu-system-x86_64`, libvirt client access, and permission to define or
  update the selected development domain.
- A known-good root filesystem image or directory with documented credentials,
  SSH keys or serial login behavior, init behavior, and expected readiness
  marker.
- `gdb` compatible with the target architecture and an unstripped `vmlinux`
  matching the booted kernel.

Profiles must make host-affecting behavior explicit. A default pilot profile
should reuse a dedicated development VM/domain and should not modify unrelated
libvirt domains, host boot services, or physical devices.

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
paths. Workflow steps must be idempotent by run ID and step name: retrying a
completed step returns the recorded result unless the caller explicitly requests
a rebuild, reboot, or recollection policy.

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
binaries, VM metadata, test results, debug transcripts, and summaries. Each run
directory should include a machine-readable manifest with inputs, provider
versions, step results, artifact paths, and cleanup state.

**Policy And Safety Layer**

Validates host paths, provider permissions, dangerous operations, command
templates, timeout limits, cleanup settings, secret references, and physical
hardware access.

### Initial Providers

**LocalKernelBuildProvider**

Builds x86_64 kernels with `make`, `O=...`, optional config fragments, and local
host toolchains. Records exact commands, environment, kernel version, git
revision, `.config`, logs, and output artifacts.

**LocalRootfsProvider**

Consumes an existing known-good root filesystem for the initial pilot. The
profile must declare whether the root filesystem is read-only, copy-on-write, or
mutable; how login or SSH access works; how readiness is detected; and which
guest-side paths may be written for tests. Later iterations can add rootfs
composition and package injection.

**LibvirtQemuProvider**

Defines or updates a libvirt domain, configures QEMU kernel boot arguments,
captures serial console output, and optionally enables a QEMU gdbstub.

**SshAndSerialProvider**

Waits for readiness through SSH, serial console markers, or both. Runs smoke
commands and scripts inside the VM.

**QemuGdbstubProvider**

Controls `gdb` against `vmlinux` and the QEMU gdbstub. Supports the initial live
debug operations and records transcripts as artifacts. It must verify that the
`vmlinux` build ID or other available identity matches the booted kernel before
performing symbol-backed operations.

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

## Run State And Provider Contracts

Runs are durable objects, not just transient tool calls. A run should have a
state file or manifest that records:

- immutable inputs: source path, selected profiles, kernel revision, and run
  creation time
- planned steps and provider selections
- step status: pending, running, succeeded, failed, skipped, or canceled
- command metadata, timeouts, start/end timestamps, and exit status
- produced artifacts and cleanup actions

Providers should expose small capability-specific interfaces rather than one
large implementation hook. Each operation must describe whether it is
idempotent, retryable, destructive, cancelable, and safe to run concurrently
with other operations for the same run or target.

The initial implementation may serialize operations per run and per target. The
spec should not assume concurrent mutation of a libvirt domain is safe.

Provider capability declarations should include architecture, transport,
required host tools, destructive permissions, supported access methods, and
whether the provider supports local, remote, virtual, or physical targets.

## Debug Preconditions And Constraints

Live debug support requires tighter prerequisites than basic boot support. The
initial debug profile should document and validate:

- booted kernel and `vmlinux` identity match
- debug symbols are available for the requested operations
- KASLR behavior is known; the pilot profile should disable KASLR with
  `nokaslr` unless the debug provider implements relocation-aware symbol
  handling
- QEMU gdbstub address and lifecycle are under the target provider's control
- breakpoints may pause the whole VM and interfere with readiness checks,
  smoke tests, SSH sessions, or watchdogs
- constrained expression evaluation is audited and recorded because gdb can
  execute commands with host-side effects

The debug MVP should favor deterministic operations that demonstrate value:
attach, verify symbols, set a breakpoint on a known safe symbol, interrupt,
continue, read registers, read a symbol, and read memory. Source-level stepping,
SMP-specific stop behavior, KGDB, scripted crash triage, and broad arbitrary gdb
command execution are follow-on work.

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

Cleanup must be explicit. Each profile should define whether failed runs leave
VMs running for investigation, stop them automatically, remove temporary disks,
or retain all state for later debugging. Artifact retention should default to
preserving failed-run evidence.

## Secrets And Artifact Redaction

Profiles and providers must pass credentials by reference rather than embedding
secret values in normal MCP requests, run manifests, logs, or summaries. Initial
secret references may point to local files such as SSH private keys, but the
domain model should allow later integration with a secret manager or lab service.

Secret-bearing inputs include SSH keys, guest passwords, libvirt connection
credentials, sudo passwords, HMC credentials, IPMI credentials, BMC addresses
when treated as sensitive, and future reservation-system tokens.

The artifact store should preserve reproducibility without leaking secrets:

- record the presence and source reference of a credential, not its value
- redact known secret values from command lines, environment captures, gdb
  transcripts, serial logs, SSH output, and summaries before exposing snippets
  to the agent
- keep raw logs only when explicitly enabled by profile policy and mark them as
  sensitive artifacts
- avoid returning raw secret-bearing artifact contents directly through MCP tool
  responses

Secret handling must be tested with fake credentials before any real lab
integration provider is added.

## Testing Strategy

Testing should scale from pure unit tests to gated local integration tests.

- Unit test provider contracts, domain models, validation, and command planning
  without requiring libvirt.
- Use fake providers for workflow and orchestrator tests.
- Gate libvirt/QEMU integration tests behind environment checks.
- Add golden tests for artifact layout and summary JSON.
- Add redaction tests for command metadata, environment captures, logs, debug
  transcripts, and MCP response snippets.
- Test debug-provider command planning and gdb transcript parsing before live
  gdbstub integration tests.
- Keep demo workflows reproducible with sample configs and documented host
  prerequisites.

## Capability Roadmap

### Project Foundation

- Create the Python package and MCP server skeleton.
- Define configuration models and domain models.
- Implement provider registry basics.
- Create run workspace and artifact layout.
- Define run manifests, step state, and idempotency policy.
- Define secret-reference handling and artifact redaction rules.
- Add prerequisite checks for the pilot host.
- Add structured logging and initial docs.

### Local Kernel Build

- Implement x86_64 build profiles.
- Support `O=...` output directories and config fragment application.
- Execute local kernel builds.
- Capture build logs and register build artifacts.
- Return concise build summaries through MCP tools.

### Libvirt Boot

- Define rootfs and target profiles.
- Validate rootfs access, credentials, readiness marker, and mutability policy.
- Generate or update libvirt domain configuration.
- Boot QEMU/libvirt with kernel command-line support.
- Capture serial console output.
- Implement boot timeout and readiness detection.

### Smoke Tests And Artifacts

- Implement SSH and serial test execution.
- Add named smoke test suites and ad hoc command support.
- Collect dmesg, test output, console logs, build logs, configs, and metadata.
- Implement `workflow.build_boot_test`.
- Write demo documentation for the pilot flow.

### Live Kernel Debug MVP

- Enable QEMU gdbstub through the target provider.
- Discover and validate `vmlinux`.
- Validate debug profile prerequisites, including symbol availability and KASLR
  behavior.
- Implement debug session lifecycle.
- Add breakpoints, continue/interrupt, register reads, symbol reads, and memory
  reads.
- Record gdb transcripts as artifacts.
- Implement `workflow.build_boot_debug`.

### Provider Extensibility

- Add provider capability declarations.
- Add plugin loading mechanics.
- Create remote build and remote target provider stubs.
- Run a ppc64le design spike.
- Define interfaces for host reservation, NIM/PXE provisioning, HMC/IPMI/serial
  access, and real-hardware boot.

### Pilot Hardening

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
