# Sprint 4 Live Kernel Debug MVP Design

Date: 2026-05-23

## Purpose

Sprint 4 adds the first live kernel debug workflow to the local x86_64 pilot.
It enables QEMU gdbstub boot, validates the matching `vmlinux`, starts a
durable debug session, exposes constrained debug operations through MCP tools,
and records debugger transcripts as run artifacts.

This sprint proves that an agentic coding environment can move from a built and
booted kernel to useful live-debug evidence without manually remembering QEMU,
libvirt, and gdb command details.

## Scope

Sprint 4 includes:

- QEMU gdbstub enablement in the local libvirt/QEMU target provider.
- Debug profile validation for KASLR behavior, symbol identity requirements,
  allowed operations, and constrained evaluation mode.
- A local `QemuGdbstubProvider` backed by a narrow subprocess `gdb` controller.
- Durable debug session files under the run workspace.
- Redacted debugger transcripts and per-command metadata artifacts.
- `workflow.build_boot_debug` orchestration.
- MCP handlers and tool wiring for:
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
- Artifact collection support for debug summaries and transcripts.
- Unit tests with fake libvirt and gdb runners.
- Opt-in live integration coverage for hosts with libvirt, QEMU, gdbstub, and a
  matching debug kernel.

Sprint 4 does not include:

- A GDB/MI client or general interactive debugger UI.
- Arbitrary gdb command execution.
- Source-level stepping, watchpoints, or thread/SMP stop-state modeling.
- KGDB, crash dump, vmcore, or scripted crash triage workflows.
- Automatic rootfs creation, package injection, SSH setup, or guest address
  discovery.
- ppc64le, remote hosts, PXE/NIM, HMC/IPMI, or real hardware provisioning.
- Smoke-test execution inside `workflow.build_boot_debug`.

## Recommended Approach

Use direct `gdb` subprocess control behind a narrow controller interface.

The provider should execute bounded, scripted gdb command batches and parse only
the stable outputs needed by the MVP. This keeps Sprint 4 dependency-light and
matches the deterministic operations required by the architecture: attach,
validate symbols, set/list/clear breakpoints, continue/interrupt, read
registers, read symbols, and read memory.

The controller boundary should still be session-oriented so a later GDB/MI
implementation can replace the subprocess implementation without changing MCP
tool names or handler behavior.

## Architecture

Sprint 4 implements a local live-debug MVP, not a full debugger.

`LibvirtQemuProvider` should accept debug-enabled target profiles and render a
QEMU/libvirt gdbstub endpoint owned by the target provider. The boot plan and
boot summary should record the endpoint, whether debug boot was enabled, and
the kernel arguments used for debug determinism.

A new `QemuGdbstubProvider` should validate the matching `vmlinux`, create a
debug session record under the run workspace, execute constrained gdb command
batches via subprocess, and write transcripts under `debug/attempt-NNN/`.

The MCP layer should coordinate manifest state, locks, idempotent session
lookup, and response shaping. Providers should own host tool checks, command
planning, transcript writing, output parsing, and operation-specific result
details.

## Workflow Behavior

`workflow.build_boot_debug` should run this sequence:

1. Create or reuse a run.
2. Build the kernel.
3. Boot the target with gdbstub enabled.
4. Wait for normal target readiness.
5. Start a debug session against the run's recorded `vmlinux`.

The workflow should not run the Sprint 3 smoke suite by default. Callers can use
`workflow.build_boot_test` or `target.run_tests` separately when they need guest
command evidence before debugging.

The workflow should stop at the first failed stage and return the failed
handler response with suggested next actions. A successful workflow should
return the debug session ID, gdbstub endpoint, transcript paths, a concise
attach summary, and artifact references.

## Tool Behavior

`debug.start_session` should be reusable after a successful debug-enabled boot.
If a run already has an active debug session and the caller does not request a
new one, the handler should return the recorded session summary.

Lower-level debug tools should operate on the active session for a run unless
the caller passes a specific `debug_session_id`. Session lookup should be
deterministic and should fail with a configuration error when no matching active
session exists.

`debug.end_session` should be idempotent. It should mark the session `ended`,
terminate any attached controller owned by the session, write a final
debug-summary artifact, release the debug lock, and keep transcripts and command
metadata for later artifact collection. If the attached controller has already
exited, `debug.end_session` should record the observed exit state and still
finalize the session instead of failing cleanup.

`debug.evaluate` should support predefined inspectors only in Sprint 4. Initial
inspectors should include:

- `kernel_version`: execute a provider-owned `p linux_banner` command and parse
  the string value when debug symbols expose it.
- `symbol_address`: resolve a caller-provided symbol name through the same
  symbol validation path used by `debug.read_symbol`.

The handler must reject arbitrary expressions, shell escapes, sourced scripts,
and raw gdb command strings.

All read-style operations must enforce provider-owned bounds before command
planning. `debug.read_memory` should require an explicit byte count with a
Sprint 4 maximum of 4096 bytes per call. `debug.read_symbol` should return
scalar values or bounded byte/string previews only, not unbounded aggregate
dumps. Register and inspector responses should be normalized into structured
fields and should cap returned transcript snippets through the same redaction
and truncation path used for artifacts.

## Profile Model

The existing `DebugProfile` model is sufficient for the initial surface but
needs stricter Sprint 4 defaults and validation in handlers/providers:

- Default profile name: `qemu-gdbstub-default`.
- `kaslr_policy`: `disabled`.
- `symbol_identity_required`: `true`.
- `evaluation_mode`: `predefined_inspectors`.
- `enabled_operations`: the Sprint 4 debug operation names.

A debug boot should require deterministic symbol addresses. The default profile
should add `nokaslr` when the debug profile is selected and the target profile
does not already include it. The boot plan should record whether `nokaslr` was
added by the provider or supplied by the profile.

Unsupported KASLR policies should fail before boot or attach. `kaslr_policy`
values other than `disabled` are reserved for later relocation-aware symbol
handling.

## Gdbstub Boot

`TargetProfile.debug_gdbstub` should become supported for the local libvirt/QEMU
provider. Sprint 4 should add `TargetProfile.gdbstub_endpoint` with a default
of `127.0.0.1:1234` for the local pilot. The provider should:

- Render a local-only gdbstub endpoint.
- Parse the profile endpoint as structured host and port fields before rendering
  libvirt XML.
- Reject malformed endpoints, non-local bind addresses, ports outside
  `1..65535`, and endpoint strings containing path, query, XML, shell, or
  whitespace syntax.
- Avoid exposing the gdbstub beyond the local host.
- Check that the requested local port is available before boot and return a
  deterministic failure if the endpoint is already in use.
- Record endpoint details in `target/boot-plan.json` and
  `summaries/boot-summary.json`.
- Include `nokaslr` in the kernel command line for the default debug profile.

Because the default endpoint is fixed, target locking must continue to serialize
operations for that domain and prevent concurrent debug boots from colliding.
Later work can replace the fixed endpoint with generated per-run ports.

## Debug Session State

Debug state should live under the run directory:

```text
<run>/
  debug/
    sessions/
      <session-id>.json
    attempt-001/
      transcript.txt
      commands.jsonl
      debug-summary.json
```

The session file should record:

- session ID
- run ID
- provider name
- gdbstub endpoint
- `vmlinux` path
- selected debug profile
- attach status
- started and ended timestamps
- current execution state: `unknown`, `running`, `stopped`, or `ended`
- breakpoint metadata
- controller mode: `batch` or `attached`
- active controller PID or handle when an attached controller is running
- controller heartbeat or last-observed state for stale-session detection
- transcript path
- command metadata path
- latest summary path
- symbol identity validation result

The manifest `debug` step should record the latest successful session start.
Detailed command history should remain in debug artifacts rather than being
embedded in the manifest.

## GDB Controller

The provider should use an injectable runner/controller boundary:

- `which("gdb")`
- `run_batch(argv, commands, timeout, transcript_path)`
- optional `interrupt(session, timeout)` abstraction if the first subprocess
  strategy needs special process signaling

The default implementation should use `subprocess` with `shell=False`, bounded
timeouts, and explicit command files or `-ex` arguments. It should always set
non-interactive gdb options such as pagination off and confirmation off.

The implementation should favor short-lived, transcript-backed gdb invocations
for stateless operations where possible. Operations that depend on debugger
continuity must use an attached controller for the session. In Sprint 4 this
means `debug.continue`, `debug.interrupt`, and breakpoint operations must either
run through the same attached controller or fail with `configuration_error`
instead of pretending batch invocations can preserve debugger state. A session
may start in `batch` mode for attach validation and read-only inspectors, but
it must transition to `attached` mode before continuing the VM or relying on
breakpoint state across calls.

Attached controllers should be owned by exactly one debug session. Before
reusing an active session, the provider should verify the recorded controller is
still alive and attached to the expected gdbstub endpoint. Stale controllers
should cause the session to be marked `ended` with an infrastructure failure
summary, and callers should be told to start a new session rather than silently
creating one for a stateful operation.

All command batches should be generated by provider-owned templates. User input
may fill only validated fields such as symbol names, breakpoint IDs, register
names, byte counts, and addresses. The provider should reject invalid symbol
syntax, negative or oversized byte counts, unsupported register names, and
addresses outside the unsigned 64-bit range before invoking gdb.

## Symbol And Identity Validation

`debug.start_session` requires:

- a succeeded debug-enabled boot
- a recorded `vmlinux` artifact from the build step
- host `gdb`
- a recorded gdbstub endpoint
- a compatible debug profile

The provider must verify that symbol-backed operations use the same kernel that
was booted. When `symbol_identity_required=true`, Sprint 4 should require both:

- Same-run artifact linkage from the manifest: the booted target must reference
  the build step's `vmlinux` artifact and kernel image from the same run.
- A live target check: `linux_banner` or an equivalent provider-owned version
  symbol read from the target must match the kernel release/version recorded by
  the build metadata.

The provider should additionally record optional evidence such as the
`vmlinux` build ID and required-symbol availability, but optional evidence must
not substitute for the required same-run linkage and live version check in
strict mode. If strict identity cannot be proven and
`symbol_identity_required=true`, session start should fail with
`debug_attach_failure` or `configuration_error`, depending on whether the
failure is caused by target state or profile/input state.

## Safety And Error Handling

Safety rules:

- Require a succeeded debug-enabled boot before starting a debug session.
- Require a recorded `vmlinux` artifact.
- Refuse symbol-backed operations when identity validation fails.
- Reject arbitrary gdb commands, shell escapes, and sourced scripts.
- Redact transcripts before returning snippets in MCP responses.
- Serialize debug operations per run with a new debug lock.
- Treat `continue` as potentially blocking and require bounded behavior.
- Keep `continue`, `interrupt`, and breakpoint state coherent through an
  attached controller or fail before executing the operation.
- Finalize sessions idempotently and terminate only controller processes owned
  by the recorded session.
- Enforce read-size and response-size limits before invoking gdb.
- Record every gdb command batch and timeout.
- Preserve failed debug artifacts for investigation.

Error categories should follow the architecture:

- `configuration_error` for missing run state, incompatible profiles, unsafe
  arguments, malformed or unsafe gdbstub endpoints, absent `vmlinux`, or
  unsupported KASLR policy.
- `missing_dependency` for absent `gdb`.
- `debug_attach_failure` for failed gdbstub attach, target not responding, or
  failed identity validation against a live target.
- `infrastructure_failure` for unexpected subprocess, filesystem, locking,
  gdbstub port availability, or transcript failures.

## Artifact Collection

`artifacts.collect` should include debug artifacts when present:

- session files
- transcripts
- command metadata JSONL
- debug summaries

Raw transcripts should be treated as potentially sensitive because gdb output
can include command strings, memory contents, register values, and paths.
Returned snippets and artifact bundle summaries should pass through the existing
redaction path.

## Provider Registry

Sprint 4 should add a `local-qemu-gdbstub` provider capability with operations
for the implemented `debug.*` tools and `workflow.build_boot_debug`.

The registry should remove Sprint 4 operations from `stub-workflows` as they
become implemented. Remaining future debug operations, if any, should continue
to return structured `not_implemented` responses rather than fake success.

## Testing Strategy

Most Sprint 4 coverage should be unit tests with fake runners. Live
libvirt/gdbstub tests should be opt-in like the existing boot integration test.

Required tests:

- Libvirt domain XML includes a QEMU gdbstub endpoint only when debug boot is
  enabled.
- Debug boot parses gdbstub endpoints into structured host/port values and
  rejects malformed endpoints, non-local hosts, out-of-range ports, and occupied
  ports before starting the domain.
- Debug boot records the gdbstub endpoint in the boot plan and summary.
- Debug boot applies or requires `nokaslr` for the default debug profile.
- Debug boot rejects unsafe or incomplete profiles.
- `debug.start_session` fails for missing `vmlinux`, missing endpoint, missing
  `gdb`, unsupported KASLR policy, and failed attach.
- GDB command planning uses constrained command batches and rejects arbitrary
  commands.
- GDB command planning rejects invalid symbols, unsupported registers, oversized
  memory reads, negative byte counts, and out-of-range addresses before invoking
  gdb.
- `debug.start_session` records a session file, manifest `debug` result,
  transcript artifacts, and redacted response snippets.
- Strict symbol identity requires both same-run artifact linkage and a live
  target version-symbol match.
- Breakpoint, register, symbol, and memory handlers parse fake gdb output into
  stable JSON.
- `debug.continue`, `debug.interrupt`, and breakpoint operations either share an
  attached controller and update session state predictably or fail before
  claiming stateful behavior.
- `debug.end_session` is idempotent, terminates owned attached controllers,
  preserves artifacts, and finalizes sessions whose controllers already exited.
- `debug.evaluate` accepts only named predefined inspectors.
- `workflow.build_boot_debug` stops at the first failed stage and does not run
  smoke tests.
- Artifact collection includes debug transcripts and summaries when present.
- Provider registry advertises the new debug provider capability and no longer
  lists implemented Sprint 4 tools under `stub-workflows`.

## Main Risk

True long-lived debugger process management can become flaky if Sprint 4 tries
to behave like a full debugger. The sprint should avoid that trap by using
short-lived, transcript-backed gdb invocations where possible and keeping only
enough durable session state to make MCP tools coherent.

The implementation should preserve a clean controller boundary so a later
GDB/MI adapter can replace the subprocess controller when deeper debugger
orchestration is justified.
