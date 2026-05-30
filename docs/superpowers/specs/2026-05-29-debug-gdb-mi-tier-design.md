# `debug.gdb` KGDB/RSP tier (gdb/MI) — design & decomposition

**Type:** Design spec · **Issue:** #13 (epic #9) · **ADR:** [0019](../../adr/0019-debug-gdb-mi-tier-decomposition.md), [0020](../../adr/0020-gdb-mi-symbol-resolution-mechanism.md), [0021](../../adr/0021-gdb-mi-phase-c-session-registry-and-execution-state.md), [0022](../../adr/0022-gdb-mi-phase-d-module-symbol-loading.md), [0023](../../adr/0023-gdb-mi-phase-d-rsp-stall-detect-and-report.md), [0024](../../adr/0024-gdb-mi-phase-d-transport-adaptation.md) · **Status:** Phases A–C implemented (2026-05-29); D designed (2026-05-29)

## Summary

Issue #13 adds the **source-level** kernel debug tier: breakpoints, single-step,
locals, backtraces, and register/memory access over the gdb Remote Serial
Protocol (RSP), driven through the gdb **Machine Interface** (`gdb --interpreter=mi3`)
and parsed with `pygdbmi` so the agent receives typed JSON instead of scraped
terminal text. It works over two transports: the QEMU gdbstub (RSP over TCP) and
serial KGDB (RSP demuxed off the console by `agent-proxy`/`kdmx`, #10).

This spec covers the tier as a whole and **intentionally splits it into four
focused sub-issues** so each ships as a defensible PR — mirroring how #11
(`debug.introspect`) was decomposed into #51–#56. ADR
[0019](../../adr/0019-debug-gdb-mi-tier-decomposition.md) records the load-bearing
decisions (persistent MI engine replacing the batch text-scraper; in-place
migration of the existing `debug.*` surface; the `pygdbmi` dependency; the phase
boundaries) and their rejected alternatives.

## Why this is a migration, not a greenfield add

A `debug.*` surface already exists from the Phase-4 live-debug MVP (#5):
`debug.start_session`, `debug.set_breakpoint`, `debug.continue`,
`debug.read_memory`, `debug.read_registers`, `debug.evaluate`,
`debug.interrupt`, `debug.end_session` (`server.py:6621–6781`). It drives gdb in
**one-shot batch mode** — `argv = [gdb_path, "-nx", "-batch", "-q"]`
(`providers/qemu_gdbstub.py:305,786`) — a fresh gdb per call, parsing
human-formatted output, unable to hold breakpoint/stepping state across calls.
#13 replaces that engine with a persistent `gdb -i=mi3` process and re-points the
existing tools at it (gaining the missing `step`/`next`/`finish`, frames, and
variable listing). Per "replace, don't deprecate," the batch paths are removed,
not kept alongside.

## Dependencies — all satisfied

| Dependency | Status | What #13 consumes |
|---|---|---|
| #10 transport abstraction | **closed** | `TransportSession.rsp_endpoint`; `transport.open()`/`close()`; `transport.inject_break` |
| #68 `StopCapableGuard` (ADR 0015) | **merged** | single stop-capable session per `TargetKey`, acquired in `transport.open()` |
| #66 `SessionGuard` (ADR 0013) | **merged** | precondition/teardown + guaranteed-resume invariant |
| #70 symbol version-lock (ADR 0017) | **merged** | pre-attach `build_id` verification primitive |
| #71 break policy (ADR 0018) | **merged** | `BreakPolicy` → break method from channel topology + `PlatformMetadata` |
| #69 watchdog relax/restore (ADR 0016) | **merged** | watchdog handling across an interactive stop |
| #65 secrets + redaction (ADR 0012) | **merged** | redaction of RSP/console transcripts before response + persistence |

### Prerequisites (verified)

The transport/admission/guard seam is not just "available" — it is **already wired
and integration-tested** for the local QEMU path, so Phase A inherits working
plumbing rather than building it:

- `target.boot` publishes a READY snapshot plus a `qemu-gdbstub` `TransportRef`
  via `_publish_boot_ready_snapshot` (`server.py:1775`, snapshot producer at
  `server.py:1485-1524`).
- `debug.start_session` has a `transport_enabled` branch (`server.py:4180`) that
  builds an `OpenRequest` from that snapshot (`_debug_open_request`,
  `server.py:3968`) and calls `transaction.open()`, which acquires the
  `StopCapableGuard` as step 4 of the admission transaction
  (`coordination/transaction.py:249`).
- `test_transport_open_close_integration.py` exercises this open/guard/close cycle
  end to end.

**Residual Phase A gap (the real work).** The dependency table is accurate, but
the seam is wired *around* the provider, not *through* it: `QemuGdbstubProvider`
still drives gdb in `-batch` mode against the **raw boot endpoint** that
`debug.start_session` reads from the boot result
(`server.py:4124` → `start_session(..., gdbstub_endpoint=...)` at `server.py:4233`;
`target remote {host}:{port}` in `providers/qemu_gdbstub.py:288-302`). It does
**not** consume `TransportSession.rsp_endpoint`. Phase A's residual scope is to
re-point the new MI engine at `TransportSession.rsp_endpoint` instead of the raw
boot endpoint, so the guard-protected transport session is the only RSP path.

## Phase breakdown (sibling issues under #13)

Each phase lands behind the constrained `ALLOWED_DEBUG_OPERATIONS` gate
(`config.py`), so partially-delivered operations stay unreachable until their
phase merges.

### Phase A — MI engine foundation
**Scope.** New `providers/gdb_mi.py`: persistent `gdb --interpreter=mi3`
subprocess + `pygdbmi` parse layer (add the pinned dependency). RSP connect via
`-target-select remote <host>:<port>` against **`TransportSession.rsp_endpoint`**
— *not* the raw boot endpoint the legacy provider reads (see "Prerequisites
(verified)"), so the guard-protected transport session owns the only RSP path.
Attach/detach lifecycle with a persisted session id. **`StopCapableGuard`
acquisition through `transport.open()`** (§5.3) on every transport — including
`qemu-gdbstub`, where there is no console lease and the guard is the only thing
preventing a second stop-capable session. **Guaranteed resume invariant:** any
engine crash, RSP timeout, or tool-level exception returns a best-effort
`continue` + report and releases the guard/lease — the target is never left
`HALTED`.

**gdb version & MI-capability probe.** Today `host.check_prerequisites` checks
only that `gdb` is *present* (`prereqs/checks.py:48`). Phase A pins a **minimum
gdb version of 9.1** — the release in which the GDB manual documents the `mi3`
interpreter was introduced ("GDB/MI" chapter) — and adds an MI-capability probe
that does more than read the version string: it **runs one mi3 MI command and
asserts a well-formed `^done` record**. As implemented, the probe is
`gdb -nx -q -ex 'interpreter-exec mi3 "-list-features"' -ex quit` — feeding the MI
command via `-ex 'interpreter-exec mi3 ...'` from CLI mode (gdb's `-ex` runs *CLI*
commands, so a bare `--interpreter=mi3 -ex "-list-features"` would report
`-list-features` as an undefined CLI command and never reach MI; `interpreter-exec`
runs it in the mi3 interpreter and prints its `^done`, with no stdin channel
needed). **Pass:** the probe returns a valid mi3 `^done` record. **Fail:** gdb absent, gdb < 9.1, or no
valid mi3 `^done` record (older gdb may accept the `mi3` *name* without yielding
usable records) → `host.check_prerequisites` reports the probe failed and the tier
**hard-fails with a clear, actionable message** naming the detected version and
the required minimum. `mi3` is required — there is no `mi2` fallback.

**Acceptance.** Against local QEMU gdbstub: attach over `rsp_endpoint`, read one
MI record as typed JSON, detach cleanly; a second concurrent stop-capable attach
is refused by the guard. The MI-capability probe passes on gdb ≥ 9.1 by returning
a valid mi3 `^done` record, and hard-fails with a version-naming message on
older/`mi3`-less gdb.
**Fault-injection acceptance.** With a session attached and `HALTED`: an induced
engine crash, an induced RSP timeout, and a raised tool exception each (a) return
the target to `EXECUTING`, (b) release the `StopCapableGuard` + any lease, and
(c) for ssh-tier concurrency, behave per the §5.6 contract on both sides of the
fault: **during the fault** (target `HALTED`) a concurrently-issued ssh-tier
operation is **fast-rejected** (not blocked behind the stop), and **after the
guaranteed resume** a fresh ssh-tier operation **succeeds** with the target back
in `EXECUTING`.

### Phase B — symbols & provenance *(implemented 2026-05-29, #80; ADR [0020](../../adr/0020-gdb-mi-symbol-resolution-mechanism.md))*
**Scope.** Load `vmlinux` symbols; verify `KernelProvenance` `build_id`
**pre-attach in the handler, not over RSP** (consumes ADR 0017 / #70); fail loud
on mismatch rather than emitting garbage.

**What was already in place vs the Phase B delta.** Two pieces landed before #80
and are consumed unchanged: (1) the pre-attach provenance gate is ADR 0017 / #70's
`_verify_gdb_symbol_version_lock`, called in `debug_start_session_handler` before
any acquisition or attach (`provenance_mismatch` / `provenance_missing` /
`vmlinux_build_id_unreadable`, plus `provenance_corrupt` for a malformed recorded
id); (2) symbol *load* is Phase A's `attach()` running `-file-exec-and-symbols`
before `-target-select remote`. The Phase B delta (ADR 0020) is **symbol
resolution by name**: `GdbMiEngine.resolve_symbol` issues
`-data-evaluate-expression "&<name>"` for a name validated to a bare C identifier,
parses the address from the `^done` value, and the attach probe resolves the fixed
canonical symbol `linux_banner` after `^connected` and before resume/detach,
surfacing the typed result under `mi_probe.symbol`. The surfaced value is the
link-time symbol-table address (`&<name>` reads the table, not target memory): it
proves the symbol resolves, not its relocated runtime address (KASLR/module
relocation is a Phase D concern). A resolution fault rides the same
guaranteed-resume teardown. No new agent-facing operation and no
`ALLOWED_DEBUG_OPERATIONS` change — `-data-evaluate-expression` is internal and
single-purpose, gated by the name-shape check (not the raw-expression hatch ADR
0019 rejected).

**Acceptance.** A `vmlinux` whose `build_id` does not match the booted image is
rejected before attach with a `configuration_error`-class response (the MI
engine's `attach()` is never reached); a boot with no recorded `KernelProvenance`
fails `provenance_missing` rather than attaching against unverified symbols; a
matching image attaches and resolves a symbol by name (the probe surfaces the
typed `linux_banner` resolution).

### Phase C — core operations, MI-typed *(design 2026-05-29, #81; ADR [0021](../../adr/0021-gdb-mi-phase-c-session-registry-and-execution-state.md))*
**Scope.** Migrate the **complete** `DEBUG_METHOD_OPERATIONS` set
(`server.py:248-259`) onto MI typed JSON — `read_registers`, `read_symbol`
(`-data-evaluate-expression "<validated_symbol>"`, a name-shape-gated value read),
`read_memory` (4096-byte cap), `evaluate`, set/clear/list breakpoints, `continue`,
`interrupt`, `end_session` — and add the new structured ops: `step`/`next`/`finish`,
`-stack-list-frames` (`backtrace`), `-stack-list-variables` (`list_variables`),
set/clear **watchpoints**. **Delete** the corresponding `-batch` paths in
`qemu_gdbstub.py`; no `DEBUG_METHOD_OPERATIONS` entry is left calling a deleted
method. `start_session`'s legacy live-banner identity scrape
(`live_banner_match`/`symbol_identity_required`) is **subsumed by** the pre-attach
build_id provenance gate (ADR 0017 / #70) and removed; the migrated `start_session`
keeps the engine attached and retains the typed `mi_probe` connect record +
`linux_banner` resolution in its success data (now from the live session, not a
detach-probe) — the existing `test_server_debug_mi_probe` assertions migrate to the
still-attached shape.

**Live session held across calls (ADR 0021 decision 1).** The acceptance spans
separate MCP tool calls (set a breakpoint, *then* continue, *then* backtrace), so
the `gdb -i=mi3` engine must stay alive between calls — a breakpoint set in a
prior, exited process never fires. A new in-process `GdbMiSessionRegistry`
(lock-guarded dict in `providers/gdb_mi.py`) holds the live `GdbMiAttachment`
keyed by the `DebugSession.session_id`. `debug.start_session` registers it (and no
longer resumes-and-detaches as the Phase-A probe did); each per-op handler looks
it up; `debug.end_session` and every guaranteed-resume teardown reap it. A lookup
miss is `CONFIGURATION_ERROR` / `no_live_session` (server restarted or session
already reaped) routing the agent back to `debug.start_session`. gdb's own MI
breakpoint numbers are the breakpoint identity; `debug.list_breakpoints` reads
`-break-list` from the live engine (source of truth), with a typed JSON ledger
persisted into the manifest for enumerability.

**Execution-state: HALTED for the whole window (ADR 0021 decision 2).** The
durable record is parked HALTED at attach and stays HALTED until `end_session`.
The interactive resume verbs (`continue`/`step`/`next`/`finish`) are
**continue-and-wait-for-stop, bounded by a validated 1–`MAX_INTERACTIVE_WAIT_SEC`
(60s) timeout** (default 10s — deliberately *not* the legacy 1–3600s, so a blocking
call holding `debug_lock` can never outlast a client request timeout or wedge
`end_session`): they issue the MI exec verb, wait for the `*stopped` async record,
and return it as a typed `StopRecord`; on timeout they issue `-exec-interrupt`
(short 10s bound) to return to a known stopped state and report `timed_out=true`.
"Run until this breakpoint" is the agent re-polling `debug.continue`, not one long
blocking call. A terminal `*stopped` reason (`exited*` — kernel panic / inferior
gone) is **not** a HALTED stop: it reaps the session and reports `session_exited`
(DEBUG_ATTACH_FAILURE) so no later verb runs against a dead inferior. The session
is otherwise always HALTED between calls, so `target.run_tests` stays gated
`target_halted` for the window and never races a breakpoint that silently halts a
"running" kernel. The kernel returns to EXECUTING exactly once, at `end_session`'s
resume-and-detach. This narrows `debug.continue` to never admit ssh-tier
mid-session — a deliberate Phase-C safety choice; a detached free-running continue
is out of scope.

**MI eval stays internal-only behind the inspector allowlist.**
`-data-evaluate-expression` is used **only as the internal implementation** of the
existing named inspectors — today `debug.evaluate` accepts `kernel_version` and
`symbol_address` and rejects any unknown inspector with `CONFIGURATION_ERROR`
(`providers/qemu_gdbstub.py:497-546`). Phase C preserves that surface exactly: it
does **not** add an arbitrary-expression capability. Swapping the batch
text-scrape for an MI `-data-evaluate-expression` call is an implementation
detail behind the same allowlist; this keeps the constrained-debug-surface
invariant (CLAUDE.md, `ALLOWED_DEBUG_OPERATIONS`) intact.
**Acceptance — integration-only (env-gated, skipped in local CI, never counted as a passing gate when skipped).**
Against local QEMU gdbstub: set a breakpoint by symbol, continue, hit it,
backtrace, read a local — all returned as structured JSON via MI;
`step`/`next`/`finish` return typed `StopRecord`/frame records; set a **watchpoint**
(`-break-watch`), continue, and stop on the write with a typed `StopRecord`. The
existing env-gated local-QEMU gdbstub coverage passes on the MI engine.

**Acceptance — unit-level (runs in CI against the injected `FakeController`/`MiController` seam, so the state machine is verified without live hardware).**
- A scripted deferred `*stopped` (arriving on a later `read()`, not the
  `-exec-continue` `^running` return) yields a typed `StopRecord` from
  `debug.continue`.
- A continue whose wait expires issues `-exec-interrupt`, collects the
  `*stopped (SIGINT)`, returns `timed_out=true`, leaves the durable
  `execution_state` HALTED, and the whole call returns within its ≤60s ceiling
  (+10s interrupt fallback).
- A `*stopped, reason=exited*` arriving during a continue reaps the session and
  returns `session_exited` (DEBUG_ATTACH_FAILURE), not a HALTED `StopRecord`.
- `debug.interrupt` against an already-stopped engine returns success (the
  non-raising interrupt primitive tolerates a "not running" `^error`).
- `debug.read_memory` with `byte_count=4097` is rejected `CONFIGURATION_ERROR`
  by the engine **before** any MI command (the 4096-byte cap, re-homed off the
  deleted batch validator).
- `debug.evaluate` with `kernel_version` / `symbol_address` returns MI-typed JSON;
  an **arbitrary expression (any unknown inspector / raw expression string) is
  rejected** with a `CONFIGURATION_ERROR`-class response — no MI
  `-data-evaluate-expression` is reachable without going through a named inspector.
- A mutating `debug.*` op against a session whose live engine is gone returns
  `CONFIGURATION_ERROR` / `no_live_session` when the durable ownership record still
  exists (post-restart orphan), and `legacy_session_no_ownership` when it does not
  (the fence runs before the live lookup, ADR 0021 decision 1) — never a silent
  no-op.
- set/clear watchpoint issue the expected `-break-watch`/`-break-delete` MI verbs
  and are refused when the `DebugProfile` narrows them out of `enabled_operations`.
- every new typed record (`StopRecord`, frames, `list_variables`, register values,
  memory bytes) is routed through `Redactor` before return **and** before
  persistence: a secret-looking local/register value is redacted in both the
  response and the manifest, and `list_variables` output is bounded
  (`MAX_RESPONSE_SNIPPET`) so a deep frame cannot bloat the response.
- the shipped default `DebugProfile`s enable the new structured/watchpoint ops
  (they ride the `ALLOWED_DEBUG_OPERATIONS` default factory); a profile that
  supplied an explicit narrowed `enabled_operations` must opt the new names in —
  this compatibility expectation is documented, not silently assumed.

**Acceptance — static.** No batch-mode (`-batch`) gdb invocation remains anywhere
(CI grep tripwire).

### Phase D — module symbols, robustness, serial transport *(designed 2026-05-29, #82; ADRs [0022](../../adr/0022-gdb-mi-phase-d-module-symbol-loading.md), [0023](../../adr/0023-gdb-mi-phase-d-rsp-stall-detect-and-report.md), [0024](../../adr/0024-gdb-mi-phase-d-transport-adaptation.md))*
**Scope.** Per-module section-address discovery + `add-symbol-file` at runtime
addresses. `set remotetimeout`, retry/backoff, transport-stall detect-and-report
(never hang the tool call). Break entry via `transport.inject_break` using ADR
0018's `BreakPolicy`. Serial-KGDB (demuxed) smoke test + transport-quality
warning (over SOL/HMC vterm, warn that RSP may be unreliable and suggest
`debug.kdb` / `debug.introspect`). `docs/debug-gdb.md` incl. ppc64le caveats.

**Decided (Phase D).** Four decisions land the open points above:

- **Module symbols (ADR 0022).** A new `debug.load_module_symbols` op reads the
  per-module section bases from guest `/sys/module/<name>/sections/{.text,.data,
  .rodata,.bss}` over the already-wired injectable `SshRunner` seam (not a live
  drgn program contending for the HALTED target, not the agent), resolves the
  module `.ko`/`.ko.debug` under the recorded build tree via an injectable finder
  confined by `safety/paths.py`, and the engine issues
  `-interpreter-exec console "add-symbol-file <ko> <text> -s .data <addr> …"`. The
  module name is gated to a C identifier and every address to a `0x` hex literal
  before interpolation; a missing object or unreachable SSH is a loud
  `CONFIGURATION_ERROR`, never a silent skip that arms an unresolved breakpoint. A
  `loaded_modules` ledger is persisted into the `DebugSession`.
- **RSP-stall (ADR 0023).** `attach()` sets `remotetimeout` before the RSP connect
  and bounds the connect with a small injectable retry/backoff for transient
  connect races only (never re-issuing an interactive verb). A timeout on an
  established session raises a `GdbMiError` carrying `code="transport_stall"` /
  `INFRASTRUCTURE_FAILURE`; the handler distinguishes it from a benign `^error`
  and runs the full guaranteed-resume teardown (reap + `force_resume` +
  transport teardown), reporting `transport_stall` and routing the agent to
  `debug.start_session` (re-attach from scratch — never re-sync a stalled RSP,
  §5.4/§9.3), `debug.kdb`, `debug.introspect.run`. Every other `GdbMiError` keeps
  Phase-C contained-error behaviour.
- **Break-entry + quality warning (ADR 0024).** Break-entry routes off the
  session's recorded `break_plan.method`: `gdbstub_native` → engine
  `-exec-interrupt` (unchanged); any other method → `transport.inject_break` then
  `wait_for_stop`. The tier never re-derives the method. A transport-quality
  warning (`data["transport_quality_warning"]` + `debug.kdb` /
  `debug.introspect.run` in `suggested_next_actions`; `ToolResponse` has no
  `warnings` field) fires when the admitted RSP rides a lossy out-of-band console
  — `line_role == SHARED_CONSOLE` and `console_kind in {HVC, VIRTIO}` — and is
  silent on the clean QEMU `RSP`/`UART` path.
- **Serial fixture (ADR 0024, path b).** The serial break/continue test
  (`tests/test_gdb_mi_serial_kgdb_integration.py`) is gated exactly like
  `test_serial_local_transport_integration.py` (skipped without `agent-proxy`/the
  PTY fixture, requirable with `LDM_REQUIRE_AGENT_PROXY=1`). No false green: in
  local-only CI it is reported **skipped** with the prerequisite named, never a
  passing gate. The QEMU-gdbstub criteria ship as the unit-testable core.
**Serial-KGDB fixture prerequisite.** The serial break/continue criterion needs a
producible target: a PTY-backed `serial-local` transport plus `agent-proxy`/`kdmx`
demux yielding an RSP endpoint + break signal, gated exactly like
`test_serial_local_transport_integration.py` (skipped when `agent-proxy`/the PTY
fixture is unavailable). That fixture today yields an RSP endpoint over PTY but no
test drives an actual RSP break/continue over it. Two acceptable paths: (a) build
this fixture as part of Phase D, or (b) gate the serial criterion on the
out-of-band-console work (#15/#16) and ship Phase D's QEMU-gdbstub criteria first.
**No false green:** in local-only CI without the serial fixture, the serial
break/continue test is reported **skipped** (with the missing prerequisite named),
never presented as a passing gate.
**Acceptance.** Module breakpoints resolve at correct runtime addresses; an
induced transport stall is reported (not hung) and the target is resumed; a basic
break/continue cycle works over a demuxed serial line **when the serial fixture
above is present** — otherwise that one criterion is explicitly skipped, not
counted as passed.

## Coordination (interface contract)

Per `docs/specs/interface-contracts.md`:

- **Stop-capable tier:** one per target, **mutually exclusive with `debug.kdb`**
  (#12), driving `EXECUTING`↔`HALTED` (§5.6), enforced by the `StopCapableGuard`
  acquired in `transport.open()` (§5.3) on every transport including
  `qemu-gdbstub`.
- Uses the transport `rsp_endpoint`; `required_caps=[provides_rsp]` (§3.3).
- Consumes `KernelProvenance` (§4.2) for symbol version-locking; MUST fail loud
  on `build_id` mismatch.
- Break entry executes #10's `inject_break` using #17's `BreakPolicy`,
  parameterized by provisioning's `PlatformMetadata` facts (§4.1).
- A provisioning `reset()` (incl. `mode=kexec`) fully invalidates an open
  session — re-attach from scratch, never re-sync RSP (§5.4, §9.3).

## Sibling issues

- **Phase A** — `debug.gdb`: persistent gdb/MI engine + RSP attach foundation. *(foundation the others build on)*
- **Phase B** — `debug.gdb`: vmlinux symbols + `KernelProvenance` version-lock.
- **Phase C** — `debug.gdb`: core MI operations (break/step/frames/eval/mem/regs); retire batch engine.
- **Phase D** — `debug.gdb`: module symbols, RSP-stall robustness, serial-KGDB transport + docs.

#13 remains the umbrella tracking issue (it is listed under epic #9). Delivery
order is strict **A → B → C → D**: C's acceptance ("set a breakpoint by symbol …
read a local") depends on B's symbol/provenance work, so C is sequenced after B
rather than reviewed in parallel with it; C also deletes the batch paths, which
must land after B is in place.

## References

- gdb/MI: gdb manual "GDB/MI" chapter; `pygdbmi`
- `Documentation/dev-tools/kgdb.rst` (kgdboc, connecting gdb)
- ADR [0017](../../adr/0017-symbol-version-lock-gdb-tier.md), [0018](../../adr/0018-break-injection-policy-mapping.md), [0019](../../adr/0019-debug-gdb-mi-tier-decomposition.md)
- `docs/specs/interface-contracts.md` §3.3, §4.1, §4.2, §5.3, §5.6, §9.3
- Decomposition precedent: `docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md`
