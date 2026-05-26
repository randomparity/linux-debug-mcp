# Transport provider abstraction + agent-proxy integration — design

**Issue:** #10 (epic #9) · **Status:** approved design, ready for implementation plan
**Contract:** `docs/specs/interface-contracts.md` (settled; this work implements 01's side)

## 1. Purpose & scope

Introduce a `transport`/console provider abstraction that turns any platform's
serial/console access into a uniform pair of artifacts — a **console byte
stream** and an optional **TCP gdb-RSP endpoint** — discoverable through
`providers.list`, with the interface contract's admission / console-lease /
stop-guard / lifecycle semantics enforced at `transport.open()`.

This issue is the keystone of the remote-interactive-debug epic: every
serial-based transport (#06 BMC, #07 POWER) later reduces to "produce a byte
stream and feed it to this layer," and the debug tiers (#12 kdb, #13 gdb) consume
the `TransportSession` it produces.

### 1.1 In scope

- A `Transport` ABC + registry, discoverable via `providers.list` with capability
  flags (`provides_console`, `provides_rsp`, `supports_uart_break`).
- A `TransportSession` exposing `console_endpoint`, `rsp_endpoint` (optional),
  `status`, and `open`/`close`/`health` lifecycle.
- A managed `agent-proxy` backend behind a `ProxyBackend` Protocol: spawn the
  `console^gdb` port pair, dynamic port allocation, crash detection, teardown.
- The contract pieces the ownership map (§6) assigns to **01**: the `ConsoleLease`
  manager, the per-`TargetKey` admission service + the `open()` transaction,
  break-plan-aware transport selection (§3.3), and the execution-state gate (§5.6).
- A `serial-local` reference transport (local `/dev/tty*`, unix socket, or PTY).
- Refactor of the existing `qemu-gdbstub` debug path onto the interface with **no
  externally observable behavior change**.
- Programmatic break injection (`inject_break`) executing a pre-admitted plan.
- An `agent-proxy` availability check in `host.check_prerequisites`.

### 1.2 Out of scope

- Concrete BMC/HMC/NovaLink/ser2net transports (#06, #07).
- The `kdmx` backend — deferred behind the `ProxyBackend` Protocol (see §11).
- The real implementations of the externally-owned seams: secret *storage* and
  break *policy* (#08), and the provisioning provider epic (#38) that will produce
  real `TargetHandle`s, lifecycle events, and the snapshot store. This issue
  defines thin Protocols + minimal local implementations for all of them (§5).

### 1.3 Resolved decisions (from brainstorming)

1. **Scope boundary.** Build 01's transport core *and* the contract pieces 01
   owns; provide thin Protocols + minimal local impls for the #08/provisioning
   pieces so the qemu-gdbstub and serial-local paths actually run and the §8
   conformance tests pass. Others replace an impl behind a stable Protocol later.
2. **Concurrency/state model.** Synchronous + threaded. An in-process session
   registry (held by the FastMCP app) owns the agent-proxy `Popen` handles,
   sockets, and lease/guard tokens, keyed by `TargetKey`. Per-`TargetKey`
   `threading` locks realize the contract's "short critical section"; a
   `threading.Event` per admission handle is the cancel fence; awaited invalidation
   is synchronous teardown bounded by `teardown_deadline` with force-reap.
3. **agent-proxy delivery.** Detect on `PATH` (or a configured path) and document a
   pinned source checkout + build in `host.check_prerequisites` remediation. No
   binary is ever vendored.
4. **kdmx.** Implement `agent-proxy` now behind a `ProxyBackend` Protocol; defer
   `kdmx` as a drop-in.
5. **Code layout.** Layered packages mirroring the ownership map:
   `transport/` (01 core), `coordination/` (01 cross-cutting), `seams/`
   (Protocols + minimal impls for externally-owned pieces).
6. **Error taxonomy.** Add two `ErrorCategory` values (`STALE_HANDLE`,
   `TRANSPORT_CONFLICT`); express the remaining contract failures via a
   machine-readable `details.code` under reused categories.
7. **ssh-tier admission.** The existing ssh-backed live ops (smoke-test reads, the
   current debug reads) route through the same `admit()` now — the local boot
   adapter registers the `TargetKey` snapshot at `READY` so those ops can resolve a
   key and be execution-state-gated.

## 2. Package layout

```
src/linux_debug_mcp/
  transport/
    base.py          # Transport ABC, TransportCapability, TransportSession,
                     #   TransportRef, OpenRequest, Endpoint, TransportRegistry
    proxy.py         # ProxyBackend Protocol + AgentProxyBackend (kdmx deferred)
    serial_local.py  # `serial-local` reference transport
    qemu_gdbstub.py  # `qemu-gdbstub` transport adapter (rsp passthrough)
    break_inject.py  # inject_break execution against an admitted break plan
  coordination/
    lease.py         # ConsoleLease manager: acquire/release/revoke (§5.2)
    admission.py     # SnapshotStore + per-TargetKey admission service +
                     #   the open() transaction & rollback (§5.3)
    selection.py     # break-plan-aware transport selection (§3.3)
    registry.py      # in-process TransportSessionRegistry + teardown reaper (§5.5)
  seams/
    target.py        # TargetKey/TargetHandle/TargetState/PlatformMetadata/
                     #   KernelProvenance/LeaseInfo schemas + local-qemu adapter [prov]
    secrets.py       # SecretsResolver Protocol (+ env/file impl)            [#08]
    guard.py         # StopCapableGuard / SessionGuard Protocol (+ impl)     [#08]
    break_policy.py  # BreakPolicy Protocol (facts -> method, §4.1) (+ impl) [#08]
    lifecycle.py     # LifecycleDispatcher Protocol (+ in-process impl)      [prov]
```

Each `seams/` Protocol ships a minimal default implementation; the bracketed owner
later replaces the impl without touching `transport/` or `coordination/`.

## 3. Data model

All new wire types are Pydantic models inheriting the project `Model` base
(`extra="forbid"`, `validate_assignment=True`). Fields transcribe the contract;
choices made here are called out.

### 3.1 Provisioning-owned schemas (`seams/target.py`)

- `TargetKey` — `(provisioner: str, target_id: str)`; hashable identity key.
- `TargetState` — enum `ACQUIRING|PREPARING|BOOTING|READY|DEBUGGING|RESETTING|
  CRASHED|RELEASING`. The `DEBUGGING` sub-states `EXECUTING|HALTED` are tracked on
  the session/registry, not the enum.
- `PlatformMetadata` — `console_kind: uart|hvc|virtio`, `console_count: int`,
  `dedicated_debug_line: bool`, `ssh_reachable: bool`, `break_hints: list[enum]`.
- `KernelProvenance` — `build_id, release, vmlinux_ref, modules_ref|None, cmdline,
  config_ref|None`.
- `LeaseInfo` — `lease_id, holder, expires_at: datetime|None, renewable: bool`.
- `SshEndpoint` — `host, port, user, key_ref` (`key_ref` resolved via Secrets).
- `TargetHandle` — `target_id, provisioner, generation: int, arch, native: bool,
  state: TargetState, access{ssh: SshEndpoint|None, transports: list[TransportRef]},
  platform: PlatformMetadata, kernel: KernelProvenance, lease: LeaseInfo|None`.

### 3.2 Transport boundary schemas (`transport/base.py`)

- `Endpoint` — `{host: str, port: int}`. **Choice:** reuse the existing
  qemu-gdbstub convention — bind/report `127.0.0.1` only; port `1..65535`. Both
  console and RSP endpoints use this shape.
- `TransportRef` — `provider, channel_id, line_role: shared_console|
  dedicated_debug|rsp, caps: list[str], target_ref: dict, opts: dict,
  secret_refs: list[str]`. `(provider, channel_id)` is the channel key;
  `channel_id` is unique within a target's `transports[]`.
- `OpenRequest` — `target_key, generation: int, transport_ref, required_caps:
  list[str], platform, lease: LeaseInfo|None, min_lease_ttl: int|None` (seconds;
  `None` ⇒ `DEFAULT_MIN_LEASE_TTL_SECONDS = 300`).
- `TransportCapability` — surfaced in `providers.list`; `provider_name`,
  `provider_family="transport"`, `architectures`, and the three bool flags
  `provides_console / provides_rsp / supports_uart_break`. **Choice:** a dedicated
  model rather than overloading `ProviderCapability`, so the flags are first-class.
- `BreakPlan` — `method: gdbstub_native|uart_break|agent_proxy_break|sysrq_g`,
  `channel_id`, `rationale: str`.
- `TransportSession` — `session_id, target_key, generation, provider, channel_id,
  console_endpoint: Endpoint|None, rsp_endpoint: Endpoint|None, status:
  opening|ready|degraded|closed, console_lease_token: str|None, stop_guard_token:
  str|None, break_plan: BreakPlan|None, backend_pid: int|None, created_at,
  ended_at|None, artifacts: list[ArtifactRef]`. **Choice:** `session_id =
  "transport-{uuid4hex}"`; the session is persisted as JSON under
  `<run>/debug/transports/<session_id>.json` for postmortem visibility, while
  liveness is owned by the in-process registry.

### 3.3 Coordination schemas

- `ConsoleLease` (`coordination/lease.py`) — `target: TargetKey, owner:
  provisioner|transport|free, token: str|None, generation: int`. Mutated only via
  `acquire`/`release`/`revoke`.
- `AdmissionHandle` (`coordination/admission.py`) — opaque scoped handle carrying a
  `threading.Event` cancel fence; states pending → promoted/rolled-back.

### 3.4 Secrets (`seams/secrets.py`)

Extends the existing `SecretReference`. `SecretsResolver` Protocol:
`resolve(refs: list[str]) -> dict[str, str]`. The minimal impl resolves `env` and
`file` kinds (not `external`). Resolved values are never returned in tool output,
session JSON, or logs.

## 4. The `open()` transaction, admission & lifecycle

### 4.1 Snapshot store

`coordination/admission.py` holds a `SnapshotStore`: `TargetKey -> {generation,
transports, lease, platform, state}`. The local-qemu adapter (`seams/target.py`)
writes the authoritative snapshot when it mints a `TargetHandle` at `READY`;
provisioning (#38) later becomes the writer. Admission re-binds every request
against this store — never against caller-supplied copies.

### 4.2 Admission service (short critical section)

A keyed lock table gives one `threading.RLock` per `TargetKey`.
`admit(target_key, op) -> AdmissionHandle`:

1. **Freshness + snapshot binding.** Reject `stale_handle` unless `generation` ==
   the snapshot's current. Re-bind `transport_ref.(provider, channel_id)` to a
   currently-offered channel whose `target_ref`/`line_role`/`caps` equal the
   snapshot's (foreign/hand-edited ref ⇒ reject). TTL admission (§3.4 of the
   contract) uses the **snapshot's** `lease.expires_at`, not the caller's copy.
2. **State gate.** Require a live, attachable-for-`op` state: `READY`, or
   `DEBUGGING/EXECUTING` for an ssh-tier op; never `ACQUIRING/PREPARING/BOOTING/
   RESETTING/RELEASING`, and never `DEBUGGING/HALTED` for an ssh-tier op.
3. Register a **pending binding** (`AdmissionHandle` + cancel fence) under the
   `TargetKey`; release the lock.

All live ops enter through `admit()`: `transport.open()` *and* the ssh-backed live
tiers (smoke-test reads, current debug reads). Only offline vmcore postmortem
bypasses it.

### 4.3 `transport.open()` is a transaction

Steps 1 and 7 take the short admission lock; steps 2–6 run **outside** it, each
checking the cancel fence before and after acquiring, aborting to rollback if
§4.5 cancelled the handle:

1. `admit(target_key, open)` → pending binding (cancel fence).            *[lock]*
2. Layer-2 capability re-validation of the selected channel (§3.3 of contract).
3. Break-plan admission for stop-capable tiers (`seams/break_policy`, §4.1).
4. `StopCapableGuard.acquire(target_key)` for stop-capable tiers →
   `TRANSPORT_CONFLICT` / `code=stop_session_conflict` on CAS failure.
5. `ConsoleLease.acquire(target, transport)` where the channel needs the console
   (no-op for qemu-gdbstub) → `TRANSPORT_CONFLICT` / `code=lease_conflict`.
6. Provider attach (spawn agent-proxy / open RSP) → `TransportSession`.
7. Retake the lock; promote the pending binding to a session binding **iff not
   cancelled**; otherwise rollback.                                        *[lock]*

On any failure or cancellation at 2–7, roll back in reverse: release lease (5),
release guard (4), deregister the pending binding (1). A failed or preempted open
leaks no lease, guard, or binding and never strands a busy target.

### 4.4 ConsoleLease & StopCapableGuard

- `ConsoleLease.acquire` is a CAS that succeeds only if `owner==free` (loser →
  `lease_conflict`); `release` is idempotent by-token (stale token = no-op);
  `revoke` (only from §4.5) forces `free`, bumps generation, invalidates the token.
  **qemu-gdbstub:** lease trivially `free`; protocol is a no-op.
- `StopCapableGuard` (`seams/guard.py`, #08-owned interface) — single-holder fenced
  token keyed by `TargetKey`. Both `debug.gdb` and `debug.kdb` acquire it on
  **every** transport, including qemu-gdbstub, enforcing one stop-capable session
  target-wide even when there is no console lease to provide exclusivity. Lifecycle
  mirrors the lease (acquire CAS / release idempotent / revoke on invalidation).

### 4.5 Lifecycle invalidation (`coordination/registry.py` + `seams/lifecycle.py`)

An in-process `LifecycleDispatcher` keyed by `TargetKey`; transports subscribe on
open. Any transition out of `READY`/`DEBUGGING` (`RESETTING`, `CRASHED`, re-entered
`BOOTING`, `RELEASING`, `lease_expired`):

1. **Close admission** (one short critical section): reject new `admit()` calls and
   set the cancel fence on every pending and promoted handle.
2. Emit the lifecycle event; invalidate **every** live binding — pending handles
   (cancel in-flight opens) and `TransportSession`s (terminate: kill agent-proxy,
   drop endpoints). An in-flight ssh-tier op is cancelled so it cannot hang across
   the transition or return results from the wrong kernel generation.
3. `revoke()` the console lease (return to `free`, or re-acquire for provisioner if
   a reboot needs it).
4. `revoke()` the `StopCapableGuard`.
5. Bump the `TargetKey`'s handle `generation`.

**Awaited but bounded.** Invalidation-class events are delivered synchronously;
each subscriber tears down under `teardown_deadline` (a transport constant) and is
idempotent. Realized with threads: teardown calls `proc.wait(timeout)` then
`SIGKILL`; on deadline expiry the dispatcher force-reaps the subscriber, records
the error, and the transition **always proceeds** to its terminal state. A wedged
provider attach is force-reaped the same way, so recovery never blocks behind a
half-open operation.

**kexec** is the normal `RESETTING → BOOTING → READY` path via `reset(mode=kexec)`
and is full invalidation — the debug session never survives (different kernel,
addresses, symbols, stale breakpoints). No transport re-sync optimization.

### 4.6 Execution-state gate (§5.6)

`DEBUGGING` is `EXECUTING` or `HALTED`. Concurrency gates on execution state, not
session type:

1. **One stop-capable session per `TargetKey`** — enforced by `StopCapableGuard`
   target-wide (above).
2. **ssh-tier ops gated on `EXECUTING`.** While `HALTED`, live `debug.introspect`
   and smoke tests are rejected immediately (`READINESS_FAILURE` /
   `code=target_halted` — "target halted in debugger; resume or detach first"),
   never left to hang. While `EXECUTING` they are permitted (racy-by-design and
   acceptable for live introspection).
3. **vmcore analysis is never gated.**

## 5. Seams (Protocols + minimal local impls)

- `SecretsResolver` (#08) — env/file resolution; values never surfaced.
- `StopCapableGuard` / `SessionGuard` (#08) — in-process single-holder fenced token.
- `BreakPolicy` (#08) — evaluates the §4.1 predicates against the selected
  channel's `line_role` + `caps` and `platform` facts to produce a `BreakPlan`;
  encodes the contract's reference mappings (rsp→`gdbstub_native`; dedicated_debug +
  uart_break→`uart_break`; hvc→`sysrq_g`; single shared console + ssh_reachable=false
  + uart_break→`agent_proxy_break`; otherwise no plan ⇒ reject).
- `LifecycleDispatcher` (provisioning) — in-process, `TargetKey`-keyed,
  awaited-delivery interface behind which the backend can later be swapped.
- `seams/target.py` local-qemu adapter (provisioning) — mints a `TargetHandle` and
  registers the `SnapshotStore` entry from the run's boot `StepResult`, leaving the
  immutable run manifest untouched.

## 6. Backends & transports

### 6.1 `ProxyBackend` Protocol + `AgentProxyBackend` (`transport/proxy.py`)

Interface: `start(source, *, console_port, gdb_port, supports_uart_break) ->
ProxyHandle`, `health(handle) -> ok|degraded`, `send_break(handle)`,
`stop(handle)`.

`AgentProxyBackend` spawns the documented invocations (list argv, never a shell):

```
agent-proxy <console>^<gdb> 0 /dev/ttyS0,115200        # local device
agent-proxy <console>^<gdb> <ts_ip> <ts_port>          # remote terminal server
```

- Adds `-s003` when `supports_uart_break` is false.
- **Dynamic ports:** bind two ephemeral `127.0.0.1` sockets, capture the ports,
  close, hand to agent-proxy, then poll until both accept (bounded retry covers the
  reuse race).
- **Crash detection / health:** poll the PID *and* probe that both ports accept;
  `degraded` if either is dead.
- **Reap:** `SIGTERM` → grace → `SIGKILL`; the registry reaper guarantees no orphan
  on close / shutdown / invalidation.
- For a remote terminal server, `health` does a **best-effort** raw-TCP assertion:
  probe the banner and fail loud if a login prompt is detected. Hard BMC/ser2net
  validation is deferred to #06.

### 6.2 `serial-local` reference transport (`transport/serial_local.py`)

Opens a local `/dev/tty*`, unix socket, or PTY and drives it through
`AgentProxyBackend` to yield `console_endpoint` (+ `rsp_endpoint` when a gdb line
exists). Declares `provides_console`, optionally `provides_rsp` and
`supports_uart_break`. `line_role` comes from the `TransportRef`. This is what the
PTY-backed unit/integration tests exercise.

### 6.3 `qemu-gdbstub` transport (`transport/qemu_gdbstub.py`)

No agent-proxy. `rsp_endpoint` is the QEMU gdbstub TCP endpoint passed straight
through; `provides_rsp` only; `line_role=rsp`; `supports_uart_break=false`; console
lease no-op. The existing `QemuGdbstubProvider` batch-gdb engine is unchanged — it
receives `rsp_endpoint` from the `TransportSession` instead of reading
`gdbstub_endpoint` off the boot step.

### 6.4 `inject_break` (`transport/break_inject.py`)

`inject_break(session, method=auto|uart_break|sysrq_g)`. The legal plan is computed
at `open()` by `BreakPolicy` and stored on the session as `break_plan`. Execution:
`uart_break` → `AgentProxyBackend.send_break` (UART BREAK on the line; `-s003`
alternate when the line-break sequence is not honored); `sysrq_g` → over
`access.ssh`, write `g` to `/proc/sysrq-trigger`; `gdbstub_native` needs no break.
`auto` uses the plan's method. A requested method not in the admitted plan is
rejected rather than attempted. The exact agent-proxy break escape is an
implementation detail pinned by the PTY integration test.

## 7. Tool surface, discovery & gating

### 7.1 MCP tools (`server.py`)

Thin wrappers → handlers → `.model_dump(mode="json")`, matching the existing
pattern. Handlers are the unit of testing (called directly with injected
providers/seams):

- `transport.open(run_id, channel_id=None, tier="debug.gdb")` — mints the
  `TargetHandle` from the run's boot result, computes `required_caps` from `tier`,
  runs break-plan-aware selection over `access.transports[]` (or honors an explicit
  `channel_id`), assembles the `OpenRequest`, and runs the open() transaction.
  Returns the `TransportSession`. Agents never hand-assemble an `OpenRequest`.
- `transport.status(run_id, session_id)` — redacted session view from the registry.
- `transport.health(run_id, session_id)` — probes backend + endpoints → `ready|
  degraded`.
- `transport.inject_break(run_id, session_id, method="auto")` — executes the
  admitted plan.
- `transport.close(run_id, session_id)` — idempotent teardown: reap proxy, release
  lease + guard, deregister binding, mark session `closed`.

`debug.start_session` keeps its current signature and behavior; internally it now
calls the same open() transaction (tier `debug.gdb`, qemu-gdbstub channel) to get
the `rsp_endpoint`, then drives the unchanged batch-gdb engine. The `transport.*`
tools are additive primitives, not a new required step for the existing flow.

### 7.2 `providers.list`

A `TransportRegistry` holds `serial-local` and `qemu-gdbstub` as
`TransportCapability` entries (family `transport`, the three flags); the existing
`providers.list` handler merges them in. **Layer-1 startup validation** runs in
`create_app()`: for the local-qemu provisioner adapter
(`compatible_transports=["qemu-gdbstub"]`), every entry must resolve to a registered
transport and the union of caps must cover the supported tiers' `required_caps`;
fail loud at startup otherwise.

### 7.3 Operation gating

Add a `TRANSPORT_OPERATIONS` allowlist in `config.py` (mirroring the existing
constrained debug-operation allowlist + `DebugProfile.enabled_operations`);
validate each `transport.*` op against it. `transport.inject_break` carries a
`destructive_permissions` entry ("drop target kernel into the debugger").

### 7.4 `host.check_prerequisites`

Add an `agent-proxy` check: detect on `PATH` (or a configured path); if absent,
emit `WARNING` with remediation — the pinned `git.kernel.org/.../agent-proxy.git`
ref + `make` step. `gdb` is already checked. No binary is vendored.

## 8. Error handling, redaction & safety

### 8.1 Error taxonomy

Add two `ErrorCategory` values: **`STALE_HANDLE`** (action: re-fetch / re-boot) and
**`TRANSPORT_CONFLICT`** (covers `lease_conflict` + `stop_session_conflict`).
Reuse `DEBUG_ATTACH_FAILURE` (provider-attach / break failure),
`CONFIGURATION_ERROR` (malformed / foreign `transport_ref`), and
`READINESS_FAILURE` (runtime preconditions: near-expiry, no break plan,
`HALTED`-state ssh reject). Every case carries a machine-readable `details.code`
(`stale_handle`, `lease_conflict`, `stop_session_conflict`, `lease_expired`,
`no_break_plan`, `target_halted`, …). `suggested_next_actions` is populated with
the literal next tool name.

### 8.2 Redaction (mandatory on console/debug paths)

Console byte streams, gdb transcripts, and break-injection output pass through
`Redactor()` before *both* the response and any manifest / session-JSON
persistence. Raw console capture
(`<run>/debug/transports/<session>/console.log`) and gdb transcripts stay on disk
as `ArtifactRef(sensitive=True)`; only redacted snippets go in responses.
`secret_refs` are never resolved into output or logs.

### 8.3 Path & command safety

`serial-local` `target_ref` (`/dev/tty*`, unix socket path) is validated through
`safety/paths.py`-style confinement + control-character rejection
(`PathSafetyError → CONFIGURATION_ERROR`). agent-proxy is spawned with a list argv,
never a shell; ports are ints; device/terminal-server host is validated — no
command-injection surface. Endpoints are pinned to `127.0.0.1`.

## 9. Testing strategy

The contract's §8 list is the conformance matrix.

### 9.1 Unit (no external tools)

- Console-lease CAS races (two `acquire` on `free` → exactly one `lease_conflict`)
  via threads; idempotent release; stale-token release no-op post-revoke.
- Admission: freshness reject; snapshot re-binding (foreign/edited ref reject; stale
  `expires_at` reject before any acquisition); state gate; near-expiry reject
  without renewal.
- open() transaction rollback at **each** step (break-plan, guard, lease, attach,
  promotion-after-cancel) leaks nothing.
- `StopCapableGuard` target-wide: gdb-on-RSP + kdb-on-console refused on a target
  exposing both paths.
- Break-plan-aware selection: skip a caps-sufficient-but-unbreakable channel and
  pick the breakable one; reject when no method's predicate holds; `line_role`
  determines `uart_break` vs `agent_proxy_break`.
- Lifecycle: invalidation cancels pending + promoted bindings; `teardown_deadline`
  force-reap still completes the transition; cross-provisioner isolation (same
  `target_id`, different `TargetKey`); `stale_handle` replay after generation bump;
  kexec full invalidation / no re-sync.
- Execution-state gate: ssh-op-while-`HALTED` rejected immediately; permitted while
  `EXECUTING`.
- `secret_refs` never resolved into output.

### 9.2 Integration (gated; skip when tools absent)

- `test_serial_local_transport_integration.py` — PTY-backed fake serial target +
  agent-proxy; skips without `agent-proxy`; asserts working `console_endpoint` and
  `rsp_endpoint` and that `inject_break` drops a kgdb-enabled target into the
  debugger.
- The existing local-QEMU gdbstub flow re-run through the new interface
  (`test_qemu_gdbstub_integration.py`), preserving the `virsh`/`gdb` gating, so
  `gdb` can `target remote` the `rsp_endpoint` with no observable change.

### 9.3 Docs

`docs/transport-providers.md` — concepts + how to add a transport.

## 10. Acceptance criteria (issue #10)

- `providers.list` shows transports with capability flags.
- Opening a `serial-local` transport against a PTY yields working console + RSP
  endpoints; gdb can `target remote` the RSP port.
- `inject_break` reliably drops a kgdb-enabled target into the debugger.
- agent-proxy processes are reaped on `close` and on server shutdown (no orphans /
  port leaks).
- The existing local QEMU gdbstub debug flow passes unchanged on the new interface.

## 11. Deferred / future work

- `kdmx` backend (drop-in behind `ProxyBackend`).
- Real `seams/` implementations: #08 (secrets storage, break policy, SessionGuard)
  and the provisioning epic #38 (real `TargetHandle`s, lifecycle events, snapshot
  store writer).
- Concrete out-of-band transports: #06 (IPMI SOL, Redfish, ser2net) and #07
  (PowerVM HMC/NovaLink, PowerNV OpenBMC).
- The dedicated debug tiers #12 (`debug.kdb`) and #13 (`debug.gdb`) that consume the
  `TransportSession`.
