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

- `Endpoint` — a **discriminated union** on `kind`:
  - `TcpEndpoint` — `{kind: "tcp", host: str, port: int}`; bind/report `127.0.0.1`
    only, port `1..65535` (the existing qemu-gdbstub convention).
  - `UnixSocketEndpoint` — `{kind: "unix", path: str, mode: int}`; a per-session
    unix-domain socket owned by the server user, `mode` `0600` by default.
  RSP endpoints are always `TcpEndpoint` (gdb/agent-proxy constraint, §6.1, §8.4);
  a console endpoint is a `UnixSocketEndpoint` when exposed without agent-proxy
  (§8.4) and a `TcpEndpoint` otherwise. Tool responses and the permissioned-console
  test (§9.1) consume the union.
- `TransportRef` — **exactly the settled-contract shape, unchanged**: `provider,
  channel_id, line_role: shared_console|dedicated_debug|rsp, caps: list[str],
  target_ref: dict, opts: dict, secret_refs: list[str]`. `(provider, channel_id)` is
  the channel key; `channel_id` is unique within a target's `transports[]`. This
  issue does **not** add a field to the contract's `TransportRef`. The §8.4
  endpoint-safety input (`endpoint_exposure`) is **not** a per-channel provisioning
  fact — it is a property of the *transport provider*, so it lives on the **01-owned
  `TransportCapability`** (below) and the gate derives it by looking up the selected
  channel's `provider` in the 01-owned transport registry. That lookup is trusted
  (registry metadata, not caller-supplied), so it cannot be spoofed by a hand-edited
  ref — strictly better than a per-ref field while keeping the contract seam intact.
- `OpenRequest` — **exactly the settled-contract shape, unchanged**: `target_key,
  generation: int, transport_ref, required_caps: list[str], platform, lease:
  LeaseInfo|None, min_lease_ttl: int|None` (seconds; `None` ⇒
  `DEFAULT_MIN_LEASE_TTL_SECONDS = 300`). This issue does **not** add a field to the
  contract's `OpenRequest`. Recovery-mode attach (§4.7) is **not** a wire bit on this
  cross-registry handoff: it is a **separate 01-internal admission path**
  (`admit_recovery`, §4.7) selected by the `transport.open` MCP tool's `recovery`
  argument (§7.1), which the transport layer owns end-to-end. A provisioning
  consumer implementing the settled contract therefore needs no knowledge of recovery
  — it mints an ordinary `OpenRequest`, and the recovery exception lives entirely
  inside the 01 admission service.
- `TransportCapability` — surfaced in `providers.list`; `provider_name`,
  `provider_family="transport"`, `architectures`, the three bool flags
  `provides_console / provides_rsp / supports_uart_break`, and an
  **`endpoint_exposure`** enum (`loopback_local | brokered_required`) that drives the
  §8.4 gate. `loopback_local` means the transport binds a loopback endpoint on the
  server's own host against a local source (`qemu-gdbstub`, `serial-local` on a local
  device); every remote/out-of-band transport (`ipmi-sol`, `redfish-serial`,
  `ser2net`, `hmc-vterm`, …) is **structurally `brokered_required`** and cannot
  declare `loopback_local`. `endpoint_exposure` is a **registry property of the
  provider**, not a per-channel field on the contract's `TransportRef` (§3.2): the
  §8.4 gate reads it by looking up the selected channel's `provider` in this 01-owned
  registry, which is trusted metadata. **Layer-1 startup validation** (§7.2) rejects
  any transport whose family is remote yet declares `loopback_local`. **Choice:** a
  dedicated model rather than overloading `ProviderCapability`, so these flags are
  first-class.
- `BreakPlan` — `method: gdbstub_native|uart_break|agent_proxy_break|sysrq_g`,
  `channel_id`, `rationale: str`.
- `TransportSession` — `session_id, target_key, generation, provider, channel_id,
  console_endpoint: Endpoint|None, rsp_endpoint: TcpEndpoint|None, record_state:
  pending|opening|ready|degraded|closing|abandoned|closed (§4.7), console_lease_token:
  str|None, stop_guard_token: str|None, attach_epoch: int (§4.7 fence), break_plan:
  BreakPlan|None, execution_state: EXECUTING|HALTED|unknown (§4.6), backend_pid:
  int|None, backend_start_time: str|None, created_at, ended_at|None, artifacts:
  list[ArtifactRef]`. **Choice:** `session_id = "transport-{uuid4hex}"`; the record
  is the write-ahead durable ownership record (§4.7), persisted as JSON under
  `<run>/debug/transports/<session_id>.json`; liveness is owned by the in-process
  registry while the server runs.

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

Steps 1 and 8 take the short admission lock; steps 2–7 run **outside** it, each
checking the cancel fence before and after acquiring, aborting to rollback if
§4.5 cancelled the handle. The transaction is **write-ahead**: a durable ownership
record (§4.7) is fsync'd *before* the first external acquisition and atomically
updated as each resource appears, so a crash at any step leaves a record for
reconciliation to find.

1. `admit(target_key, open)` → pending binding (cancel fence).            *[lock]*
2. **Write-ahead: create + fsync a `pending` ownership record** (§4.7) under
   `<run>/debug/transports/` (record + containing dir fsync'd) **before** any guard,
   lease, or backend resource exists. Nothing external acquired yet ⇒ a crash here
   reconciles to a no-op.
3. Layer-2 capability re-validation of the selected channel (§3.3 of contract).
4. **Break-plan admission** for stop-capable tiers (`seams/break_policy`, §4.1) —
   **topology-first with disproof-only pruning** (§4.8): admit if at least one method
   whose topology predicate holds is **not positively disproved**. `no_break_plan`
   when **no** topology predicate holds at all; `break_disproved` when topology
   candidates exist but **every** one is positively disproved. Either ⇒
   `READINESS_FAILURE`, **before any guard/lease/session is created**.
5. `StopCapableGuard.acquire(target_key)` for stop-capable tiers →
   `TRANSPORT_CONFLICT` / `code=stop_session_conflict` on CAS failure. **On success,
   atomically update + fsync the record** (guard token recorded) before continuing.
6. `ConsoleLease.acquire(target, transport)` where the channel needs the console
   (no-op for qemu-gdbstub) → `TRANSPORT_CONFLICT` / `code=lease_conflict`. **Update +
   fsync the record** (lease token) on success.
7. **Cancellation-aware provider attach** (§6.1) on a supervised worker thread:
   spawn agent-proxy / open RSP. The backend registers each partial resource (child
   pid, bound sockets, opened device fd) **into the record (fsync'd) and the pending
   binding the instant it is created**, *before* readiness — so the reaper can
   force-kill a `start` that never returns and reconciliation can find a mid-attach
   crash. All blocking IO uses bounded timeouts. → `TransportSession`.
8. Retake the lock; promote the pending binding to a session binding and flip the
   record to `ready` **iff not cancelled**; otherwise rollback.            *[lock]*

On any failure or cancellation at 3–8, roll back in reverse: kill any registered
partial attach resources (7), release lease (6), release guard (5), and mark the
record `closed` then deregister the pending binding (2/1). A failed or preempted
open leaks no process, socket, device fd, lease, guard, binding, or durable record,
and never strands a busy target.

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

**Authoritative execution state (single writer).** The session's `EXECUTING|
HALTED|unknown` flag is **owned solely by the stop-capable controller** that holds
the `StopCapableGuard` — the only actor that can halt or resume the kernel. That
controller MUST record every transition it causes — interrupt, breakpoint hit,
`continue`, `detach`, and a *failed or uncertain* break injection — onto the
session binding before returning. **Recovery-relevant transitions are write-ahead
(§4.7):** before the controller issues an operation that *will* halt the kernel (a
break/interrupt), it first writes `execution_state=HALTED` (or `unknown` for a break
whose outcome it can't confirm) to the durable record **and fsyncs** — so a crash
during the halt cannot leave a stale `EXECUTING` on disk. Resuming to `EXECUTING` is
recorded *after* the resume confirms. A failed/uncertain `inject_break` sets the
state to **`unknown`**, which the gate treats as **not-`EXECUTING`** (ssh ops
rejected) until a controller re-establishes ground truth. Where no stop-capable session is
attached **and the `TargetKey` is not in `recovery_required` (§4.7)**, the target is
`EXECUTING` by definition. A `recovery_required` `TargetKey` is the explicit
exception — it is treated as not-`EXECUTING` and admission is closed for it until
recovery clears (§4.7), so a crash that orphaned a halted kernel can never be read
as "no session, therefore running."

**`EXECUTING`→`HALTED` cancels in-flight ssh ops.** Gating only *new* admissions is
not enough: an ssh-tier op that passed the `EXECUTING` gate can still be running when
a breakpoint fires and the kernel halts under it, freezing the network. So when the
stop-capable controller records an `EXECUTING`→`HALTED` transition, that is a
**registry event** (same mechanism as §5.4) that **sets the cancel fence on every
in-flight ssh-tier admission handle for the `TargetKey`** — an already-admitted ssh
op is cancelled when the kernel halts under it, not left to hang. Combined with the
admission close on `HALTED`, both new and in-flight ssh ops are covered.

**No silent drift.** Two further safeguards keep a cached flag from masking reality:
- *Defense-in-depth probe.* ssh-tier admission does not trust the flag alone: it
  also issues a **bounded** liveness probe (short timeout) on the ssh channel, and
  every ssh-tier op runs under its admission handle with bounded timeouts. A probe or
  op timeout ⇒ reject/abort with `code=probe_timeout` rather than hang — so even a
  stale `EXECUTING` flag cannot wedge an ssh op when the kernel is actually halted.
- *Raw-endpoint caveat.* The contract assumes the agent drives the kernel **through
  the MCP tools**. A client that connects directly to a returned `rsp_endpoint` /
  `console_endpoint` and halts the kernel out-of-band is **out of contract** and can
  desync the flag; this is a documented limitation (§8.4), mitigated by the
  localhost trust boundary now and brokered/permissioned endpoints later (#08).

### 4.7 Crash recovery & reconciliation

The in-process registry is the liveness *authority while the server runs*, but it
is **not** the durable record. If the MCP server crashes or restarts, orphaned
agent-proxy children, open serial devices, and a halted target can outlive it; a
naive new server would see a `free` lease and admit a second session against a
console/RSP path an orphan still holds. The design closes this with durable
ownership plus startup reconciliation.

- **Write-ahead durable ownership record.** The persisted session JSON (§3.2) is the
  ownership record, not just postmortem visibility, and it is **write-ahead** (§4.3):
  created + fsync'd *before* the first external acquisition and atomically updated
  (record + containing dir fsync'd) as each resource appears, so there is no window
  where a guard/lease/child exists without a durable record. It carries a
  `record_state` (`pending|opening|ready|closing|closed`), `backend_pid`,
  `backend_start_time` (proc start-time ticks — reusing the existing
  `_controller_identity` start-time technique in `qemu_gdbstub.py`, which already
  fingerprints a pid against start-time to avoid pid reuse), the owned
  `console_lease`/`stop_guard` tokens, `target_key`, `generation`, the **last-known
  execution state** (`EXECUTING|HALTED|unknown`) written by the stop-capable
  controller (§4.6), and whether the session was stop-capable.
- **Single-instance guard.** The server takes an OS advisory lock
  (`flock`) on `<artifact-root>/transport.lock` at startup. A second server
  instance against the same artifact root fails loud rather than racing the first
  for transport ownership.
- **Per-device / per-target lock.** Where the source is an exclusive device
  (`/dev/tty*`, a unix socket), the backend takes an OS lock on it (`flock` /
  open-exclusive) so an orphaned agent-proxy still holding the line is *detectable*
  and a duplicate open fails fast instead of silently double-driving the line.
- **Startup reconciliation (before admission opens).** On `create_app()` the
  registry scans persisted records for the artifact root and, for every record that
  is **not `closed`** — `pending`/`opening` write-ahead records from a mid-open
  crash, `ready`/`degraded` sessions, **and `abandoned`/`closing` records from an
  abandoned attach worker (§6.1)**: validates `backend_pid` + `backend_start_time`;
  if the child is gone, marks the record `closed` and releases any lease/guard it
  recorded; if the child is still alive (a true orphan from a hard crash), **reaps
  it** (`SIGTERM`→`SIGKILL`) and releases its resources. Admission does not accept
  any open until reconciliation completes. Reconciliation is idempotent and bounded
  by `teardown_deadline` per record.
- **Halted-target recovery gate (do not free a parked kernel).** Reaping a child and
  releasing tokens does **not** by itself make the kernel runnable — a stop-capable
  record may have left the kernel parked in the debugger after the crash.
  **Conservative default (do not trust a possibly-stale `EXECUTING`):** because a
  crash can land in the window between observing a halt and the write-ahead landing
  (§4.6), reconciliation treats **every unclosed stop-capable record as `unknown`
  regardless of its on-disk `execution_state`**, *unless* a bounded liveness probe
  positively proves `EXECUTING`. A record that is `HALTED`/`unknown` (or any
  stop-capable record not probe-proven `EXECUTING`) is therefore gated. For such a
  record, reconciliation writes a **durable `recovery_required` tombstone** for the
  `TargetKey` — a small persisted record under `<artifact-root>/transport-recovery/`
  whose **filename is a canonical hash** (`sha256(f"{provisioner}\0{target_id}")`,
  not the raw components, so opaque `TargetKey` parts are never trusted as path
  segments and cannot collide), with the full `TargetKey` **and the `generation` it
  was minted at** stored inside the JSON. It is written **before** the session record
  is closed, so the gate survives any number of further crashes. Startup
  reconciliation **loads recovery tombstones first**, before scanning session
  records, and admission consults them.

  **Authoritative generation source + fail-closed at startup.** The current
  authoritative generation for a `TargetKey` comes from the `TargetHandle` minted by
  provisioning (here, the local-qemu adapter when a run boots to `READY`), recorded
  into the `SnapshotStore` (§4.2). At **bare startup**, before any handle is minted,
  reconciliation has **no** authoritative generation — so it does **not** guess: a
  loaded tombstone is **fail-closed**, gating its `TargetKey` until an authority
  appears. The generation *comparison* therefore happens **at handle-mint time**, not
  at bare startup: when provisioning next mints a `TargetHandle` for the key, that
  handle's `generation` is the authority against which the tombstone is judged. If no
  authority ever appears, the gate simply stays closed (safe). This removes the
  "reconciliation guesses the generation" hole — admission for a tombstoned key is
  closed until an authoritative handle is present to adjudicate.

  **Generation semantics (idempotent across reset).** Once an authoritative handle is
  present, a tombstone gates admission **only while `tombstone.generation == the
  TargetKey's current authoritative generation`** (§3.1). A `reset` advances
  generation (N→N+1) on reaching `READY`, which makes the N tombstone *stale*: it is
  superseded — the N+1 incarnation is a freshly-booted kernel, not the parked one, so
  the stale tombstone is cleared and does **not** block the new incarnation.
  Conversely a tombstone whose generation still matches is honored even across
  repeated restarts. This prevents both failure modes: a crash-after-reset can't
  permanently strand a fresh incarnation, and a crash-before-reset can't free a
  still-parked one. A tombstone is otherwise cleared **only** by the three clearance
  paths below (probe→`EXECUTING`, `reset` advancing `generation`, or recovery-mode
  attach). With a generation-current tombstone present,
  **normal** admission stays **closed** for that key (every ordinary `admit()`
  returns
  `READINESS_FAILURE` / `code=recovery_required`, including ssh-tier ops — §4.6's "no
  session ⇒ EXECUTING" rule explicitly excludes it). Clearance is via **exactly three
  explicitly-defined paths**, none of which is an ordinary `admit()`, so there is no
  unspecified bypass:
  1. **Liveness probe (no admission).** The registry runs a bounded read-only ssh
     probe; if it proves the kernel is `EXECUTING`, the key clears to normal.
  2. **Provisioning `reset(mode)` (invalidation path, not admit).** A reset runs the
     §4.5 invalidation/reboot path — it is *not* gated by admission — and on reaching
     `READY` bumps `generation` and clears the key.
  3. **Recovery-mode attach (its own narrow admission exception).** A stop-capable
     `transport.open(recovery=true)` enters through a **distinct 01-internal
     admission entry (`admit_recovery`)** — not an ordinary `admit()` and not a field
     on the contract `OpenRequest` (§3.2) — which is the **one** path accepted while
     `recovery_required`. It is audited, time-boxed (`recovery_deadline`), acquires
     the `StopCapableGuard` like any stop session, and is permitted to do **only**
     resume/detach/observe to re-establish ground truth; on success it either
     transitions the key to a normal `DEBUGGING/EXECUTING` session or detaches and
     clears to normal. A non-recovery open is still rejected. This removes the
     iteration-2 contradiction where the listed "fresh attach" clearance was itself
     blocked by the closed admission.

### 4.8 Break-plan executable preflight

**The settled contract's admission rule is authoritative.** Per §4.1 of the
interface contract, a method is *admissible* when its topology predicate holds —
including the single shared-console + `ssh_reachable=false` + `supports_uart_break`
→ `agent_proxy_break` case, which the contract explicitly admits. This issue
**implements** that contract and therefore MUST NOT reject a topology-admissible
method. The preflight added here is a **disproof-only** safety layer, not a second
admission gate: it can reject a method **only when it positively observes the method
is non-executable**, never merely because evidence is unavailable (absence of
evidence ≠ disproof).

Break-plan admission (step 4) admits a plan if at least one method's topology
predicate holds; for each candidate it additionally runs a non-destructive probe and
**disqualifies that method only on a positive negative observation**:

| Method              | Disproof probe (reject the method only if it OBSERVES this) |
| ------------------- | ----------------------------------------------------------- |
| `gdbstub_native`    | RSP endpoint not reachable. |
| `sysrq_g`           | over ssh (ssh is in this method's predicate): `/proc/sys/kernel/sysrq` observed `0` or missing the SysRq-`g` bit, or `/proc/sysrq-trigger` observed non-writable. |
| `uart_break` / `agent_proxy_break` | **iff ssh happens to be reachable** (an optional bonus probe): `/sys/module/kgdboc/parameters/kgdboc` observed bound to a *different* line. Without ssh there is **no disproof** and the method stays admitted per the contract flag. |

So: a target the contract admits is always admitted; the preflight only prunes a
candidate that is *demonstrably* dead, and falls back to the next admissible method
(or, if a method is disproved, surfaces it) — it never converts "can't prove" into a
rejection. A break that is admitted but later fails at `inject_break` time is a
**runtime** `DEBUG_ATTACH_FAILURE` that sets `execution_state=unknown` (§4.6), which
is the contract's intended detection path for an over-asserted `supports_uart_break`
— not an admission-time refusal. The two admission-time rejections are exact and
distinct: `code=no_break_plan` only when **no method's topology predicate holds at
all** (the contract case), and `code=break_disproved` only when topology candidates
exist but **every** one was *positively disproved* by its §4.8 probe (e.g. the sole
candidate is `sysrq_g` and sysrq is observed disabled). A method with no disproof
probe available (no-ssh serial break) is never disproved and so never triggers
`break_disproved`.
The local-qemu path uses `gdbstub_native`, unaffected. (Richer authoritative
`PlatformMetadata` facts from provisioning, §11, would let the preflight *prove*
serial-break executability up front and avoid the runtime-failure fallback, but their
absence never blocks a contract-admissible attach.)

## 5. Seams (Protocols + minimal local impls)

- `SecretsResolver` (#08) — env/file resolution; values never surfaced.
- `StopCapableGuard` / `SessionGuard` (#08) — in-process single-holder fenced token.
- `BreakPolicy` (#08) — evaluates the §4.1 predicates against the selected
  channel's `line_role` + `caps` and `platform` facts to produce a `BreakPlan`;
  encodes the contract's reference mappings (rsp→`gdbstub_native`; dedicated_debug +
  uart_break→`uart_break`; hvc→`sysrq_g`; single shared console + ssh_reachable=false
  + uart_break→`agent_proxy_break`). Admission is **topology-first**: a
  topology-admissible method is admitted; the §4.8 probe is **disproof-only** and
  prunes a candidate only on a positive negative observation — it never rejects for
  absent evidence (`no_break_plan` only when no topology predicate holds;
  `break_disproved` only when every topology candidate is positively disproved).
- `LifecycleDispatcher` (provisioning) — in-process, `TargetKey`-keyed,
  awaited-delivery interface behind which the backend can later be swapped.
- `seams/target.py` local-qemu adapter (provisioning) — mints a `TargetHandle` and
  registers the `SnapshotStore` entry from the run's boot `StepResult`, leaving the
  immutable run manifest untouched.

## 6. Backends & transports

### 6.1 `ProxyBackend` Protocol + `AgentProxyBackend` (`transport/proxy.py`)

Interface (cancellation-aware, §4.3 step 7):
`start(source, *, console_port, gdb_port, supports_uart_break, cancel: Event,
deadline, on_partial: Callable) -> ProxyHandle`, `health(handle) -> ok|degraded`,
`send_break(handle)`, `stop(handle)`. `start` MUST: use bounded timeouts on every
blocking step (open device, connect terminal server, spawn, await readiness);
report each partial resource (child pid, bound fds) through `on_partial` the instant
it is created so the reaper can kill a `start` that never returns; and abort if
`cancel` is set or `deadline` passes.

**Attach execution model (explicit).** Python threads cannot be force-killed, so
"force-reap a hung attach" is realized as: the open() transaction runs `start` on a
**dedicated supervised worker thread** and waits on it with `teardown_deadline`. The
contract that makes this safe is *bounded syscalls before any partial resource
exists* — every step that runs before the first `on_partial` (device open, TCP
connect, spawn) MUST use an OS-level timeout (`open` with `O_NONBLOCK`+select,
`socket` connect timeout, `subprocess` start timeout), so the worker cannot block
indefinitely and unwinds on its own shortly after the deadline.

On deadline or `cancel`, the transaction **abandons the worker without promotion**:
it kills every resource already reported via `on_partial`, then moves the record to
the **`abandoned`** state (a *non-`closed`* terminal-pending state) and bumps the
record's `attach_epoch`. The abandonment is fenced two ways so a still-unwinding
worker cannot leak: (1) `on_partial` is **epoch-fenced** — a report whose epoch no
longer matches the record is rejected, and the registry immediately reaps the
resource it names rather than recording it; (2) the record stays `abandoned`
(reconciliation-visible, §4.7) until the worker is **confirmed exited**, only then
transitioning to `closed`. A resource the worker creates after abandonment is thus
either reaped on its fenced `on_partial` or found under the `abandoned` record by
reconciliation — never an ignored orphan. Recovery never blocks behind a stuck
attach, including in the pre-`on_partial` window.

`AgentProxyBackend` spawns the documented invocations (list argv, never a shell):

```
agent-proxy <console>^<gdb> 0 /dev/ttyS0,115200        # local device
agent-proxy <console>^<gdb> <ts_ip> <ts_port>          # remote terminal server
```

- Adds `-s003` when `supports_uart_break` is false.
- **Port allocation (race-minimized).** agent-proxy's CLI fixes ports as args, so
  there is an irreducible bind-time window; the design minimizes and *fences* it
  rather than pretending it away: allocate ephemeral `127.0.0.1` ports, keep the
  probe sockets bound until immediately before `exec`, retry the whole allocation on
  a bind conflict, then — critically — **verify listener identity** before returning
  endpoints. Identity verification connects to each port and confirms it is the
  spawned agent-proxy child (the RSP port answers RSP framing; the child pid owns the
  listener where `/proc` allows checking), so "any accepting listener" is never
  treated as healthy. A mismatched listener ⇒ kill + reallocate, not a returned
  endpoint. (A fully race-free model — passing bound fds, or fronting agent-proxy
  with a unix-socket broker — requires patching agent-proxy or the #06/#08 broker and
  is out of scope here; see §8.4.)
- **Crash detection / health:** poll the PID *and* probe that both ports accept
  *and that the listener is still the owning child*; `degraded` if any fails.
- **Reap:** `SIGTERM` → grace → `SIGKILL`; the registry reaper guarantees no orphan
  on close / shutdown / invalidation, and start-time-fingerprinted pids (§4.7) make
  reaping safe against pid reuse.
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

`inject_break(session, method=auto|uart_break|agent_proxy_break|sysrq_g)` — the
method enum is **exactly** `BreakPlan.method` (minus `gdbstub_native`, which needs no
break), so every admittable plan method is namable and dispatchable. The legal plan
is computed at `open()` by `BreakPolicy` and stored on the session as `break_plan`.
Execution:
- `uart_break` → `AgentProxyBackend.send_break` (UART BREAK) on the selected
  **`dedicated_debug`** line; `-s003` alternate when the line-break sequence is not
  honored.
- `agent_proxy_break` → the **same** `AgentProxyBackend.send_break` call, on the
  selected **`shared_console`** line. It is a distinct `BreakPlan.method` from
  `uart_break` only because the contract keys the break plan on `line_role` (§4.1);
  the executable mechanism is identical, so `auto` and explicit selection both have a
  defined dispatch.
- `sysrq_g` → over `access.ssh`, write `g` to `/proc/sysrq-trigger`.
- `gdbstub_native` → no break (gdb interrupts directly); not an `inject_break`
  argument.

`auto` uses `break_plan.method`. A requested method not in the admitted plan is
rejected rather than attempted. The exact agent-proxy break escape is an
implementation detail pinned by the PTY integration test.

## 7. Tool surface, discovery & gating

### 7.1 MCP tools (`server.py`)

Thin wrappers → handlers → `.model_dump(mode="json")`, matching the existing
pattern. Handlers are the unit of testing (called directly with injected
providers/seams):

- `transport.open(run_id, channel_id=None, tier="debug.gdb", recovery=False)` — mints
  the `TargetHandle` from the run's boot result, computes `required_caps` from `tier`,
  runs break-plan-aware selection over `access.transports[]` (or honors an explicit
  `channel_id`), assembles the (contract-unchanged) `OpenRequest`, and runs the
  open() transaction. `recovery=true` is a **tool argument**, not an `OpenRequest`
  field: it routes the open through the 01-internal `admit_recovery` path (§4.7;
  audited, time-boxed; the only open admitted while the `TargetKey` is
  `recovery_required`). Returns the `TransportSession`. Agents never hand-assemble an
  `OpenRequest`.
- `transport.status(run_id, session_id)` — redacted session view from the registry.
- `transport.health(run_id, session_id)` — probes backend + endpoints → `ready|
  degraded`.
- `transport.inject_break(run_id, session_id, method="auto")` — executes the
  admitted plan.
- `transport.close(run_id, session_id)` — idempotent teardown: reap proxy, release
  lease + guard, deregister binding, mark record `closed`. **Stop-capable close is
  execution-state-conditional** (§4.6): before releasing the `StopCapableGuard` it
  MUST prove the kernel is `EXECUTING` (issue resume/detach and verify); if it cannot
  — `execution_state` is `HALTED`/`unknown` and resume/detach fails or the transport
  is already dead — it does **not** silently release into a false-`EXECUTING` state.
  Instead it follows a fixed **atomic ordering** so recovery can never be
  self-blocked on the guard: (1) **write + fsync the `recovery_required` tombstone**
  for the `TargetKey` (§4.7) — this closes *normal* admission first; (2) **then
  `revoke()` the `StopCapableGuard`** back to free. The guard is *released, not
  retained* — but the tombstone, not guard-retention, is what enforces exclusivity
  during recovery: an ordinary `admit()` is rejected `recovery_required`, while a
  `recovery=true` attach (§4.7) passes admission and then cleanly acquires the
  now-free guard. So a close-while-halted neither strands the target (recovery attach
  can acquire the guard) nor reopens it to ordinary ops (tombstone blocks them).
  **This is keyed on the stop-capable tier, not the provider:** `debug.gdb` over
  `qemu-gdbstub` holds the `StopCapableGuard` like any stop session, so its close
  follows the same prove-`EXECUTING`-or-(tombstone-then-revoke) path — there is no
  qemu-gdbstub exception. Only a genuinely non-stop-capable session (a console-only
  channel with no stop tier, which never acquired the guard) is the plain teardown.

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
`HALTED`-state ssh reject, ssh liveness-probe timeout). Every case carries a
machine-readable `details.code` (`stale_handle`, `lease_conflict`,
`stop_session_conflict`, `lease_expired`, `no_break_plan`, `break_disproved`,
`target_halted`, `probe_timeout`, `recovery_required`, `endpoint_unsafe`, …).
`suggested_next_actions` is populated with the literal next tool name.

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

### 8.4 Endpoint construction & trust boundary

The control-plane invariants (`TRANSPORT_OPERATIONS`, destructive permissions,
`StopCapableGuard`, the single-writer execution-state model) are enforced for all
access **mediated by the MCP tools** — which is how the agent operates and how the
in-process debug tiers consume a `TransportSession`. The returned endpoints are the
*tier's* attach target, not a published control surface. The open question this
section answers is what stops an **out-of-band local process** from connecting to a
returned endpoint and bypassing all of that. The design uses the strongest
permissioning each channel's toolchain allows, and states the residual precisely.

**Console channel — permissioned by default where feasible.** When the console does
not require agent-proxy demux (a console-only `serial-local` channel, no RSP), it is
exposed as a **per-session unix-domain socket with mode `0600`**, owned by the
server user. OS file permissions then *are* the access-control boundary: a process
without the owner's uid cannot connect. A conformance test asserts a foreign-uid /
unauthorized connect is refused (§9.1).

**RSP / demuxed channel — TCP, with a stated residual.** agent-proxy listens on
**TCP only** and gdb's RSP transport is TCP, so an agent-proxy-backed `rsp_endpoint`
(and a demuxed console sharing the same agent-proxy) **cannot** be reduced to a
mode-`0600` unix socket without a broker process fronting agent-proxy. That broker
(a tokenized/permissioned front-end, or an agent-proxy patch) is **out of scope here
and owned by #08**; this issue does not pretend to authenticate the TCP RSP. The
residual is bounded, not ignored:

- Endpoints are pinned to `127.0.0.1`; port allocation is race-minimized and
  **listener-identity-verified** (§6.1), so a *hijacked* port is detected (kill +
  reallocate), never returned as healthy.
- An out-of-band client that connects to a TCP endpoint and halts the kernel is
  **out of contract** and sets execution state to `unknown` once the controller next
  observes it (§4.6); it cannot silently masquerade as `EXECUTING`.
- **`127.0.0.1` is a reachability boundary, not an access-control boundary.** On a
  shared multi-user host another local uid can connect to the TCP RSP. This issue's
  threat model is the **single-user local dev target** the project serves today;
  the multi-tenant case is explicitly deferred to the #08 broker. This is stated so
  a reviewer evaluates the design against its real threat model, not an unstated one.

**Runtime guardrail — per-transport, not a global flag.** Returning an
unauthenticated TCP RSP/demuxed endpoint is gated, default-deny, and the permission
is a property of the **selected channel's provider**, read from the 01-owned
transport registry's `TransportCapability.endpoint_exposure` (§3.2) — not a
process-wide switch (a global flag would let enabling local qemu also unlock a future
remote transport's raw RSP) and not a caller-supplied ref field (which could be
spoofed). At admission the selected channel's `provider` is re-bound from the
authoritative snapshot (§4.2), then its registry `endpoint_exposure` is looked up.
`transport.open()` returns a `TcpEndpoint` only when that is `loopback_local` **and**
the bound address is loopback; otherwise it fails `READINESS_FAILURE` /
`code=endpoint_unsafe`. Because every
remote/out-of-band transport is structurally `brokered_required` (§3.2) and startup
validation forbids a remote family from declaring `loopback_local`, a remote
transport can **never** return an unauthenticated RSP — it MUST provide a brokered/
`UnixSocketEndpoint` (the #08 broker) — and the local exposure cannot escape to it. A
permissioned `UnixSocketEndpoint` console is never gated (OS perms enforce access).
The existing qemu-gdbstub flow is unchanged because that channel is `loopback_local`.

The transport surface is shaped so the #08 broker is an **endpoint-construction
swap** (replace `TcpEndpoint` with a brokered/tokenized endpoint variant in the
`Endpoint` union), not a contract change.

This assumption is stated here so a reviewer evaluates the design against its actual
threat model (local single-user) rather than an unstated multi-tenant one.

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
  `EXECUTING`; an **asynchronous** halt (breakpoint hit while an ssh op is admitted)
  and a subsequent resume are observed by the gate; a stale-`EXECUTING` flag with a
  silent kernel triggers `probe_timeout` (bounded probe) rather than a hang; a
  failed `inject_break` sets state `unknown` and ssh ops are then rejected (§4.6).
- Cancellable attach: a `ProxyBackend.start` that **never returns** is force-reaped
  under `teardown_deadline`, its registered partial pid/sockets are killed, and the
  open rolls back leaking nothing (§4.3 step 7, §6.1).
- Crash recovery: a persisted ownership record whose `backend_pid`/`start_time` no
  longer matches is reconciled to `closed` and its lease/guard released; a live
  orphan child is reaped before admission accepts opens; a second server instance on
  the same artifact root fails loud on the `flock` (§4.7).
- Write-ahead crash points: a simulated crash *after* each transaction step (pending
  record written; guard acquired; lease acquired; partial attach resource reported)
  leaves a durable record that reconciliation finds and fully releases — no orphaned
  guard/lease/child without a record (§4.3, §4.7).
- Halted-target recovery gate: a reconciled stop-capable record with last-known
  `HALTED`/`unknown` puts the `TargetKey` in `recovery_required`; admission (incl.
  ssh-tier) returns `code=recovery_required` until a probe/resume/reset clears it —
  a restart never admits against a still-parked kernel (§4.6, §4.7).
- Pre-`on_partial` hang: a `ProxyBackend.start` that blocks *before* reporting any
  partial resource is abandoned at `teardown_deadline`; the open rolls back and
  recovery is not blocked behind the stuck worker (§6.1).
- Permissioned console: a console-only `serial-local` channel is exposed as a
  mode-`0600` unix-domain socket and an unauthorized connect is refused (§8.4).
- Break-plan disproof: a target whose **only** topology candidate is `sysrq_g` with
  sysrq **disabled** / `/proc/sysrq-trigger` not writable is rejected
  (`break_disproved`, not `no_break_plan` — topology matched but was disproved) before
  the guard is acquired; the same target with sysrq enabled/writable admits (§4.8).
- Port identity: a foreign listener occupying the intended port is detected by
  identity verification (kill + reallocate), never returned as a healthy endpoint
  (§6.1).
- Recovery-mode attach: while `recovery_required`, an ordinary open is rejected
  (`recovery_required`) but `transport.open(recovery=true)` is admitted, resumes/
  detaches, and clears the key; a `reset` and a passing probe also clear it (§4.7).
- Close-while-halted: `transport.close` on a stop-capable session whose
  `execution_state` is `HALTED`/`unknown` does **not** release into a false-
  `EXECUTING` state — it proves resume/detach first, or writes the durable
  `recovery_required` tombstone and keeps admission closed (§7.1, §4.6).
- Two-restart recovery durability: a `recovery_required` tombstone written before a
  record is closed survives a *second* crash/restart — reconciliation loads the
  tombstone first and the gate still holds against a possibly-parked kernel (§4.7).
- Tombstone generation idempotency: at bare startup (no authoritative handle yet) a
  loaded tombstone is fail-closed and gates; once an authoritative `TargetHandle` is
  minted, a stale tombstone at generation N is superseded (cleared) when the key is at
  N+1 after a reset, while a generation-current tombstone keeps blocking across
  restarts (§4.7).
- In-flight halt cancel: an admitted ssh-tier op is cancelled (not hung) when the
  stop-capable controller records `EXECUTING`→`HALTED` under it (§4.6).
- Per-transport endpoint policy: a `loopback_local` channel returns a `TcpEndpoint`;
  a `brokered_required` (remote) transport is refused `endpoint_unsafe`, and startup
  validation rejects a remote family that declares `loopback_local` (§3.2, §8.4).
- Break-plan contract conformance: the single shared-console + `ssh_reachable=false`
  + `supports_uart_break` target **admits** via `agent_proxy_break` (contract §4.1);
  the disproof preflight rejects a method only on a positive negative observation
  (e.g. ssh-reachable with sysrq observed disabled), never on absent evidence;
  `no_break_plan` only when no topology predicate holds at all, and `break_disproved`
  only when every topology candidate is positively disproved (§4.3, §4.8).
- Execution-state crash window: a halt observed but with the server crashing *before*
  the write-ahead `HALTED` lands still gates on restart — reconciliation defaults the
  unclosed stop-capable record to `unknown`/`recovery_required` regardless of a stale
  on-disk `EXECUTING`, unless a bounded probe proves `EXECUTING` (§4.6, §4.7).
- Abandoned-attach reconciliation: a worker that reports a child/socket *after* its
  record was abandoned is epoch-fenced (resource reaped, not recorded), and an
  `abandoned` record left by a crash is scanned and fully released on restart
  (§6.1, §4.7).
- Endpoint-safety gate: a `brokered_required` channel's stop-capable/RSP open is
  refused (`endpoint_unsafe`); a `loopback_local` channel (qemu-gdbstub, local
  serial) returns a `TcpEndpoint`, so the qemu-gdbstub flow is unchanged (§8.4).
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

### 10.1 Functional (from the issue)

- `providers.list` shows transports with capability flags.
- Opening a `serial-local` transport against a PTY yields working console + RSP
  endpoints; gdb can `target remote` the RSP port.
- `inject_break` reliably drops a kgdb-enabled target into the debugger.
- agent-proxy processes are reaped on `close` and on server shutdown (no orphans /
  port leaks).
- The existing local QEMU gdbstub debug flow passes unchanged on the new interface.

### 10.2 Blocking conformance (must pass to merge `transport.open`)

These are **not** optional test strategy — the hard invariants ship with the issue,
so `transport.open` cannot merge while any of them is unmet. Each maps to a §9.1
case:

- Console-lease CAS exclusivity and `StopCapableGuard` target-wide single-holder.
- Admission freshness + snapshot re-binding; the open() transaction rolls back at
  **every** step (incl. write-ahead crash points) leaking nothing.
- Crash recovery: write-ahead record found and released; orphan reaped before
  admission opens; **halted-target `recovery_required` gate** with its three
  clearance paths; abandoned-attach epoch fence + reconciliation.
- Cancellable attach incl. the pre-`on_partial` hang.
- Execution-state gate: `HALTED` ssh-reject, `probe_timeout`, `unknown`-on-failed-
  break.
- Break-plan executable preflight (fail-closed before guard).
- **Endpoint-safety gate** (`endpoint_unsafe` default-deny) and permissioned
  `UnixSocketEndpoint` console refusal of an unauthorized connect.
- Port identity verification; `secret_refs` never surfaced; redaction on
  console/transcript paths.

If delivering all of §10.2 in one issue proves too large, the fallback is to split
along the seam (e.g. a follow-up issue for the #08 broker and richer recovery),
but `transport.open` must not ship advertising stop-capable debug without the
crash-recovery, execution-state, and endpoint-safety invariants above.

## 11. Deferred / future work

- `kdmx` backend (drop-in behind `ProxyBackend`).
- Real `seams/` implementations: #08 (secrets storage, break policy, SessionGuard)
  and the provisioning epic #38 (real `TargetHandle`s, lifecycle events, snapshot
  store writer).
- Authenticated/permissioned endpoints (per-session unix-domain socket for the
  console, brokered RSP with a capability token) — the §8.4 hardening, owned by #08;
  shaped as an endpoint-construction swap, not a contract change.
- Richer `PlatformMetadata` break facts (e.g. sysrq/kgdb configured) supplied by
  provisioning, letting §4.8's preflight *prove* serial-break executability up front
  (and avoid the runtime-failure fallback) instead of relying on the contract flag +
  the active ssh disproof probe.
- Concrete out-of-band transports: #06 (IPMI SOL, Redfish, ser2net) and #07
  (PowerVM HMC/NovaLink, PowerNV OpenBMC).
- The dedicated debug tiers #12 (`debug.kdb`) and #13 (`debug.gdb`) that consume the
  `TransportSession`.
