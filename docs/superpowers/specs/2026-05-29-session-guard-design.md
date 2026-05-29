# SessionGuard — interactive session preconditions + teardown invariants — design

**Issue:** #66 (epic #9, split from #17) · **Status:** proposed design
**Contract:** `docs/specs/interface-contracts.md` §5.5, §5.6, §9.1
**ADR:** [0013](../../adr/0013-session-guard-precondition-teardown-seam.md)

## 1. Purpose & scope

Introduce a `SessionGuard` seam: the lifecycle backbone that wraps every
interactive stop-capable `debug.*` session with **ordered preconditions on
enter** and an **idempotent teardown invariant on exit** — guaranteed resume of
the target and reaping of helper processes on success, error, and timeout. It is
the plug-in point the watchdog helper (#69), symbol version-lock (#70), and the
`StopCapableGuard` (#68) hang off.

This issue is deliberately a **thin composition layer**. The transport-abstraction
work (#10) already shipped the primitives this seam orchestrates:
`StopCapableGuard` (`seams/guard.py`), the awaited `LifecycleDispatcher`
(`seams/lifecycle.py`), the `open()`/`close()` write-ahead transaction with full
rollback and out-of-band force-reap (`coordination/transaction.py`), the
admission service, and the ssh-tier `HALTED` fast-reject (`admit_ssh_tier`,
`coordination/admission.py`). `SessionGuard` does **not** replace any of them; it
names and centralizes the precondition/teardown lifecycle that is today implicit
and scattered across three call sites, and it adds one new enforced invariant:
the target is never left stopped.

### 1.1 In scope

- A `SessionGuard` seam in `seams/guard.py` (beside `StopCapableGuard`):
  - `PreAttachPrecondition`, `PostAttachPrecondition`, and `TeardownStep`
    Protocols (the #69/#70 plug-in points).
  - A `SessionGuardContext` carrying the run-scoped facts steps need, including a
    `phase` discriminator (`"bounded"` vs `"force_drop"`) distinct from `reason`.
  - `SessionGuard` with injected **ordered** `pre_attach`, `post_attach`, and
    `teardown_steps` lists (empty default in #66), `enter(ctx)` /
    `verify_attached(ctx, session)` methods, and one idempotent
    `teardown(ctx, *, close, read_record)` routine returning a `TeardownReport`.
- The **guaranteed-resume / no-orphan invariant**: every exit path (clean end,
  attach error, timeout/invalidation) runs the same `teardown` so the durable
  `execution_state` is never left `HALTED` and helper processes are reaped.
- Routing the three lifecycle entry points through `SessionGuard`:
  `debug_start_session_handler` (enter + attach-error teardown),
  `debug_end_session_handler` (clean teardown), and the dispatcher's
  `_SessionSubscriber` (timeout/invalidation teardown).
- Conformance tests proving the §5.6 rule 2 **`HALTED` fast-reject** for ssh-tier
  ops (the reject already exists in `admit_ssh_tier`; this issue locks it with a
  test bound to the `SessionGuard` lifecycle), plus resume-on-error,
  resume-on-timeout, and no-orphaned-helpers tests.

### 1.2 Out of scope

- Watchdog relax/restore mechanics (#69), symbol verification (#70), and the
  stop-capable token semantics themselves (#68 — already shipped as
  `InProcessStopCapableGuard`). This issue defines **where** they hook in, not
  what they do; #66 ships the hook slots empty.
- Any change to the `TransportSession` durable schema, the admission protocol, or
  the lifecycle dispatcher's bounded force-reap machinery.
- Re-enabling ssh-tier ops mid-session on `debug.continue` (flipping the durable
  record back to `EXECUTING`). That is execution-state-gate territory; this issue
  only guarantees resume at session **exit**, not mid-session re-admission.

## 2. Background: what already exists

| Concern | Where | Status for #66 |
|---|---|---|
| One stop-capable holder per `TargetKey` | `seams/guard.py` `InProcessStopCapableGuard` | reused; #68 owns its semantics |
| Acquire/release guard + lease, write-ahead record, rollback | `coordination/transaction.py` `open()`/`close()` | reused; `teardown` delegates to `close()` |
| Out-of-band reap on invalidation/timeout | `transaction.py` `_SessionSubscriber.invalidate/force_drop` | reused; teardown steps added here |
| Awaited, bounded lifecycle delivery | `seams/lifecycle.py` `InProcessLifecycleDispatcher` | reused unchanged |
| ssh-tier `HALTED` fast-reject (`target_halted`) | `admission.py` `admit_ssh_tier`; wired in `server.py` run-tests admit | exists + tested; #66 adds lifecycle-bound conformance test |
| HALTED parked before attach | `server.py` `_halt_debug_transport` | reused; teardown reverses it |

The gap #66 fills: there is no single named object that (a) runs preconditions
before a stop-capable attach, (b) owns one idempotent teardown all three exit
paths share, and (c) guarantees the target is resumed on every exit. Today the
attach-error path calls `transaction.close(force=False)`, the clean path calls
`transaction.close(force=True)`, and the timeout path runs `_SessionSubscriber`
— three places, no shared resume assertion, and no slot for #69/#70 to extend.

## 3. Components (`seams/guard.py`)

### 3.1 `SessionGuardContext`

A frozen dataclass carrying exactly the facts the preconditions/teardown steps
and the resume assertion need — no live handles, so it can be reconstructed on any
of the three entry points from the durable record:

```python
TeardownReason = Literal["ended", "attach_error", "invalidated", "lease_expired"]
TeardownPhase = Literal["bounded", "force_drop"]

@dataclass(frozen=True)
class SessionGuardContext:
    target_key: TargetKey
    generation: int
    session_id: str | None       # None before the attach commits a session
    reason: TeardownReason       # why teardown is running (caller intent)
    phase: TeardownPhase         # execution constraint: "bounded" allows blocking; "force_drop" must not block
    halt_recorded: bool          # True iff the durable record was parked HALTED before this teardown
```

`session_id` is `None` only during `enter`/attach-error before the transaction
commits a session id; teardown paths always carry it.

`reason` is the caller's intent (clean end, a failed attach, an invalidation, or a
lease expiry) so a step can branch on *why* it is tearing down. `phase` is the
orthogonal **execution constraint**, set by the call site and distinct from
`reason` (Finding 2 of the spec review): `"bounded"` is the clean-end and
dispatcher-`invalidate` path where a step runs on a deadline-supervised worker and
MAY block on I/O; `"force_drop"` is the dispatcher's non-blocking out-of-band path
(§5.5) where a step MUST NOT block. A blocking step (e.g. #69's ssh
watchdog-restore) inspects `ctx.phase` and no-ops when `phase == "force_drop"`,
leaving its restore to the `bounded` `invalidate` worker; the same lifecycle event
delivers a `bounded` `invalidate` and (only if that overruns the deadline) a
`force_drop`, so the step is reachable on the path where blocking is allowed and
skipped on the path where it is not. `halt_recorded` lets a step and the resume
post-condition (§3.5) distinguish a session that actually parked the kernel
`HALTED` from a failed attach that never did.

### 3.2 `Precondition` Protocol

Preconditions run at **two distinct phases**, because some checks are static
(runnable before attach) while others must read the live target (Finding 3 of the
spec review): #70's symbol version-lock must "verify `vmlinux` build-id/`vermagic`
matches the **running** kernel," which requires the RSP/gdb channel that only the
attach opens. A single pre-attach phase therefore cannot host #70's core check, so
`SessionGuard` exposes both:

```python
@runtime_checkable
class PreAttachPrecondition(Protocol):
    name: str
    def check(self, ctx: SessionGuardContext) -> None: ...

@runtime_checkable
class PostAttachPrecondition(Protocol):
    name: str
    def check(self, ctx: SessionGuardContext, session: TransportSession) -> None: ...
```

- A `PreAttachPrecondition.check` runs **before any resource is acquired** (no
  `session` yet). It raises `PreconditionError` (a new exception mapped to
  `READINESS_FAILURE`) to abort the enter; nothing has been acquired, so there is
  nothing to roll back. Static symbol checks (vmlinux exists/parses) live here.
- A `PostAttachPrecondition.check` runs **after the attach commits a session but
  before the session is handed back to the caller** — it receives the live
  `TransportSession` so it can read the running kernel over RSP. Raising
  `PreconditionError` here aborts the open *after* acquisition, so the handler runs
  the full teardown (`reason="attach_error"`, §3.5) to release the guard/lease and
  reap the backend — the same rollback path an attach failure takes. #70's
  build-id-vs-running-kernel match is a `PostAttachPrecondition`.

#66 ships **none** of either; it defines the two slots and proves (via tests) that
a post-attach failure tears the session down cleanly. The handler ordering is:
pre-attach preconditions → `transaction.open()` + `_halt` → post-attach
preconditions → return session.

### 3.3 `TeardownStep` Protocol

```python
@runtime_checkable
class TeardownStep(Protocol):
    name: str
    def teardown(self, ctx: SessionGuardContext) -> None: ...
```

Contract obligations a `TeardownStep` MUST honor (enforced by review + tests, not
the type system):

- **Idempotent** — it runs once per session in the common case but MAY be invoked
  again on a retry or across the wedge/unwedge of an invalidate worker.
- **Non-fatal** — it MUST NOT raise to abort teardown; a step that fails records
  the failure and teardown continues to the next step (the resume + reap of the
  target can never be blocked by a misbehaving extension). `SessionGuard.teardown`
  wraps each step in `contextlib.suppress`-with-logging and aggregates errors.
- **Phase-aware (non-blocking under `force_drop`)** — a step inspects
  `ctx.phase` and MUST NOT block when `phase == "force_drop"` (the dispatcher's
  non-blocking out-of-band path, §5.5). Under `phase == "bounded"` (clean end or
  the dispatcher's deadline-supervised `invalidate` worker) it MAY block on I/O.
  #69's ssh watchdog-restore blocks, so it acts under `"bounded"` and no-ops under
  `"force_drop"`. This is the explicit discriminator from §3.1 — a step never has
  to guess its execution constraint from `reason`.

A `TeardownStep` is a single object; `SessionGuard` does not run it twice for one
event. The `bounded` `invalidate` runs the step; the `force_drop` (only on
deadline overrun) runs it again with `phase="force_drop"` — idempotency (above)
makes the second, non-blocking invocation safe.

#69's watchdog-restore is a `TeardownStep`. #66 ships none beyond the built-in
resume (§3.5), which is not a `TeardownStep` but a fixed core action.

### 3.3a `TeardownReport`

`teardown()` returns a `TeardownReport` so the handler can surface (never
re-raise) what happened:

```python
@dataclass(frozen=True)
class TeardownReport:
    step_errors: dict[str, str]          # step.name -> repr(exc) for any step that raised (suppressed)
    resume_ok: bool                      # the §3.5 resume post-condition held after close()
    resume_detail: str                   # observational note when resume_ok is False (logged, not raised)
```

`step_errors` feeds the handler's `teardown_step_errors` response detail (§5).
`resume_ok`/`resume_detail` record the §3.5 post-condition check; a `False`
`resume_ok` is a logged contract-violation, not a control-flow error.

### 3.4 `SessionGuard`

```python
class SessionGuard:
    def __init__(
        self,
        *,
        pre_attach: Sequence[PreAttachPrecondition] = (),
        post_attach: Sequence[PostAttachPrecondition] = (),
        teardown_steps: Sequence[TeardownStep] = (),
    ) -> None: ...

    def enter(self, ctx: SessionGuardContext) -> None:
        """Run pre_attach preconditions in declared order; the first failure raises
        PreconditionError and aborts. No resource is acquired here — the caller
        performs the stop-capable attach after enter() returns."""

    def verify_attached(self, ctx: SessionGuardContext, session: TransportSession) -> None:
        """Run post_attach preconditions in declared order against the live session;
        the first failure raises PreconditionError. The caller catches it and runs
        teardown(reason="attach_error") so the just-acquired guard/lease/backend are
        released — a post-attach precondition failure is rolled back exactly like an
        attach failure."""

    def teardown(
        self,
        ctx: SessionGuardContext,
        *,
        close: Callable[[], None],
        read_record: Callable[[], TransportSession | None],
    ) -> TeardownReport:
        """The single idempotent teardown invariant. Runs teardown_steps in REVERSE
        declared order (LIFO unwind), each guarded by ctx.phase, then invokes the
        injected `close` callable (the existing transaction.close path) which reaps
        the backend and releases guard/lease/record. After close, calls `read_record`
        to evaluate the §3.5 resume post-condition and records the result in the
        report. Never raises; per-step exceptions are suppressed+aggregated, and a
        violated resume post-condition is logged, not raised."""
```

`SessionGuard` holds no per-session state — it is a stateless policy object
constructed once and injected into the handlers (matching the repo's
constructor-injection-for-tests convention). The per-session state lives where it
already does: the durable `TransportSession` record and the transaction's
in-memory token map.

`close` and `read_record` are passed in rather than `SessionGuard` reaching into
the transaction/registry, so the guard stays decoupled from `TransportTransaction`
and is unit-testable with fakes. For the **dispatcher path** (§4 item 3) the same
`teardown_steps` must reach `_SessionSubscriber`; rather than give the transaction
a `SessionGuard` reference (which would break the decoupling in ADR 0013 decision
1), `bind_lifecycle(dispatcher, teardown_steps=...)` passes the **step list as
opaque data** into the transaction, which forwards it to each `_SessionSubscriber`
it constructs. The subscriber invokes the steps directly with the correct
`ctx.phase` (`"bounded"` in `invalidate`, `"force_drop"` in `force_drop`); the
guard's `enter`/`verify_attached`/`teardown` methods are not on that path. The
transaction thus holds a step list (data), never a guard object — "decoupled"
stays honest.

### 3.5 The resume invariant

The coarse admission snapshot for a local-qemu target is published `READY` at boot
and is **not** transitioned to `DEBUGGING` while a gdbstub session is open
(verified: there is no snapshot `DEBUGGING` writer; the snapshot stays `READY`).
The ssh-tier `HALTED` gating is carried entirely by the **durable
`TransportSession` record's `execution_state`**, which `_halt_debug_transport`
parks `HALTED` before attach and which `probe_execution_state` reads (returning
`UNKNOWN` when the record is absent — `exec_probe.py:27`). So "resume" is not a
snapshot state change; it is the guarantee that **after teardown the durable
record no longer advertises a live `HALTED` session that no owner will resume.**

The resume invariant is a **post-condition `teardown` checks observationally**
(via `read_record`) after `close` — it is recorded in `TeardownReport.resume_ok`
and logged on violation, never used as control flow (teardown must complete and
never raise). The post-condition, by exit path:

- **Clean end** (`reason="ended"`, `phase="bounded"`):
  `transaction.close(force=True)` deletes the record. `read_record()` is then
  `None` → `resume_ok=True`. The kernel is resumed (QEMU auto-resumes the VM when
  gdb disconnects in the batch-controller model) and ssh-tier admits again because
  the next probe reads `UNKNOWN` against a `READY` snapshot.
- **Attach error / post-attach precondition failure** (`reason="attach_error"`):
  the resume action depends on `ctx.halt_recorded` — the fact recorded by whether
  `_halt_debug_transport` ran before the failure. **If the kernel was never parked
  `HALTED`** (`halt_recorded=False` — the attach failed before/at connect, so the
  kernel is still running), `close(force=True)` deletes the record so ssh-tier is
  **not** gated: a failed attach that never stopped the kernel does not strand the
  target (this resolves the AC1 tension — a running kernel is never left
  ssh-blocked). **If the kernel was parked `HALTED`** (`halt_recorded=True`, the
  halt landed but the controller never confirmed a clean resume), `close(force=False)`
  leaves a `closed_while_halted` recovery tombstone, because the server cannot
  prove the kernel resumed; the agent clears it with `transport.open(recovery=True)`
  (the same documented clearance the transport layer already exposes). In both
  cases the backend/gdb is reaped. `resume_ok=True` when the record is either
  deleted or carries a current recovery tombstone.
- **Timeout / invalidation / lease expiry** (`reason in {"invalidated",
  "lease_expired"}`, `phase` `"bounded"` then possibly `"force_drop"`): the
  dispatcher's `_SessionSubscriber` releases guard/lease/record and reaps the
  backend; #66 routes the same `teardown_steps` through it (§4 item 3) so #69's
  restore runs under `"bounded"`. The record is dropped, so `resume_ok=True`.

The resume invariant is therefore the testable statement of AC1: **on every exit
path the durable record is either deleted or, only when a halt was recorded and a
clean resume was not confirmed, carries a current recovery tombstone — never a
live `HALTED` record with no owner.** A failed attach that never halted the kernel
resumes cleanly (no tombstone), so a running kernel is never left ssh-blocked.

## 4. Wiring (`server.py`)

`create_app` constructs one `SessionGuard(pre_attach=(), post_attach=(),
teardown_steps=())` and injects it into the debug handlers (additive keyword arg,
default `None` → the seam is inert on a non-wired server, matching the existing
transaction/admission/registry optionality). The same empty `teardown_steps` are
passed to `transaction.bind_lifecycle(dispatcher, teardown_steps=())` so the
dispatcher path (item 3) carries the identical list.

1. **`debug_start_session_handler`** — call `guard.enter(ctx)` (pre-attach) **before**
   `transaction.open()`; after `open()`+`_halt`+`provider.start_session` commit,
   call `guard.verify_attached(ctx, session)` (post-attach) before returning. On any
   exception from `open()`/`_halt`/`provider.start_session`/`verify_attached`, call
   `guard.teardown(ctx_with(reason="attach_error", phase="bounded", halt_recorded=<did _halt run?>),
   close=lambda: transaction.close(sid, force=<not halt_recorded>), read_record=...)`
   instead of today's bare `transaction.close(force=False)`. `halt_recorded` is
   `True` iff `_halt_debug_transport` ran before the failure, and drives the
   `force` flag per §3.5.
2. **`debug_end_session_handler`** — on a clean provider detach, call
   `guard.teardown(ctx_with(reason="ended", phase="bounded", halt_recorded=True),
   close=lambda: transaction.close(sid, force=True), read_record=...)` instead of
   today's bare `transaction.close(force=True)`.
3. **`_SessionSubscriber`** (`transaction.py`) — `invalidate` and `force_drop` gain
   a `teardown_steps` list (forwarded as opaque data from `bind_lifecycle`, never a
   `SessionGuard` reference — §3.4). `invalidate` runs them with `phase="bounded"`;
   `force_drop` runs them with `phase="force_drop"`. The existing guard/lease/record
   release + backend reap is unchanged; the steps run before that release so a
   restore step acts while the line still exists.

The handlers' existing manifest/redaction/`ToolResponse` behavior is unchanged;
`SessionGuard` slots in around the attach/teardown only.

## 5. Error handling & failure contract

- A failed **pre-attach** `PreconditionError` → handler maps to
  `READINESS_FAILURE` with the precondition `name` in details and
  `suggested_next_actions=["artifacts.get_manifest"]`. Nothing acquired.
- A failed **post-attach** `PreconditionError` → the handler runs
  `teardown(reason="attach_error", halt_recorded=...)` to release the
  just-acquired guard/lease and reap the backend, then returns
  `READINESS_FAILURE` with the precondition `name`. The session is fully torn
  down — a post-attach rejection never leaves an acquired session live.
- A `TeardownStep` that raises is suppressed, logged, and aggregated into
  `TeardownReport.step_errors`; teardown always proceeds to `close`. The handler
  still returns the underlying operation's `ToolResponse`; a teardown-step failure
  is surfaced in details (`teardown_step_errors`) but does not flip a successful
  end to a failure — the invariant (resume + reap) is satisfied by `close`
  regardless.
- A violated resume post-condition (`resume_ok=False`) is logged as a
  contract-violation with `resume_detail`; it does not raise (teardown must
  complete) but it is the signal a conformance test asserts must never fire.
- `close` itself is the existing transaction path; its errors propagate as they do
  today.

## 6. Testing

Handler/seam-level (no MCP, injected fakes), following the repo convention:

- **`enter` ordering**: pre-attach preconditions run in declared order; first
  failure raises `PreconditionError` and no later one runs; nothing acquired.
- **Post-attach precondition rollback**: a `post_attach` check that raises drives
  `teardown(reason="attach_error")`; assert the just-acquired guard/lease are
  released and the backend reaped (a post-attach rejection never leaves a live
  session), and the handler returns `READINESS_FAILURE` with the precondition name.
- **Resume-on-error, halt recorded** (`halt_recorded=True`): a failure after
  `_halt` drives `teardown` → `close(force=False)`; assert backend reaped,
  guard/lease released, and a current `closed_while_halted` recovery tombstone
  exists (`resume_ok=True`).
- **Resume-on-error, no halt** (`halt_recorded=False`): a failure before `_halt`
  drives `teardown` → `close(force=True)`; assert the record is deleted, **no**
  recovery tombstone, and a subsequent ssh-tier admit succeeds (a never-halted
  kernel is not left ssh-blocked — the AC1 edge).
- **Resume-on-timeout**: a wedged `invalidate` worker → `force_drop` runs the
  steps with `phase="force_drop"` and the record is dropped; assert no orphaned
  helper (fake proxy `stop_by_identity` called) and guard released.
- **Clean end resume**: `teardown(reason="ended")` deletes the record
  (`resume_ok=True`); a subsequent ssh-tier admit succeeds.
- **No-orphan / idempotency**: across error/timeout/clean paths the fake backend's
  reap hook is invoked, and a double `teardown` (e.g. `invalidate` then a re-fired
  event) is a safe no-op the second time.
- **Teardown-step ordering + isolation**: steps run in reverse; a raising step is
  suppressed (recorded in `step_errors`) and the next step + `close` still run;
  `resume_ok` still holds.
- **`phase` discrimination**: a step that blocks under `phase="bounded"` is
  invoked under `invalidate` and **skipped/no-ops** under `force_drop`; assert the
  step observes the correct `ctx.phase` on each path.
- **HALTED fast-reject conformance**: with a `SessionGuard`-opened session parked
  `HALTED`, an ssh-tier `target.run_tests` admit is rejected `target_halted` (not
  hung); after clean teardown the same admit succeeds. (Reject logic already in
  `_admit_run_tests_ssh_tier`/`admit_ssh_tier`; this binds it to the guard
  lifecycle.)
- Integration tests touching real `gdb`/`virsh` stay env-gated and untouched.

## 7. Open questions

None. The resume locus (teardown), the hook mechanism (injected ordered Protocol
steps), and the shared-idempotent-teardown decision are settled in ADR 0013 with
their rejected alternatives.
