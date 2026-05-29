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
  - `Precondition` and `TeardownStep` Protocols (the #69/#70 plug-in points).
  - A `SessionGuardContext` carrying the run-scoped facts steps need.
  - `SessionGuard` with injected **ordered** `preconditions` and `teardown_steps`
    lists (empty default in #66), an `enter(ctx)` method, and one idempotent
    `teardown(ctx, *, reason)` routine.
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
@dataclass(frozen=True)
class SessionGuardContext:
    target_key: TargetKey
    generation: int
    session_id: str | None       # None before the attach commits a session
    reason: str                  # "ended" | "attach_error" | "invalidated" | "timeout"
```

`session_id` is `None` only during `enter`/attach-error before the transaction
commits a session id; teardown paths always carry it. `reason` is set by the
caller and threaded to every step so a step can branch (e.g. a watchdog-restore
step is a no-op when `reason == "attach_error"` and no relax ran).

### 3.2 `Precondition` Protocol

```python
@runtime_checkable
class Precondition(Protocol):
    name: str
    def check(self, ctx: SessionGuardContext) -> None: ...
```

`check` runs **before** any resource is acquired. It raises `PreconditionError`
(a new exception mapped to `READINESS_FAILURE`) to abort the enter; nothing has
been acquired, so there is nothing to roll back. #70's symbol version-lock is a
`Precondition`. #66 ships none.

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
- **`force_drop`-safe** — because one entry point is the dispatcher's
  `force_drop` (which the §5.5 contract requires be non-blocking), a teardown step
  invoked on that path MUST be non-blocking. #69's watchdog-restore over ssh is
  blocking, so it runs on the `invalidate` (bounded-worker) path and the clean
  path, and is a no-op on `force_drop`; the spec records this so #69 wires it
  correctly.

#69's watchdog-restore is a `TeardownStep`. #66 ships none beyond the built-in
resume (§3.5), which is not a `TeardownStep` but a fixed core action.

### 3.4 `SessionGuard`

```python
class SessionGuard:
    def __init__(
        self,
        *,
        preconditions: Sequence[Precondition] = (),
        teardown_steps: Sequence[TeardownStep] = (),
    ) -> None: ...

    def enter(self, ctx: SessionGuardContext) -> None:
        """Run preconditions in declared order; the first failure raises
        PreconditionError and aborts. No resource is acquired here — the caller
        performs the stop-capable attach after enter() returns."""

    def teardown(self, ctx: SessionGuardContext, *, close: Callable[[], None]) -> TeardownReport:
        """The single idempotent teardown invariant. Runs teardown_steps in
        REVERSE declared order (LIFO unwind), then invokes the injected `close`
        callable (the existing transaction.close path) which reaps the backend and
        releases guard/lease/record. Resume (§3.5) is asserted as part of close's
        record handling. Never raises; aggregates per-step errors into the report."""
```

`SessionGuard` holds no per-session state — it is a stateless policy object
constructed once and injected into the handlers (matching the repo's
constructor-injection-for-tests convention). The per-session state lives where it
already does: the durable `TransportSession` record and the transaction's
in-memory token map.

`close` is passed in rather than `SessionGuard` reaching into the transaction, so
the guard stays decoupled from `TransportTransaction` and is unit-testable with a
fake `close`.

### 3.5 The resume invariant

"No target left stopped" is enforced inside the `close` callable's record
handling, which `teardown` always invokes:

- **Clean end** (`reason="ended"`): `transaction.close(force=True)` deletes the
  durable record. With the record gone the target returns to `READY`, where
  ssh-tier ops are admitted normally — the kernel is resumed (QEMU auto-resumes
  the VM when gdb disconnects in the batch controller model). Teardown asserts the
  record no longer reports `HALTED` (it is deleted) before returning success.
- **Attach error** (`reason="attach_error"`): `transaction.close(force=False)`.
  The gdb attach failed, so the kernel may be running or halted; teardown reaps
  any spawned gdb/backend and ensures the durable record is not left advertising a
  live `HALTED` session. A `closed_while_halted` recovery tombstone is the correct
  outcome (a future `recovery=True` reattach clears it) — the target is gated, not
  stranded mid-halt.
- **Timeout / invalidation** (`reason in {"timeout","invalidated"}`): the
  dispatcher's `_SessionSubscriber` already releases guard/lease/record and reaps
  the backend; #66 routes its teardown steps through the same `teardown` so #69's
  restore runs, and the resume assertion holds because the record is deleted.

The resume invariant is therefore: **on every exit path, the durable record for
the target either is deleted or carries a recovery tombstone — never a live
`HALTED` session with no owner.** This is the testable statement of AC1.

## 4. Wiring (`server.py`)

`create_app` constructs one `SessionGuard(preconditions=(), teardown_steps=())`
and injects it into the debug handlers (additive keyword arg, default `None` →
the seam is inert on a non-wired server, matching the existing
transaction/admission/registry optionality).

1. **`debug_start_session_handler`** — build `SessionGuardContext(reason="enter")`;
   call `guard.enter(ctx)` **before** `transaction.open()`. On any exception from
   `open()`/`_halt`/`provider.start_session`, call
   `guard.teardown(ctx_with(reason="attach_error"), close=lambda: transaction.close(sid, force=False))`
   instead of today's bare `transaction.close(force=False)`.
2. **`debug_end_session_handler`** — on a clean provider detach, call
   `guard.teardown(ctx_with(reason="ended"), close=lambda: transaction.close(sid, force=True))`
   instead of today's bare `transaction.close(force=True)`.
3. **`_SessionSubscriber`** (`transaction.py`) — its `invalidate`/`force_drop`
   gain a `teardown_steps` hook so #69's restore runs out-of-band. Because the
   subscriber is constructed by the transaction, `SessionGuard`'s `teardown_steps`
   are threaded to it at `bind_lifecycle`/subscribe time. `force_drop` runs only
   the `force_drop`-safe steps (§3.3).

The handlers' existing manifest/redaction/`ToolResponse` behavior is unchanged;
`SessionGuard` slots in around the attach/teardown only.

## 5. Error handling & failure contract

- A failed `Precondition` → `PreconditionError` → handler maps to
  `READINESS_FAILURE` with the precondition `name` in details and
  `suggested_next_actions=["artifacts.get_manifest"]`. Nothing acquired.
- A `TeardownStep` that raises is suppressed, logged, and aggregated into the
  `TeardownReport`; teardown always proceeds to `close`. The handler still returns
  the underlying operation's `ToolResponse`; a teardown-step failure is surfaced
  in details (`teardown_step_errors`) but does not flip a successful end to a
  failure — the invariant (resume + reap) is satisfied by `close` regardless.
- `close` itself is the existing transaction path; its errors propagate as they do
  today.

## 6. Testing

Handler/seam-level (no MCP, injected fakes), following the repo convention:

- **`enter` ordering**: preconditions run in declared order; first failure aborts
  and no later precondition runs; nothing acquired.
- **Resume-on-error**: a `provider.start_session` that raises drives
  `teardown(reason="attach_error")`; assert backend reaped, guard/lease released,
  and the durable record is not a live `HALTED` (tombstone present).
- **Resume-on-timeout**: a wedged invalidate worker → `force_drop` runs the
  `force_drop`-safe teardown steps and the record is dropped; assert no orphaned
  helper (fake proxy `stop_by_identity` called) and guard released.
- **Clean end resume**: `teardown(reason="ended")` deletes the record; target
  returns to `READY`; a subsequent ssh-tier admit succeeds.
- **No-orphan**: across error/timeout/clean paths the fake backend's reap hook is
  always invoked exactly once (idempotent on double-teardown).
- **Teardown-step ordering + isolation**: steps run in reverse; a raising step is
  suppressed and the next step + `close` still run.
- **`force_drop`-safety**: a blocking step is skipped on the `force_drop` path.
- **HALTED fast-reject conformance**: with a `SessionGuard`-opened session parked
  `HALTED`, an ssh-tier `target.run_tests` admit is rejected `target_halted` (not
  hung); after clean teardown the same admit succeeds. (Reject logic already in
  `admit_ssh_tier`; this binds it to the guard lifecycle.)
- Integration tests touching real `gdb`/`virsh` stay env-gated and untouched.

## 7. Open questions

None. The resume locus (teardown), the hook mechanism (injected ordered Protocol
steps), and the shared-idempotent-teardown decision are settled in ADR 0013 with
their rejected alternatives.
