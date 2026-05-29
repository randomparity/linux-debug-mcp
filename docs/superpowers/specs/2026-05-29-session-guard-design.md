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
  - A `SessionGuardContext` carrying the run-scoped facts steps need (`reason`,
    `halt_recorded`, the `TargetKey`/generation/session id).
  - `SessionGuard` with injected **ordered** `pre_attach`, `post_attach`, and
    `teardown_steps` lists (empty default in #66), `enter(ctx)` /
    `verify_attached(ctx, session)` methods, and one idempotent
    `teardown(ctx, *, close, read_record, force_reap)` routine returning a
    `TeardownReport`.
- The **guaranteed-resume / no-orphan invariant**: the two `SessionGuard` exit
  paths (clean end, attach error) run the same `teardown` — reap the backend,
  leave the durable record non-`HALTED`, and on a partial close actively remediate
  via `force_reap`. The timeout/invalidation path is already covered by the
  existing `_SessionSubscriber` reap; #66 verifies it by conformance test, not new
  code.
- Routing the two handler entry points through `SessionGuard`:
  `debug_start_session_handler` (enter + verify_attached + attach-error teardown)
  and `debug_end_session_handler` (clean teardown). The lifecycle dispatcher is
  left unchanged.
- One thin `transaction.force_release(session_id)` wrapper exposing the existing
  out-of-band release so the handler `force_reap` reuses the proven path.
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
| Out-of-band reap on invalidation/timeout | `transaction.py` `_SessionSubscriber.invalidate/force_drop` | reused unchanged; conformance-tested; `force_release` wrapper added |
| Awaited, bounded lifecycle delivery | `seams/lifecycle.py` `InProcessLifecycleDispatcher` | reused unchanged |
| ssh-tier `HALTED` fast-reject (`target_halted`) | `admission.py` `admit_ssh_tier`; wired in `server.py` run-tests admit | exists + tested; #66 adds lifecycle-bound conformance test |
| HALTED parked before attach | `server.py` `_halt_debug_transport` | reused; teardown reverses it |

The gap #66 fills: there is no single named object that (a) runs preconditions
before/after a stop-capable attach, (b) owns one idempotent teardown the two
handler exit paths share, and (c) actively guarantees (not merely logs) the target
is resumed on those exits. Today the attach-error path calls
`transaction.close(force=False)` and the clean path calls
`transaction.close(force=True)` with no shared resume verification, no remediation
when a close leaves a stranded `HALTED` record, and no slot for #69/#70 to extend.

## 3. Components (`seams/guard.py`)

### 3.1 `SessionGuardContext`

A frozen dataclass carrying exactly the facts the preconditions/teardown steps
and the resume assertion need — no live handles, so it can be reconstructed on any
of the three entry points from the durable record:

```python
TeardownReason = Literal["ended", "attach_error"]

@dataclass(frozen=True)
class SessionGuardContext:
    target_key: TargetKey
    generation: int
    session_id: str | None       # None before the attach commits a session
    reason: TeardownReason       # why teardown is running: clean end vs failed attach
    halt_recorded: bool          # True iff the durable record was parked HALTED before this teardown
```

`session_id` is `None` only during `enter` before the transaction commits a
session id; both teardown reasons carry it.

`reason` is the caller's intent — `"ended"` (a clean `debug.end_session`) or
`"attach_error"` (an attach failure or a post-attach precondition rejection). #66
deliberately does **not** route `SessionGuard` teardown through the lifecycle
dispatcher's invalidation path (reset/crash/release): that path is the target
being torn down or rebooted, where the existing `_SessionSubscriber` reap already
guarantees no orphan (§4 item 3) and where a session-level teardown step (e.g.
watchdog-restore) would be meaningless — a reboot restores defaults anyway. So
`SessionGuard` has no `force_drop`/blocking distinction to model; every
`SessionGuard.teardown` runs synchronously on the handler thread and MAY block.
(Spec-review round 2, Findings 2/3: a `phase` discriminator and dispatcher
routing were dropped as speculative — no teardown step does useful work on the
invalidation path.)

`halt_recorded` lets `teardown` distinguish a session that actually parked the
kernel `HALTED` from a failed attach that never did, which drives the resume
post-condition and the `close` `force` flag (§3.5).

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
  again on a retry (e.g. a re-attempted `debug.end_session`).
- **Non-fatal** — it MUST NOT raise to abort teardown; a step that fails records
  the failure and teardown continues to the next step (the resume + reap of the
  target can never be blocked by a misbehaving extension). `SessionGuard.teardown`
  wraps each step in `contextlib.suppress`-with-logging and aggregates errors into
  `TeardownReport.step_errors`.

Teardown steps run only on the synchronous handler path (clean end + attach
error), so they MAY block on I/O; there is no non-blocking out-of-band path to
guard against (§3.1). #69's ssh watchdog-restore is a `TeardownStep` — it is
relevant exactly on those two paths (the same kernel keeps running), not on the
dispatcher invalidation path (where the target is resetting). #66 ships no steps
beyond the built-in resume (§3.5), which is not a `TeardownStep` but a fixed core
action.

### 3.3a `TeardownReport`

`teardown()` returns a `TeardownReport` so the handler can surface (never
re-raise) what happened:

```python
@dataclass(frozen=True)
class TeardownReport:
    step_errors: dict[str, str]          # step.name -> repr(exc) for any step that raised (suppressed)
    close_error: str | None              # repr(exc) if the injected close() raised (suppressed); else None
    resume_ok: bool                      # §3.5 post-condition after close() (+ force_reap fallback)
    resume_detail: str                   # observational note when resume_ok is False (logged, not raised)
```

`step_errors` feeds the handler's `teardown_step_errors` response detail (§5).
`close_error` records a partial close (§3.4 step 1). `resume_ok`/`resume_detail`
record the §3.5 post-condition after the `force_reap` fallback; a `False`
`resume_ok` is a logged `INFRASTRUCTURE_FAILURE`, not a control-flow error.

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
        force_reap: Callable[[], None],
    ) -> TeardownReport:
        """The single idempotent teardown invariant. Runs teardown_steps in REVERSE
        declared order (LIFO unwind), then:

        1. invokes `close` (the existing transaction.close path: reap backend,
           release guard/lease, delete record). A raise from `close` is
           suppressed+recorded (`close_error`) — it MUST NOT abort teardown, since
           the resume verification below is exactly what catches a partial close.
        2. calls `read_record` to verify the §3.5 post-condition (no orphaned
           HALTED record).
        3. if the post-condition does NOT hold (close raised partway and left a
           live HALTED record with no owner), invokes `force_reap` — the
           transaction's existing session-id-fenced out-of-band release (the same
           primitive the dispatcher's force_drop uses) — and re-reads.

        Sets `resume_ok` from the final read. `resume_ok=False` means even
        `force_reap` could not clear a live HALTED record — a genuine
        INFRASTRUCTURE_FAILURE the handler logs loudly. Never raises."""
```

`SessionGuard` holds no per-session state — it is a stateless policy object
constructed once and injected into the handlers (matching the repo's
constructor-injection-for-tests convention). The per-session state lives where it
already does: the durable `TransportSession` record and the transaction's
in-memory token map.

`close`, `read_record`, and `force_reap` are passed in rather than `SessionGuard`
reaching into the transaction/registry, so the guard stays decoupled from
`TransportTransaction` and is unit-testable with fakes. All three are wired by the
handler to the existing transaction primitives: `close` →
`transaction.close(sid, force=...)`, `read_record` →
`session_registry.read_record(target_key)`, `force_reap` → the transaction's
session-id-fenced out-of-band release (the same call the dispatcher's `force_drop`
makes). `SessionGuard` itself touches none of them directly.

The lifecycle dispatcher's invalidation path is **not** routed through
`SessionGuard` (§3.1): `_SessionSubscriber` keeps its existing reap unchanged, so
#66 adds no code there — it only adds a conformance test that the
timeout/invalidation path already leaves no orphan and no live `HALTED` record
(§6). This keeps the guard a pure handler-side composition and avoids the
speculative `phase`/`force_drop`-step apparatus.

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

**The `resume_ok` post-condition is exactly the AC1 property and nothing else**
(spec-review round 2, Finding 4): after teardown, `read_record()` is either `None`
(record deleted) or non-`None` but **not** `HALTED`. The recovery tombstone is a
separate, orthogonal concern (it gates *future* ssh-admission, not whether the
target is stopped now) and is **not** part of `resume_ok`; where a tombstone is
expected it is asserted by its own test (§6), not folded into the resume check.
`teardown` checks the post-condition via `read_record` after `close`; on failure
it invokes `force_reap` and re-checks (§3.4). The two `SessionGuard` exit paths:

- **Clean end** (`reason="ended"`, `halt_recorded=True`):
  `transaction.close(force=True)` reaps the backend (QEMU auto-resumes the VM when
  gdb disconnects in the batch-controller model) and deletes the record.
  `read_record()` → `None` → `resume_ok=True`. ssh-tier admits again because the
  next probe reads `UNKNOWN` against the (still-`READY`) snapshot.
- **Attach error / post-attach precondition failure** (`reason="attach_error"`):
  the `close` `force` flag follows `ctx.halt_recorded`. **Kernel never parked
  `HALTED`** (`halt_recorded=False` — attach failed before/at connect, kernel
  still running): `close(force=True)` deletes the record with **no** tombstone, so
  a never-halted kernel is not left ssh-blocked (resolves the AC1 tension). **Halt
  was recorded** (`halt_recorded=True` — the halt landed but no clean resume was
  confirmed): `close(force=False)` reaps the backend (resuming the kernel) and
  leaves a `closed_while_halted` recovery tombstone, because the server cannot
  *prove* the kernel resumed; the agent clears it with
  `transport.open(recovery=True)` (the existing clearance path). Either way the
  backend is reaped and the record is deleted, so `resume_ok=True`; the tombstone
  presence on the halted branch is asserted separately.

The **timeout / invalidation** path (`target.resetting/crashed/released/...`) is
not a `SessionGuard` exit path: the dispatcher's `_SessionSubscriber` already
releases guard/lease/record and reaps the backend under the bounded
`teardown_deadline` (§5.5). #66 verifies — via a conformance test (§6) — that this
existing path leaves no orphaned helper and no live `HALTED` record, satisfying
the "times out" clause of AC1 without new teardown code.

The resume invariant is therefore the testable statement of AC1: **on every exit
path — clean end, attach error, or timeout/invalidation — the backend is reaped
and the durable record is left non-`HALTED` (deleted, or tombstoned only when a
halt was recorded), never a live `HALTED` record with no owner.** A failed attach
that never halted the kernel resumes cleanly with no tombstone.

## 4. Wiring (`server.py`)

`create_app` constructs one `SessionGuard(pre_attach=(), post_attach=(),
teardown_steps=())` and injects it into the two debug handlers (additive keyword
arg, default `None` → the seam is inert on a non-wired server, matching the
existing transaction/admission/registry optionality). The lifecycle dispatcher and
`_SessionSubscriber` are **not touched** by #66.

1. **`debug_start_session_handler`** — call `guard.enter(ctx)` (pre-attach) **before**
   `transaction.open()`; after `open()`+`_halt`+`provider.start_session` commit,
   call `guard.verify_attached(ctx, session)` (post-attach) before returning. On any
   exception from `open()`/`_halt`/`provider.start_session`/`verify_attached`, call
   `guard.teardown` with `reason="attach_error"`, `halt_recorded=<did _halt run?>`,
   `close=lambda: transaction.close(sid, force=not halt_recorded)`,
   `read_record=lambda: session_registry.read_record(target_key)`, and
   `force_reap=lambda: transaction.force_release(sid)` — replacing today's bare
   `transaction.close(force=False)`. `halt_recorded` is `True` iff
   `_halt_debug_transport` ran before the failure (§3.5).
2. **`debug_end_session_handler`** — on a clean provider detach, call
   `guard.teardown` with `reason="ended"`, `halt_recorded=True`,
   `close=lambda: transaction.close(sid, force=True)`, the same `read_record`, and
   `force_reap` — replacing today's bare `transaction.close(force=True)`.

`transaction.force_release(session_id)` is a thin public wrapper exposing the
existing session-id-fenced out-of-band release that `_SessionSubscriber.force_drop`
already performs internally (`transaction.py:105-138`); #66 adds this one method so
the handler-side `force_reap` reuses the proven path rather than duplicating it.

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
  guard/lease released, the record left non-`HALTED` (`resume_ok=True`), **and**
  (separate assertion) a current `closed_while_halted` recovery tombstone exists.
- **Resume-on-error, no halt** (`halt_recorded=False`): a failure before `_halt`
  drives `teardown` → `close(force=True)`; assert the record is deleted, **no**
  recovery tombstone, and a subsequent ssh-tier admit succeeds (a never-halted
  kernel is not left ssh-blocked — the AC1 edge).
- **Partial-close remediation**: a fake `close` that releases nothing and raises
  (leaving a live `HALTED` record) → `teardown` records `close_error`, invokes
  `force_reap`, re-reads, and `resume_ok=True`; assert `force_reap` was called and
  the record is gone. A `force_reap` that also fails → `resume_ok=False` with
  `resume_detail` set (the loud `INFRASTRUCTURE_FAILURE` signal).
- **Clean end resume**: `teardown(reason="ended")` deletes the record
  (`resume_ok=True`); a subsequent ssh-tier admit succeeds.
- **Idempotency**: a double `teardown` (a re-attempted `debug.end_session`) is a
  safe no-op the second time (`close` idempotent, `read_record` → `None`,
  `resume_ok=True`, `force_reap` not called).
- **Teardown-step ordering + isolation**: steps run in reverse; a raising step is
  suppressed (recorded in `step_errors`) and the next step + `close` still run;
  `resume_ok` still holds.
- **Resume-on-timeout (existing dispatcher path, conformance only)**: emit a
  `target.resetting`/`releasing` event for a `SessionGuard`-opened session and
  assert the existing `_SessionSubscriber` leaves no orphaned helper (fake proxy
  `stop_by_identity` called) and no live `HALTED` record — proving the "times out"
  clause of AC1 holds **without** #66 adding teardown code on that path.
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
