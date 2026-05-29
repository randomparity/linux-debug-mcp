# ADR 0013 — SessionGuard: a precondition/teardown seam composing existing primitives, with one shared idempotent teardown and a guaranteed-resume invariant

**Status:** Accepted (2026-05-29) · **Issue:** #66 (epic #9, split from #17) · **Affects:** `seams/guard.py` (new `SessionGuard` beside `StopCapableGuard`), `coordination/transaction.py` (`_SessionSubscriber` teardown-step hook), `server.py` (debug start/end wiring); plug-in point for #69 (watchdog), #70 (symbol version-lock), #68 (StopCapableGuard, already shipped)

## Context

The interface contract (§5.5, §5.6, §9.1) and issue #17 call for a `SessionGuard`
context that runs preconditions on enter and teardown on exit for every
interactive `debug.*` session, with a **guaranteed-resume / no-orphan** invariant
and named plug-in points for the watchdog helper and symbol version-lock.

By the time #66 is implemented, the transport-abstraction work (#10) has already
shipped most of the substrate: `InProcessStopCapableGuard`, the awaited bounded
`LifecycleDispatcher`, the `open()`/`close()` write-ahead transaction with full
rollback and out-of-band force-reap (`_SessionSubscriber`), the admission service,
and the ssh-tier `HALTED` fast-reject in `admit_ssh_tier`. The transport spec
explicitly framed `seams/guard.py` as "a minimal impl the seam #08 later swaps"
and listed `SessionGuard` as #08-owned but unbuilt.

So #66 is not greenfield. The open questions are: **(1) what shape does
`SessionGuard` take given the existing primitives; (2) where does the
guaranteed-resume invariant bite; (3) how do the three exit paths (clean end,
attach error, timeout/invalidation) share teardown; and (4) how do #69/#70 plug
in?**

## Decision

1. **`SessionGuard` is a thin, stateless composition layer**, not a new owner of
   the session lifecycle. It is constructed once and injected into the debug
   handlers. It composes the existing primitives (guard token, lease, transaction
   `close`, dispatcher subscriber) and adds two things only: ordered
   precondition/teardown extension points, and the resume invariant. It does
   **not** subsume `TransportTransaction`, the dispatcher, or admission.

2. **The guaranteed-resume invariant bites in teardown** as an observational
   post-condition (detailed in decision 6): on every exit path the durable
   `TransportSession` record is either deleted or carries a `recovery_required`
   tombstone — **never a live `HALTED` record with no owner**. Teardown checks this
   via `read_record` and records it, rather than relying on QEMU auto-resume as an
   untested implicit side effect.

3. **One idempotent `teardown(ctx, *, close, read_record)` routine is the single
   source of truth**, invoked by the handler exit paths:
   `debug_start_session_handler`'s attach-error path and
   `debug_end_session_handler`'s clean path. `close` and `read_record` are
   **injected** so `SessionGuard` stays decoupled from the transaction/registry and
   is unit-testable with fakes. The dispatcher's `_SessionSubscriber`
   (timeout/invalidation) does **not** call this method — see decision 3a — but it
   runs the same `teardown_steps`, so the precondition/teardown *steps* are shared
   even though the orchestration entry points differ.

3a. **The dispatcher carries the `teardown_steps` as opaque data, not a
   `SessionGuard` reference.** `bind_lifecycle(dispatcher, teardown_steps=...)`
   passes the step list into `TransportTransaction`, which forwards it to each
   `_SessionSubscriber`; the subscriber invokes the steps directly with the correct
   `phase`. The transaction never holds a `SessionGuard` object, so decision 1's
   decoupling holds — the coupling is to a list of `TeardownStep` data, which the
   transaction already conceptually owns (it owns session teardown). This keeps the
   single shared step set without inverting the layer dependency.

4. **Plug-in points are injected, ordered, Protocol-typed lists**, in three slots:
   `pre_attach` (`PreAttachPrecondition`, runs before any acquisition),
   `post_attach` (`PostAttachPrecondition`, runs after the attach with the live
   `TransportSession` so it can read the running kernel), and `teardown_steps`
   (`TeardownStep`). #66 ships all three empty (plus the built-in resume in
   `close`). #70's symbol version-lock adds a `pre_attach` static check **and** a
   `post_attach` build-id-vs-running-kernel check (the live check cannot run before
   attach, so a single pre-attach slot would not host it). #69's watchdog-restore
   adds a `TeardownStep`. Teardown steps run in reverse declared order (LIFO
   unwind), are idempotent, non-fatal (suppressed + aggregated, never block
   resume/reap).

5. **Execution constraint is an explicit `phase` on the context, not inferred from
   `reason`.** `SessionGuardContext.phase ∈ {"bounded","force_drop"}` tells a
   teardown step whether it may block: `"bounded"` (clean end and the dispatcher's
   deadline-supervised `invalidate` worker) allows I/O; `"force_drop"` (the
   dispatcher's non-blocking out-of-band path, §5.5) forbids it. A blocking step
   no-ops under `"force_drop"`. Without this, a step could not distinguish the two
   dispatcher methods (they carry the same `reason`) and the non-blocking contract
   would be unsatisfiable.

6. **The resume invariant is an observational post-condition, not a snapshot
   transition.** The local-qemu admission snapshot stays `READY` throughout a
   gdbstub session; ssh-tier `HALTED` gating is carried by the durable
   `TransportSession` record's `execution_state`. "Resume" therefore means: after
   `teardown` the durable record is deleted, or — only when a halt was recorded and
   a clean resume was not confirmed — carries a current `recovery_required`
   tombstone; never a live `HALTED` record with no owner. `teardown` checks this
   via an injected `read_record` and records `resume_ok` in the report; a violation
   is logged, never raised. A **failed attach that never halted the kernel**
   (`halt_recorded=False`) deletes the record with no tombstone, so a running
   kernel is never left ssh-blocked.

## Consequences

- #66 is a small, low-risk change: a new stateless seam class, three call-site
  rewrites that wrap (not replace) existing `transaction.close` calls, one
  teardown-step hook on `_SessionSubscriber`, and tests. No working, tested
  primitive is rewritten.
- The resume invariant becomes an explicit, tested statement (record deleted or
  tombstoned; never orphaned `HALTED`) rather than an emergent property.
- #69 and #70 land as single injected steps with no further `SessionGuard`
  changes; #69's blocking ssh restore is constrained to the `invalidate`/clean
  paths and is a documented no-op on `force_drop`.
- The §5.6 rule 2 `HALTED` fast-reject is left in `admit_ssh_tier` where it
  already lives and is already tested; #66 adds a conformance test binding it to
  the `SessionGuard` lifecycle rather than relocating the check.
- `SessionGuard.teardown` aggregating teardown-step errors means a misbehaving
  extension (e.g. a watchdog-restore that throws) is visible in the response
  details but can never strand the target stopped or leak a helper.

## Considered & rejected

1. **Full orchestrator — `SessionGuard` owns the session lifecycle, subsuming or
   wrapping `TransportTransaction` and the dispatcher subscription.** Rejected: it
   is a large refactor of working, tested code (the transaction's write-ahead
   rollback and the dispatcher's bounded force-reap are intricate and conformance-
   tested), for no behavioral gain over composition. Violates "replace, don't
   deprecate" only in the sense that there is nothing broken to replace, and "no
   premature abstraction" — the composition layer is the minimal thing that
   satisfies the contract.

2. **Protocol + interfaces only — define the `SessionGuard` Protocol and the
   precondition/teardown signatures as types/ABCs and defer the in-process impl to
   #68/#69/#70.** Rejected: AC1 ("no target left stopped after any session
   ends/errors/times out") is a behavioral guarantee, not an interface; shipping
   only types would leave the guaranteed-resume invariant unimplemented and
   untested, failing the acceptance criteria.

3. **Per-request guard reconstruction — reconstruct a full `SessionGuard` from the
   durable record on every `debug.*` request and enter/exit it around each
   operation.** Rejected: a debug session spans many stateless MCP requests, so
   "enter" would re-run preconditions (symbol-lock, watchdog-relax) on every read,
   which is both wrong (watchdog already relaxed) and expensive. Preconditions
   belong at attach (once); teardown belongs at the three real exit points. A
   stateless policy object whose `teardown` all three paths call is the correct
   granularity.

4. **Overridable subclass hook methods (`check_symbols()`,
   `relax_watchdog()`/`restore_watchdog()`) instead of injected step lists.**
   Rejected: couples extension to subclassing, so #69 and #70 would each need to
   subclass (and a combined deployment would need multiple-inheritance or a
   merged subclass). Injected ordered lists compose additively — each sibling
   issue contributes one step — and match the repo's constructor-injection-for-
   tests convention.

5. **Global registry / callback list of teardown callbacks.** Rejected: least
   explicit about ordering and lifetime, and hides the dependency from the call
   site. Injected lists make the ordered, per-`SessionGuard` step set visible and
   testable.

6. **Re-enable ssh-tier mid-session on `debug.continue` (flip the durable record
   back to `EXECUTING` + bump epoch) as part of the resume invariant.** Rejected
   for #66 scope: that is execution-state-gate territory (§5.6 rule 2's
   *permitted-while-EXECUTING* half), a distinct change to the live admission
   path, not the session-exit resume invariant #66 owns. Deferred; #66 guarantees
   resume at exit only.

## References

contract §5.5 (awaited bounded lifecycle delivery + force-reap), §5.6 (rule 1
guard authority; rule 2 ssh-tier `HALTED` fast-reject), §9.1 (in-process
dispatcher); [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md)
(guard token is the stop-controller authority, owned by 08's SessionGuard);
[ADR 0003](0003-layer3-backend-attachment-vs-transport-session-ownership.md)
(Layer-4 owns the `TransportSession`); spec
`docs/superpowers/specs/2026-05-29-session-guard-design.md`.
