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

3. **One idempotent `teardown(ctx, *, close, read_record, force_reap)` routine is
   the single source of truth**, invoked by the two handler exit paths:
   `debug_start_session_handler`'s attach-error path and
   `debug_end_session_handler`'s clean path. `close`, `read_record`, and
   `force_reap` are **injected** so `SessionGuard` stays decoupled from the
   transaction/registry and is unit-testable with fakes. The dispatcher's
   `_SessionSubscriber` (timeout/invalidation) is **not** routed through
   `SessionGuard` at all (see decision 5) — its existing reap already satisfies the
   "times out" clause of AC1 and #66 only conformance-tests it.

4. **Plug-in points are injected, ordered, Protocol-typed lists**, in three slots:
   `pre_attach` (`PreAttachPrecondition`, runs before any acquisition),
   `post_attach` (`PostAttachPrecondition`, runs after the attach with the live
   `TransportSession` so it can read the running kernel), and `teardown_steps`
   (`TeardownStep`, run on the two synchronous handler exit paths only). #66 ships
   all three empty (plus the built-in resume in `close`). #70's symbol version-lock
   adds a `pre_attach` static check **and** a `post_attach`
   build-id-vs-running-kernel check (the live check cannot run before attach, so a
   single pre-attach slot would not host it). #69's watchdog-restore adds a
   `TeardownStep`, which is meaningful exactly on the clean-end and attach-error
   paths (same kernel keeps running) and not on the dispatcher path (target
   resetting). Teardown steps run in reverse declared order (LIFO unwind), are
   idempotent, non-fatal (suppressed + aggregated, never block resume/reap).

5. **The lifecycle-dispatcher invalidation path is NOT routed through
   `SessionGuard`.** Every dispatcher invalidation (`resetting`, `crashed`,
   `releasing`, `lease_expired`, `booting`) is a target teardown/reboot, where the
   existing `_SessionSubscriber` already reaps the backend and releases
   guard/lease/record under the bounded `teardown_deadline`, and where a
   session-level teardown step (e.g. watchdog-restore) would be meaningless (a
   reboot restores defaults). Routing `teardown_steps` through that path would
   require a `phase`/`force_drop`-safety discriminator on the context to honor
   §5.5's non-blocking rule — machinery with **no consumer that does useful work
   there**. So #66 leaves the dispatcher untouched, drops the `phase` concept, and
   `SessionGuard.teardown` always runs synchronously on the handler thread (may
   block). The "times out" clause of AC1 is satisfied by the existing reap and
   proven by a conformance test.

6. **Resume is actively guaranteed, not merely observed.** The local-qemu
   admission snapshot stays `READY` throughout a gdbstub session; ssh-tier `HALTED`
   gating is carried by the durable `TransportSession` record's `execution_state`.
   The `resume_ok` post-condition is exactly the AC1 property — after `teardown`,
   `read_record()` is `None` or non-`HALTED` (the recovery tombstone is a separate
   ssh-admission concern, asserted by its own test, not folded into `resume_ok`).
   `teardown` runs `close` (suppressing+recording any raise as `close_error`),
   verifies the post-condition via `read_record`, and **if it does not hold,
   invokes `force_reap`** — `transaction.force_release(session_id)`, a **more
   forceful primitive than `close`, not a retry of it**: it skips the
   failure-prone `transport.close` (the likely cause of the partial close) and does
   only the session-id-fenced `delete_record` + `guard.revoke` + lease release that
   stops the ssh-tier probe reading `HALTED`, rebuilt from the durable record;
   any still-live backend is reaped by `reconcile()` on next start (§5.5 backstop).
   `resume_ok=False` therefore means even `force_reap` failed: a genuine
   `INFRASTRUCTURE_FAILURE` logged loudly, not a silently-stranded target. The
   attach-error path keeps today's `close(force=False)`/`closed_while_halted`
   tombstone semantics — see rejected-alt 9 for why no `halt_recorded` discriminator
   is introduced.

## Consequences

- #66 is a small, low-risk change: a new stateless seam class, two handler
  call-site rewrites that wrap (not replace) existing `transaction.close` calls,
  one thin `transaction.force_release` wrapper over the existing out-of-band
  release, and tests. No working, tested primitive is rewritten; the dispatcher is
  untouched.
- Resume becomes an actively-enforced, tested guarantee (verify post-condition,
  then `force_reap` remediation, then loud `INFRASTRUCTURE_FAILURE` only if even
  that fails) rather than an emergent or merely-logged property.
- #69 and #70 land as single injected steps with no further `SessionGuard`
  changes; #69's restore runs on the clean-end/attach-error paths (same kernel
  running) and is simply absent from the dispatcher path (target resetting).
- The §5.6 rule 2 `HALTED` fast-reject is left in `admit_ssh_tier` where it
  already lives and is already tested; #66 adds a conformance test binding it to
  the `SessionGuard` lifecycle rather than relocating the check.
- `SessionGuard.teardown` aggregating teardown-step + close errors means a
  misbehaving extension (a watchdog-restore that throws) or a partial close is
  visible in the response details but can never strand the target stopped or leak
  a helper — `force_reap` is the backstop.

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
   belong at attach (once); teardown belongs at the real exit points. A stateless
   policy object whose `teardown` the handler exit paths call is the correct
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

6. **Route `teardown_steps` through the lifecycle dispatcher's
   `invalidate`/`force_drop` (with a `phase` discriminator so steps know whether
   they may block).** Considered in spec-review round 1, rejected in round 2: no
   teardown step does useful work on the invalidation path — every invalidation is
   a target reset/crash/release/reboot, where a watchdog-restore is meaningless and
   the existing `_SessionSubscriber` reap already prevents orphans. Routing through
   it would add a `phase`/`force_drop`-safety contract to satisfy §5.5's
   non-blocking rule purely to serve a consumer that does nothing there —
   speculative machinery the repo's "no speculative features" rule forbids. #66
   leaves the dispatcher untouched and conformance-tests that its existing reap
   satisfies the "times out" clause of AC1.

7. **Treat resume as an observe-and-log post-condition with no remediation** (the
   round-1 design: `teardown` reads the record after `close` and logs
   `resume_ok=False` but takes no further action). Rejected in round 2: AC1 demands
   a *guarantee*, and a monitor that only logs its own violation is not one — a
   partial `close` that left a stranded `HALTED` record (or a fenced `delete_record`
   no-op under a concurrent reopen) would leave `target.run_tests` gated
   indefinitely. The accepted design adds the `force_reap` remediation so
   `resume_ok=False` means *even the backstop failed*, a true infrastructure fault —
   not a routine stranding.

8. **Define `force_reap` as a re-run of `close` / `_SessionSubscriber.force_drop`.**
   Rejected in round 3: `force_reap` is invoked *because* `close` already failed and
   stranded a `HALTED` record, so repeating `close`'s `transport.close → release →
   delete` sequence would wedge identically and back nothing up; and `force_drop`'s
   release reads in-memory `_OpenState` the `TransportTransaction` cannot address by
   `session_id`. The accepted `force_release(session_id)` is therefore strictly more
   forceful and record-derived: skip `transport.close`, do the fenced
   `delete_record` + `guard.revoke` + lease release, leave any live backend to
   `reconcile()`.

9. **Add a `halt_recorded` discriminator so a failed attach that never halted the
   kernel resumes with no recovery tombstone.** Considered in round 2, rejected in
   round 3: `_halt_debug_transport` runs *before* `provider.start_session`
   (`server.py:4111` precedes `4113`) and a `SessionGuard` teardown is reached only
   *after* `open()` commits a session, so every teardown-reachable attach failure
   has the kernel already parked `HALTED` — the `halt_recorded=False` branch has no
   trigger in the real handler and only a synthetic test could exercise it.
   Introducing it would also silently change the existing deliberate unconditional
   `close(force=False)` attach-error semantics for a case that cannot occur. The
   accepted design keeps the unconditional `force=False` on attach-error.

10. **Re-enable ssh-tier mid-session on `debug.continue` (flip the durable record
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
