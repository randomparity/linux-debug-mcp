# ADR 0016 — Watchdog relax/restore helper: a stateful capture/restore policy behind the SessionGuard slots, wired inert with a documented post-acquire placement contract

**Status:** Accepted (2026-05-29) · **Issue:** #69 (epic #9, split from #17, consumed by #66) · **Affects:** `seams/watchdog.py` (new); the restore plugs into `seams/guard.py` `SessionGuard`'s exit (`TeardownStep`) slot, the relax is a post-acquire `policy.relax(ctx)` call (decision 4). No change to `guard.py`, `transaction.py`, the dispatcher, or `server.py` wiring.

## Context

A naive interactive stop wedges a target: the kernel lockup detectors (and, on
POWER, the PHYP/hardware watchdog) keep counting while a CPU is held at a
breakpoint, so on resume a soft/hardlockup fires and the target panics or resets.
Issue #69 calls for a helper that relaxes the relevant watchdogs before a stop and
restores them after — on success, error, and timeout — for **x86 and POWER**,
hooked into `SessionGuard` enter/exit.

ADR 0013 already designed `SessionGuard` with this exactly in mind: it ships
`PreAttachPrecondition` / `PostAttachPrecondition` / `TeardownStep` slots empty and
names #69's watchdog-restore as the first `TeardownStep`. So #69 is not greenfield
seam design — it is the **content** of two slots plus the helper behind them.

Three questions the contract leaves open: **(1)** how far should #69 wire the
helper, given the only implemented interactive tier (QEMU gdbstub) freezes the whole
VM during a stop so its lockup detectors cannot fire; **(2)** where does the *relax*
run, given the enter slot runs before `transaction.open()` and the live handler
skips teardown on an `open()` failure; and **(3)** how does "restore on timeout"
reconcile with ADR 0013's decision that the lifecycle-dispatcher invalidation path
is not a `SessionGuard` exit and a reboot restores watchdog defaults anyway.

## Decision

1. **The helper is a stateful capture/restore policy behind a channel
   abstraction.** `WatchdogPolicy` holds, keyed by `session_id`, the knob values it
   read at relax time; `relax` reads-then-captures-then-writes-relaxed **once per
   session**, `restore` writes the captured values back idempotently and clears the
   capture. The key is `session_id` — **not** `generation` — because `generation` is
   a 0 placeholder at enter and falls back to 0 at clean-end teardown when the record
   is already gone (`server.py:4845`), so it is not stable across the relax and
   restore contexts; `session_id` is authoritative wherever relax runs (post-acquire)
   and at teardown. All target I/O goes through an injected `WatchdogControl` Protocol
   (`read_knob`/`write_knob`), so the mechanism is decoupled from any transport and
   unit-testable with a fake. #69 ships **no** concrete channel; the live tier
   supplies one over `SshRunner` (in-band) and/or an out-of-band power channel.

2. **Architecture variants are an ordered knob list, not branching code.** A
   `WatchdogArch` enum selects the `WatchdogKnob` list. x86_64 and ppc64le share the
   five generic lockup-detector sysctls (`kernel.nmi_watchdog`, `kernel.watchdog`,
   `kernel.watchdog_thresh`, `kernel.softlockup_panic`, `kernel.hardlockup_panic`);
   ppc64le adds an `out_of_band=True` `phyp_partition_watchdog` knob that, absent an
   out-of-band channel, is **recorded skipped, never executed** — matching the
   repo's future-stub posture for power/console tools.

3. **#69 wires the helper inert, like #66's empty slots.** The QEMU gdbstub tier
   freezes the whole VM (no guest time passes), so its lockup detectors cannot fire
   during a stop and there is nothing to relax; wiring an ssh sysctl path into the
   gdbstub handler would be speculative dead code on a tier that does not need it. So
   `create_app` is **unchanged**: the `WatchdogRestoreStep` adapter and the
   `policy.relax` call are exercised through `SessionGuard.teardown` + a direct
   `relax` call in **tests** with a fake channel, and the live KGDB/remote/POWER tier
   (epic #9) owns the concrete channel and the wiring.

4. **Only restore is a SessionGuard Protocol adapter; relax is a post-acquire
   call.** `WatchdogRestoreStep` is a `TeardownStep` (the exit slot). Relax is a
   direct `policy.relax(ctx)` call the live integrator places in the **post-acquire /
   pre-halt window** — after `transaction.open()` commits (every later failure runs
   `teardown`, so a restore is guaranteed, and `session_id` is now authoritative for
   the key) and before `provider.start_session` attaches (the in-band channel is
   still reachable). Relax is deliberately **not** a `pre_attach` precondition: that
   slot runs before `open()` with `session_id=None`, and the handler early-returns on
   an `open()` failure without calling teardown, so a relax there would both mis-key
   under a `None` session and leak a relaxed watchdog. #69's tests invoke relax with a
   post-acquire-shaped context (real `session_id`) and restore via `teardown` with the
   same `session_id`; the live tier must place the relax in that window (or add a
   dedicated hook there).

5. **"Restore on timeout" is the operation timeout via the synchronous teardown;
   the dispatcher reboot path is a deliberate no-op.** An attach/interactive-stop
   timeout surfaces as a timeout-category `ProviderDebugError` from
   `provider.start_session`, which drives the same `teardown(reason="attach_error")`
   the error path takes — so restore runs. The lifecycle-dispatcher invalidation
   path (`resetting`/`crashed`/`releasing`/`lease_expired`) is **not** a restore
   path: ADR 0013 already established it is not a `SessionGuard` exit and the target
   reboots with default watchdog settings. #69 adds a conformance assertion that the
   restore step is correctly absent there, reaffirming ADR 0013 without reopening it.

6. **Both `relax` and `restore` never raise; restore-write failure is non-fatal.**
   They return reports. `WatchdogRestoreStep.teardown` raises only on a restore-write
   failure so the failure is captured into `TeardownReport.step_errors`
   (suppressed+aggregated by `SessionGuard.teardown`); it never blocks `close`, so
   the resume + reap invariant (ADR 0013) holds regardless. `relax` failures do not
   abort the enter — a watchdog that could not be relaxed is a logged degradation,
   not a reason to refuse a debug session.

## Consequences

- #69 is a self-contained new module (`seams/watchdog.py`) plus tests; it touches no
  existing runtime path, so it cannot regress #66/#68's tested invariants.
- The relax/restore round-trip, idempotency, restore-on-error, restore-on-timeout,
  channel-failure aggregation, and x86-vs-POWER variance are all proven at the seam
  with a fake channel — the same granularity #66 was tested at.
- The live tier inherits a precise contract: supply a `WatchdogControl`, place the
  relax in the post-acquire/pre-halt window, add the restore as a `TeardownStep`.
- POWER's platform watchdog is declared but deferred; when an out-of-band channel
  lands, the `out_of_band` knob becomes executable with no change to the policy core.
- `restore` deleting its whole capture after one pass means a restore-write failure
  is not auto-retried within #69; a live tier wanting post-resume retry re-`relax`/
  re-`restore`. This matches `SessionGuard.teardown`'s bounded-best-effort posture
  for `close`.

## Considered & rejected

1. **Live-wire an ssh sysctl relax/restore into `debug_start_session_handler`
   now.** Rejected: the only implemented tier is the QEMU gdbstub, which freezes the
   whole VM during a stop, so the lockup detectors cannot fire and the relax is a
   no-op against the only real target; it would also force the gdbstub handler to
   resolve a rootfs/ssh channel it otherwise does not need. Speculative dead code on
   a tier that does not need it ("no speculative features"). The inert-with-seam-tests
   posture matches how #66 shipped its slots.

2. **Add a new post-acquire / pre-halt hook to `SessionGuard` so the relax can run
   live in a guaranteed-teardown window.** Rejected for #69: it enlarges the #66 seam
   (a fourth ordered slot, plus the handler reordering between `open()` and
   `start_session`) to serve a consumer (#69 live) that #69 does not ship. The
   placement requirement is documented (decision 4) and the hook is deferred to the
   live KGDB/remote tier that actually needs it — the same "defer the slot to the
   issue that fills it" discipline ADR 0013 used.

3. **Relax as a `PreAttachPrecondition`.** Rejected on two counts: (a)
   `debug_start_session_handler` early-returns on an `open()` failure without
   teardown, so a pre-attach relax would leave the watchdog relaxed with no restore —
   a correctness leak; and (b) at enter `session_id` is `None`, so a relax keyed on
   `session_id` there would store under a placeholder and never match the teardown
   lookup — restore would silently no-op. Relax is a post-acquire call instead
   (decision 4).

4. **Relax as a `PostAttachPrecondition` (runs after `open()` commits, so teardown
   is guaranteed).** Rejected: the post-attach phase runs **after**
   `provider.start_session` has halted the kernel, so an in-band sysctl channel
   cannot reach the stopped target to read/write the knobs. The relax must precede
   the halt.

5. **Restore over the gdb/RSP channel (poke kernel memory while halted) instead of
   an in-band sysctl channel.** Rejected for #69: it couples the watchdog helper to a
   specific debug backend's memory-write surface and to per-kernel symbol/layout
   knowledge of the watchdog state, far more fragile than sysctl and unavailable
   uniformly across tiers. The `WatchdogControl` Protocol leaves this open to a live
   tier that wants it, but the modeled path is the in-band sysctl channel.

6. **Make the relaxed values full disables only (`0` everywhere) with no capture —
   "relax" = disable, "restore" = re-enable to a fixed default.** Rejected: the
   target's prior watchdog configuration is policy the operator set (a non-default
   `watchdog_thresh`, panic-on-hardlockup for a CI fleet); restoring a fixed default
   would silently change it. Capturing the prior value and writing exactly it back is
   the only correct restore.

7. **Route the restore through the lifecycle-dispatcher invalidation path too, so a
   `lease_expired`/`reset` also restores.** Rejected: contradicts ADR 0013 decision 5
   — every dispatcher invalidation reboots/releases the target, which restores
   watchdog defaults, so a restore is meaningless and would add a blocking I/O step
   on the bounded-deadline teardown path that §5.5 forbids. #69 reaffirms ADR 0013
   with a conformance assertion instead.

8. **Per-knob restore retained on write failure for later auto-retry (do not clear
   the whole capture after one restore pass).** Rejected for #69 scope: it
   complicates idempotency (a second `teardown` would re-attempt only the failed
   knobs, needing a partial-capture state machine) for a retry that the synchronous
   teardown has no second trigger for. A live tier that wants post-resume retry
   re-runs `relax`/`restore`. #69 keeps the simple "clear after one pass" rule that
   makes the second `teardown` a clean no-op.

9. **Re-read the live knobs on a re-`relax` (replace the capture each time).**
   Rejected: after the first relax, the live knob values **are** the relaxed values,
   so a re-read would capture e.g. `nmi_watchdog=0` as the "prior" value and `restore`
   would write the relaxed value back — destroying the operator's true baseline. The
   accepted rule is capture-once per `session_id`: a re-`relax` re-issues the relax
   writes but never re-reads into the capture, so the baseline survives until a
   `restore` consumes it. ("Stacking relaxed-over-relaxed" was never the hazard;
   baseline corruption is.)

## References

contract §5.5 (bounded lifecycle teardown), §5.6 (ssh-tier HALTED gating);
[ADR 0013](0013-session-guard-precondition-teardown-seam.md) (the SessionGuard seam,
empty slots, dispatcher-not-routed decision); spec
`docs/superpowers/specs/2026-05-29-watchdog-relax-restore-design.md`; kernel
`Documentation/admin-guide/lockup-watchdogs.rst`.
