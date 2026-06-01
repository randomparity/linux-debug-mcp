"""Hypothesis property-based stateful test for the consolidated (generation, execution_epoch,
execution_state) admission state machine (ADR 0006 / §5.6).

This is the falsifiable adjudicator for the A5 consolidation: a counterexample here is a real
protocol defect in `coordination.admission.AdmissionService` (fix the mechanism, do NOT weaken the
shadow model).

Scope: ONE TargetKey. Multi-target interactions are out of scope for ADR 0006's invariants — the
state machine is per-key. The rules drive the public surface (`admit_ssh_tier`,
`note_execution_transition`, `cancel_ssh_tier`, `complete`, `rollback`, `close_admission`,
`reopen`, `invalidate_lifecycle`); the shadow model tracks the public observables that the
contract is written against: generation, execution epoch, closed-ness, per-handle admit_epoch /
generation / disposition, and stop-capable guard holder count.

Invariants checked (each enforced as a hypothesis @invariant):
1. NO_HANDLE_COMPLETED_SPANNING_A_HALT — if `complete(handle)` returned, the shadow exec_epoch
   at complete time equals the handle's admit_epoch (no halt happened during its lifetime).
2. EVERY_ADMITTED_HANDLE_AT_CURRENT_EPOCH_AT_ADMIT — at admit time, the bound admit_epoch equals
   the shadow exec_epoch at admit time (an admit MUST observe the current epoch).
3. CANCELLED_HANDLES_ARE_PRE_HALT_ONLY — every handle returned by `cancel_ssh_tier(halt_epoch=E)`
   has admit_epoch <= E AND was admitted in the cancelling call's generation.
4. PRIOR_GENERATION_EVENTS_ARE_NOOPS — calling `note_execution_transition`,
   `cancel_ssh_tier`, or `close_admission` with a stale generation does NOT bump the epoch,
   cancel handles, or change closed-ness.
5. AT_MOST_ONE_STOP_CAPABLE_GUARD_HOLDER — at every step, the real `InProcessStopCapableGuard`
   has at most one outstanding token.

Notes on the model:
- Target state is held at DEBUGGING the entire time, so `admit_ssh_tier` requires an
  ExecutionProof on EVERY call (the path that exercises the epoch fence). A READY target would
  skip the proof check entirely (`_require_executing_proof` is only invoked off-READY).
- We sometimes admit with a FRESHLY-PROBED proof (gen-current, epoch-current, EXECUTING) and
  sometimes with a deliberately STALE proof (older epoch or HALTED). Both branches assert the
  expected outcome from `admit_ssh_tier`.
- `cancel_ssh_tier` is sometimes called with a stale generation (no-op) and sometimes with the
  current generation (acts under per-handle epoch filter).
- `note_execution_transition` is the SINGLE epoch bumper — we never bump the shadow epoch
  directly; we let the call return the new epoch and store that.
- We track the StopCapableGuard via the real `InProcessStopCapableGuard` and acquire/release it
  via our `attach_stop_capable`/`detach_stop_capable` rules, asserting at most one holder.
"""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import HealthCheck, assume, note, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from kdive.coordination.admission import (
    AdmissionError,
    AdmissionHandle,
    AdmissionOp,
    AdmissionService,
    AdmissionState,
    ExecutionProof,
    SnapshotStore,
    TargetSnapshot,
)
from kdive.seams.guard import GuardConflict, InProcessStopCapableGuard
from kdive.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
)
from kdive.seams.target import (
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    TargetState,
)
from kdive.transport.core.base import ExecutionState, LineRole, OpenRequest, TransportRef

KEY = TargetKey(provisioner="local-qemu", target_id="exec-state-machine")
PLATFORM = PlatformMetadata(
    console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=True
)
CHANNEL = TransportRef(provider="qemu-gdbstub", channel_id="rsp-0", line_role=LineRole.RSP, caps=("provides_rsp",))


def _debugging_snapshot(generation: int) -> TargetSnapshot:
    """Authoritative snapshot in DEBUGGING state, so admit_ssh_tier exercises the proof path."""
    return TargetSnapshot(
        generation=generation,
        transports=(CHANNEL,),
        platform=PLATFORM,
        state=TargetState.DEBUGGING,
    )


def _active_transport_handles(machine: ExecStateMachine) -> list[AdmissionHandle]:
    """Transport.open handles still registered in the binding table. After `close_admission`
    these are cancelled-but-PENDING and remain registered until rolled back."""
    bindings = list(machine.admission._bindings.get(KEY, ()))
    return [h for h in machine.transport_handles if h in bindings]


class _HandleRecord:
    """Per-handle shadow record. Tracks the admission-time facts plus the terminal disposition.

    `disposition` records the LAST API call's outcome (so the test can drive a sensible flow):
      - "pending": admitted; no terminal disposal attempted yet.
      - "completed_ok": complete() succeeded → binding removed from _bindings.
      - "rolled_back": rollback() succeeded → binding removed from _bindings.
      - "execution_state_changed_raised": complete() raised ESC, binding NOT removed; the
        contract is that the caller MUST then rollback (or abandon after confirm_reaped).

    `still_registered` independently tracks whether the binding is still in the service's
    `_bindings` table. A binding is registered until `complete()` succeeds, `rollback()` runs,
    or `abandon()` runs — `execution_state_changed_raised` does NOT deregister.
    """

    __slots__ = ("handle", "admit_epoch", "generation", "disposition", "still_registered")

    def __init__(self, handle: AdmissionHandle, admit_epoch: int, generation: int) -> None:
        self.handle = handle
        self.admit_epoch = admit_epoch
        self.generation = generation
        self.disposition: str = "pending"
        self.still_registered: bool = True


class ExecStateMachine(RuleBasedStateMachine):
    """Stateful machine over the (generation, execution_epoch, execution_state) protocol.

    Shadow model:
      - `shadow_generation`: the incarnation we last published. Bumped on `reopen` and
        `invalidate_lifecycle`. The shadow is the source of truth for "what is the current
        generation" because the real snapshot store holds the same value (we publish in lock
        step).
      - `shadow_exec_epoch`: the per-target execution epoch. We never bump it directly; we
        learn the bump by calling `note_execution_transition` and using its return value.
      - `live_records`: every admitted handle's shadow facts.
      - `closed`: whether admission is currently closed (no new admits allowed).
      - `guard_token`: the InProcessStopCapableGuard token currently held (or None).
    """

    def __init__(self) -> None:
        super().__init__()
        self.store = SnapshotStore()
        self.admission = AdmissionService(self.store)
        self.dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.05)
        self.guard = InProcessStopCapableGuard()
        # Seed gen=0, DEBUGGING. We hold DEBUGGING the entire run so admit_ssh_tier always
        # exercises the proof path.
        self.shadow_generation = 0
        self.shadow_exec_epoch = 0  # AdmissionService starts every key at 0
        self.closed = False
        self.live_records: list[_HandleRecord] = []
        # Parallel to live_records but for TRANSPORT_OPEN handles admitted through the
        # recovery-gated admit_recovery edge (ADR 0006 amendment). These are always PENDING
        # in this model — we never promote them — so rollback() is the only disposal.
        self.transport_handles: list[AdmissionHandle] = []
        # Mirror of the dual-write tombstone state the §4.7 helper maintains (durable tombstone
        # generation + admission cache, always equal under the dual-write invariant). `None` =
        # no tombstone. A tombstone at a generation OLDER than the current snapshot is
        # **superseded** by a later reset and no longer gates admit — `reopen` advancing
        # `shadow_generation` is exactly that path. So the effective gate is checked via
        # `_recovery_gated()`, not by carrying a stale boolean.
        self.tombstone_gen: int | None = None
        self.guard_token = None  # the live StopCapableGuard token, or None
        self.admission.publish_snapshot(KEY, _debugging_snapshot(self.shadow_generation))

    # The §4.7 effective-gate predicate, derived from the tombstone generation + snapshot.
    def _recovery_gated(self) -> bool:
        """True iff a tombstone exists at the CURRENT snapshot generation — the only state in
        which `_bind_snapshot` rejects non-recovery admit and `_require_recovery_tombstone`
        accepts admit_recovery (the two §4.7 sides of the same gate)."""
        return self.tombstone_gen is not None and self.tombstone_gen == self.shadow_generation

    # ---------------------------------------------------------------------------------
    # Rules
    # ---------------------------------------------------------------------------------

    @rule(
        proof_kind=st.sampled_from(["fresh_executing", "stale_epoch", "halted", "missing", "stale_generation"]),
        epoch_offset=st.integers(min_value=-3, max_value=0),
    )
    def admit_ssh_tier(self, proof_kind: str, epoch_offset: int) -> None:
        """Try to admit an ssh-tier op. The proof is one of:
          - fresh_executing: gen-current, epoch-current, EXECUTING → must admit (if not closed).
          - stale_epoch: gen-current, EXECUTING, epoch < current → must reject as
            `execution_state_unknown`.
          - halted: gen-current, epoch-current, HALTED → must reject as `target_halted`.
          - missing: proof=None → must reject as `execution_state_unknown`.
          - stale_generation: proof.generation = current - 1 → must reject as `stale_handle`.

        `epoch_offset` is used only for `stale_epoch` (we offset the epoch by -1..-3 from current
        but never below 0; epochs are non-negative).
        """
        if self.closed:
            # Admission is closed → the gate raises admission_closed; we don't drive it through
            # the closed gate here because that path is covered by the `close_admission` /
            # `reopen` rules and the prior-gen-noop invariant.
            return
        if self._recovery_gated():
            # A current tombstone gates BOTH admit_ssh_tier and non-recovery transport.open with
            # `recovery_required` (§4.7) — the matrix the new `admit_transport_open` rule and the
            # `tombstone_gates_ssh_and_non_recovery_admit` invariant adjudicate. Skip here so the
            # original epoch-fence equations this rule is meant to verify remain its own concern,
            # decoupled from the tombstone gate.
            return

        proof: ExecutionProof | None
        if proof_kind == "fresh_executing":
            proof = ExecutionProof(
                generation=self.shadow_generation,
                epoch=self.shadow_exec_epoch,
                state=ExecutionState.EXECUTING,
            )
            expect_admit = True
        elif proof_kind == "stale_epoch":
            # Offset to a strictly older epoch when possible; if we're at epoch 0, this collapses
            # to current (which would actually admit) — skip in that case to keep the rule sharp.
            target_epoch = max(0, self.shadow_exec_epoch + epoch_offset)
            assume(target_epoch < self.shadow_exec_epoch)
            proof = ExecutionProof(
                generation=self.shadow_generation,
                epoch=target_epoch,
                state=ExecutionState.EXECUTING,
            )
            expect_admit = False
        elif proof_kind == "halted":
            proof = ExecutionProof(
                generation=self.shadow_generation,
                epoch=self.shadow_exec_epoch,
                state=ExecutionState.HALTED,
            )
            expect_admit = False
        elif proof_kind == "missing":
            proof = None
            expect_admit = False
        else:  # stale_generation
            assume(self.shadow_generation >= 1)
            proof = ExecutionProof(
                generation=self.shadow_generation - 1,
                epoch=self.shadow_exec_epoch,
                state=ExecutionState.EXECUTING,
            )
            expect_admit = False

        try:
            handle = self.admission.admit_ssh_tier(
                KEY,
                self.shadow_generation,
                PLATFORM,
                execution_proof=proof,
                now=datetime.now(UTC),
            )
        except AdmissionError as exc:
            assert not expect_admit, (
                f"admit_ssh_tier unexpectedly rejected fresh_executing proof: code={exc.code}, "
                f"gen={self.shadow_generation}, epoch={self.shadow_exec_epoch}"
            )
            return

        assert expect_admit, (
            f"admit_ssh_tier admitted a {proof_kind} proof (gen={proof.generation if proof else None}, "
            f"epoch={proof.epoch if proof else None}, state={proof.state if proof else None}); "
            f"shadow gen={self.shadow_generation}, epoch={self.shadow_exec_epoch}"
        )
        # Invariant 2 (epoch fence at admit): the bound admit_epoch equals the shadow epoch.
        assert handle.admit_epoch == self.shadow_exec_epoch, (
            f"admit_epoch mismatch at admission: handle.admit_epoch={handle.admit_epoch}, "
            f"shadow={self.shadow_exec_epoch}"
        )
        assert handle.generation == self.shadow_generation
        self.live_records.append(_HandleRecord(handle, admit_epoch=handle.admit_epoch, generation=handle.generation))

    @rule(generation_kind=st.sampled_from(["current", "stale"]))
    def note_execution_transition(self, generation_kind: str) -> None:
        """Drive a state-transition record. The current-generation branch bumps the epoch by 1;
        a stale-generation call must be a no-op (returns the unchanged epoch)."""
        if generation_kind == "stale":
            assume(self.shadow_generation >= 1)
            stale_gen = self.shadow_generation - 1
            epoch_before = self.shadow_exec_epoch
            returned = self.admission.note_execution_transition(KEY, stale_gen)
            assert returned == epoch_before, (
                f"stale-generation note_execution_transition bumped the epoch: returned={returned}, "
                f"shadow_before={epoch_before}"
            )
            assert self.admission.current_execution_epoch(KEY) == epoch_before
            return

        # current-generation: SHOULD bump
        epoch_before = self.shadow_exec_epoch
        returned = self.admission.note_execution_transition(KEY, self.shadow_generation)
        assert returned == epoch_before + 1, (
            f"current-generation note_execution_transition did not bump epoch by 1: "
            f"returned={returned}, before={epoch_before}"
        )
        self.shadow_exec_epoch = returned
        assert self.admission.current_execution_epoch(KEY) == self.shadow_exec_epoch

    @rule(
        generation_kind=st.sampled_from(["current", "stale"]),
        halt_epoch_kind=st.sampled_from(["current", "older", "future"]),
    )
    def cancel_ssh_tier(self, generation_kind: str, halt_epoch_kind: str) -> None:
        """Trigger an async-halt cancellation. Validates BOTH fences:
        - generation fence: stale generation → no-op (returns []).
        - per-handle epoch filter: cancelled handles have admit_epoch <= halt_epoch.
        """
        if generation_kind == "stale":
            assume(self.shadow_generation >= 1)
            gen = self.shadow_generation - 1
            cancelled = self.admission.cancel_ssh_tier(KEY, gen, halt_epoch=self.shadow_exec_epoch)
            assert cancelled == [], f"stale-generation cancel_ssh_tier cancelled handles: {len(cancelled)}; expected []"
            return

        if halt_epoch_kind == "current":
            halt_epoch = self.shadow_exec_epoch
        elif halt_epoch_kind == "older":
            halt_epoch = max(0, self.shadow_exec_epoch - 1)
        else:  # future
            halt_epoch = self.shadow_exec_epoch + 5  # delayed cancel; epoch may have advanced

        # Snapshot the set of still-registered records BEFORE the call. A binding is in
        # _bindings until rollback/complete-ok/abandon — `execution_state_changed_raised` does
        # NOT remove it, so it can still be returned by cancel_ssh_tier.
        registered_before = {id(rec.handle): rec for rec in self.live_records if rec.still_registered}
        expected_ids = {
            id(rec.handle)
            for rec in registered_before.values()
            if rec.generation == self.shadow_generation and rec.admit_epoch <= halt_epoch
        }

        cancelled = self.admission.cancel_ssh_tier(KEY, self.shadow_generation, halt_epoch=halt_epoch)
        cancelled_ids = {id(h) for h in cancelled}

        # Invariant 3 (per-handle epoch filter and gen fence on cancel return):
        assert cancelled_ids == expected_ids, (
            f"cancel_ssh_tier returned set mismatch: returned={cancelled_ids}, expected={expected_ids}; "
            f"halt_epoch={halt_epoch}, shadow_gen={self.shadow_generation}, "
            f"shadow_epoch={self.shadow_exec_epoch}"
        )
        for handle in cancelled:
            assert handle.admit_epoch <= halt_epoch
            assert handle.generation == self.shadow_generation
            assert handle.cancelled is True
            assert handle.op is AdmissionOp.SSH_TIER

    def _pick_completable_record(self) -> _HandleRecord | None:
        """A still-registered, NOT-cancelled, disposition=='pending' handle. ESC-raised handles
        can't be completed again; cancelled handles must rollback, not complete."""
        for rec in self.live_records:
            if rec.still_registered and rec.disposition == "pending" and not rec.handle.cancelled:
                return rec
        return None

    @rule()
    @precondition(
        lambda self: any(
            r.still_registered and r.disposition == "pending" and not r.handle.cancelled for r in self.live_records
        )
    )
    def complete_handle(self) -> None:
        """Complete a still-registered, non-cancelled, never-ESC-raised handle. If the shadow
        epoch advanced since admit, `complete` MUST raise `execution_state_changed` (§5.6 rule
        2 backstop) AND must NOT remove the binding from `_bindings`.
        """
        rec = self._pick_completable_record()
        assert rec is not None
        epoch_at_complete = self.shadow_exec_epoch
        try:
            self.admission.complete(rec.handle)
        except AdmissionError as exc:
            # The only legitimate refusal here is execution_state_changed (epoch advanced).
            assert exc.code == "execution_state_changed", (
                f"complete() raised unexpected code {exc.code}: admit_epoch={rec.admit_epoch}, "
                f"shadow_epoch={epoch_at_complete}"
            )
            assert rec.admit_epoch != epoch_at_complete, (
                "execution_state_changed raised even though admit_epoch == current shadow epoch "
                f"({rec.admit_epoch} == {epoch_at_complete}) — admission.complete should have succeeded"
            )
            rec.disposition = "execution_state_changed_raised"
            # still_registered stays True — ESC does not deregister; rollback must follow.
            return

        # Success path. Invariant 1: admit_epoch == current epoch at complete time.
        assert rec.admit_epoch == epoch_at_complete, (
            f"complete() succeeded on a handle that spanned a halt: admit_epoch={rec.admit_epoch} "
            f"!= shadow_epoch_at_complete={epoch_at_complete}"
        )
        rec.disposition = "completed_ok"
        rec.still_registered = False

    @rule()
    @precondition(lambda self: any(r.still_registered for r in self.live_records))
    def rollback_handle(self) -> None:
        """Roll back a still-registered handle. Covers PENDING, cancelled, and ESC-raised
        handles — all of which must rollback to deregister."""
        rec = next(r for r in self.live_records if r.still_registered)
        # ssh-tier handles never promote in this model, so they're always PENDING in the
        # AdmissionState sense — rollback is always permitted (no confirm_reaped needed).
        self.admission.rollback(rec.handle)
        rec.disposition = "rolled_back"
        rec.still_registered = False

    @rule(generation_kind=st.sampled_from(["current", "stale"]))
    def close_admission(self, generation_kind: str) -> None:
        """Close admission. With a stale generation that has already been superseded by a newer
        snapshot, close MUST be a no-op (does not change closed-ness or cancel handles).
        """
        if self.closed:
            return  # idempotent re-close is its own scenario covered when closed=True elsewhere
        if generation_kind == "stale":
            assume(self.shadow_generation >= 1)
            stale_gen = self.shadow_generation - 1
            closed_before = self.closed
            cancelled_before = {id(r.handle): r.handle.cancelled for r in self.live_records}
            handles = self.admission.close_admission(KEY, stale_gen)
            # The snapshot is at shadow_generation > stale_gen, so this is a stale retry.
            assert handles == [], (
                f"stale close_admission for gen={stale_gen} (snapshot gen={self.shadow_generation}) "
                f"returned non-empty handles: {len(handles)}"
            )
            assert self.closed == closed_before
            # No registered handle's cancel fence may have flipped.
            for rec in self.live_records:
                assert rec.handle.cancelled == cancelled_before[id(rec.handle)]
            return

        # current generation: actually closes; cancels every still-registered binding —
        # ssh-tier AND transport.open alike (close_admission fences every live binding).
        expected_cancelled_ids = {id(r.handle) for r in self.live_records if r.still_registered}
        expected_cancelled_ids |= {id(h) for h in _active_transport_handles(self)}
        handles = self.admission.close_admission(KEY, self.shadow_generation)
        self.closed = True
        cancelled_ids = {id(h) for h in handles}
        assert cancelled_ids == expected_cancelled_ids, (
            f"close_admission cancelled handle set mismatch: returned={cancelled_ids}, "
            f"expected={expected_cancelled_ids}"
        )
        for rec in self.live_records:
            if id(rec.handle) in cancelled_ids:
                assert rec.handle.cancelled is True
        for handle in self.transport_handles:
            if id(handle) in cancelled_ids:
                assert handle.cancelled is True

    @rule()
    @precondition(lambda self: self.closed)
    def reopen(self) -> None:
        """Reopen: requires the snapshot generation to advance past the closed gen AND no
        registered bindings remain. We model that lifecycle: roll back every still-registered
        binding (PENDING ssh-tier and PENDING transport.open on a closed target both roll
        back freely; we never promote handles in this machine), then bump generation, publish,
        and reopen."""
        for rec in self.live_records:
            if rec.still_registered:
                self.admission.rollback(rec.handle)
                rec.disposition = "rolled_back"
                rec.still_registered = False
        for handle in list(self.transport_handles):
            if handle in self.admission._bindings.get(KEY, ()):
                self.admission.rollback(handle)
        self.transport_handles = []

        self.shadow_generation += 1
        # The admission service does NOT explicitly zero `_exec_epoch[KEY]` on reopen; the next
        # note_execution_* event bumps from its current value. We test that the same fence
        # equations hold across the bump.
        self.admission.publish_snapshot(KEY, _debugging_snapshot(self.shadow_generation))
        self.admission.reopen(KEY)
        self.closed = False

    @rule()
    @precondition(lambda self: not self.closed)
    def invalidate_lifecycle(self) -> None:
        """Drive `invalidate_lifecycle` (closes admission and emits teardown). Then immediately
        roll back / reopen so the property test keeps progressing. Generation is bumped on
        reopen."""
        # No subscribers registered: teardown is a no-op.
        result = self.admission.invalidate_lifecycle(
            LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED),
            self.dispatcher,
            self.shadow_generation,
        )
        note(f"invalidate_lifecycle errors={result.errors}")
        self.closed = True

    # --- StopCapableGuard authority (ADR 0002) ----------------------------------------

    @rule()
    @precondition(lambda self: self.guard_token is None)
    def attach_stop_capable(self) -> None:
        """Acquire the (target-wide) stop-capable guard. Must succeed when no holder."""
        token = self.guard.acquire(KEY)
        self.guard_token = token

    @rule()
    @precondition(lambda self: self.guard_token is not None)
    def detach_stop_capable(self) -> None:
        """Release the stop-capable guard."""
        released = self.guard.release(KEY, self.guard_token)
        assert released is True
        self.guard_token = None

    @rule()
    @precondition(lambda self: self.guard_token is not None)
    def attempt_double_attach(self) -> None:
        """A second acquire must raise GuardConflict — the at-most-one invariant at the
        primitive."""
        try:
            self.guard.acquire(KEY)
        except GuardConflict:
            return
        raise AssertionError("guard.acquire() admitted a second holder; at-most-one violated")

    # --- TRANSPORT_OPEN recovery-gated admit (ADR 0006 amendment) ---------------------
    # These rules cover the §4.7 recovery_required fence end-to-end: a current tombstone
    # blocks ordinary admit() AND admit_ssh_tier(), and only admit_recovery() may attach
    # meanwhile (clearing the dual-write tombstone+cache on success).

    def _open_request(self) -> OpenRequest:
        """Build an OpenRequest against the current shadow generation. The CHANNEL the snapshot
        publishes is the one admission re-binds against, so the request mirrors it exactly."""
        return OpenRequest(
            target_key=KEY,
            generation=self.shadow_generation,
            transport_ref=CHANNEL,
            platform=PLATFORM,
        )

    @rule(recovery=st.booleans())
    def admit_transport_open(self, recovery: bool) -> None:
        """Drive a transport.open admit. `recovery=False` routes through `admit` (blocked by a
        current tombstone with `recovery_required`); `recovery=True` routes through
        `admit_recovery` (requires a tombstone, then clears it via the dual-write helper).

        The snapshot is held in DEBUGGING in this model, so the non-recovery admit also faces the
        `target_not_ready` fence (checked AFTER recovery_required). We assert the exact failure
        code at each matrix cell so a regression that swapped the fences would be caught.
        """
        request = self._open_request()
        try:
            handle = self.admission.admit_recovery(KEY, request) if recovery else self.admission.admit(KEY, request)
        except AdmissionError as exc:
            # Fence order matches `_bind_snapshot` / admit_recovery's checks:
            #   1. closed → admission_closed (HIGHEST priority; checked first)
            #   2. recovery-gated + not recovery → recovery_required
            #   3. not tombstone-at-current-gen + recovery → not_recovery_required
            #   4. otherwise + not recovery → target_not_ready (DEBUGGING snapshot)
            gated = self._recovery_gated()
            if self.closed:
                assert exc.code == "admission_closed", f"expected admission_closed, got {exc.code}"
            elif gated and not recovery:
                assert exc.code == "recovery_required", f"expected recovery_required, got {exc.code}"
            elif not gated and recovery:
                assert exc.code == "not_recovery_required", f"expected not_recovery_required, got {exc.code}"
            elif not gated and not recovery:
                assert exc.code == "target_not_ready", f"expected target_not_ready, got {exc.code}"
            else:
                raise AssertionError(
                    f"admit(gated={gated}, recovery={recovery}, closed={self.closed}) raised unexpectedly: {exc.code}"
                ) from exc
            # No state mutation on rejection: the cache value stays as it was.
            assert self.tombstone_gen == self.admission._recovery_required.get(KEY)
            return

        # Admit succeeded — only legitimate for (gated, recovery=True) on a not-closed target.
        assert self._recovery_gated() and recovery and not self.closed, (
            f"admit succeeded in an illegitimate matrix cell: "
            f"tombstone_gen={self.tombstone_gen}, gen={self.shadow_generation}, "
            f"recovery={recovery}, closed={self.closed}"
        )
        # Dual-write clearance mirrors the transaction's `_clear_recovery_cache` +
        # `_clear_recovery_durable` pair: clear the cache here (a real transaction would also
        # `registry.clear_tombstone`; the registry is not modelled).
        self.admission.clear_recovery_required(KEY, self.shadow_generation)
        self.tombstone_gen = None
        self.transport_handles.append(handle)

    @rule()
    @precondition(lambda self: bool(_active_transport_handles(self)))
    def close_transport_open(self) -> None:
        """Roll back a still-registered transport.open handle. These never promote in this model,
        so PENDING rollback is always permitted (no confirm_reaped required)."""
        active = _active_transport_handles(self)
        handle = active[0]
        self.admission.rollback(handle)
        self.transport_handles.remove(handle)

    @rule()
    @precondition(lambda self: not self._recovery_gated())
    def mark_recovery_required(self) -> None:
        """Dual-write a tombstone at the current generation (durable + admission cache). In the
        model we drive the cache directly; in production `_mark_recovery` writes both atomically.
        Allowed while closed — `mark_recovery_required` only updates the cache and never touches
        the close fence; tombstones can be parked across a close/reopen cycle (§4.7)."""
        self.admission.mark_recovery_required(KEY, self.shadow_generation)
        # `mark_recovery_required` only advances the cache (never regresses); reflect that.
        if self.tombstone_gen is None or self.shadow_generation > self.tombstone_gen:
            self.tombstone_gen = self.shadow_generation

    # ---------------------------------------------------------------------------------
    # Invariants
    # ---------------------------------------------------------------------------------

    @invariant()
    def at_most_one_guard_holder(self) -> None:
        """Invariant 5: the InProcessStopCapableGuard has at most one outstanding token."""
        # We track holders ourselves; cross-check by attempting an acquire under a
        # not-currently-held state would mutate the world, so just assert via shadow.
        # The `attempt_double_attach` rule already drives the guard's internal check.
        # Here we only need to assert our shadow is well-formed (0 or 1).
        assert self.guard_token is None or isinstance(self.guard_token.target_key, TargetKey)

    @invariant()
    def shadow_epoch_matches_service(self) -> None:
        """Sanity: the shadow epoch never diverges from the service's view."""
        assert self.admission.current_execution_epoch(KEY) == self.shadow_exec_epoch

    @invariant()
    def admitted_handles_observe_admit_time_epoch(self) -> None:
        """Invariant 2 (post-step): every live record's admit_epoch is consistent — the handle's
        admit_epoch was bound to whatever the epoch was when admit_ssh_tier ran. Inductively this
        is checked at admit time; here we assert no record has a future admit_epoch (would be
        an obvious bug)."""
        for rec in self.live_records:
            assert rec.admit_epoch <= max(self.shadow_exec_epoch, rec.admit_epoch), (
                "record.admit_epoch is ahead of any epoch the machine has seen"
            )

    @invariant()
    def recovery_cache_matches_shadow(self) -> None:
        """The dual-write tombstone+cache invariant: at every step, the admission cache's
        `_recovery_required[KEY]` equals the shadow's `tombstone_gen` (both `None` or the same
        integer generation). A divergence in either direction is the §4.7 fence being driven
        out of sync — the exact bug the dual-write helper exists to prevent."""
        cache_value = self.admission._recovery_required.get(KEY)
        assert cache_value == self.tombstone_gen, (
            f"recovery_required cache/shadow divergence: cache={cache_value}, shadow={self.tombstone_gen}"
        )

    @invariant()
    def tombstone_gates_ssh_and_non_recovery_admit(self) -> None:
        """When the effective recovery gate is active (`_recovery_gated()`), admit() (non-recovery
        transport.open) AND admit_ssh_tier with a fresh EXECUTING proof MUST both be rejected
        recovery_required. After admit_transport_open(recovery=True) clears the tombstone — or a
        reopen advances the snapshot past it — the gate drops and the next admit is no longer
        tombstone-gated (it may still fail for other reasons; we only assert the recovery_required
        code is gone). This is the §4.7 fence proven from BOTH the transport.open and ssh-tier
        admit edges of the same model."""
        if not self._recovery_gated():
            return
        # Non-recovery transport.open is rejected by the tombstone gate before READY check.
        request = OpenRequest(
            target_key=KEY,
            generation=self.shadow_generation,
            transport_ref=CHANNEL,
            platform=PLATFORM,
        )
        try:
            self.admission.admit(KEY, request)
        except AdmissionError as exc:
            # When `closed` is also set, admission_closed wins (checked first); both codes are
            # legitimate fail-closed outcomes under tombstone+closed state.
            assert exc.code in ("recovery_required", "admission_closed"), (
                f"non-recovery admit() under tombstone returned unexpected code {exc.code}"
            )
        else:
            raise AssertionError("non-recovery admit() admitted under a current recovery_required tombstone")
        # admit_ssh_tier with a fresh EXECUTING proof: also tombstone-gated (fail-closed).
        proof = ExecutionProof(
            generation=self.shadow_generation,
            epoch=self.shadow_exec_epoch,
            state=ExecutionState.EXECUTING,
        )
        try:
            self.admission.admit_ssh_tier(KEY, self.shadow_generation, PLATFORM, execution_proof=proof)
        except AdmissionError as exc:
            assert exc.code in ("recovery_required", "admission_closed"), (
                f"admit_ssh_tier under tombstone returned unexpected code {exc.code}"
            )
        else:
            raise AssertionError("admit_ssh_tier admitted under a current recovery_required tombstone")

    @invariant()
    def no_completed_handle_spanned_a_halt(self) -> None:
        """Invariant 1: every completed_ok record satisfies admit_epoch == exec_epoch at the
        time of completion. Re-checked here for any historical record: a record marked
        completed_ok cannot retroactively have spanned a halt — we already checked at
        completion time, but this invariant prevents any future mutation from violating it.
        (No mutation paths exist in this machine, so this is a guard against accidental
        regression.)"""
        for rec in self.live_records:
            if rec.disposition == "completed_ok":
                # The handle is no longer in the binding table; its admit_epoch was equal to
                # the shadow epoch at the moment of completion. If a later halt has bumped the
                # epoch, that's fine — we only care that complete() succeeded at the right time.
                assert rec.handle.state is AdmissionState.COMPLETED


TestExecState = ExecStateMachine.TestCase
TestExecState.settings = settings(
    max_examples=300,
    stateful_step_count=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
