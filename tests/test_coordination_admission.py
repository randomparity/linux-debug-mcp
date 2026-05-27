import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from linux_debug_mcp.coordination.admission import (
    AdmissionError,
    AdmissionOp,
    AdmissionService,
    AdmissionState,
    ExecutionProof,
    SnapshotStore,
    TargetSnapshot,
)
from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.lifecycle import InProcessLifecycleDispatcher, LifecycleEvent, LifecycleKind
from linux_debug_mcp.seams.target import (
    ConsoleKind,
    LeaseInfo,
    PlatformMetadata,
    TargetKey,
    TargetState,
)
from linux_debug_mcp.transport.base import ExecutionState, LineRole, OpenRequest, TransportRef


def _key() -> TargetKey:
    return TargetKey(provisioner="local-qemu", target_id="run-1")


def _platform() -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=True
    )


def _channel() -> TransportRef:
    return TransportRef(provider="qemu-gdbstub", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp"])


def _snapshot(*, generation: int = 0, state: TargetState = TargetState.READY, lease=None) -> TargetSnapshot:
    return TargetSnapshot(
        generation=generation,
        transports=(_channel(),),
        platform=_platform(),
        state=state,
        lease=lease,
    )


def _request(
    *, generation: int = 0, channel: TransportRef | None = None, min_lease_ttl=None, lease: LeaseInfo | None = None
) -> OpenRequest:
    return OpenRequest(
        target_key=_key(),
        generation=generation,
        transport_ref=channel or _channel(),
        required_caps=["provides_rsp"],
        platform=_platform(),
        min_lease_ttl=min_lease_ttl,
        lease=lease,
    )


def _service(snapshot: TargetSnapshot) -> AdmissionService:
    store = SnapshotStore()
    store.put(_key(), snapshot)
    return AdmissionService(store)


def test_admit_success_registers_pending_handle():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    assert handle.state is AdmissionState.PENDING
    assert handle.cancelled is False
    assert handle.channel.channel_id == "rsp-0"


def test_missing_snapshot_is_stale_handle():
    service = AdmissionService(SnapshotStore())
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request())
    assert excinfo.value.category is ErrorCategory.STALE_HANDLE


def test_generation_mismatch_is_stale_handle():
    service = _service(_snapshot(generation=5))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=4))
    assert excinfo.value.category is ErrorCategory.STALE_HANDLE


def test_foreign_channel_id_is_rejected():
    service = _service(_snapshot())
    foreign = TransportRef(provider="qemu-gdbstub", channel_id="ghost", line_role=LineRole.RSP, caps=["provides_rsp"])
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(channel=foreign))
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_edited_caps_on_known_channel_is_rejected():
    service = _service(_snapshot())
    edited = TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp-0",
        line_role=LineRole.RSP,
        caps=["provides_rsp", "supports_uart_break"],
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(channel=edited))
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_rebind_uses_snapshot_channel_object_not_caller_copy():
    snapshot = _snapshot()
    service = _service(snapshot)
    handle = service.admit(_key(), _request())
    # the bound channel is the snapshot's offered (frozen, shared) object, not the request copy
    assert handle.channel is snapshot.transports[0]


def test_admit_rejects_insufficient_required_caps():
    # The snapshot channel offers only provides_rsp; a tier requiring more is refused even
    # though the (provider, channel_id) rebind matches.
    service = _service(_snapshot())
    request = OpenRequest(
        target_key=_key(),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp", "supports_uart_break"],
        platform=_platform(),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), request)
    assert excinfo.value.code == "insufficient_caps"


def test_admit_rejects_platform_drift():
    # platform is a cached OpenRequest fact: if it has drifted from the authoritative snapshot
    # (here ssh_reachable True vs the request's False) admission rejects before any acquisition.
    snap_platform = PlatformMetadata(
        console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=True
    )
    store = SnapshotStore()
    store.put(
        _key(),
        TargetSnapshot(generation=0, transports=(_channel(),), platform=snap_platform, state=TargetState.READY),
    )
    service = AdmissionService(store)
    request = OpenRequest(
        target_key=_key(),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp"],
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=False
        ),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), request)
    assert excinfo.value.code == "stale_platform"


def test_handle_binds_authoritative_platform_when_request_matches():
    # When the request platform matches the snapshot, it passes the drift check and the handle
    # carries the snapshot's authoritative platform object.
    service = _service(_snapshot())  # snapshot + _request both use _platform()
    handle = service.admit(_key(), _request())
    assert handle.platform == _platform()


def test_handle_platform_is_defensively_copied():
    # Mutating the platform returned from the handle must not change the bound authoritative
    # facts (the property hands out a fresh deep copy each access).
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    leaked = handle.platform
    leaked.ssh_reachable = not leaked.ssh_reachable  # mutate the returned copy
    assert handle.platform.ssh_reachable == _platform().ssh_reachable  # bound facts unchanged


def test_stale_lease_identity_rejected():
    later = datetime.now(UTC) + timedelta(hours=1)
    snap_lease = LeaseInfo(lease_id="snap-lease", holder="h", renewable=True, expires_at=later)
    service = _service(_snapshot(lease=snap_lease))
    request = OpenRequest(
        target_key=_key(),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp"],
        platform=_platform(),
        lease=LeaseInfo(lease_id="FOREIGN", holder="h", renewable=True, expires_at=later),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), request)
    assert excinfo.value.code == "stale_lease"


def test_snapshot_store_isolates_mutable_facts():
    later = datetime.now(UTC) + timedelta(hours=1)
    original = _snapshot(lease=LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=later))
    store = SnapshotStore()
    store.put(_key(), original)
    # mutating the caller's original after put() must not change the published facts
    original.lease.expires_at = datetime.now(UTC) + timedelta(seconds=1)
    assert store.get(_key()).lease.expires_at == later
    # mutating a returned copy must not change the store either
    returned = store.get(_key())
    returned.lease.expires_at = datetime.now(UTC) + timedelta(seconds=1)
    assert store.get(_key()).lease.expires_at == later


@pytest.mark.parametrize(
    "state",
    [
        TargetState.ACQUIRING,
        TargetState.PREPARING,
        TargetState.BOOTING,
        TargetState.RESETTING,
        TargetState.RELEASING,
        TargetState.CRASHED,
    ],
)
def test_non_live_state_rejected(state):
    service = _service(_snapshot(state=state))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.category is ErrorCategory.READINESS_FAILURE


def test_transport_open_requires_ready_state():
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError):
        service.admit(_key(), _request())


def test_ssh_tier_admits_on_ready():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    assert handle.state is AdmissionState.PENDING


def test_ssh_tier_on_debugging_without_proof_is_failclosed():
    # §5.6: a DEBUGGING target needs a FRESH EXECUTING probe (Layer 4) to admit ssh-tier; with no
    # proof (incl. probe_timeout) Layer 2 fails closed rather than admit on a possibly-stale flag.
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.code == "execution_state_unknown"


def test_ssh_tier_on_debugging_admits_with_fresh_executing_proof():
    # §5.3/§5.6: Layer 4 probes, then registers the EXECUTING ssh op in the SAME admission service
    # so it shares the cancel fence and lifecycle invalidation. A generation- AND epoch-current
    # EXECUTING proof admits.
    service = _service(_snapshot(generation=3, state=TargetState.DEBUGGING))
    epoch = service.current_execution_epoch(_key())
    handle = service.admit_ssh_tier(
        _key(),
        3,
        _platform(),
        execution_proof=ExecutionProof(generation=3, epoch=epoch, state=ExecutionState.EXECUTING),
    )
    assert handle.state is AdmissionState.PENDING
    assert handle.op is AdmissionOp.SSH_TIER


def test_ssh_tier_on_debugging_rejected_when_proof_is_halted():
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    epoch = service.current_execution_epoch(_key())
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(
            _key(),
            0,
            _platform(),
            execution_proof=ExecutionProof(generation=0, epoch=epoch, state=ExecutionState.HALTED),
        )
    assert excinfo.value.code == "target_halted"


def test_ssh_tier_on_debugging_rejected_when_proof_is_stale_generation():
    # A proof probed at a prior incarnation must not admit against the current snapshot — the
    # generation fence stops a stale EXECUTING from a pre-reset generation leaking ssh work in.
    service = _service(_snapshot(generation=4, state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(
            _key(),
            4,
            _platform(),
            execution_proof=ExecutionProof(generation=3, epoch=0, state=ExecutionState.EXECUTING),
        )
    assert excinfo.value.code == "stale_handle"


def test_ssh_tier_executing_proof_is_rejected_after_a_same_generation_halt():
    # §4.6/§5.6 replay defense: an EXECUTING proof taken before an EXECUTING->HALTED transition
    # MUST NOT be replayable afterwards. A halt does not bump generation, so the epoch fence is
    # what catches it: cancel_ssh_tier (the halt) bumps the execution epoch, so the pre-halt proof
    # no longer matches and a new admit must re-probe rather than attach to a halted kernel.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    proof = ExecutionProof(generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING)
    op = service.admit_ssh_tier(_key(), 1, _platform(), execution_proof=proof)
    service.cancel_ssh_tier(_key(), 1)  # the kernel halted: cancel in-flight ops AND bump the epoch
    service.rollback(op)
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 1, _platform(), execution_proof=proof)  # SAME pre-halt proof
    assert excinfo.value.code == "execution_state_unknown"
    # a fresh re-probe (current epoch) admits again once the kernel is EXECUTING
    fresh = ExecutionProof(generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING)
    assert service.admit_ssh_tier(_key(), 1, _platform(), execution_proof=fresh).state is AdmissionState.PENDING


def test_cancel_ssh_tier_cancels_in_flight_without_closing_admission():
    # §5.6 async halt: in-flight ssh ops are cancelled when the kernel halts, but the target is
    # NOT torn down — once it resumes, a fresh EXECUTING proof admits ssh work again.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    ssh = service.admit_ssh_tier(
        _key(),
        1,
        _platform(),
        execution_proof=ExecutionProof(
            generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING
        ),
    )
    cancelled = service.cancel_ssh_tier(_key(), 1)
    assert ssh.cancelled and [h.handle_id for h in cancelled] == [ssh.handle_id]
    service.rollback(ssh)  # the op owner unwinds its cancelled handle
    # admission was NOT closed: a fresh EXECUTING proof (current epoch) admits after the resume
    resumed = service.admit_ssh_tier(
        _key(),
        1,
        _platform(),
        execution_proof=ExecutionProof(
            generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING
        ),
    )
    assert resumed.state is AdmissionState.PENDING


def test_stale_generation_cancel_leaves_newer_generation_ssh_handle_untouched():
    # A late HALTED from a prior incarnation must not cancel ssh work admitted after a reopen.
    # The handle carries the generation it was admitted at; cancel_ssh_tier fences on it, so a
    # cancel for the OLD generation is a no-op against a NEW-generation handle.
    service = _service(_snapshot(generation=5, state=TargetState.DEBUGGING))
    fresh = service.admit_ssh_tier(
        _key(),
        5,
        _platform(),
        execution_proof=ExecutionProof(
            generation=5, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING
        ),
    )
    cancelled = service.cancel_ssh_tier(_key(), 4)  # stale controller, prior generation
    assert cancelled == []
    assert fresh.cancelled is False  # the newer-generation ssh op is untouched
    assert service.cancel_ssh_tier(_key(), 5) == [fresh]  # the matching-generation cancel does fire


def test_ssh_only_target_with_no_transports_admits_ssh_tier():
    # An ssh-only target may have transports == (); admit_ssh_tier carries no transport_ref.
    store = SnapshotStore()
    store.put(_key(), TargetSnapshot(generation=0, transports=(), platform=_platform(), state=TargetState.READY))
    service = AdmissionService(store)
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    assert handle.op is AdmissionOp.SSH_TIER
    assert handle.channel is None


def test_ssh_only_target_rejects_resetting_state():
    store = SnapshotStore()
    store.put(_key(), TargetSnapshot(generation=0, transports=(), platform=_platform(), state=TargetState.RESETTING))
    service = AdmissionService(store)
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.code == "target_not_ready"


def test_near_expiry_lease_rejected_using_snapshot_copy():
    soon = datetime.now(UTC) + timedelta(seconds=10)
    lease = LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=soon)
    service = _service(_snapshot(lease=lease))
    # caller holds the matching lease but asks for a 300s minimum; snapshot expires in 10s -> reject
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(min_lease_ttl=300, lease=lease))
    assert excinfo.value.code == "lease_near_expiry"


def test_healthy_lease_admits():
    later = datetime.now(UTC) + timedelta(hours=1)
    lease = LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=later)
    service = _service(_snapshot(lease=lease))
    handle = service.admit(_key(), _request(min_lease_ttl=300, lease=lease))
    assert handle.state is AdmissionState.PENDING


def test_leased_target_rejects_request_with_no_lease():
    # Scarce-target fence: a leased snapshot requires the request to carry the matching lease;
    # omitting it must not bypass lease-holder identity even if generation/channel/platform match.
    later = datetime.now(UTC) + timedelta(hours=1)
    service = _service(_snapshot(lease=LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=later)))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request())  # no lease in the request
    assert excinfo.value.code == "stale_lease"


def test_promote_then_rollback_state_transitions():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    service.promote(handle)
    assert handle.state is AdmissionState.PROMOTED
    service.rollback(handle)  # a promoted-but-failed open rolls back
    assert handle.state is AdmissionState.ROLLED_BACK


def test_complete_on_pending_transport_open_is_rejected():
    # A pending transport.open must promote or rollback — never complete straight from PENDING,
    # which would drop an in-flight open without rolling back its partial resources.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    with pytest.raises(AdmissionError) as excinfo:
        service.complete(handle)
    assert excinfo.value.code == "invalid_terminal_transition"
    # promoting first, then completing, is allowed
    service.promote(handle)
    service.complete(handle)
    assert handle.state is AdmissionState.COMPLETED


def test_ssh_tier_complete_deregisters_handle():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    service.complete(handle)
    assert handle.state is AdmissionState.COMPLETED
    # a completed handle is deregistered: a later invalidation does not re-touch it
    assert service.close_admission(_key()) == []


def test_promote_after_rollback_is_rejected():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    service.rollback(handle)
    with pytest.raises(AdmissionError) as excinfo:
        service.promote(handle)
    assert excinfo.value.code == "handle_not_pending"


def test_double_completion_is_rejected():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    service.complete(handle)
    with pytest.raises(AdmissionError) as excinfo:
        service.complete(handle)
    assert excinfo.value.code == "handle_already_disposed"


def test_rollback_after_completion_is_rejected():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    service.complete(handle)
    with pytest.raises(AdmissionError) as excinfo:
        service.rollback(handle)
    assert excinfo.value.code == "handle_already_disposed"


def test_admission_handle_cancellation_is_read_only_and_monotonic():
    # The cancel fence is private: callers cannot clear or reassign it, and there is no public
    # Event. Only the service signals cancellation (monotonically), via close_admission.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    assert handle.cancelled is False
    assert not hasattr(handle, "cancel")  # no public Event to clear/reassign
    with pytest.raises(AttributeError):
        handle.cancelled = False  # read-only property
    with pytest.raises(AttributeError):
        handle.state = AdmissionState.PROMOTED  # read-only property
    service.close_admission(_key())
    assert handle.cancelled is True
    with pytest.raises(AdmissionError):
        service.promote(handle)  # a cancelled handle cannot be promoted


def test_close_admission_cancels_pending_and_promoted_and_blocks_new():
    service = _service(_snapshot())
    pending = service.admit_ssh_tier(_key(), 0, _platform())
    promoted = service.admit_ssh_tier(_key(), 0, _platform())
    service.promote(promoted)
    cancelled = service.close_admission(_key())
    assert pending.cancelled and promoted.cancelled
    assert {pending.handle_id, promoted.handle_id} == {h.handle_id for h in cancelled}
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.code == "admission_closed"


def test_promote_after_cancel_is_rejected():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    service.close_admission(_key())
    with pytest.raises(AdmissionError):
        service.promote(handle)


def test_invalidate_lifecycle_closes_admission_before_any_teardown():
    # §4.5 ordering, enforced in one place: invalidate_lifecycle runs step 1 (close_admission)
    # to completion BEFORE step 2 (dispatcher.emit teardown). A teardown subscriber that probes
    # admission at the moment it runs must find it already CLOSED — so no subscriber can release
    # a lease/guard while a concurrent admit could still slip in against the stale generation.
    store = SnapshotStore()
    store.put(_key(), _snapshot())
    service = AdmissionService(store)
    dispatcher = InProcessLifecycleDispatcher()
    observed_closed: list[bool] = []

    class _ProbingSubscriber:
        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            try:
                service.admit(_key(), _request())
                observed_closed.append(False)  # admission was still open during teardown — BUG
            except AdmissionError as exc:
                observed_closed.append(exc.code == "admission_closed")

        def force_drop(self, event: LifecycleEvent) -> None:
            pass

    dispatcher.subscribe(_key(), "transport", _ProbingSubscriber())
    pending = service.admit_ssh_tier(_key(), 0, _platform())
    service.invalidate_lifecycle(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED), dispatcher)
    assert pending.cancelled  # step 1 cancelled the in-flight handle
    assert observed_closed == [True]  # admission was already closed when teardown ran


def test_reopen_after_generation_bump_allows_admission():
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    service.close_admission(_key())  # records closed-at generation 0
    # provisioning publishes the new-incarnation snapshot, THEN admission reopens
    store.put(_key(), _snapshot(generation=1))
    service.reopen(_key())
    handle = service.admit(_key(), _request(generation=1))
    assert handle.state is AdmissionState.PENDING


def test_early_reopen_before_new_snapshot_stays_closed():
    # The race the fence prevents: reopen is called before the generation-1 snapshot is
    # published. reopen reads the authoritative store (still generation 0) and refuses, so a
    # stale generation-0 OpenRequest cannot replay during reset/release.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    service.close_admission(_key())
    with pytest.raises(AdmissionError) as excinfo:
        service.reopen(_key())  # store still has generation 0
    assert excinfo.value.code == "generation_not_advanced"
    with pytest.raises(AdmissionError) as still_closed:
        service.admit(_key(), _request(generation=0))
    assert still_closed.value.code == "admission_closed"


def test_reopen_blocked_while_prior_bindings_outstanding():
    # reopen must not admit new work while a prior-generation handle is still unwinding, or
    # stale work could return/mutate alongside the new incarnation.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    handle = service.admit(_key(), _request())
    service.close_admission(_key())  # handle cancelled but still a registered PENDING binding
    store.put(_key(), _snapshot(generation=1))
    with pytest.raises(AdmissionError) as excinfo:
        service.reopen(_key())
    assert excinfo.value.code == "bindings_outstanding"
    service.rollback(handle)  # the open transaction disposes the stale handle
    service.reopen(_key())  # now there are no outstanding bindings -> reopen succeeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_abandon_force_drops_overdue_handle_so_reopen_can_proceed():
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    handle = service.admit(_key(), _request())
    service.close_admission(_key())
    service.confirm_reaped(handle)  # the Layer-4 reaper reclaimed its resources
    service.abandon(handle)  # owner could not roll it back -> explicit force-drop
    assert handle.state is AdmissionState.ABANDONED
    store.put(_key(), _snapshot(generation=1))
    service.reopen(_key())  # the abandoned handle was deregistered, so reopen proceeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_abandon_requires_reaper_confirmation_before_reopen():
    # A cancelled PROMOTED handle on a closed target must not be deregistered (and so must not
    # unblock reopen) until the reaper proves its external resources were reclaimed. Otherwise a
    # new incarnation could be admitted alongside a still-live backend/lease/guard.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    handle = service.admit(_key(), _request())
    service.promote(handle)
    service.close_admission(_key())  # cancelled, but resources not yet reaped
    with pytest.raises(AdmissionError) as not_reaped:
        service.abandon(handle)
    assert not_reaped.value.code == "reaper_confirmation_required"
    store.put(_key(), _snapshot(generation=1))
    with pytest.raises(AdmissionError) as still_outstanding:
        service.reopen(_key())  # the live binding still blocks reopen
    assert still_outstanding.value.code == "bindings_outstanding"
    service.confirm_reaped(handle)
    service.abandon(handle)
    service.reopen(_key())
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_confirm_reaped_requires_closed_target_and_cancelled_handle():
    # confirm_reaped is the reaper's hook: it is rejected on a live (not-closed) target so it can
    # never falsely mark a live binding as reaped.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    with pytest.raises(AdmissionError) as excinfo:
        service.confirm_reaped(handle)
    assert excinfo.value.code == "reap_not_permitted"
    assert handle.reaped is False


def test_snapshot_store_rejects_generation_regression():
    # generation is the monotonic freshness fence: a stale/out-of-order writer storing an older
    # generation after a newer one must be refused, or _bind_snapshot would treat the stale
    # generation as current and admit a pre-reset OpenRequest.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=2))
    store.put(_key(), _snapshot(generation=2))  # idempotent re-publish at the same gen is allowed
    with pytest.raises(AdmissionError) as excinfo:
        store.put(_key(), _snapshot(generation=1))
    assert excinfo.value.code == "snapshot_generation_regression"
    assert store.get(_key()).generation == 2  # the authoritative generation did not regress


def test_tombstone_ahead_of_snapshot_fails_closed():
    # A recovery_required tombstone parked AHEAD of the published snapshot (e.g. the snapshot has
    # not yet caught up) must gate ordinary admit closed, not be treated as a superseded stale
    # tombstone. Only a tombstone strictly older than the snapshot is superseded.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=1))
    service = AdmissionService(store)
    service.mark_recovery_required(_key(), 2)  # parked ahead of the gen-1 snapshot
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=1))
    assert excinfo.value.code == "recovery_required"


def test_stale_recovery_clear_does_not_free_a_newer_tombstone():
    # A stale actor clearing generation N must NOT free a newer N+1 recovery_required mark.
    # READY (not DEBUGGING): this test is about the tombstone-clear gate, and the final
    # assertion does an ordinary admit() — which requires READY (test_transport_open_requires_ready_state).
    service = _service(_snapshot(generation=1, state=TargetState.READY))
    service.mark_recovery_required(_key(), 1)
    service.clear_recovery_required(_key(), 0)  # stale clear for the old generation -> no-op
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=1))
    assert excinfo.value.code == "recovery_required"
    service.clear_recovery_required(_key(), 1)  # generation-current clear succeeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_stale_recovery_mark_does_not_regress_a_current_tombstone():
    # A stale mark for generation N must not overwrite a current N+1 mark.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 1)
    service.mark_recovery_required(_key(), 0)  # stale -> ignored, the N=1 tombstone stands
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=1))
    assert excinfo.value.code == "recovery_required"


def test_request_target_key_mismatch_is_rejected():
    # The OpenRequest's own target_key must match the admission target; a foreign request
    # whose generation/channel happen to match must not be admitted cross-target.
    service = _service(_snapshot())
    foreign = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="OTHER"),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp"],
        platform=_platform(),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), foreign)
    assert excinfo.value.code == "target_mismatch"


def test_admit_recovery_requires_a_generation_current_tombstone():
    service = _service(_snapshot(generation=0, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 0)
    handle = service.admit_recovery(_key(), _request())
    assert handle.op is AdmissionOp.TRANSPORT_OPEN
    assert handle.state is AdmissionState.PENDING


def test_admit_recovery_without_tombstone_is_rejected():
    # admit_recovery is not a general bypass: with no current recovery_required tombstone it
    # must be rejected, not silently admitted against a DEBUGGING target.
    service = _service(_snapshot(generation=0, state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_recovery(_key(), _request())
    assert excinfo.value.code == "not_recovery_required"


def test_ordinary_lifecycle_close_blocks_even_admit_recovery():
    # During an ordinary reset/release teardown, NO new work registers — not even recovery —
    # before leases/guards are revoked. (close_admission is the lifecycle gate.)
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    service.close_admission(_key())
    with pytest.raises(AdmissionError) as ordinary:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert ordinary.value.code == "admission_closed"
    with pytest.raises(AdmissionError) as recovery:
        service.admit_recovery(_key(), _request())
    assert recovery.value.code == "admission_closed"


def test_recovery_required_blocks_ordinary_admit_but_allows_recovery():
    # The recovery_required tombstone gate (distinct from lifecycle close): ordinary admit is
    # rejected, but admit_recovery is the one path allowed to resume/detach the parked kernel.
    service = _service(_snapshot(generation=0, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 0)  # parked at the current generation
    with pytest.raises(AdmissionError) as ordinary:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert ordinary.value.code == "recovery_required"
    handle = service.admit_recovery(_key(), _request())
    assert handle.state is AdmissionState.PENDING


def test_stale_recovery_tombstone_is_superseded_after_generation_bump():
    # A reset advanced the incarnation past the parked generation: the N=0 tombstone is stale
    # and must NOT strand the freshly-booted N=1 kernel (§4.7 generation idempotency).
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0, state=TargetState.READY))
    service = AdmissionService(store)
    service.mark_recovery_required(_key(), 0)
    store.put(_key(), _snapshot(generation=1, state=TargetState.READY))
    handle = service.admit(_key(), _request(generation=1))
    assert handle.state is AdmissionState.PENDING


def test_recovery_tombstone_fails_closed_without_authoritative_snapshot():
    # Bare startup: a tombstone exists but no authoritative snapshot/generation yet -> the gate
    # FAILS CLOSED with recovery_required (not stale_handle), so a parked key can't be admitted.
    service = AdmissionService(SnapshotStore())
    service.mark_recovery_required(_key(), 0)
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request())
    assert excinfo.value.code == "recovery_required"


def test_abandon_requires_closed_target_and_cancelled_handle():
    # abandon is not a way to drop a live binding: it is rejected before close, and rejected
    # for a promoted live session that was never cancelled.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    with pytest.raises(AdmissionError) as before_close:
        service.abandon(handle)  # target not closed, handle not cancelled
    assert before_close.value.code == "abandon_not_permitted"
    service.promote(handle)
    with pytest.raises(AdmissionError) as promoted_live:
        service.abandon(handle)  # still not closed/cancelled
    assert promoted_live.value.code == "abandon_not_permitted"


def test_close_admission_is_idempotent_across_generation_publication():
    # A duplicate close after generation N+1 is published must NOT push the reopen bar to N+2:
    # the first closed-at generation (N) is preserved, so reopen at N+1 still succeeds.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    service.close_admission(_key())  # closed at generation 0
    store.put(_key(), _snapshot(generation=1))
    service.close_admission(_key())  # duplicate close after N+1 published -> still closed-at 0
    service.reopen(_key())  # 1 > 0 -> succeeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_publish_snapshot_serializes_with_the_admission_key_lock():
    # F3: a generation bump must not interleave between an admit's snapshot read and its handle
    # registration. publish_snapshot takes the SAME per-TargetKey lock as admit, so while that
    # lock is held (standing in for an in-flight admit critical section) a concurrent publication
    # blocks until the section completes — it cannot split an admit.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    published = threading.Event()

    def publisher() -> None:
        service.publish_snapshot(_key(), _snapshot(generation=1))
        published.set()

    with service._key_lock(_key()):  # hold the key lock as an in-flight admit would
        worker = threading.Thread(target=publisher)
        worker.start()
        time.sleep(0.05)
        assert not published.is_set()  # blocked on the shared per-TargetKey lock
    worker.join(2.0)
    assert published.is_set()  # released once the critical section ended
    assert store.get(_key()).generation == 1
