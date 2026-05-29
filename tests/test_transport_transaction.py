import time
from types import MappingProxyType

import pytest
from _layer4_fakes import (
    KEY,
    FakeBlockingReapProxy,
    FakeBrokeredTransport,
    FakeQemuTransport,
    build_txn,
    make_request,
)

from linux_debug_mcp.coordination.admission import AdmissionError, TargetSnapshot
from linux_debug_mcp.coordination.endpoint_safety import EndpointSafetyError
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager, LeaseOwner
from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.seams.guard import GuardConflict, InProcessStopCapableGuard
from linux_debug_mcp.seams.lifecycle import InProcessLifecycleDispatcher, LifecycleEvent, LifecycleKind
from linux_debug_mcp.transport.base import RecordState, TcpEndpoint


def test_open_happy_path_returns_loopback_session(tmp_path):
    txn, admission = build_txn(FakeQemuTransport(), registry=SessionRegistry(directory=tmp_path))
    session = txn.open(make_request())
    assert session.record_state is RecordState.READY
    assert isinstance(session.rsp_endpoint, TcpEndpoint) and session.rsp_endpoint.host == "127.0.0.1"
    assert session.stop_guard_token is not None
    # promoted: a second open on the same target is refused by the guard
    with pytest.raises(GuardConflict):
        txn.open(make_request())


def test_brokered_required_refused_before_any_acquisition(tmp_path):
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    txn, _ = build_txn(
        FakeBrokeredTransport(), guard=guard, leases=leases, registry=SessionRegistry(directory=tmp_path)
    )
    with pytest.raises(EndpointSafetyError) as exc:
        txn.open(make_request(provider="redfish-sol"))
    assert exc.value.code == "endpoint_unsafe"
    # no guard acquired, no lease, no record written
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE
    assert SessionRegistry(directory=tmp_path).read_record(KEY) is None


def test_attach_failure_rolls_back_everything(tmp_path):
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(crash=True), guard=guard, leases=leases, registry=reg)
    with pytest.raises(RuntimeError, match="attach blew up"):
        txn.open(make_request())
    assert reg.read_record(KEY) is None  # write-ahead record deleted
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE  # no lease leaked
    # guard freed via the FENCED release → a fresh open can now acquire
    txn_ok, _ = build_txn(FakeQemuTransport(), guard=guard, leases=leases, registry=reg)
    assert txn_ok.open(make_request()).record_state is RecordState.READY


def test_on_partial_writes_backend_pid_through_before_ready(tmp_path):
    # Finding #1: the backend pid must be in the durable OPENING record the instant the
    # backend_process partial fires — before attach() returns — so a death before READY is
    # reapable. A transport that reads its own record mid-attach proves the write-through ordering.
    reg = SessionRegistry(directory=tmp_path)

    class ReadsOwnRecordAtAttach(FakeQemuTransport):
        def attach(self, request, *, cancel, deadline, on_partial, secrets=MappingProxyType({})):
            attachment = super().attach(
                request, cancel=cancel, deadline=deadline, on_partial=on_partial, secrets=secrets
            )
            self.seen = reg.read_record(KEY)  # after the backend_process partial wrote through
            return attachment

    transport = ReadsOwnRecordAtAttach(backend_pid=4321, backend_start_time="999")
    txn, _ = build_txn(transport, registry=reg)
    txn.open(make_request())
    assert transport.seen is not None and transport.seen.backend_pid == 4321
    assert transport.seen.record_state is RecordState.OPENING


def test_close_reaps_and_clears(tmp_path):
    transport = FakeQemuTransport()
    reg = SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, _ = build_txn(transport, registry=reg)
    txn.bind_lifecycle(dispatcher)
    session = txn.open(make_request())
    txn.close(session.session_id)
    assert transport.closed == [session.session_id]
    assert reg.read_record(KEY) is None
    # close() unsubscribes from the lifecycle dispatcher — no stale binding accretes.
    assert dispatcher._subscribers.get(KEY, {}) == {}


def test_lifecycle_invalidation_revokes_guard_and_reaps(tmp_path):
    transport = FakeQemuTransport()
    guard, leases, reg = InProcessStopCapableGuard(), ConsoleLeaseManager(), SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(transport, guard=guard, leases=leases, registry=reg)
    txn.bind_lifecycle(dispatcher)
    txn.open(make_request())
    # an invalidation tears the session down: admission closed, guard freed (FENCED release), record gone
    admission.invalidate_lifecycle(LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=1)
    assert reg.read_record(KEY) is None
    # force_drop unsubscribes from the lifecycle dispatcher — no stale binding accretes.
    assert dispatcher._subscribers.get(KEY, {}) == {}
    # guard is free → a new incarnation (after a generation bump) could acquire
    assert guard.acquire(KEY) is not None


def _bump_generation(admission, *, generation: int) -> None:
    """Publish a strictly-newer authoritative snapshot for KEY (the §4.5 step-5 generation bump),
    reusing the current snapshot's facts so only the generation advances."""
    current = admission.current_snapshot(KEY)
    admission.publish_snapshot(
        KEY,
        TargetSnapshot(
            generation=generation,
            transports=current.transports,
            platform=current.platform,
            state=current.state,
        ),
    )


def test_open_close_open_succeeds(tmp_path):
    # A cleanly-closed session must leave NO admission binding behind, so a fresh open on the same
    # target admits and reaches READY again. Before the fix the first promoted handle was never
    # deregistered, so it lingered PROMOTED in the binding table.
    transport = FakeQemuTransport()
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(transport, registry=SessionRegistry(directory=tmp_path))
    txn.bind_lifecycle(dispatcher)
    first = txn.open(make_request())
    txn.close(first.session_id)
    # close() deregistered the promoted handle → no binding outstanding for the target.
    assert admission._bindings.get(KEY, []) == []
    # close() unsubscribes from the lifecycle dispatcher → no stale binding accretes across cycles.
    assert dispatcher._subscribers.get(KEY, {}) == {}
    second = txn.open(make_request())
    assert second.record_state is RecordState.READY


def test_lifecycle_invalidation_then_reopen_succeeds(tmp_path):
    # After a CRASHED invalidation force-drops the session, the promoted handle must be
    # deregistered (confirm_reaped → abandon), so once the snapshot advances admission can reopen
    # and admit the next incarnation. Before the fix the cancelled-but-undisposed handle blocked
    # reopen() with `bindings_outstanding`.
    transport = FakeQemuTransport()
    guard, leases, reg = InProcessStopCapableGuard(), ConsoleLeaseManager(), SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(transport, guard=guard, leases=leases, registry=reg)
    txn.bind_lifecycle(dispatcher)
    txn.open(make_request())
    admission.invalidate_lifecycle(LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=1)
    # force_drop deregistered the handle → no binding outstanding blocks reopen.
    assert admission._bindings.get(KEY, []) == []
    # force_drop unsubscribed from the lifecycle dispatcher → no stale binding accretes.
    assert dispatcher._subscribers.get(KEY, {}) == {}
    # §4.5 step 5: bump the authoritative generation, then admission can reopen for the next open.
    _bump_generation(admission, generation=2)
    admission.reopen(KEY)
    second = txn.open(make_request(generation=2))
    assert second.record_state is RecordState.READY


def test_lifecycle_invalidation_between_promote_and_subscribe_force_drops_cleanly(tmp_path):
    """Finding F3: a concurrent `invalidate_lifecycle` that lands between the admission promote
    and the dispatcher subscribe must NOT leave a bound-but-not-subscribed session whose later
    close() silently swallows `admission_cancelled`. Before the fix the open() ran promote and
    subscribe under separate critical sections — a concurrent cancel between them left the
    binding outstanding with no force_drop reachable.

    After the fix open() holds the admission key lock across `promote → register handle →
    clear_recovery → subscribe`, so an invalidation arriving in that window cannot interleave.
    The test proves the new behavior by issuing the invalidation immediately after open()
    returns and verifying force_drop ran end-to-end (binding deregistered, record deleted, lease
    + guard released)."""
    transport = FakeQemuTransport()
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    reg = SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(transport, guard=guard, leases=leases, registry=reg)
    txn.bind_lifecycle(dispatcher)

    session = txn.open(make_request())
    # The subscriber is now registered under the admission key lock — invalidate_lifecycle is
    # delivered to it cleanly, force_drop runs, the binding is deregistered.
    admission.invalidate_lifecycle(
        LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=session.generation
    )
    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []
    # force_drop unsubscribed from the lifecycle dispatcher → no stale binding accretes.
    assert dispatcher._subscribers.get(KEY, {}) == {}
    # close() on the long-dead session_id is now a no-op (record is gone) — it must NOT raise,
    # nor leak the cancelled binding back into the table.
    txn.close(session.session_id)
    assert admission._bindings.get(KEY, []) == []


def test_recovery_clear_failure_restores_cache_gate(tmp_path):
    """When the durable tombstone clear (`clear_tombstone`) raises (EIO, EACCES, …), the
    in-memory admission cache MUST be at its parked generation so the gate stays fail-closed —
    cache and on-disk tombstone agree, the next non-recovery `admit()` is rejected
    `recovery_required`.

    The dual-write clearance now runs durable-first: the cache is cleared only AFTER
    `_clear_recovery_durable` succeeds. An OSError leaves both halves marked end-to-end with
    no try/except-restore handshake. The earlier ordering (cache cleared inside the admission
    key lock, durable I/O outside) opened a window — scaling with filesystem latency — where a
    concurrent non-recovery admit could slip past the cleared cache while the durable I/O was
    still in flight. The test name preserves the contract — "the cache gate is asserted after
    a durable failure" — even though the mechanism is now keep-by-construction rather than
    restore-on-failure.
    """

    class FailingClearRegistry(SessionRegistry):
        def clear_tombstone(self, target_key, *, expected_generation):
            raise OSError("simulated EIO")

    reg = FailingClearRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    # Park the target at generation 1: durable tombstone on disk + admission cache marked.
    reg.write_tombstone(RecoveryTombstone(target_key=KEY, generation=1, reason="test"))
    admission.mark_recovery_required(KEY, 1)
    # The recovery-mode open admits, promotes, clears the cache under the lock, then post-lock
    # the durable clear raises OSError — Fix A re-marks the cache before re-raising.
    with pytest.raises(OSError, match="simulated EIO"):
        txn.open(make_request(), recovery=True)
    # The cache is back at the parked generation: the gate is fail-closed again.
    assert admission._recovery_required.get(KEY) == 1
    # A subsequent non-recovery admit is rejected `recovery_required` (cache + still-present
    # durable tombstone both agree). Without Fix A this open would slip past.
    with pytest.raises(AdmissionError) as exc:
        txn.open(make_request())
    assert exc.value.code == "recovery_required"


def test_force_drop_keeps_durable_record_when_invalidate_wedged(tmp_path):
    """Fix B — when `invalidate`'s `proxy.stop_by_identity` is wedged, `force_drop` MUST NOT
    delete the durable ownership record. The orphan-reap safety net is
    `SessionRegistry.reconcile()` iterating `owner-*.json` on the next process start; if
    force_drop deletes the record while the backend kill is still pending, the orphan PID has no
    paper trail and a process restart leaves it permanently orphaned.

    Before the fix, force_drop unconditionally called `delete_record`, so a wedge erased the only
    trace of the orphan backend the next start could have reaped.
    """
    proxy = FakeBlockingReapProxy()
    transport = FakeQemuTransport(backend_pid=9999, backend_start_time="t")
    transport._proxy = proxy
    reg = SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    txn, admission = build_txn(transport, registry=reg)
    txn.bind_lifecycle(dispatcher)
    session = txn.open(make_request())
    assert reg.read_record(KEY) is not None  # baseline: open committed the durable record

    try:
        # invalidate's stop_by_identity blocks on `proxy._block`. The dispatcher times out after
        # the teardown_deadline and runs force_drop on a separate worker, which (with Fix B)
        # drops the in-memory line but leaves the durable record in place for reconcile().
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED),
            dispatcher,
            generation=session.generation,
        )
        # Confirm the invalidate worker is genuinely wedged INSIDE `proxy.stop_by_identity` —
        # not just-started-but-not-yet-entered (which would let it finish before the
        # `outstanding_overdue() == 1` assertion lands on a heavily-loaded CI host). `entered`
        # is set by the first line of `stop_by_identity`; the only way to leave it now is
        # `proxy.unblock()` in the finally block below.
        assert proxy.entered.wait(timeout=2.0)
        # The durable record persists — it is the only trace reconcile() will find on the next
        # process start to drive a fingerprint-fenced reap.
        assert reg.read_record(KEY) is not None
        # The in-memory line is dropped: confirm_reaped → abandon ran on the admission handle,
        # so reopen() will not be blocked by `bindings_outstanding`.
        assert admission._bindings.get(KEY, []) == []
        # The wedged invalidate worker is still tracked by the dispatcher (single-flight).
        assert dispatcher.outstanding_overdue() == 1
    finally:
        # Unblock the wedged worker so the test does not leave a hung thread behind. The worker
        # will return from stop_by_identity, set `_killed`, and then its own self.force_drop()
        # tail will delete the durable record.
        proxy.unblock()

    deadline = time.monotonic() + 5.0
    while reg.read_record(KEY) is not None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert reg.read_record(KEY) is None


def test_close_unsubscribes_from_lifecycle_dispatcher(tmp_path):
    """A cleanly-closed session must remove its dispatcher subscriber. Stale subscribers
    left behind would receive every future invalidate_lifecycle event for the target_key —
    each one driving a force_drop that, before the session-id fence, would erase a
    fresh session's record at the same target_key path. Regression for the HIGH finding."""
    transport = FakeQemuTransport()
    dispatcher = InProcessLifecycleDispatcher()
    txn, _ = build_txn(transport, registry=SessionRegistry(directory=tmp_path))
    txn.bind_lifecycle(dispatcher)
    session = txn.open(make_request())
    # Baseline: the subscriber is registered.
    assert session.session_id in dispatcher._subscribers.get(KEY, {})
    txn.close(session.session_id)
    # close() unsubscribed → no stale subscriber remains.
    assert dispatcher._subscribers.get(KEY, {}) == {}


def test_force_drop_unsubscribes_after_dispatcher_invocation(tmp_path):
    """A force_drop driven by `invalidate_lifecycle` must remove the dispatcher subscriber
    that just ran. Without the unsubscribe, the cancelled-handle subscriber would still
    receive the NEXT invalidate for this target_key and re-run its tear-down. Regression
    for the HIGH finding via the lifecycle-invalidation path (the other entry into the
    stale-subscriber bug)."""
    transport = FakeQemuTransport()
    guard, leases, reg = InProcessStopCapableGuard(), ConsoleLeaseManager(), SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(transport, guard=guard, leases=leases, registry=reg)
    txn.bind_lifecycle(dispatcher)
    session = txn.open(make_request())
    assert session.session_id in dispatcher._subscribers.get(KEY, {})
    admission.invalidate_lifecycle(
        LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=session.generation
    )
    # force_drop unsubscribed → no stale subscriber remains for a future invalidate.
    assert dispatcher._subscribers.get(KEY, {}) == {}


def test_delete_record_session_id_fence_skips_on_mismatch(tmp_path):
    """Registry-level contract for the session-id fence on `delete_record`: a delete keyed by
    a NON-matching `expected_session_id` is a no-op; a delete keyed by the MATCHING
    `expected_session_id` removes the record. The fence is the second of the two layers
    closing the HIGH finding — even if a stale caller (or wedge-tail unblock) reaches
    `delete_record`, it can no longer erase a fresh session's record at the same target_key
    path."""
    from datetime import UTC, datetime

    from linux_debug_mcp.transport.base import ExecutionState as ES
    from linux_debug_mcp.transport.base import TransportSession as TS
    from linux_debug_mcp.transport.base import new_session_id

    fresh_id = new_session_id()
    stale_id = new_session_id()
    reg = SessionRegistry(directory=tmp_path)
    fresh = TS(
        session_id=fresh_id,
        target_key=KEY,
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.READY,
        attach_epoch=0,
        execution_state=ES.EXECUTING,
        created_at=datetime.now(UTC),
    )
    reg.write_record(fresh)
    # A stale caller whose remembered session_id does NOT match the on-disk record must NOT
    # erase the fresh record.
    reg.delete_record(KEY, expected_session_id=stale_id)
    assert reg.read_record(KEY) is not None
    # The current owner can still delete it cleanly.
    reg.delete_record(KEY, expected_session_id=fresh_id)
    assert reg.read_record(KEY) is None


def test_force_release_skips_transport_close(tmp_path):
    # force_release is the SessionGuard remediation backstop (issue #66): it MUST NOT call
    # transport.close (which is the failure-prone op that wedged), only drop the in-memory/durable
    # line. So the transport's close() must not be invoked.
    transport = FakeQemuTransport()
    txn, _ = build_txn(transport, registry=SessionRegistry(directory=tmp_path))
    session = txn.open(make_request())
    transport.closed.clear()
    txn.force_release(session.session_id)
    assert transport.closed == []


def test_force_release_deletes_record_and_releases_guard(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    txn, _ = build_txn(FakeQemuTransport(), registry=reg)
    session = txn.open(make_request())
    assert reg.read_record(KEY) is not None
    txn.force_release(session.session_id)
    assert reg.read_record(KEY) is None
    # guard is free again: a fresh acquire succeeds (no GuardConflict)
    txn._guard.acquire(KEY)


def test_force_release_unknown_session_is_noop(tmp_path):
    txn, _ = build_txn(FakeQemuTransport(), registry=SessionRegistry(directory=tmp_path))
    txn.force_release("no-such-session")  # must not raise


def test_force_release_does_not_clobber_newer_holder(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    txn, _ = build_txn(FakeQemuTransport(), registry=reg)
    session = txn.open(make_request())
    # release the first session's guard cleanly (mirrors close()), then a NEW holder acquires the
    # SAME target_key, then force_release the stale session id.
    txn._guard.release(session.target_key, txn._tokens[session.session_id])
    new_token = txn._guard.acquire(session.target_key)
    txn.force_release(session.session_id)  # stale session id -> must NOT revoke the new holder
    # the NEW holder still owns the guard: releasing new_token succeeds (it was never revoked)
    assert txn._guard.release(session.target_key, new_token) is True
