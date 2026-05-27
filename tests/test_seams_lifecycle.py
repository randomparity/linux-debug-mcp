import threading
import time

from linux_debug_mcp.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
    LifecycleSubscriber,
    OverdueSubscriber,
)
from linux_debug_mcp.seams.target import TargetKey


def _key(target_id: str = "run-1", provisioner: str = "local-qemu") -> TargetKey:
    return TargetKey(provisioner=provisioner, target_id=target_id)


class _RecordingSubscriber:
    def __init__(self) -> None:
        self.events: list[LifecycleEvent] = []
        self.deadlines: list[float] = []

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        self.events.append(event)
        self.deadlines.append(deadline)

    def force_drop(self, event: LifecycleEvent) -> None:
        pass


class _RaisingSubscriber:
    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        raise RuntimeError("teardown boom")

    def force_drop(self, event: LifecycleEvent) -> None:
        pass


class _StuckSubscriber:
    def __init__(self) -> None:
        self.force_dropped = threading.Event()

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        time.sleep(60)  # never returns within the deadline (contract violation)

    def force_drop(self, event: LifecycleEvent) -> None:
        self.force_dropped.set()  # release recorded resources, independently of invalidate


class _SlowButFinishingSubscriber:
    def __init__(self, sleep_for: float) -> None:
        self._sleep_for = sleep_for

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        time.sleep(self._sleep_for)  # overruns the deadline but eventually finishes

    def force_drop(self, event: LifecycleEvent) -> None:
        pass


def test_impls_satisfy_protocols():
    assert isinstance(InProcessLifecycleDispatcher(), LifecycleDispatcher)
    assert isinstance(_RecordingSubscriber(), LifecycleSubscriber)


def test_emit_delivers_to_subscribers_for_the_key_only():
    dispatcher = InProcessLifecycleDispatcher()
    here, elsewhere = _RecordingSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(target_id="a"), "here", here)
    dispatcher.subscribe(_key(target_id="b"), "elsewhere", elsewhere)
    event = LifecycleEvent(target_key=_key(target_id="a"), kind=LifecycleKind.RESETTING)
    result = dispatcher.emit(event)
    assert here.events == [event]
    assert elsewhere.events == []
    assert result.errors == {}


def test_cross_provisioner_same_target_id_isolated():
    dispatcher = InProcessLifecycleDispatcher()
    a, b = _RecordingSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(provisioner="provA"), "a", a)
    dispatcher.subscribe(_key(provisioner="provB"), "b", b)
    dispatcher.emit(LifecycleEvent(target_key=_key(provisioner="provA"), kind=LifecycleKind.CRASHED))
    assert len(a.events) == 1
    assert b.events == []


def test_invalidate_receives_the_teardown_deadline_budget():
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=2.5)
    sub = _RecordingSubscriber()
    dispatcher.subscribe(_key(), "s", sub)
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.RELEASING))
    assert sub.deadlines == [2.5]  # the subscriber is told its self-bounding budget


def test_subscriber_error_is_aggregated_not_propagated():
    dispatcher = InProcessLifecycleDispatcher()
    boom, good = _RaisingSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(), "boom", boom)
    dispatcher.subscribe(_key(), "good", good)
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.RELEASING))
    assert "boom" in result.errors  # the raised error is captured, not propagated
    assert good.events  # the healthy subscriber still ran; the transition completed


def test_stuck_subscriber_is_abandoned_and_emit_returns_within_deadline():
    # A subscriber that overruns the deadline must NOT block the transition: emit() returns
    # within ~the deadline, records it overdue + errors, and the healthy subscriber still ran.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    stuck, good = _StuckSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(), "stuck", stuck)
    dispatcher.subscribe(_key(), "good", good)
    start = time.monotonic()
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    elapsed = time.monotonic() - start
    assert elapsed < 2.0  # bounded by the deadline, not the 60s sleep
    assert "stuck" in result.overdue
    assert stuck.force_dropped.is_set()  # force_drop was invoked on the overdue subscriber
    assert "stuck" in result.force_dropped
    assert good.events  # the transition completed for the healthy subscriber


def test_force_drop_releases_externally_held_resources_when_invalidate_wedges():
    # The contract requirement (§4.5): a subscriber whose invalidate() is stuck must still
    # have its line dropped. force_drop releases the lease the subscriber recorded out-of-band
    # (in shared state), independently of the wedged invalidate() frame, before emit returns.
    from linux_debug_mcp.coordination.lease import ConsoleLease, LeaseOwner

    lease = ConsoleLease(_key())
    lease.acquire(LeaseOwner.TRANSPORT)

    class _WedgedOwner:
        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            time.sleep(60)  # wedges before it can release the lease itself

        def force_drop(self, event: LifecycleEvent) -> None:
            lease.revoke()  # releases the out-of-band resource the subscriber owned

    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    dispatcher.subscribe(_key(), "owner", _WedgedOwner())
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert "owner" in result.overdue
    assert "owner" in result.force_dropped
    assert lease.snapshot()[0] is LeaseOwner.FREE  # the line was dropped despite the wedge


def test_overdue_worker_is_observable_then_pruned_when_it_finishes():
    # CPython cannot kill the abandoned worker, so it is tracked as observable overdue state;
    # once a (slow-but-finishing) subscriber completes, the count prunes back to 0.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    dispatcher.subscribe(_key(), "slow", _SlowButFinishingSubscriber(sleep_for=0.6))
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert "slow" in result.overdue
    assert dispatcher.outstanding_overdue() >= 1  # abandoned worker still running
    time.sleep(0.7)  # let it finish
    assert dispatcher.outstanding_overdue() == 0  # pruned -> no permanent accumulation


def test_self_bounded_subscriber_leaves_no_overdue_across_repeated_emits():
    # A correctly self-bounded (fast) subscriber finishes within the deadline every time, so
    # repeated lifecycle events never accumulate overdue workers.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=1.0)
    dispatcher.subscribe(_key(), "s", _RecordingSubscriber())
    for _ in range(20):
        result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
        assert result.overdue == ()
    assert dispatcher.outstanding_overdue() == 0


def test_single_flight_caps_workers_for_a_permanently_stuck_subscriber():
    # Repeated lifecycle events against a permanently-wedged subscriber must NOT spawn a new
    # stuck thread each time: it is tracked single-flight by (TargetKey, name) and not
    # re-invoked while still overdue, so worker count stays bounded at one.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.1)
    dispatcher.subscribe(_key(), "stuck", _StuckSubscriber())
    for _ in range(5):
        result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
        assert "stuck" in result.overdue
    assert dispatcher.outstanding_overdue() == 1  # not 5
    overdue = dispatcher.overdue_subscribers()
    assert overdue == {OverdueSubscriber(target_key=_key(), name="stuck", instance_id=next(iter(overdue)).instance_id)}


def test_new_subscriber_under_a_reused_overdue_name_is_still_torn_down():
    # Single-flight keys on the subscriber instance: a fresh subscriber registered under a name
    # whose predecessor is still wedged is NOT skipped — it is invalidated and force-dropped.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.1)
    first = _StuckSubscriber()
    dispatcher.subscribe(_key(), "s", first)
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))  # "s" now overdue
    fresh = _StuckSubscriber()
    dispatcher.subscribe(_key(), "s", fresh)  # reuse the name with a NEW instance
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert fresh.force_dropped.is_set()  # the new binding was torn down, not skipped
    assert "s" in result.overdue
    # BOTH wedged instances stay observable as DISTINCT records (the reaper can act on each);
    # the new entry never overwrote/hid the old one, and identity is not collapsed by name.
    assert dispatcher.outstanding_overdue() == 2
    overdue = dispatcher.overdue_subscribers()
    assert len(overdue) == 2
    assert {o.name for o in overdue} == {"s"}
    assert {o.instance_id for o in overdue} == {id(first), id(fresh)}  # distinct per-instance ids


def test_subscriber_teardown_side_effect_is_token_fenced():
    # A subscriber forcibly releases its resource (revoke) inside its bounded invalidate; a
    # later stale-token release by any actor is a no-op, so resource state cannot be corrupted
    # after the transition (§4.4/§4.5 fencing, defense-in-depth over the supervised contract).
    from linux_debug_mcp.coordination.lease import ConsoleLease, LeaseOwner

    lease = ConsoleLease(_key())
    stale_token = lease.acquire(LeaseOwner.TRANSPORT)

    class _RevokingSubscriber:
        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            lease.revoke()  # the bounded, forced release this subscriber owns

        def force_drop(self, event: LifecycleEvent) -> None:
            pass

    dispatcher = InProcessLifecycleDispatcher()
    dispatcher.subscribe(_key(), "revoke", _RevokingSubscriber())
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert lease.snapshot()[0] is LeaseOwner.FREE  # revoke took effect
    assert lease.release(stale_token) is False  # stale token fenced -> no-op


def test_unsubscribe_stops_delivery():
    dispatcher = InProcessLifecycleDispatcher()
    sub = _RecordingSubscriber()
    dispatcher.subscribe(_key(), "s", sub)
    dispatcher.unsubscribe(_key(), "s")
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.BOOTING))
    assert sub.events == []
