"""§10.2 green-together conformance suite (Task C1, the merge bar for issue #10).

These tests assert the §10.2 Layer-4 invariant set TOGETHER against the real Phase-A/B wiring,
sharing the `_layer4_fakes` harness with the per-task tests. Each test is a behavior assertion of
ONE §10.2 invariant; together they describe the contract the merge must hold.
"""

from __future__ import annotations

import contextlib
import inspect
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from _layer4_fakes import (
    CHANNEL,
    KEY,
    PLATFORM,
    FakeBreakPolicy,
    FakeBrokeredTransport,
    FakeQemuTransport,
    FakeReapProxy,
    FakeSshRunner,
    build_txn,
    make_request,
    seed_snapshot,
)
from _secrets_helpers import make_env_secrets as EnvSecretsResolver
from conftest import (
    LEGACY_FENCE_KEY,
    LEGACY_FENCE_RUN_ID,
    CancelAwareTestProvider,
    FakeBootProvider,
    FakeMiEngine,
    FakeTestProvider,
    create_booted_run,
    create_run,
    legacy_fence_build_transaction,
    legacy_fence_make_registry,
    legacy_fence_profiles,
    profiles,
    record_build,
    rootfs,
    seed_legacy_debug_session,
    target_profile,
)

from kdive.artifacts.store import ArtifactStore
from kdive.config import TARGET_DESTRUCTIVE_PERMISSIONS, TRANSPORT_DESTRUCTIVE_PERMISSIONS
from kdive.coordination.admission import (
    AdmissionError,
    AdmissionOp,
    AdmissionService,
    SnapshotStore,
    TargetSnapshot,
    publish_ready_snapshot,
)
from kdive.coordination.endpoint_safety import EndpointSafetyError
from kdive.coordination.exec_probe import probe_execution_state
from kdive.coordination.lease import ConsoleLeaseManager, LeaseOwner
from kdive.coordination.registry import (
    InstanceLockError,
    RecoveryTombstone,
    SessionRegistry,
)
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.bound_handlers import debug_continue_handler, debug_read_registers_handler
from kdive.debug.handlers import DebugRuntime
from kdive.debug.policy import halt_debug_transport
from kdive.domain import ErrorCategory, StepResult, StepStatus
from kdive.providers.local.debug.gdb_mi import GdbMiSessionRegistry
from kdive.safety.redaction import REDACTION, Redactor
from kdive.seams.guard import InProcessStopCapableGuard
from kdive.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
)
from kdive.seams.target import (
    TargetKey,
    TargetState,
)
from kdive.server import (
    target_boot_handler,
    target_run_tests_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from kdive.transport.core.base import (
    ExecutionState,
    LineRole,
    OpenRequest,
    RecordState,
    TcpEndpoint,
    TransportRef,
    TransportSession,
    new_session_id,
)

RUN_ID_FRESH = "run-abc123"  # matches conftest.create_booted_run default
FRESH_KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID_FRESH)
INJECT_PERMS = TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _mark_recovery(reg: SessionRegistry, admission: AdmissionService, *, generation: int = 1) -> None:
    """Dual-write: durable tombstone (source of truth) + admission cache (write-through)."""
    reg.write_tombstone(RecoveryTombstone(target_key=KEY, generation=generation, reason="halted"))
    admission.mark_recovery_required(KEY, generation)


def _make_fresh_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _seed_run_tests_admission(generation: int = 1) -> AdmissionService:
    admission = AdmissionService(SnapshotStore())
    publish_ready_snapshot(
        admission, target_key=FRESH_KEY, generation=generation, transports=[CHANNEL], platform=PLATFORM
    )
    return admission


def _write_executing_record(reg: SessionRegistry, key: TargetKey, *, generation: int = 1) -> None:
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=key,
            generation=generation,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.READY,
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
    )


def _write_halted_record(reg: SessionRegistry, key: TargetKey, *, generation: int = 1) -> None:
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=key,
            generation=generation,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.READY,
            execution_state=ExecutionState.HALTED,
            created_at=datetime.now(UTC),
        )
    )


# ---------------------------------------------------------------------------
# open() transaction: rollback at every crash point
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("crash_after", ["selected", "guard", "lease", "record_written", "ready"])
def test_open_rollback_at_each_crash_point(tmp_path: Path, crash_after: str) -> None:
    """Every labeled crash point inside `transaction.open` MUST roll back the resources acquired
    so far — no guard, lease, durable record, or admission binding may leak — so a fresh
    `txn.open` against the same target via a fresh transaction (sharing the guard/leases/registry)
    succeeds afterwards."""
    guard = InProcessStopCapableGuard()
    leases = ConsoleLeaseManager()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), guard=guard, leases=leases, registry=reg)

    with pytest.raises(RuntimeError):
        txn.open(make_request(), crash_after=frozenset({crash_after}))

    # NO LEAK at any crash point:
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE
    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []

    # …and the guard is free → a fresh transaction over the SAME guard/leases/registry can open.
    txn_ok, _ = build_txn(FakeQemuTransport(), guard=guard, leases=leases, registry=reg)
    session = txn_ok.open(make_request())
    assert session.record_state is RecordState.READY


# ---------------------------------------------------------------------------
# endpoint-safety
# ---------------------------------------------------------------------------


def test_brokered_required_open_refused_endpoint_unsafe_pre_attach(tmp_path: Path) -> None:
    """A brokered_required transport's endpoint-returning open is refused PRE-attach with
    `endpoint_unsafe`. No guard, lease, secret, attach, or durable record is created."""
    guard = InProcessStopCapableGuard()
    leases = ConsoleLeaseManager()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeBrokeredTransport(), guard=guard, leases=leases, registry=reg)

    with pytest.raises(EndpointSafetyError) as excinfo:
        txn.open(make_request(provider="redfish-sol"))

    assert excinfo.value.code == "endpoint_unsafe"
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE
    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []


def test_loopback_local_returns_tcp_endpoint(tmp_path: Path) -> None:
    """A loopback_local qemu-gdbstub open returns READY with a loopback TcpEndpoint."""
    reg = SessionRegistry(directory=tmp_path)
    txn, _admission = build_txn(FakeQemuTransport(), registry=reg)
    session = txn.open(make_request())
    assert session.record_state is RecordState.READY
    assert isinstance(session.rsp_endpoint, TcpEndpoint)
    assert session.rsp_endpoint.host == "127.0.0.1"
    assert session.rsp_endpoint.port == 5551


# ---------------------------------------------------------------------------
# crash recovery — RECONCILE-AFTER-DEATH
# ---------------------------------------------------------------------------


def test_orphan_reaped_after_death_between_spawn_and_ready(tmp_path: Path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=1,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.OPENING,
            backend_pid=4321,
            backend_start_time="999",
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
    )
    proxy, admission = FakeReapProxy(), AdmissionService(SnapshotStore())
    fresh = SessionRegistry(directory=tmp_path)
    fresh.reconcile(proxy=proxy, admission=admission)
    assert proxy.reaped == [(4321, "999")]
    assert fresh.read_record(KEY) is None


def test_writeahead_record_found_and_released_on_restart(tmp_path: Path) -> None:
    """A durable OPENING record persists across a server restart: a fresh SessionRegistry over the
    same directory finds it via reconcile(), reaps the orphan backend by identity, and deletes the
    record so the next admit() sees a clean slate."""
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=2,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.OPENING,
            backend_pid=9999,
            backend_start_time="t-99",
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
    )
    # "Restart": a brand-new SessionRegistry over the SAME directory still sees the record.
    restarted = SessionRegistry(directory=tmp_path)
    assert restarted.read_record(KEY) is not None

    proxy = FakeReapProxy()
    restarted.reconcile(proxy=proxy, admission=AdmissionService(SnapshotStore()))
    assert proxy.reaped == [(9999, "t-99")]
    assert restarted.read_record(KEY) is None


def test_close_releases_owned_lines_when_backend_close_raises(tmp_path: Path) -> None:
    class FailingCloseTransport(FakeQemuTransport):
        def close(self, session) -> None:  # type: ignore[override]
            super().close(session)
            raise RuntimeError("backend close failed")

    registry = SessionRegistry(directory=tmp_path)
    transport = FailingCloseTransport()
    txn, admission = build_txn(transport, registry=registry)
    session = txn.open(make_request())

    with pytest.raises(RuntimeError, match="backend close failed"):
        txn.close(session.session_id)

    assert transport.closed == [session.session_id]
    assert registry.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []

    reopened = txn.open(make_request())
    assert reopened.session_id != session.session_id


def test_open_rollback_unsubscribes_lifecycle_subscriber_after_subscribe_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = SessionRegistry(directory=tmp_path)
    txn, _admission = build_txn(FakeQemuTransport(), registry=registry)
    dispatcher = InProcessLifecycleDispatcher()
    txn.bind_lifecycle(dispatcher)
    original_subscribe = txn._subscribe_session

    def subscribe_then_fail(session, state) -> None:
        original_subscribe(session, state)
        raise RuntimeError("post-subscribe failure")

    monkeypatch.setattr(txn, "_subscribe_session", subscribe_then_fail)

    with pytest.raises(RuntimeError, match="post-subscribe failure"):
        txn.open(make_request())

    assert registry.read_record(KEY) is None
    assert dispatcher._subscribers.get(KEY, {}) == {}


def test_second_server_instance_fails_loud_on_flock(tmp_path: Path) -> None:
    """Two SessionRegistry instances on the same directory: only the first acquires the
    host-global instance flock; the second MUST raise InstanceLockError loudly."""
    first = SessionRegistry(directory=tmp_path)
    second = SessionRegistry(directory=tmp_path)
    first.acquire_instance_lock()
    try:
        with pytest.raises(InstanceLockError):
            second.acquire_instance_lock()
    finally:
        first.release_instance_lock()


# ---------------------------------------------------------------------------
# recovery_required gate
# ---------------------------------------------------------------------------


def test_halted_target_recovery_required_gate(tmp_path: Path) -> None:
    """After _mark_recovery, an ORDINARY (recovery=False) open is refused at the admission gate;
    a recovery=True open is admitted."""
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    _mark_recovery(reg, admission, generation=1)

    with pytest.raises(AdmissionError) as excinfo:
        txn.open(make_request())
    assert excinfo.value.code == "recovery_required"

    # recovery=True admits through the recovery gate.
    session = txn.open(make_request(), recovery=True)
    assert session.record_state is RecordState.READY
    txn.close(session.session_id)


def test_recovery_clearance_recovery_true_attach(tmp_path: Path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    _mark_recovery(reg, admission)
    session = txn.open(make_request(), recovery=True)
    assert session.record_state is RecordState.READY
    assert reg.read_tombstone(KEY) is None
    assert admission._recovery_required.get(KEY) is None
    txn.close(session.session_id)


def test_stale_generation_tombstone_is_no_op_after_reboot(tmp_path: Path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    _, admission = build_txn(FakeQemuTransport(), registry=reg, generation=1)
    _mark_recovery(reg, admission, generation=1)
    reg2 = SessionRegistry(directory=tmp_path)
    admission2 = AdmissionService(SnapshotStore())
    seed_snapshot(admission2._store, generation=2)
    reg2.reconcile(proxy=FakeReapProxy(), admission=admission2)
    assert reg2.read_tombstone(KEY) is not None
    assert admission2._recovery_required.get(KEY) == 1


def test_recovery_cleared_then_restart_admittable(tmp_path: Path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    _mark_recovery(reg, admission)
    txn.open(make_request(), recovery=True)
    reg2 = SessionRegistry(directory=tmp_path)
    admission2 = AdmissionService(SnapshotStore())
    reg2.reconcile(proxy=FakeReapProxy(), admission=admission2)
    assert reg2.read_tombstone(KEY) is None
    assert admission2._recovery_required.get(KEY) is None


def test_two_restart_durability_of_tombstone(tmp_path: Path) -> None:
    """A tombstone persists across multiple restarts: each fresh registry's reconcile re-asserts
    the tombstone into a fresh admission cache, so a server bouncing twice still gates the target."""
    seed_reg = SessionRegistry(directory=tmp_path)
    seed_reg.write_tombstone(RecoveryTombstone(target_key=KEY, generation=1, reason="halted"))

    # restart #1 — fresh registry + fresh admission cache:
    reg1 = SessionRegistry(directory=tmp_path)
    admission1 = AdmissionService(SnapshotStore())
    reg1.reconcile(proxy=FakeReapProxy(), admission=admission1)
    assert reg1.read_tombstone(KEY) is not None
    assert admission1._recovery_required.get(KEY) == 1

    # restart #2 — fresh registry + fresh admission cache again; tombstone survives:
    reg2 = SessionRegistry(directory=tmp_path)
    admission2 = AdmissionService(SnapshotStore())
    reg2.reconcile(proxy=FakeReapProxy(), admission=admission2)
    assert reg2.read_tombstone(KEY) is not None
    assert admission2._recovery_required.get(KEY) == 1


def test_tombstone_generation_idempotency_fail_closed_at_bare_startup(tmp_path: Path) -> None:
    """Bare-startup reconcile with NO records/tombstones marks nothing. After a tombstone is
    written, every restart re-marks once per restart at the tombstone's generation."""
    # bare startup: nothing recorded -> nothing marked.
    reg = SessionRegistry(directory=tmp_path)
    admission = AdmissionService(SnapshotStore())
    reg.reconcile(proxy=FakeReapProxy(), admission=admission)
    assert admission._recovery_required.get(KEY) is None

    # write a tombstone, then "restart" twice — admission is re-marked each time at gen 1.
    reg.write_tombstone(RecoveryTombstone(target_key=KEY, generation=1, reason="halted"))
    for _ in range(2):
        fresh_reg = SessionRegistry(directory=tmp_path)
        fresh_admission = AdmissionService(SnapshotStore())
        fresh_reg.reconcile(proxy=FakeReapProxy(), admission=fresh_admission)
        assert fresh_admission._recovery_required.get(KEY) == 1


def test_abandoned_attach_epoch_fence(tmp_path: Path) -> None:
    """An AdmissionHandle whose admit_epoch is now stale relative to the target's current
    `_exec_epoch` (after a `note_execution_transition`) cannot complete: `complete(handle)` raises
    AdmissionError(execution_state_changed) — the backstop §5.6 rule 2."""
    store = SnapshotStore()
    # DEBUGGING state so admit_ssh_tier admits at the EXECUTING epoch.
    store.put(
        KEY,
        TargetSnapshot(generation=1, transports=(CHANNEL,), platform=PLATFORM, state=TargetState.DEBUGGING),
    )
    admission = AdmissionService(store)
    # First fence an EXECUTING proof at the current epoch (0), so admit_ssh_tier admits.
    proof = probe_execution_state(
        registry=_RegisteredExecutingRecord(generation=1),
        admission=admission,
        target_key=KEY,
        generation=1,
    )
    assert proof.state is ExecutionState.EXECUTING
    handle = admission.admit_ssh_tier(KEY, 1, PLATFORM, execution_proof=proof)

    # Now record a halt: the epoch bumps. The handle's admit_epoch is now stale.
    admission.note_execution_transition(KEY, 1)
    with pytest.raises(AdmissionError) as excinfo:
        admission.complete(handle)
    assert excinfo.value.code == "execution_state_changed"


class _RegisteredExecutingRecord:
    """Minimal SessionRegistry-shaped stand-in for `probe_execution_state` that returns an
    EXECUTING record at the requested generation, so the fence test can mint a fresh proof
    without touching the durable filesystem (the probe only calls `read_record`)."""

    def __init__(self, *, generation: int) -> None:
        self._generation = generation

    def read_record(self, target_key: TargetKey) -> TransportSession:
        return TransportSession(
            session_id=new_session_id(),
            target_key=target_key,
            generation=self._generation,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.READY,
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------


def test_invalidation_cancels_pending_and_promoted_bindings(tmp_path: Path) -> None:
    """A CRASHED lifecycle invalidation tears down a promoted session: the durable record is
    deleted and the promoted admission binding deregistered (confirm_reaped + abandon)."""
    reg = SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    txn.bind_lifecycle(dispatcher)
    txn.open(make_request())
    assert reg.read_record(KEY) is not None
    assert admission._bindings.get(KEY, []) != []

    admission.invalidate_lifecycle(LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=1)

    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []


def test_invalidation_awaited_blocks_until_teardown(tmp_path: Path) -> None:
    """The dispatcher's emit() contract: it runs the subscribers' invalidate (which delegates to
    force_drop for our subscriber) and joins them under the teardown deadline before returning.
    So when `invalidate_lifecycle` returns, the durable record/binding teardown has happened —
    not been scheduled. An observer recorded during force_drop is set BEFORE the call returns."""
    reg = SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    txn.bind_lifecycle(dispatcher)
    txn.open(make_request())

    teardown_observed = threading.Event()

    class _Observer:
        """Second subscriber whose force_drop sets the sentinel. emit() joins ALL subscribers
        under one deadline, so its return implies every subscriber's invalidate/force_drop ran."""

        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            self.force_drop(event)

        def force_drop(self, event: LifecycleEvent) -> None:
            teardown_observed.set()

    dispatcher.subscribe(KEY, "observer", _Observer())

    admission.invalidate_lifecycle(LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=1)

    # When invalidate_lifecycle returned, the subscriber's teardown was already done.
    assert teardown_observed.is_set()
    # …and the session's teardown is observable as state.
    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []


# ---------------------------------------------------------------------------
# execution-state gate (run_tests + cancel bridge)
# ---------------------------------------------------------------------------


def test_run_tests_rejected_while_halted(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    _write_halted_record(reg, FRESH_KEY)
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=_seed_run_tests_admission(),
        session_registry=reg,
    )
    assert response.ok is False
    assert response.error.category is ErrorCategory.READINESS_FAILURE
    assert response.error.details["code"] == "target_halted"


def test_run_tests_admitted_while_executing(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    _write_executing_record(reg, FRESH_KEY)
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=_seed_run_tests_admission(),
        session_registry=reg,
    )
    assert response.ok is True
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID_FRESH).step_results.get("run_tests")
    assert step is not None and step.status is StepStatus.SUCCEEDED


def test_async_halt_cancels_in_flight_run_tests(tmp_path: Path) -> None:
    """An admitted run_tests that spans a HALTED transition must: (a) be cancelled by the
    watcher, (b) terminalize its run_tests step to FAILED, (c) leave NO leftover watcher thread,
    AND (d) deregister its promoted ssh-tier handle (B-punch Fix 2).

    The halt is driven through the PRODUCTION helper `halt_debug_transport`, not via a manual
    `note_execution_transition` + `cancel_ssh_tier` from the test thread."""
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    _write_executing_record(reg, FRESH_KEY)
    admission = _seed_run_tests_admission()
    provider = CancelAwareTestProvider()

    def _halt() -> None:
        assert provider.started.wait(timeout=2)
        # Read the executing record back so the helper writes HALTED over the SAME row the
        # run_tests probe is reading; matches the production caller (which has the live session).
        record = next(r for r in reg.list_records() if r.target_key == FRESH_KEY)
        halt_debug_transport(session=record, admission=admission, session_registry=reg)

    live_before = set(threading.enumerate())
    timer = threading.Thread(target=_halt, daemon=True)
    timer.start()
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    timer.join(timeout=2)

    assert provider.cancel_observed.is_set()
    assert response.ok is False
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before and t is not timer]
    assert leftover == []
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID_FRESH).step_results.get("run_tests")
    assert step is not None and step.status is StepStatus.FAILED
    # B-punch Fix 2: the promoted ssh-tier handle is reaped, so reopen()/admit isn't blocked.
    assert admission._bindings.get(FRESH_KEY, []) == []


def test_inject_break_cancels_in_flight_run_tests_end_to_end(tmp_path: Path) -> None:
    """End-to-end async-halt cancel via the PRODUCTION inject_break path: open a transport session
    through `transport.open`, race `transport.inject_break` against an in-flight
    `target.run_tests`, and assert the run is cancelled. This is the integration assertion
    the suite was missing — `test_async_halt_cancels_in_flight_run_tests` drives `halt_debug_transport`
    directly; this drives it through the actual inject_break tool handler, so a regression in the
    handler's call site (Fix 1's `cancel_ssh_tier` invocation) is detected here even if the helper
    itself stays correct in isolation.
    """
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    admission = _seed_run_tests_admission()
    txn = TransportTransaction(
        admission=admission,
        registry=reg,
        guard=InProcessStopCapableGuard(),
        leases=ConsoleLeaseManager(),
        secrets=EnvSecretsResolver([]),
        break_policy=FakeBreakPolicy(),
        transports={"qemu-gdbstub": FakeQemuTransport()},
    )

    open_response = transport_open_handler(
        run_id=RUN_ID_FRESH,
        transaction=txn,
        admission=admission,
        session_registry=reg,
    )
    assert open_response.ok is True
    session_id = open_response.data["session_id"]

    provider = CancelAwareTestProvider()

    def _ok_break(**kwargs: Any) -> None:
        return None

    def _probe_halted(session: Any) -> bool:
        return True

    def _inject() -> None:
        assert provider.started.wait(timeout=2)
        result = transport_inject_break_handler(
            run_id=RUN_ID_FRESH,
            session_id=session_id,
            acknowledged_permissions=INJECT_PERMS,
            transaction=txn,
            admission=admission,
            session_registry=reg,
            break_mechanism=_ok_break,
            probe_halted=_probe_halted,
        )
        # If inject_break itself fails, surface that in the test by recording on the closure —
        # the outer assertions would otherwise blame the run_tests handler for a missed cancel.
        assert result.ok is True, result.error.message if not result.ok else ""

    live_before = set(threading.enumerate())
    timer = threading.Thread(target=_inject, daemon=True)
    timer.start()
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    timer.join(timeout=2)

    assert provider.cancel_observed.is_set()
    assert response.ok is False
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before and t is not timer]
    assert leftover == []
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID_FRESH).step_results.get("run_tests")
    assert step is not None and step.status is StepStatus.FAILED
    # The SSH_TIER binding was cancelled and reaped; the TRANSPORT_OPEN binding remains live
    # (inject_break does NOT close the transport — that's transport.close's job).
    ssh_tier_bindings = [h for h in admission._bindings.get(FRESH_KEY, ()) if h.op is AdmissionOp.SSH_TIER]
    assert ssh_tier_bindings == []


def test_cancel_bridge_watcher_torn_down_no_leak(tmp_path: Path) -> None:
    """A CLEAN (non-halted) admitted run leaves no leftover watcher thread — `complete()` runs
    and the daemon polling watcher is joined on the success exit path."""
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    _write_executing_record(reg, FRESH_KEY)
    admission = _seed_run_tests_admission()
    live_before = set(threading.enumerate())

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )

    assert response.ok is True
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before]
    assert leftover == []


def test_stale_executing_proof_probe_timeout(tmp_path: Path) -> None:
    """A DEBUGGING-state snapshot with no durable record yields an UNKNOWN probe; admit_ssh_tier
    fails closed with READINESS_FAILURE / execution_state_unknown — never an optimistic admit."""
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    # No record → probe returns UNKNOWN.
    admission = AdmissionService(SnapshotStore())
    admission.publish_snapshot(
        FRESH_KEY,
        TargetSnapshot(
            generation=1,
            transports=(CHANNEL,),
            platform=PLATFORM,
            state=TargetState.DEBUGGING,
        ),
    )
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    assert response.ok is False
    assert response.error.category is ErrorCategory.READINESS_FAILURE
    assert response.error.details["code"] == "execution_state_unknown"


def test_failed_inject_break_records_unknown(tmp_path: Path) -> None:
    """A break mechanism that raises (OSError here) writes execution_state=UNKNOWN to the durable
    record and returns INFRASTRUCTURE_FAILURE / break_unconfirmed — never stale HALTED/EXECUTING."""
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    open_response = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert open_response.ok is True

    def _exploding_break(**kwargs: Any) -> None:
        raise OSError("proxy socket vanished mid-break")

    result = transport_inject_break_handler(
        run_id="run-1",
        session_id=open_response.data["session_id"],
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=_exploding_break,
    )

    assert result.ok is False
    assert result.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert result.error.details["code"] == "break_unconfirmed"
    # NEVER stale EXECUTING, NEVER stranded at the optimistic HALTED — fail closed to UNKNOWN.
    assert reg.read_record(KEY).execution_state is ExecutionState.UNKNOWN


def test_out_of_band_halt_recorded_unknown_not_executing(tmp_path: Path) -> None:
    """Symmetric to the OSError path with a generic exception (TypeError): an unconfirmable break
    NEVER leaves the durable record EXECUTING. The no-double-write angle: the optimistic HALTED
    write is overwritten with UNKNOWN, never left stale, never reverted to EXECUTING."""
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    open_response = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert open_response.ok is True

    def _typing_error_break(**kwargs: Any) -> None:
        raise TypeError("real-mechanism missing kwargs")

    result = transport_inject_break_handler(
        run_id="run-1",
        session_id=open_response.data["session_id"],
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=_typing_error_break,
    )

    assert result.ok is False
    record = reg.read_record(KEY)
    assert record is not None
    assert record.execution_state is ExecutionState.UNKNOWN
    assert record.execution_state is not ExecutionState.EXECUTING


def test_cached_succeeded_served_while_halted(tmp_path: Path) -> None:
    """A SUCCEEDED cached run_tests step is served while the target is HALTED — the ssh-tier gate
    is never entered (no spurious admit)."""
    artifact_root = create_booted_run(tmp_path)
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        RUN_ID_FRESH, StepResult(step_name="run_tests", status=StepStatus.SUCCEEDED, summary="cached pass")
    )
    reg = _make_fresh_registry(tmp_path)
    _write_halted_record(reg, FRESH_KEY)

    class _SpyAdmission(AdmissionService):
        ssh_tier_calls = 0

        def admit_ssh_tier(self, *a: Any, **k: Any) -> Any:  # noqa: ANN401
            type(self).ssh_tier_calls += 1
            return super().admit_ssh_tier(*a, **k)

    admission = _SpyAdmission(SnapshotStore())
    publish_ready_snapshot(admission, target_key=FRESH_KEY, generation=1, transports=[CHANNEL], platform=PLATFORM)
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    assert response.ok is True
    assert _SpyAdmission.ssh_tier_calls == 0


def test_cached_running_terminalized_while_halted(tmp_path: Path) -> None:
    """A stale RUNNING run_tests step against a HALTED target is terminalized to FAILED — the
    gate runs (and rejects target_halted) and the stale RUNNING is terminalized."""
    artifact_root = create_booted_run(tmp_path)
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        RUN_ID_FRESH,
        StepResult(step_name="run_tests", status=StepStatus.RUNNING, summary="stuck"),
    )
    reg = _make_fresh_registry(tmp_path)
    _write_halted_record(reg, FRESH_KEY)
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=_seed_run_tests_admission(),
        session_registry=reg,
    )
    assert response.ok is False
    assert response.error.details["code"] == "target_halted"
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID_FRESH).step_results.get("run_tests")
    assert step is not None and step.status is StepStatus.FAILED


def test_gdbstub_reads_exempt_from_ssh_gate() -> None:
    """B4 invariant (re-asserted): debug.* read handlers run under the StopCapableGuard, NOT the
    ssh-tier admission gate, so they take no `admission` parameter. Ownership dependencies now flow
    through DebugRuntime instead of individual dependency-forwarding parameters, but `admission` is
    still absent — the read/ssh-tier structural separation holds."""
    parameters = inspect.signature(debug_read_registers_handler).parameters
    assert "admission" not in parameters
    assert "runtime" in parameters


# ---------------------------------------------------------------------------
# close / legacy
# ---------------------------------------------------------------------------


def test_close_while_halted_tombstones_then_revokes_never_false_executing(tmp_path: Path) -> None:
    """Open a session, force the durable record to HALTED, then close(force=False): the close-
    while-halted path must dual-write a recovery tombstone and delete the record; the persisted
    execution_state is NEVER observed as EXECUTING again."""
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    session = txn.open(make_request())
    # Force HALTED on the durable record (mirrors the gdb-attach halt path).
    reg.write_record(session.model_copy(update={"execution_state": ExecutionState.HALTED}))
    admission.note_execution_transition(session.target_key, session.generation)

    txn.close(session.session_id, force=False)

    # recovery tombstone dual-written; record deleted; binding deregistered.
    assert reg.read_tombstone(KEY) is not None
    assert reg.read_tombstone(KEY).reason == "closed_while_halted"
    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []
    assert admission._recovery_required.get(KEY) is not None


def test_legacy_debug_session_refused_on_load(tmp_path: Path) -> None:
    """A persisted DebugSession with no SessionRegistry record (the pre-Layer-4 shape) makes a
    debug.* mutating op (e.g. debug.continue) refuse with DEBUG_ATTACH_FAILURE /
    legacy_session_no_ownership AND dual-write a recovery_required tombstone."""
    artifact_root = seed_legacy_debug_session(tmp_path)
    registry = legacy_fence_make_registry(tmp_path)
    _txn, admission = legacy_fence_build_transaction(registry=registry)
    assert registry.read_record(LEGACY_FENCE_KEY) is None

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=LEGACY_FENCE_RUN_ID,
        runtime=DebugRuntime(
            debug_profiles=legacy_fence_profiles(),
            admission=admission,
            session_registry=registry,
            gdb_mi_engine=FakeMiEngine(),
            gdb_mi_sessions=GdbMiSessionRegistry(),
        ),
    )

    assert response.ok is False
    assert response.error.category is ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.error.details["code"] == "legacy_session_no_ownership"
    # dual-write: durable tombstone + admission cache.
    tombstone = registry.read_tombstone(LEGACY_FENCE_KEY)
    assert tombstone is not None
    assert admission._recovery_required.get(LEGACY_FENCE_KEY) == tombstone.generation


# ---------------------------------------------------------------------------
# redaction / secrets
# ---------------------------------------------------------------------------


def test_secret_refs_never_surfaced_in_response_or_record(tmp_path: Path, monkeypatch) -> None:
    """Open a session whose channel carries a secret ref pointing at a REAL env var holding a known
    literal secret value. Neither the raw secret_ref string NOR the resolved literal secret value
    may appear in the transport.open response body OR the durable record's JSON. The resolver
    returns a non-empty dict, exercising the full happy path through resolve()."""
    from kdive.safety.secrets import SecretReference, SecretReferenceKind

    # A real env var with a known literal value; the resolver returns it to the transaction, which
    # MUST hold the §3.4/§8 invariant that resolved values are never surfaced/persisted.
    env_var_name = "KDIVE_CONFORMANCE_SECRET_VALUE"
    raw_secret_value = "TOP_SECRET_LITERAL_xyzzy"
    monkeypatch.setenv(env_var_name, raw_secret_value)

    secret_channel = TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp0",
        line_role=LineRole.RSP,
        caps=("rsp",),
        secret_refs=(env_var_name,),
    )
    reg = SessionRegistry(directory=tmp_path)
    store = SnapshotStore()
    seed_snapshot(store, transports=(secret_channel,))
    admission = AdmissionService(store)
    txn = TransportTransaction(
        admission=admission,
        registry=reg,
        guard=InProcessStopCapableGuard(),
        leases=ConsoleLeaseManager(),
        # Resolver reads the env var; resolve() returns {env_var_name: raw_secret_value}.
        secrets=EnvSecretsResolver(
            [
                SecretReference(
                    kind=SecretReferenceKind.ENV,
                    label="conformance",
                    reference=env_var_name,
                    required=True,
                )
            ]
        ),
        break_policy=FakeBreakPolicy(),
        transports={"qemu-gdbstub": FakeQemuTransport()},
    )

    response = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert response.ok is True

    # The RAW secret_ref string is never echoed back to the agent OR persisted into the record.
    response_text = response.model_dump_json()
    assert env_var_name not in response_text

    record = reg.read_record(KEY)
    assert record is not None
    record_text = record.model_dump_json()
    assert env_var_name not in record_text
    # And — the load-bearing assertion — the resolved literal SECRET VALUE never appears in either
    # the response body or the durable record JSON. A leak here is the spec §3.4/§8 violation.
    assert raw_secret_value not in response_text
    assert raw_secret_value not in record_text


def test_console_and_gdb_transcript_redacted_into_durable_record(tmp_path: Path) -> None:
    """Console/gdb transcript text containing a secret pattern is redacted via Redactor() before
    being persisted into a durable structure — the raw secret never appears in the record/JSON."""
    redactor = Redactor()
    raw_transcript = "login OK\npassword=hunter2\ndone"
    safe_transcript = redactor.redact_text(raw_transcript)
    assert "hunter2" not in safe_transcript
    assert REDACTION in safe_transcript

    # The on-disk transcript may contain the raw text (sensitive artifact under <run>/debug/), but
    # what is PERSISTED into the durable session record / step result must be the redacted form.
    redacted_details = redactor.redact_value({"transcript": raw_transcript, "password": "leak"})
    assert "hunter2" not in str(redacted_details)
    assert "leak" not in str(redacted_details["password"])  # secret-keyed value redacted


# ---------------------------------------------------------------------------
# guard for the FakeSshRunner import — it's part of the harness contract and the conformance
# suite asserts the harness still exposes the cancel-aware shape Task B1/B2 depend on.
# ---------------------------------------------------------------------------


def test_fake_ssh_runner_has_cancel_aware_shape() -> None:
    """The shared Layer-4 harness must keep exposing a cancel-aware SshRunner stand-in (B1/B2)."""
    runner = FakeSshRunner()
    sig = inspect.signature(runner.run)
    assert "cancel" in sig.parameters
    # Suppress: ensure no import-time side-effects mutated harness state we just imported.
    with contextlib.suppress(Exception):
        runner.started.clear()


# ---------------------------------------------------------------------------
# Post-implementation review findings
# ---------------------------------------------------------------------------


def _debug_target_profile():
    """A target_profile that requests a debug-gdbstub boot, so FakeBootProvider's plan publishes
    a gdbstub_endpoint into the boot step details (the value the short-circuit republish reads)."""
    return target_profile().model_copy(update={"debug_gdbstub": True})


def _boot_run(artifact_root, tmp_path, admission, *, force_reboot: bool = False):
    return target_boot_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=FakeBootProvider(),
        admission=admission,
        force_reboot=force_reboot,
        acknowledged_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"],
        **profiles(tmp_path, target=_debug_target_profile()),
    )


def test_target_boot_short_circuit_republishes_snapshot(tmp_path: Path) -> None:
    """Finding #2: an idempotent `target.boot` short-circuit MUST republish the boot READY
    snapshot, so a post-restart re-invocation (in-memory `_store` empty, durable manifest still
    SUCCEEDED) restores the snapshot the next ssh-tier / transport.open gate reads via
    `_require_snapshot`. Without this, target.run_tests would fail `snapshot_missing` after a
    server restart even though the kernel is still running."""
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    # First boot publishes the snapshot.
    first_admission = AdmissionService(SnapshotStore())
    first = _boot_run(artifact_root, tmp_path, first_admission)
    assert first.ok is True
    target_key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    assert first_admission.current_snapshot(target_key) is not None

    # Simulate a server restart: drop the admission service entirely; the durable manifest
    # still records SUCCEEDED boot, so the second target.boot will short-circuit.
    fresh_admission = AdmissionService(SnapshotStore())
    assert fresh_admission.current_snapshot(target_key) is None

    second = _boot_run(artifact_root, tmp_path, fresh_admission)
    assert second.ok is True
    # The short-circuit republished the snapshot into the fresh admission service.
    snapshot = fresh_admission.current_snapshot(target_key)
    assert snapshot is not None
    assert snapshot.generation == 1  # same attempt number, same generation
    # And the next snapshot-reading path (`_require_snapshot`) succeeds — _require_snapshot is
    # what target.run_tests / debug.start_session / transport.open / inject_break all use.
    request = OpenRequest(
        target_key=target_key,
        generation=snapshot.generation,
        transport_ref=TransportRef(
            provider="qemu-gdbstub",
            channel_id="rsp0",
            line_role=LineRole.RSP,
            caps=("rsp",),
            target_ref={"host": "127.0.0.1", "port": 1234},
        ),
        required_caps=["rsp"],
        platform=snapshot.platform,
    )
    # The snapshot's READY state lets a transport.open admit succeed (not target_not_ready).
    handle = fresh_admission.admit(target_key, request)
    assert handle is not None


def test_target_boot_short_circuit_republish_is_idempotent(tmp_path: Path) -> None:
    """The republish is idempotent on `SnapshotStore`: two consecutive short-circuit calls in the
    same process leave the published snapshot unchanged after the second (no error, no generation
    bump, no orphaned binding) — `SnapshotStore.put` accepts an equal-generation write."""
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    admission = AdmissionService(SnapshotStore())
    first = _boot_run(artifact_root, tmp_path, admission)
    assert first.ok is True
    target_key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    snapshot_after_first = admission.current_snapshot(target_key)

    # Short-circuit twice — neither call may regress the snapshot or raise.
    second = _boot_run(artifact_root, tmp_path, admission)
    assert second.ok is True
    third = _boot_run(artifact_root, tmp_path, admission)
    assert third.ok is True
    snapshot_after_third = admission.current_snapshot(target_key)
    assert snapshot_after_third is not None
    assert snapshot_after_third.generation == snapshot_after_first.generation
    # No phantom transport bindings were registered by the republish — short-circuit republishes
    # the snapshot but does not admit anything.
    assert admission._bindings.get(target_key, []) == []


# ---------------------------------------------------------------------------
# Finding #3 — reconcile() orphan reap as the production LifecycleEvent source
# ---------------------------------------------------------------------------


def test_reconcile_orphan_backend_emits_lifecycle_event(tmp_path: Path) -> None:
    """Finding #3: `registry.reconcile()`'s orphan-backend reap is the production producer for
    `LifecycleEvent` in #10. Seed a durable record with a dead backend_pid, subscribe a
    `_SessionSubscriber` for the target via `transaction.open`, then run `reconcile()`. The
    reaper's callback MUST drive `admission.invalidate_lifecycle(target_key, CRASHED)`, which
    flows through the §4.5 chain: close_admission → dispatcher.emit → subscriber.force_drop →
    handle deregister + record delete."""
    reg = SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    txn.bind_lifecycle(dispatcher)
    # Open a session — this registers _SessionSubscriber AND mints a live promoted admission
    # binding the reaper's invalidate_lifecycle will deregister via force_drop.
    session = txn.open(make_request())
    assert reg.read_record(KEY) is not None
    assert admission._bindings.get(KEY, []) != []

    # Wire the production reap-callback the same way `_build_transport_machinery` does it.
    from kdive.coordination.registry import OrphanReap

    invalidated: list[OrphanReap] = []

    def on_orphan_reaped(reap: OrphanReap) -> None:
        invalidated.append(reap)
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=reap.target_key, kind=LifecycleKind.CRASHED),
            dispatcher,
            generation=session.generation,
        )

    # Force the durable record to point at a dead pid, then reconcile.
    reg.write_record(session.model_copy(update={"backend_pid": 999999, "backend_start_time": "stale"}))
    reaper_reg = SessionRegistry(directory=tmp_path, on_orphan_reaped=on_orphan_reaped)
    reaper_reg.reconcile(proxy=FakeReapProxy(), admission=admission)

    # The reaper saw a record with a backend_pid → invoked the callback → admission invalidated.
    assert len(invalidated) == 1
    assert invalidated[0].target_key == KEY
    assert invalidated[0].session_id == session.session_id
    assert invalidated[0].reason == "backend_died"
    # End-to-end: durable record deleted, promoted binding deregistered.
    assert reg.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []


def test_reconcile_no_records_emits_no_lifecycle_event(tmp_path: Path) -> None:
    """Symmetric negative case: with no durable records to reap, the reap-callback is never
    invoked. A backend that hasn't been recorded — or a record without a `backend_pid` — does
    not trigger the production lifecycle source path."""
    from kdive.coordination.registry import OrphanReap

    invocations: list[OrphanReap] = []

    def on_orphan_reaped(reap: OrphanReap) -> None:
        invocations.append(reap)

    reg = SessionRegistry(directory=tmp_path, on_orphan_reaped=on_orphan_reaped)
    admission = AdmissionService(SnapshotStore())
    reg.reconcile(proxy=FakeReapProxy(), admission=admission)
    assert invocations == []


# ---------------------------------------------------------------------------
# Finding #4 — inject_break success-path post-probe
# ---------------------------------------------------------------------------


def _seed_executing_session_for_break(tmp_path: Path):
    """Open a Layer-4 session against the FakeQemuTransport so `transport_inject_break_handler`
    has a record/admission/transaction trio to drive. Returns (reg, txn, admission, session_id)."""
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    open_response = transport_open_handler(run_id="run-1", transaction=txn, admission=admission, session_registry=reg)
    assert open_response.ok is True
    return reg, txn, admission, open_response.data["session_id"]


def test_inject_break_silent_failure_falls_to_unknown(tmp_path: Path) -> None:
    """Finding #4 / Findings F2+F5: when `break_mechanism` returns success but the post-probe
    (bounded RSP `?` exchange — `probe_rsp_halted`) does NOT observe a stop reply, the handler
    MUST dual-write UNKNOWN to the durable record and return DEBUG_ATTACH_FAILURE/
    break_unconfirmed — never leave a falsely optimistic HALTED in the record. (The cached-flag
    `probe_execution_state` was rejected for this path: `halt_debug_transport` writes HALTED to
    the very flag, so reading it back was circular — see ADR 0001.)"""
    reg, txn, admission, session_id = _seed_executing_session_for_break(tmp_path)

    def _silent_break(**kwargs: Any) -> None:
        return None  # mechanism reports success without raising

    result = transport_inject_break_handler(
        run_id="run-1",
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=_silent_break,
        probe_halted=lambda _session: False,  # RSP `?` produced no stop reply
    )
    assert result.ok is False
    assert result.error.category is ErrorCategory.DEBUG_ATTACH_FAILURE
    assert result.error.details["code"] == "break_unconfirmed"
    assert reg.read_record(KEY).execution_state is ExecutionState.UNKNOWN


def test_inject_break_genuine_success_keeps_halted(tmp_path: Path) -> None:
    """The post-probe ratifies a real halt: when `probe_rsp_halted` returns True (a `T..`/`S..`
    stop reply was observed), the handler reports success and the durable record stays HALTED
    (no dual-write to UNKNOWN, no failure response)."""
    reg, txn, admission, session_id = _seed_executing_session_for_break(tmp_path)

    def _ok_break(**kwargs: Any) -> None:
        return None

    result = transport_inject_break_handler(
        run_id="run-1",
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=_ok_break,
        probe_halted=lambda _session: True,
    )
    assert result.ok is True
    assert reg.read_record(KEY).execution_state is ExecutionState.HALTED


def test_inject_break_probe_timeout_falls_to_unknown(tmp_path: Path) -> None:
    """A probe that raises (timeout / connection drop / unreachable target) MUST fail closed to
    UNKNOWN — the success branch never tolerates an unconfirmable halt observation."""
    reg, txn, admission, session_id = _seed_executing_session_for_break(tmp_path)

    def _ok_break(**kwargs: Any) -> None:
        return None

    def _probe_raises(_session):
        raise TimeoutError("probe timed out")

    result = transport_inject_break_handler(
        run_id="run-1",
        session_id=session_id,
        acknowledged_permissions=INJECT_PERMS,
        transaction=txn,
        admission=admission,
        session_registry=reg,
        break_mechanism=_ok_break,
        probe_halted=_probe_raises,
    )
    assert result.ok is False
    assert result.error.details["code"] == "break_unconfirmed"
    assert result.error.details["probe_code"] == "probe_failed"
    assert result.error.details["exception_type"] == "TimeoutError"
    assert reg.read_record(KEY).execution_state is ExecutionState.UNKNOWN


# ---------------------------------------------------------------------------
# Finding F1 — reconcile() must not permanently lock admission after restart
# ---------------------------------------------------------------------------


def test_reconcile_with_dead_backend_does_not_lock_admission(tmp_path: Path) -> None:
    """Finding F1: when `stop_by_identity` does NOT kill a live backend (dead pid / unfenceable /
    None pid), the orphan-reap callback MUST NOT close admission. Otherwise a single surviving
    durable record from a prior server lifetime permanently bricks the target until process
    restart, because no production code path ever calls `reopen()`."""
    from kdive.coordination.registry import OrphanReap

    # Seed a record whose backend the reaper will NOT kill (FakeReapProxy default is
    # kills_live_backend=False, mirroring the dead-backend / qemu-gdbstub case).
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=1,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.OPENING,
            backend_pid=4321,
            backend_start_time="dead",
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
    )

    dispatcher = InProcessLifecycleDispatcher()
    admission = AdmissionService(SnapshotStore())
    seen: list[OrphanReap] = []

    def on_reap(reap: OrphanReap) -> None:
        seen.append(reap)
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=reap.target_key, kind=LifecycleKind.CRASHED),
            dispatcher,
            generation=reap.record.generation,
            close_admission=reap.close_admission_required,
        )

    reaper_reg = SessionRegistry(directory=tmp_path, on_orphan_reaped=on_reap)
    reaper_reg.reconcile(proxy=FakeReapProxy(kills_live_backend=False), admission=admission)

    assert len(seen) == 1 and seen[0].close_admission_required is False
    # admission was NOT closed — _closed_at is empty for the target.
    assert KEY not in admission._closed_at
    # the record was still deleted by reconcile.
    assert reaper_reg.read_record(KEY) is None


def test_reconcile_with_live_orphan_closes_admission_and_recovers_via_reopen(tmp_path: Path) -> None:
    """Finding F1, mirror: when `stop_by_identity` DID kill a fingerprint-matched live backend,
    `close_admission=True` is required — the §4.5 cancel-fence runs against any subscriber. A
    subsequent `publish_snapshot` at a higher generation + `reopen()` re-admits cleanly."""
    from kdive.coordination.registry import OrphanReap

    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=1,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.OPENING,
            backend_pid=4321,
            backend_start_time="alive",
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
    )

    store = SnapshotStore()
    seed_snapshot(store, generation=1, state=TargetState.READY)
    admission = AdmissionService(store)
    dispatcher = InProcessLifecycleDispatcher()
    seen: list[OrphanReap] = []

    def on_reap(reap: OrphanReap) -> None:
        seen.append(reap)
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=reap.target_key, kind=LifecycleKind.CRASHED),
            dispatcher,
            generation=reap.record.generation,
            close_admission=reap.close_admission_required,
        )

    reaper_reg = SessionRegistry(directory=tmp_path, on_orphan_reaped=on_reap)
    reaper_reg.reconcile(proxy=FakeReapProxy(kills_live_backend=True), admission=admission)

    assert len(seen) == 1 and seen[0].close_admission_required is True
    # admission IS closed at the record's generation — a live orphan was reaped.
    assert admission._closed_at.get(KEY) == 1
    # Publish a fresh snapshot at a higher generation (the production target.boot path), then
    # reopen() succeeds — the target is admittable again.
    seed_snapshot(store, generation=2, state=TargetState.READY)
    admission.reopen(KEY)
    assert KEY not in admission._closed_at


def test_crash_recovery_round_trip_admits_after_restart(tmp_path: Path) -> None:
    """End-to-end smoke for Finding F1: simulate a server crash mid-`transport.open` by writing a
    durable session record with a backend_pid that is NOT alive, then start a fresh registry +
    admission over the SAME directory, run reconcile, and verify a subsequent `transport.open`
    against a freshly-published snapshot SUCCEEDS — never `admission_closed`."""
    reg_first = SessionRegistry(directory=tmp_path)
    # A surviving OPENING record from a previous server lifetime — no live backend.
    reg_first.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=1,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.OPENING,
            backend_pid=None,  # qemu-gdbstub case: no fenceable pid
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
    )

    # "Restart" — fresh registry, fresh admission, the same on-disk state.
    reg = SessionRegistry(directory=tmp_path)
    store = SnapshotStore()
    seed_snapshot(store, generation=2, state=TargetState.READY)
    admission = AdmissionService(store)
    dispatcher = InProcessLifecycleDispatcher()

    def on_reap(reap):
        admission.invalidate_lifecycle(
            LifecycleEvent(target_key=reap.target_key, kind=LifecycleKind.CRASHED),
            dispatcher,
            generation=reap.record.generation,
            close_admission=reap.close_admission_required,
        )

    reg.bind_orphan_reap_callback(on_reap)
    reg.reconcile(proxy=FakeReapProxy(kills_live_backend=False), admission=admission)
    # The stale record is gone and admission is NOT closed (no live backend was reaped).
    assert reg.read_record(KEY) is None
    assert KEY not in admission._closed_at

    # Now wire a fresh transaction over the cleaned-up state — transport.open admits cleanly.
    transport = FakeQemuTransport()
    txn = TransportTransaction(
        admission=admission,
        registry=reg,
        guard=InProcessStopCapableGuard(),
        leases=ConsoleLeaseManager(),
        secrets=EnvSecretsResolver([]),
        break_policy=FakeBreakPolicy(),
        transports={transport.capability.provider_name: transport},
    )
    txn.bind_lifecycle(dispatcher)
    response = transport_open_handler(
        run_id="run-1",
        transaction=txn,
        admission=admission,
        session_registry=reg,
    )
    # Without the F1 fix this would fail with category=READINESS_FAILURE/code=admission_closed.
    assert response.ok is True, response.model_dump()
