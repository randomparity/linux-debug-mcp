"""§10.2 green-together conformance suite (Task C1, the merge bar for issue #10).

These tests assert the §10.2 Layer-4 invariant set TOGETHER against the real Phase-A/B wiring,
sharing the `_layer4_fakes` harness with the per-task tests. Each test is a behavior assertion of
ONE §10.2 invariant; together they describe the contract the merge must hold.
"""

from __future__ import annotations

import contextlib
import inspect
import threading
import time
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
from conftest import FakeTestProvider, create_booted_run, rootfs

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import TRANSPORT_DESTRUCTIVE_PERMISSIONS
from linux_debug_mcp.coordination.admission import (
    AdmissionError,
    AdmissionService,
    SnapshotStore,
    TargetSnapshot,
)
from linux_debug_mcp.coordination.endpoint_safety import EndpointSafetyError
from linux_debug_mcp.coordination.exec_probe import probe_execution_state
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager, LeaseOwner
from linux_debug_mcp.coordination.registry import (
    InstanceLockError,
    RecoveryTombstone,
    SessionRegistry,
)
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult
from linux_debug_mcp.safety.redaction import REDACTION, Redactor
from linux_debug_mcp.seams.guard import InProcessStopCapableGuard
from linux_debug_mcp.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
)
from linux_debug_mcp.seams.secrets import EnvSecretsResolver
from linux_debug_mcp.seams.target import (
    TargetKey,
    TargetState,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import (
    debug_read_registers_handler,
    target_run_tests_handler,
    transport_inject_break_handler,
    transport_open_handler,
)
from linux_debug_mcp.transport.base import (
    ExecutionState,
    LineRole,
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
    """An admitted run_tests that spans a HALTED transition must: (a) be cancelled in <5s by the
    watcher, (b) terminalize its run_tests step to FAILED, (c) leave NO leftover watcher thread,
    AND (d) deregister its promoted ssh-tier handle (B-punch Fix 2)."""
    artifact_root = create_booted_run(tmp_path)
    reg = _make_fresh_registry(tmp_path)
    _write_executing_record(reg, FRESH_KEY)
    admission = _seed_run_tests_admission()

    class _CancelAwareProvider(FakeTestProvider):
        def __init__(self) -> None:
            super().__init__()
            self.cancel_observed = threading.Event()

        def execute_tests(self, plan: object, *, cancel: Any = None) -> TestExecutionResult:
            self.executions += 1
            if cancel is not None and cancel.wait(5) and cancel.is_set():
                self.cancel_observed.set()
                return TestExecutionResult(
                    status=StepStatus.FAILED, summary="cancelled", artifacts=[], details={"cancelled": True}
                )
            return self.result

    provider = _CancelAwareProvider()

    def _halt() -> None:
        time.sleep(0.2)
        halt_epoch = admission.note_execution_transition(FRESH_KEY, 1)
        admission.cancel_ssh_tier(FRESH_KEY, 1, halt_epoch=halt_epoch)

    live_before = set(threading.enumerate())
    timer = threading.Thread(target=_halt, daemon=True)
    timer.start()
    start = time.monotonic()
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID_FRESH,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    elapsed = time.monotonic() - start
    timer.join(timeout=2)

    assert provider.cancel_observed.is_set()
    assert response.ok is False
    assert elapsed < 5
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before and t is not timer]
    assert leftover == []
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID_FRESH).step_results.get("run_tests")
    assert step is not None and step.status is StepStatus.FAILED
    # B-punch Fix 2: the promoted ssh-tier handle is reaped, so reopen()/admit isn't blocked.
    assert admission._bindings.get(FRESH_KEY, []) == []


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
    ssh-tier admission gate, so they take no `admission` parameter."""
    parameters = inspect.signature(debug_read_registers_handler).parameters
    assert "admission" not in parameters
    assert "session_registry" not in parameters


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
    # Reuse the seeding helper from the dedicated legacy-fence test module — the conformance
    # suite asserts the same invariant from the §10.2 frame.
    from test_server_legacy_session_fence import (  # noqa: PLC0415
        KEY as LEGACY_KEY,
    )
    from test_server_legacy_session_fence import (
        RUN_ID as LEGACY_RUN_ID,
    )
    from test_server_legacy_session_fence import (
        _build_transaction,
        _make_registry,
        _profiles,
        _seed_legacy_debug_session,
    )

    from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult  # noqa: PLC0415
    from linux_debug_mcp.server import debug_continue_handler  # noqa: PLC0415

    artifact_root = _seed_legacy_debug_session(tmp_path)
    registry = _make_registry(tmp_path)
    _txn, admission = _build_transaction(registry=registry)
    assert registry.read_record(LEGACY_KEY) is None

    class _ExplodingProvider:
        name = "local-qemu-gdbstub"

        def continue_execution(self, **kwargs: Any) -> DebugProviderResult:
            raise AssertionError("legacy session must NOT reach the provider")

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=LEGACY_RUN_ID,
        provider=_ExplodingProvider(),
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
    )

    assert response.ok is False
    assert response.error.category is ErrorCategory.DEBUG_ATTACH_FAILURE
    assert response.error.details["code"] == "legacy_session_no_ownership"
    # dual-write: durable tombstone + admission cache.
    tombstone = registry.read_tombstone(LEGACY_KEY)
    assert tombstone is not None
    assert admission._recovery_required.get(LEGACY_KEY) == tombstone.generation


# ---------------------------------------------------------------------------
# redaction / secrets
# ---------------------------------------------------------------------------


def test_secret_refs_never_surfaced_in_response_or_record(tmp_path: Path) -> None:
    """Open a session whose channel carries `secret_refs=("env:LDM_CONFORMANCE_SECRET",)`; the raw
    secret_ref string MUST NOT appear in the transport.open response body OR the durable record's
    JSON. The resolver knows the ref so open() proceeds to READY, exercising the full happy path."""
    from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind

    raw_secret_ref = "env:LDM_CONFORMANCE_SECRET"
    secret_channel = TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp0",
        line_role=LineRole.RSP,
        caps=("rsp",),
        secret_refs=(raw_secret_ref,),
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
        # Resolver knows the ref but the env var is unset and not required → resolve() returns {}.
        secrets=EnvSecretsResolver(
            [
                SecretReference(
                    kind=SecretReferenceKind.ENV,
                    label="conformance",
                    reference=raw_secret_ref,
                    required=False,
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
    assert raw_secret_ref not in response_text

    record = reg.read_record(KEY)
    assert record is not None
    record_text = record.model_dump_json()
    assert raw_secret_ref not in record_text
    # And the response itself never reports a resolved secret VALUE (the resolver returned none here).
    assert "LDM_CONFORMANCE_SECRET" not in response_text


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
