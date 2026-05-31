"""Phase-B integration-gap closures (Fix 1/2/3).

These tests assert the three correctness fixes that close gaps surfaced by the whole-phase review:

1. create_app's `_build_transport_machinery` BINDS an `InProcessLifecycleDispatcher` into the
   transaction. Without binding, the §4.5 force_drop teardown path is unreachable in production —
   no out-of-band event source can drive a CRASHED invalidation through the wired admission/
   transaction/dispatcher trio. Asserted by driving a CRASHED LifecycleEvent through the WIRED
   dispatcher (the one stashed on `app._transport_machinery`) and observing the durable record /
   admission binding are cleared, matching the in-isolation test in test_transport_transaction.

2. target.run_tests must reap its PROMOTED ssh-tier admission handle on the error paths after
   `_execute_tests_under_gate` raises. The halt-cancel path sets the handle's cancel fence; without
   `admission.rollback(handle)` the binding lingers PROMOTED and blocks reopen()/admit. Asserted by
   running an admitted test through a halt and confirming `admission._bindings[KEY]` is empty.

3. debug.start_session must `transaction.close()` the transport on a failed gdb attach AFTER the
   transaction.open() committed READY + _halt_debug_transport persisted HALTED. Otherwise the
   guard stays held / record stays live / handle stays PROMOTED and run_tests stays gated
   `target_halted` forever. Asserted by failing the gdb attach and observing the durable record is
   GONE and a subsequent recovery=True reattach succeeds.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from _layer4_fakes import KEY, PLATFORM, FakeQemuTransport
from conftest import (
    CancelAwareTestProvider,
    FakeMiEngine,
    FakeTestProvider,
    create_booted_run,
    kernel_provenance_details,
    rootfs,
    write_vmlinux_with_build_id,
)

from kdive.artifacts.store import ArtifactStore
from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService, publish_ready_snapshot
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from kdive.providers.local.debug.gdb_mi import GdbMiSessionRegistry
from kdive.providers.local.local_ssh_tests import TestExecutionResult
from kdive.seams.lifecycle import LifecycleEvent, LifecycleKind
from kdive.seams.target import (
    TargetKey,
)
from kdive.server import (
    create_app,
    debug_start_session_handler,
    target_run_tests_handler,
)
from kdive.transport.core.base import (
    ExecutionState,
    LineRole,
    RecordState,
    TransportRef,
    TransportSession,
    new_session_id,
)
from kdive.transport.handlers import _halt_debug_transport

RUN_ID = "run-1"
GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
RSP_CHANNEL = TransportRef(
    provider="qemu-gdbstub",
    channel_id="rsp0",
    line_role=LineRole.RSP,
    caps=("rsp",),
    target_ref=GDBSTUB_ENDPOINT,
)


# ---------------------------------------------------------------------------
# Fix 1: lifecycle dispatcher wired in production
# ---------------------------------------------------------------------------


def test_create_app_binds_lifecycle_dispatcher_and_force_drop_reaches_admission(tmp_path: Path) -> None:
    # create_app must construct AND BIND an InProcessLifecycleDispatcher into the transaction. The
    # wired trio (admission + transaction + dispatcher) must share state, so a CRASHED event driven
    # through admission.invalidate_lifecycle(..., dispatcher, ...) reaches the live
    # _SessionSubscriber.force_drop() — and that force_drop deregisters the promoted admission
    # binding (confirm_reaped → abandon) for the just-opened session, the production equivalent of
    # the in-isolation transaction test test_lifecycle_invalidation_revokes_guard_and_reaps.
    reg_dir = tmp_path / "reg"
    reg_dir.mkdir(parents=True, exist_ok=True)
    registry = SessionRegistry(directory=reg_dir)
    app = create_app(session_registry=registry)
    machinery = app._transport_machinery
    transaction = machinery.transaction
    admission = machinery.admission
    dispatcher = machinery.lifecycle_dispatcher

    # Swap the wired qemu-gdbstub Transport for the FakeQemuTransport so transaction.open() can
    # complete without a real gdbstub backend. The transaction's _transports/_admission/_registry/
    # _dispatcher remain the WIRED instances — what we are proving is that the dispatcher and
    # admission share state with the just-opened session's subscriber, not the transport backend.
    transaction._transports["qemu-gdbstub"] = FakeQemuTransport()

    # Seed the snapshot and open a session through the WIRED transaction so the subscriber is
    # registered on the WIRED dispatcher.
    publish_ready_snapshot(admission, target_key=KEY, generation=1, transports=[RSP_CHANNEL], platform=PLATFORM)
    from kdive.transport.core.base import OpenRequest

    request = OpenRequest(
        target_key=KEY,
        generation=1,
        transport_ref=RSP_CHANNEL,
        platform=PLATFORM,
        required_caps=["rsp"],
    )
    transaction.open(request)
    assert registry.read_record(KEY) is not None
    assert admission._bindings.get(KEY, []) != []

    # Drive a CRASHED event through the wired dispatcher. invalidate_lifecycle closes admission
    # (step 1) and emits to the dispatcher (step 2); the bound _SessionSubscriber.force_drop()
    # deregisters its promoted handle and deletes the durable record.
    admission.invalidate_lifecycle(LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=1)

    assert registry.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []


# ---------------------------------------------------------------------------
# Fix 2: target.run_tests reaps its ssh-tier handle on error paths
# ---------------------------------------------------------------------------


def _make_test_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _seed_run_tests_admission(generation: int = 1) -> AdmissionService:
    from kdive.coordination.admission import AdmissionService, SnapshotStore

    admission = AdmissionService(SnapshotStore())
    publish_ready_snapshot(
        admission,
        target_key=TargetKey(provisioner="local-qemu", target_id="run-abc123"),
        generation=generation,
        transports=[RSP_CHANNEL],
        platform=PLATFORM,
    )
    return admission


def _executing_record(reg: SessionRegistry, key: TargetKey, generation: int = 1) -> None:
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


def test_run_tests_halt_during_execute_deregisters_ssh_tier_handle(tmp_path: Path) -> None:
    # An admitted run_tests op that spans a HALTED transition must not leave its promoted ssh-tier
    # handle in admission._bindings — without the rollback, reopen()/admit would block with
    # `bindings_outstanding`. Asserts the live AdmissionService (NOT a spy) records an empty
    # binding list for the target after the halt-cancelled run terminalizes.
    #
    # The halt is driven through the PRODUCTION helper `_halt_debug_transport`, so the rollback is
    # proven against the production code path (a test-thread `cancel_ssh_tier` would still pass
    # even if `_halt_debug_transport` itself never delivered the cancel — Fix 1 forecloses that).
    artifact_root = create_booted_run(tmp_path)
    test_key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    reg = _make_test_registry(tmp_path)
    _executing_record(reg, test_key)
    admission = _seed_run_tests_admission()
    provider = CancelAwareTestProvider()

    def _halt() -> None:
        assert provider.started.wait(timeout=2)
        record = next(r for r in reg.list_records() if r.target_key == test_key)
        _halt_debug_transport(session=record, admission=admission, session_registry=reg)

    timer = threading.Thread(target=_halt, daemon=True)
    timer.start()
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )
    timer.join(timeout=2)

    assert response.ok is False
    # cancel_ssh_tier set the cancel fence BEFORE complete() ran, so complete() raised
    # `admission_cancelled`; an alternative race (epoch advanced but fence not yet set) would have
    # raised `execution_state_changed`. Either way the run was rolled back rather than completed.
    assert response.error.details["code"] in {"admission_cancelled", "execution_state_changed"}
    # FIX 2: the promoted ssh-tier handle is rolled back; no binding lingers to block reopen/admit.
    assert admission._bindings.get(test_key, []) == []


def test_run_tests_unexpected_provider_failure_deregisters_ssh_tier_handle(tmp_path: Path) -> None:
    # Symmetric to the halt case: an arbitrary provider exception after admit must also reap the
    # promoted handle. Without rollback the binding lingers and blocks the next admit.
    artifact_root = create_booted_run(tmp_path)
    test_key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    reg = _make_test_registry(tmp_path)
    _executing_record(reg, test_key)
    admission = _seed_run_tests_admission()

    class ExplodingProvider(FakeTestProvider):
        def execute_tests(self, plan: object, *, cancel: Any = None) -> TestExecutionResult:
            self.executions += 1
            raise RuntimeError("provider blew up")

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=ExplodingProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission,
        session_registry=reg,
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    # FIX 2 (symmetric path): the promoted handle is rolled back on the generic-exception path too.
    assert admission._bindings.get(test_key, []) == []


# ---------------------------------------------------------------------------
# Fix 3: debug.start_session closes the transport on failed gdb attach
# ---------------------------------------------------------------------------


def _build_debug_transaction(
    registry: SessionRegistry, *, generation: int = 1
) -> tuple[TransportTransaction, AdmissionService]:
    from _layer4_fakes import build_txn

    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    # Re-publish the READY snapshot with the recorded gdbstub endpoint as target_ref so the
    # handler's transport.open request re-binds against the exact channel.
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=generation,
        transports=[RSP_CHANNEL],
        platform=PLATFORM,
    )
    return txn, admission


def _create_debug_ready_run(tmp_path: Path) -> Path:
    artifact_root = tmp_path / "runs"
    source = tmp_path / "source"
    source.mkdir()
    store = ArtifactStore(artifact_root, source_paths=[source])
    manifest = store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            debug_profile="qemu-gdbstub-default",
            run_id=RUN_ID,
        )
    )
    vmlinux = artifact_root / manifest.run_id / "build" / "vmlinux"
    kernel = artifact_root / manifest.run_id / "build" / "bzImage"
    write_vmlinux_with_build_id(vmlinux)
    kernel.write_text("kernel", encoding="utf-8")
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="built",
            artifacts=[
                ArtifactRef(path=str(kernel), kind="kernel-image"),
                ArtifactRef(path=str(vmlinux), kind="vmlinux"),
            ],
            details={"kernel_release": "6.9.0-test"},
        ),
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="booted",
            details={
                "debug_boot": True,
                "gdbstub_endpoint": GDBSTUB_ENDPOINT,
                "kernel_provenance": kernel_provenance_details(),
            },
        ),
    )
    return artifact_root


def _profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


def test_debug_start_session_closes_transport_on_failed_attach(tmp_path: Path) -> None:
    # When provider.start_session raises after the transaction's open + halt, the handler must
    # transaction.close(force=False) the just-opened session so the guard is released, the durable
    # record is deleted (a `closed_while_halted` recovery tombstone replaces it), and the promoted
    # admission handle is deregistered. Otherwise the next debug.start_session would refuse with
    # stop_capable_conflict (guard still held) and run_tests would stay gated target_halted.
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        # An engine probe fault whose un-halt cannot be confirmed leaves the conservative
        # closed_while_halted recovery tombstone (the failed-attach gap this test pins).
        gdb_mi_engine=FakeMiEngine(fail_on="probe", resume_confirmed=False),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    # (a) the response is DEBUG_ATTACH_FAILURE and carries the transport_session_id for diagnostics.
    assert response.ok is False
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert "transport_session_id" in response.error.details
    # (b) the durable SessionRegistry record is GONE (transaction.close ran).
    assert registry.read_record(KEY) is None
    # close(force=False) on a HALTED execution_state leaves a closed_while_halted recovery tombstone.
    tombstone = registry.read_tombstone(KEY)
    assert tombstone is not None
    assert tombstone.reason == "closed_while_halted"
    # the promoted admission binding was deregistered on close.
    assert admission._bindings.get(KEY, []) == []

    # (c) the guard is free: a subsequent recovery=True debug.start_session on the same target
    # succeeds — no DEBUG_ATTACH_FAILURE / stop_capable_conflict. recovery=True is required because
    # close(force=False) on a HALTED state correctly tombstoned the target as recovery_required.
    reattach = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        new_session=True,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        recovery=True,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )
    assert reattach.ok is True
    assert registry.read_tombstone(KEY) is None  # recovery attach cleared it
