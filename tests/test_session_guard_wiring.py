"""Handler-level wiring + conformance tests for SessionGuard (issue #66).

The run/manifest/transaction setup helpers (`_create_debug_ready_run`, `_build_debug_transaction`,
`_make_test_registry`) and the fake providers are adapted from `tests/test_phase_b_integration_gaps.py`,
which already drives `debug_start_session_handler` through a wired Layer-4 transaction. The
`test_debug_start_session_closes_transport_on_failed_attach` test there is the resume-on-error
regression anchor this SessionGuard routing must keep green.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _layer4_fakes import KEY, PLATFORM, FakeQemuTransport, build_txn
from conftest import FakeMiEngine, kernel_provenance_details, write_vmlinux_with_build_id

from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionError, AdmissionService, publish_ready_snapshot
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.session_end import debug_end_session_handler
from kdive.debug.session_handlers import debug_start_session_handler
from kdive.domain import ArtifactRef, RunRequest, StepResult, StepStatus
from kdive.providers.local.debug.gdb_mi import GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard, SessionGuardContext
from kdive.seams.lifecycle import InProcessLifecycleDispatcher, LifecycleEvent, LifecycleKind
from kdive.target.handlers import _admit_run_tests_ssh_tier
from kdive.transport.core.base import LineRole, TransportRef

from kdive.artifacts.store import ArtifactStore  # isort: skip

RUN_ID = "run-1"
GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
RSP_CHANNEL = TransportRef(
    provider="qemu-gdbstub",
    channel_id="rsp0",
    line_role=LineRole.RSP,
    caps=("rsp",),
    target_ref=GDBSTUB_ENDPOINT,
)


def _make_test_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _build_debug_transaction(
    registry: SessionRegistry, *, generation: int = 1
) -> tuple[TransportTransaction, AdmissionService]:
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    publish_ready_snapshot(
        admission, target_key=KEY, generation=generation, transports=[RSP_CHANNEL], platform=PLATFORM
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


# --------------------------------------------------------------------------- Task 5: wiring


def test_start_session_runs_enter_before_open(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    calls: list[str] = []

    class _Pre:
        name = "pre"

        def check(self, ctx: SessionGuardContext) -> None:
            calls.append("pre")

    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(pre_attach=[_Pre()]),
    )
    assert resp.ok is True
    assert calls == ["pre"]


def test_start_session_open_failure_does_not_call_guard_teardown(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    txn._guard.acquire(KEY)  # pre-hold the stop-capable guard so open() raises GuardConflict
    teardown_reasons: list[str] = []

    class _Guard(SessionGuard):
        def teardown(self, ctx, **kw):  # type: ignore[override]
            teardown_reasons.append(ctx.reason)
            return super().teardown(ctx, **kw)

    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=_Guard(),
    )
    assert resp.ok is False  # the existing early TRANSPORT_CONFLICT return
    assert teardown_reasons == []  # open() failure is NOT a guard teardown path


def test_end_session_routes_through_guard_teardown(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert start.ok is True
    seen: list[str] = []

    class _Guard(SessionGuard):
        def teardown(self, ctx, **kw):  # type: ignore[override]
            seen.append(ctx.reason)
            return super().teardown(ctx, **kw)

    resp = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=_Guard(),
    )
    assert resp.ok is True
    assert seen == ["ended"]


# --------------------------------------------------------------------------- Task 6: conformance


def test_resume_on_error_reaps_and_tombstones(tmp_path):
    # provider.start_session raises after _halt parked HALTED -> guard.teardown(reason="attach_error")
    # -> transaction.close(force=False): record deleted, closed_while_halted tombstone gates future
    # ssh-tier admit, guard freed. Mirrors test_phase_b_integration_gaps.py's resume-on-error anchor.
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(fail_on="probe", resume_confirmed=False),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert resp.ok is False
    assert registry.read_record(KEY) is None  # record deleted (not left HALTED)
    tombstone = registry.read_tombstone(KEY)
    assert tombstone is not None and tombstone.reason == "closed_while_halted"
    assert admission._bindings.get(KEY, []) == []  # promoted binding deregistered
    txn._guard.acquire(KEY)  # guard is free (no GuardConflict)


def test_ssh_tier_rejected_while_halted_then_admitted_after_end(tmp_path):
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert start.ok is True  # session parked HALTED
    with pytest.raises(AdmissionError) as exc:
        _admit_run_tests_ssh_tier(run_id=RUN_ID, admission=admission, session_registry=registry)
    assert exc.value.code == "target_halted"  # AC2: fast-rejected, not hung
    end = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert end.ok is True
    handle = _admit_run_tests_ssh_tier(run_id=RUN_ID, admission=admission, session_registry=registry)
    assert handle is not None  # resumed -> ssh-tier admits again


def test_timeout_path_leaves_no_orphan_or_halted_record(tmp_path):
    # The dispatcher invalidation path is NOT routed through SessionGuard; the existing
    # _SessionSubscriber reap satisfies AC1's "times out" clause (no orphan, no live HALTED record).
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_test_registry(tmp_path)
    txn, admission = _build_debug_transaction(registry)
    # Bind a dispatcher so the opened session subscribes (production binds one in create_app;
    # build_txn does not). The bound _SessionSubscriber is what reaps on invalidation.
    dispatcher = InProcessLifecycleDispatcher()
    txn.bind_lifecycle(dispatcher)
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        session_guard=SessionGuard(),
    )
    assert start.ok is True
    admission.invalidate_lifecycle(
        LifecycleEvent(target_key=KEY, kind=LifecycleKind.RESETTING), dispatcher, generation=1
    )
    assert registry.read_record(KEY) is None  # reaped by _SessionSubscriber
