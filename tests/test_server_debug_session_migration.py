"""Task B3: debug.start_session migrated onto the open() transaction.

These handler-level tests inject a real TransportTransaction (over a FakeQemuTransport) plus a fake
gdbstub debug provider, and assert the transaction wiring: the StopCapableGuard is acquired and a
durable HALTED record is written BEFORE the gdb attach runs, a halt makes target.run_tests reject,
a second stop-capable session is refused, and a recovery attach clears the tombstone.
"""

from __future__ import annotations

from pathlib import Path

from _layer4_fakes import FakeQemuTransport, build_txn
from conftest import FakeMiEngine, FakeTestProvider, kernel_provenance_details, rootfs, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile, RootfsProfile
from linux_debug_mcp.coordination.admission import AdmissionService
from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.gdb_mi import GdbMiSessionRegistry
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import (
    debug_end_session_handler,
    debug_start_session_handler,
    target_run_tests_handler,
)
from linux_debug_mcp.transport.base import ExecutionState, LineRole, TransportRef

# build_txn seeds the snapshot for TargetKey("local-qemu", "run-1"); use that run_id so the
# handler's target_key = TargetKey("local-qemu", run_id) matches.
RUN_ID = "run-1"
KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID)
GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
# The snapshot the boot producer publishes carries the RSP channel with the recorded endpoint as
# target_ref (mirrors _publish_boot_ready_snapshot), so admission can re-bind the handler's
# transport.open request against it.
RSP_CHANNEL = TransportRef(
    provider="qemu-gdbstub",
    channel_id="rsp0",
    line_role=LineRole.RSP,
    caps=("rsp",),
    target_ref=GDBSTUB_ENDPOINT,
)
PLATFORM_WITH_SSH = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)


class _HaltSpyEngine(FakeMiEngine):
    """Reads the durable registry record when the engine attaches so the test can prove the transport
    HALTED write happened BEFORE the gdb/MI attach (which halts the kernel) ran."""

    def __init__(self, registry: SessionRegistry) -> None:
        super().__init__()
        self._registry = registry
        self.execution_state_at_attach: ExecutionState | None = None
        self.guard_token_at_attach: str | None = None

    def attach(self, *, rsp_endpoint, vmlinux_path, transcript_path):
        record = self._registry.read_record(KEY)
        if record is not None:
            self.execution_state_at_attach = record.execution_state
            self.guard_token_at_attach = record.stop_guard_token
        return super().attach(rsp_endpoint=rsp_endpoint, vmlinux_path=vmlinux_path, transcript_path=transcript_path)


def _make_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _build_transaction(
    *,
    registry: SessionRegistry,
    generation: int = 1,
) -> tuple[TransportTransaction, AdmissionService]:
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    # Re-publish the READY snapshot so its RSP channel carries the recorded gdbstub endpoint as
    # target_ref (build_txn seeds an empty target_ref); the handler's transport.open request must
    # re-bind against this exact channel.
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=generation,
        transports=[RSP_CHANNEL],
        platform=PLATFORM_WITH_SSH,
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


def test_start_session_acquires_guard_and_writes_durable_record(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)
    engine = _HaltSpyEngine(registry)

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    assert response.ok is True
    record = registry.read_record(KEY)
    assert record is not None
    assert record.stop_guard_token is not None
    assert record.execution_state == ExecutionState.HALTED
    # ordering proof: the engine attach observed the HALTED durable write and the guard token.
    assert engine.execution_state_at_attach == ExecutionState.HALTED
    assert engine.guard_token_at_attach == record.stop_guard_token


def test_halt_via_start_session_makes_run_tests_reject(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)

    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
    )
    assert start.ok is True

    rootfs_profile: RootfsProfile = rootfs(tmp_path)
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile},
        admission=admission,
        session_registry=registry,
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.READINESS_FAILURE
    assert response.error.details["code"] == "target_halted"


def test_second_stop_capable_session_refused(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)

    first = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
    )
    assert first.ok is True

    # new_session forces a fresh attach attempt instead of returning the idempotent active session,
    # so the transaction's open() runs again and the guard is re-acquired against the still-held one.
    second = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        new_session=True,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
    )

    assert second.ok is False
    # Finding F13: guard/endpoint conflicts now route through TRANSPORT_CONFLICT, not the
    # gdb-attach-specific DEBUG_ATTACH_FAILURE.
    assert second.error.category == ErrorCategory.TRANSPORT_CONFLICT


def test_recovery_attach_clears_tombstone(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)
    # Park the target: durable tombstone + admission cache, mirroring close-while-halted.
    registry.write_tombstone(RecoveryTombstone(target_key=KEY, generation=1, reason="closed_while_halted"))
    admission.mark_recovery_required(KEY, 1)

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        recovery=True,
    )

    assert response.ok is True
    assert registry.read_tombstone(KEY) is None


def test_end_session_closes_transaction_and_frees_guard(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)

    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
    )
    assert start.ok is True
    assert registry.read_record(KEY) is not None

    end = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_session_id=start.data["debug_session_id"],
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        transaction=txn,
    )

    assert end.ok is True
    # close() released the guard/lease, deleted the durable record, and deregistered the handle.
    assert registry.read_record(KEY) is None
    assert admission._bindings.get(KEY, []) == []
    # the guard is free: a fresh stop-capable session on the same target is admitted (no conflict).
    reattach = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        new_session=True,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
    )
    assert reattach.ok is True


def test_debug_open_request_carries_gdbstub_endpoint_in_transport_opts() -> None:
    # The qemu-gdbstub transport reads host/port from transport_ref.opts (see its unit test), so the
    # open-request builder must populate opts — not only target_ref — or a real attach raises
    # KeyError: 'port'. This guards the live debug-attach path the gated integration test cannot in CI.
    from linux_debug_mcp.coordination.admission import SnapshotStore
    from linux_debug_mcp.server import _debug_open_request

    admission = AdmissionService(SnapshotStore())
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=7,
        transports=(RSP_CHANNEL,),
        platform=PLATFORM_WITH_SSH,
    )

    request = _debug_open_request(run_id=RUN_ID, gdbstub_endpoint=GDBSTUB_ENDPOINT, admission=admission)

    assert request.transport_ref.opts == GDBSTUB_ENDPOINT
    assert request.transport_ref.opts["port"] == 1234
    assert request.generation == 7
