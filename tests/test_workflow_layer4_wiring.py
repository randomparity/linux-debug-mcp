"""Workflow-level Layer-4 wiring tests.

These tests prove that the workflow tools thread the same shared Layer-4 machinery
(AdmissionService / SessionRegistry / TransportTransaction) into the inner step
handlers as the per-step `@app.tool` wrappers do. Without the wiring, the inner
run_tests / debug.start_session calls would run ungated and bypass the snapshot
publish, halt-gate, and open() transaction (the workflow tools would silently
skip Layer 4).

Test #1 pre-seeds a HALTED durable record and asserts the workflow propagates
READINESS_FAILURE/target_halted from run_tests. Test #2 asserts the workflow
successfully acquires the stop guard and writes a HALTED durable record via the
debug.start_session inner call.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from _layer4_fakes import CHANNEL, FakeQemuTransport, build_txn
from conftest import (
    FakeMiEngine,
    FakeTestProvider,
    kernel_provenance_details,
    make_source_tree,
    rootfs,
    write_vmlinux_with_build_id,
)

from kdive.artifacts.store import ArtifactStore
from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService, SnapshotStore, publish_ready_snapshot
from kdive.coordination.registry import SessionRegistry
from kdive.domain import (
    ArtifactRef,
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
    ToolResponse,
)
from kdive.providers.local.gdb_mi import GdbMiSessionRegistry
from kdive.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
)
from kdive.server import (
    workflow_build_boot_debug_handler,
    workflow_build_boot_test_handler,
)
from kdive.transport.base import (
    ExecutionState,
    LineRole,
    RecordState,
    TransportRef,
    TransportSession,
    new_session_id,
)

RUN_ID = "run-abc123"
KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID)
PLATFORM_WITH_SSH = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)


def _make_registry(tmp_path: Path) -> SessionRegistry:
    directory = tmp_path / "reg"
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _seed_run_tests_admission(generation: int = 1) -> AdmissionService:
    admission = AdmissionService(SnapshotStore())
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=generation,
        transports=[CHANNEL],
        platform=PLATFORM_WITH_SSH,
    )
    return admission


def _write_halted_record(reg: SessionRegistry, *, generation: int = 1) -> None:
    reg.write_record(
        TransportSession(
            session_id=new_session_id(),
            target_key=KEY,
            generation=generation,
            provider="qemu-gdbstub",
            channel_id="rsp0",
            record_state=RecordState.READY,
            execution_state=ExecutionState.HALTED,
            created_at=datetime.now(UTC),
        )
    )


def _create_booted_run_with_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    """Seed a build+boot SUCCEEDED manifest with the kernel-image artifact the boot handler requires
    when it runs again under the workflow (the cached-build short-circuit consults the artifact set
    before the boot step), so workflow_build_boot_test can short-circuit both steps and reach the
    real target.run_tests halt-gate.

    Returns (artifact_root, source_path)."""
    artifact_root = tmp_path / "runs"
    source = make_source_tree(tmp_path / "src-test")
    store = ArtifactStore(artifact_root, source_paths=[source])
    manifest = store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            run_id=RUN_ID,
        )
    )
    kernel = artifact_root / manifest.run_id / "build" / "bzImage"
    kernel.write_text("kernel", encoding="utf-8")
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="built",
            artifacts=[ArtifactRef(path=str(kernel), kind="kernel-image")],
            details={"kernel_release": "6.9.0-test"},
        ),
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="booted",
            details={},
        ),
    )
    return artifact_root, source


def test_workflow_run_tests_rejects_when_target_halted(tmp_path: Path, monkeypatch) -> None:
    """workflow.build_boot_test must thread admission + session_registry through to the inner
    target.run_tests call. With a pre-seeded HALTED durable record, the inner run_tests halt-gate
    rejects with READINESS_FAILURE/target_halted and the workflow propagates that failure."""
    artifact_root, source = _create_booted_run_with_artifacts(tmp_path)
    registry = _make_registry(tmp_path)
    admission = _seed_run_tests_admission()
    _write_halted_record(registry)

    # Provide a default rootfs profile via the run_tests handler's monkey-patched DEFAULT registry so
    # the real handler can resolve the manifest's "minimal" profile to something testable.
    monkeypatch.setattr(
        "kdive.server.DEFAULT_ROOTFS_PROFILES",
        {"minimal": rootfs(tmp_path)},
    )
    # The real test provider would actually attempt SSH; replace its plan_tests/execute_tests with a
    # passing FakeTestProvider so the gate is the only thing that can reject. The handler instantiates
    # LocalSshTestProvider() when provider is None, so swap the constructor.
    monkeypatch.setattr(
        "kdive.server.LocalSshTestProvider",
        lambda: FakeTestProvider(),
    )

    response = workflow_build_boot_test_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=RUN_ID,
        admission=admission,
        session_registry=registry,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == ErrorCategory.READINESS_FAILURE
    # The workflow stopped at run_tests (after the cached build + boot short-circuits); the inner
    # failed_response carries the run_tests handler's target_halted code.
    assert response.data["failing_step"] == "run_tests"
    failed_inner = response.error.details["failed_response"]
    assert failed_inner["error"]["category"] == "readiness_failure"
    assert failed_inner["error"]["details"]["code"] == "target_halted"


def _create_debug_ready_run(tmp_path: Path) -> tuple[Path, Path]:
    """Mirrors test_server_debug_session_migration._create_debug_ready_run: seed a debug-boot
    manifest with build+boot SUCCEEDED so workflow_build_boot_debug short-circuits both steps.

    Returns (artifact_root, source_path); source_path is the validated Linux source tree the
    manifest pinned (workflow re-validates source_path on every call)."""
    artifact_root = tmp_path / "runs"
    source = make_source_tree(tmp_path / "src-debug")
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
                "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234},
                "kernel_provenance": kernel_provenance_details(),
            },
        ),
    )
    return artifact_root, source


def test_workflow_debug_acquires_guard_and_writes_halted_record(tmp_path: Path, monkeypatch) -> None:
    """workflow.build_boot_debug must thread admission + session_registry + transaction through to
    the inner debug.start_session. After success, the durable SessionRegistry record exists with
    execution_state=HALTED and a stop_guard_token (the open() transaction acquired the guard and
    wrote the HALTED record before the gdb attach ran)."""
    artifact_root, source_path = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=1)
    # Re-publish the READY snapshot so its RSP channel carries the recorded gdbstub endpoint as
    # target_ref (build_txn seeds an empty target_ref); the inner debug.start_session rebinds against
    # this exact channel.
    rsp_channel = TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp0",
        line_role=LineRole.RSP,
        caps=("rsp",),
        target_ref={"host": "127.0.0.1", "port": 1234},
    )
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=1,
        transports=[rsp_channel],
        platform=PLATFORM_WITH_SSH,
    )

    # Profile registry: the workflow uses DEFAULT_DEBUG_PROFILES; the existing default already
    # contains qemu-gdbstub-default, but pin via monkeypatch for isolation.
    monkeypatch.setattr(
        "kdive.server.DEFAULT_DEBUG_PROFILES",
        {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    response: ToolResponse = workflow_build_boot_debug_handler(
        artifact_root=artifact_root,
        source_path=str(source_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id=RUN_ID,
        debug_profile="qemu-gdbstub-default",
        admission=admission,
        session_registry=registry,
        transaction=txn,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
    )

    assert response.ok is True
    record = registry.read_record(KEY)
    assert record is not None
    assert record.execution_state == ExecutionState.HALTED
    assert record.stop_guard_token is not None
