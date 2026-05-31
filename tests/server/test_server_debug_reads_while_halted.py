"""Regression guardrail: gdbstub debug.* reads execute under the stop-capable guard (HALTED),
NOT through the ssh admit_ssh_tier gate.

Per ADR 0001/0002, gdb register/memory reads are valid precisely because the kernel is halted.
The read handler path (_debug_read_response -> _debug_operation_response) accepts no `admission`
parameter and contains no call to admit_ssh_tier -- ssh gating is structurally unreachable.

These tests pin that invariant so a future refactor cannot accidentally re-route reads through
the ssh execution gate.
"""

import inspect
from pathlib import Path

from conftest import FakeMiEngine, build_debug_transport, kernel_provenance_details, write_vmlinux_with_build_id

from kdive.artifacts.store import ArtifactStore
from kdive.config import DebugProfile
from kdive.debug.handlers import DebugRuntime
from kdive.domain import ArtifactRef, RunRequest, StepResult, StepStatus
from kdive.providers.local.debug.gdb_mi import GdbMiSessionRegistry
from kdive.server import debug_read_registers_handler, debug_start_session_handler

RUN_ID = "run-halted"


def _create_debug_ready_run(tmp_path: Path) -> tuple[Path, str]:
    """Create a run with build + debug-boot steps recorded, ready for a debug session."""
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
                "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234},
                "kernel_provenance": kernel_provenance_details(),
            },
        ),
    )
    return artifact_root, manifest.run_id


def _profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


def _debug_runtime(*, registry, engine, sessions) -> DebugRuntime:
    return DebugRuntime(
        debug_profiles=_profiles(),
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )


def test_read_registers_works_while_halted(tmp_path: Path) -> None:
    """A register read SUCCEEDS when the debug session is parked HALTED (stopped).

    gdb reads are valid precisely because the kernel is stopped at the gdbstub.
    """
    artifact_root, run_id = _create_debug_ready_run(tmp_path)
    registry, txn, admission = build_debug_transport(tmp_path, run_id)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()

    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )
    assert start.ok is True
    assert start.data["current_execution_state"] == "stopped"  # kernel is HALTED

    response = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        registers=["rip", "rsp"],
        runtime=_debug_runtime(registry=registry, engine=engine, sessions=sessions),
    )

    assert response.ok is True, f"expected SUCCEEDED but got: {response}"
    assert ("read_registers", ("rip", "rsp")) in engine.calls


def test_debug_read_not_ssh_gated(tmp_path: Path) -> None:
    """debug_read_registers_handler must NOT be routed through the ssh admit_ssh_tier gate.

    Approach: structural verification. The handler signature accepts no `admission` parameter
    (checked below), and _debug_read_response -> _debug_operation_response likewise accept no
    admission. Because there is no injection point for an AdmissionService on the read path,
    admit_ssh_tier is structurally unreachable -- the test exercises the handler successfully
    without any AdmissionService being present, confirming the ssh gate is not in the call chain.
    """
    from kdive.server import debug_read_registers_handler as _handler

    # Structural check: the read handler must not accept an admission parameter.
    sig = inspect.signature(_handler)
    assert "admission" not in sig.parameters, (
        "debug_read_registers_handler has an 'admission' parameter — "
        "this means ssh gating may have been accidentally introduced on the read path. "
        "Reads must execute under the stop-capable guard (HALTED), not the ssh tier gate."
    )

    # Functional check: the read works end-to-end with no AdmissionService threaded into the read
    # path, confirming no code on the read path requires or calls admit_ssh_tier.
    artifact_root, run_id = _create_debug_ready_run(tmp_path)
    registry, txn, admission = build_debug_transport(tmp_path, run_id)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()

    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )
    assert start.ok is True

    response = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        registers=["rip"],
        runtime=_debug_runtime(registry=registry, engine=engine, sessions=sessions),
    )

    assert response.ok is True, (
        "debug_read_registers_handler failed without an AdmissionService — "
        "the read path may have accidentally acquired an ssh dependency."
    )
