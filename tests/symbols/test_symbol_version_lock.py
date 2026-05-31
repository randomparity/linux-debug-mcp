"""Behavior tests for the #70 gdb-tier symbol version-lock (ADR 0017).

The handler is called directly with injected fakes (the repo convention). The gate
compares the on-disk vmlinux ELF build-id against the boot-recorded
KernelProvenance.build_id BEFORE attaching gdb (the live gdb/MI engine).
"""

from pathlib import Path

from conftest import (
    GDB_TEST_BUILD_ID,
    FakeMiEngine,
    build_debug_transport,
    kernel_provenance_details,
    write_vmlinux_with_build_id,
)

from kdive.artifacts.store import ArtifactStore
from kdive.config import DebugProfile
from kdive.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from kdive.providers.local.debug.gdb_mi import GdbMiSessionRegistry
from kdive.server import debug_start_session_handler
from kdive.symbols.build_id import BuildIdReadError

_OTHER_BUILD_ID = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret
RUN_ID = "run-vlock"


def _seed(tmp_path: Path, *, provenance: dict | None, real_elf: bool = True) -> tuple[Path, str]:
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
    if real_elf:
        write_vmlinux_with_build_id(vmlinux)
    else:
        vmlinux.parent.mkdir(parents=True, exist_ok=True)
        vmlinux.write_text("not-an-elf", encoding="utf-8")
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
    boot_details: dict = {"debug_boot": True, "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234}}
    if provenance is not None:
        boot_details["kernel_provenance"] = provenance
    store.record_step_result(
        manifest.run_id,
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="booted", details=boot_details),
    )
    return artifact_root, manifest.run_id


def _profiles(symbol_identity_required: bool = True) -> dict[str, DebugProfile]:
    return {
        "qemu-gdbstub-default": DebugProfile(
            name="qemu-gdbstub-default", symbol_identity_required=symbol_identity_required
        )
    }


def _start(tmp_path: Path, artifact_root: Path, run_id: str, *, engine: FakeMiEngine | None = None, **overrides):
    """Drive debug.start_session over the live-engine path with the transport machinery wired."""
    engine = engine or FakeMiEngine()
    registry, txn, admission = build_debug_transport(tmp_path, run_id)
    return debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=GdbMiSessionRegistry(),
        **overrides,
    )


def test_matching_build_id_attaches(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    engine = FakeMiEngine()
    resp = _start(tmp_path, artifact_root, run_id, engine=engine)
    assert resp.ok is True
    assert engine.attached is True


def test_mismatched_build_id_fails_and_never_attaches(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    engine = FakeMiEngine()
    resp = _start(tmp_path, artifact_root, run_id, engine=engine, build_id_reader=lambda _p: _OTHER_BUILD_ID)
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert resp.error.details["observed"] == _OTHER_BUILD_ID
    assert resp.error.details["expected"] == GDB_TEST_BUILD_ID
    assert engine.attached is False
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert "debug" not in manifest.step_results


def test_unreadable_vmlinux_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details(), real_elf=False)
    engine = FakeMiEngine()

    def _boom(_p):
        raise BuildIdReadError("not an ELF file (bad magic)")

    resp = _start(tmp_path, artifact_root, run_id, engine=engine, build_id_reader=_boom)
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "vmlinux_build_id_unreadable"
    assert engine.attached is False


def test_missing_provenance_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=None)
    engine = FakeMiEngine()
    resp = _start(tmp_path, artifact_root, run_id, engine=engine)
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_missing"
    assert engine.attached is False


def test_capture_error_surfaces_as_provenance_missing(tmp_path):
    # Boot recorded a typed capture error instead of provenance.
    artifact_root, run_id = _seed(tmp_path, provenance=None)
    store = ArtifactStore(artifact_root, create_root=False)
    boot = store.load_manifest(run_id).step_results["boot"]
    store.record_step_result(
        run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary=boot.summary,
            details={
                **boot.details,
                "kernel_provenance_capture_error": {"code": "build_id_unavailable", "message": "no build_id"},
            },
        ),
        replace_succeeded=True,
    )
    engine = FakeMiEngine()
    resp = _start(tmp_path, artifact_root, run_id, engine=engine)
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_missing"
    assert resp.error.details["capture_error"] == "build_id_unavailable"
    assert engine.attached is False


def test_corrupt_recorded_build_id_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details("NOT-HEX"))
    engine = FakeMiEngine()
    resp = _start(tmp_path, artifact_root, run_id, engine=engine)
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "provenance_corrupt"
    assert engine.attached is False


def test_mismatch_fails_even_when_identity_not_required(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    engine = FakeMiEngine()
    registry, txn, admission = build_debug_transport(tmp_path, run_id)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profiles=_profiles(symbol_identity_required=False),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=GdbMiSessionRegistry(),
        build_id_reader=lambda _p: _OTHER_BUILD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "provenance_mismatch"
    assert engine.attached is False


def test_idempotent_reattach_skips_version_lock(tmp_path):
    # First attach (matching provenance + real ELF) records a SUCCEEDED debug step.
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    registry, txn, admission = build_debug_transport(tmp_path, run_id)
    sessions = GdbMiSessionRegistry()
    first = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=sessions,
    )
    assert first.ok is True
    session_id = first.data["debug_session_id"]
    # Strip the recorded provenance from the boot step to prove the idempotent return does NOT re-gate.
    store = ArtifactStore(artifact_root, create_root=False)
    boot = store.load_manifest(run_id).step_results["boot"]
    store.record_step_result(
        run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary=boot.summary,
            details={k: v for k, v in boot.details.items() if k != "kernel_provenance"},
        ),
        replace_succeeded=True,
    )
    second = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeMiEngine(),
        gdb_mi_sessions=sessions,
    )
    assert second.ok is True  # returned the existing session, not provenance_missing
    assert second.data["debug_session_id"] == session_id
