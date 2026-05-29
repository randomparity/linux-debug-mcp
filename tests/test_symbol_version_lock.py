"""Behavior tests for the #70 gdb-tier symbol version-lock (ADR 0017).

The handler is called directly with injected fakes (the repo convention). The gate
compares the on-disk vmlinux ELF build-id against the boot-recorded
KernelProvenance.build_id BEFORE attaching gdb.
"""

from pathlib import Path

from conftest import GDB_TEST_BUILD_ID, kernel_provenance_details, write_vmlinux_with_build_id
from test_debug_handlers import FakeDebugProvider  # reuse the existing fake (top-level sibling import)

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.server import debug_start_session_handler
from linux_debug_mcp.symbols.build_id import BuildIdReadError

_OTHER_BUILD_ID = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret


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
            run_id="run-vlock",
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


def test_matching_build_id_attaches(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles()
    )
    assert resp.ok is True
    assert provider.calls == 1


def test_mismatched_build_id_fails_and_never_attaches(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles=_profiles(),
        build_id_reader=lambda _p: _OTHER_BUILD_ID,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert resp.error.details["observed"] == _OTHER_BUILD_ID
    assert resp.error.details["expected"] == GDB_TEST_BUILD_ID
    assert provider.calls == 0
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert "debug" not in manifest.step_results


def test_unreadable_vmlinux_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details(), real_elf=False)
    provider = FakeDebugProvider()

    def _boom(_p):
        raise BuildIdReadError("not an ELF file (bad magic)")

    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles=_profiles(),
        build_id_reader=_boom,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "vmlinux_build_id_unreadable"
    assert provider.calls == 0


def test_missing_provenance_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=None)
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles()
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_missing"
    assert provider.calls == 0


def test_corrupt_recorded_build_id_fails(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details("NOT-HEX"))
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=provider, debug_profiles=_profiles()
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "provenance_corrupt"
    assert provider.calls == 0


def test_mismatch_fails_even_when_identity_not_required(tmp_path):
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    provider = FakeDebugProvider()
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles=_profiles(symbol_identity_required=False),
        build_id_reader=lambda _p: _OTHER_BUILD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "provenance_mismatch"
    assert provider.calls == 0


def test_idempotent_reattach_skips_version_lock(tmp_path):
    # First attach (matching provenance + real ELF) records a SUCCEEDED debug step.
    artifact_root, run_id = _seed(tmp_path, provenance=kernel_provenance_details())
    first = debug_start_session_handler(
        artifact_root=artifact_root, run_id=run_id, provider=FakeDebugProvider(), debug_profiles=_profiles()
    )
    assert first.ok is True
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
        artifact_root=artifact_root, run_id=run_id, provider=FakeDebugProvider(), debug_profiles=_profiles()
    )
    assert second.ok is True  # returned the existing session, not provenance_missing
    assert second.data["debug_session_id"] == "debug-1"
