"""Regression guardrail: gdbstub debug.* reads execute under the stop-capable guard (HALTED),
NOT through the ssh admit_ssh_tier gate.

Per ADR 0001/0002, gdb register/memory reads are valid precisely because the kernel is halted.
The read handler path (_debug_read_response → _debug_operation_response) accepts no `admission`
parameter and contains no call to admit_ssh_tier — ssh gating is structurally unreachable.

These tests pin that invariant so a future refactor cannot accidentally re-route reads through
the ssh execution gate.
"""

import inspect
from pathlib import Path

from conftest import kernel_provenance_details, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult, DebugSession
from linux_debug_mcp.server import debug_read_registers_handler, debug_start_session_handler

# ---------------------------------------------------------------------------
# Minimal fake provider — only the methods this test exercises
# ---------------------------------------------------------------------------


class _FakeReadProvider:
    """Fake gdbstub provider that supports start_session and read_registers."""

    name = "local-qemu-gdbstub"

    def __init__(self) -> None:
        self.read_calls: int = 0

    def start_session(self, **kwargs):  # noqa: ANN003
        run_dir = kwargs["run_dir"]
        session_path = run_dir / "debug" / "sessions" / "debug-1.json"
        transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
        commands_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
        summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
        for path in [session_path, transcript_path, commands_path, summary_path]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
        session = DebugSession(
            session_id="debug-1",
            run_id=kwargs["run_id"],
            provider_name=self.name,
            gdbstub_endpoint=kwargs["gdbstub_endpoint"],
            vmlinux_path=str(kwargs["vmlinux_path"]),
            selected_debug_profile=kwargs["debug_profile"].name,
            attach_status="attached",
            started_at="2026-05-27T00:00:00+00:00",
            # "stopped" is the provider-level name for HALTED (kernel is paused at gdbstub)
            current_execution_state="stopped",
            transcript_path=str(transcript_path),
            command_metadata_path=str(commands_path),
            latest_summary_path=str(summary_path),
            symbol_identity_validation={"same_run_artifact_linkage": True, "live_banner_match": True},
        )
        session_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="debug session started",
            session=session,
            artifacts=[
                ArtifactRef(path=str(session_path), kind="debug-session"),
                ArtifactRef(path=str(transcript_path), kind="debug-transcript", sensitive=True),
                ArtifactRef(path=str(commands_path), kind="debug-command-metadata"),
                ArtifactRef(path=str(summary_path), kind="debug-summary"),
            ],
            details={"debug_session_id": "debug-1"},
        )

    def read_registers(self, **kwargs):  # noqa: ANN003
        self.read_calls += 1
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="registers read succeeded",
            session=kwargs["session"],
            details={
                "registers": {"rip": "0xffffffff81000000", "rsp": "0xffffffff82000000"},
                "stdout_snippet": "rip 0xffffffff81000000\nrsp 0xffffffff82000000\n",
            },
        )


# ---------------------------------------------------------------------------
# Shared setup helper
# ---------------------------------------------------------------------------


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
            run_id="run-halted",
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


# ---------------------------------------------------------------------------
# Behavior tests
# ---------------------------------------------------------------------------


def test_read_registers_works_while_halted(tmp_path: Path) -> None:
    """A register read SUCCEEDS when the debug session records execution_state=stopped (HALTED).

    gdb reads are valid precisely because the kernel is stopped at the gdbstub.  This test
    pins that the read path accepts a HALTED session and returns SUCCEEDED — not a gate error.
    """
    artifact_root, run_id = _create_debug_ready_run(tmp_path)
    provider = _FakeReadProvider()

    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert start.ok is True
    assert start.data["current_execution_state"] == "stopped"  # kernel is HALTED

    response = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        registers=["rip", "rsp"],
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert response.ok is True, f"expected SUCCEEDED but got: {response}"
    assert provider.read_calls == 1


def test_debug_read_not_ssh_gated(tmp_path: Path) -> None:
    """debug_read_registers_handler must NOT be routed through the ssh admit_ssh_tier gate.

    Approach: structural verification.  The handler signature accepts no `admission` parameter
    (checked below), and _debug_read_response → _debug_operation_response likewise accept no
    admission.  Because there is no injection point for an AdmissionService on the read path,
    admit_ssh_tier is structurally unreachable — the test exercises the handler successfully
    without any AdmissionService being present, confirming the ssh gate is not in the call chain.
    """
    from linux_debug_mcp.server import debug_read_registers_handler as _handler

    # Structural check: the read handler must not accept an admission parameter.
    sig = inspect.signature(_handler)
    assert "admission" not in sig.parameters, (
        "debug_read_registers_handler has an 'admission' parameter — "
        "this means ssh gating may have been accidentally introduced on the read path. "
        "Reads must execute under the stop-capable guard (HALTED), not the ssh tier gate."
    )

    # Functional check: the handler works end-to-end with no AdmissionService present,
    # confirming no code on the read path requires or calls admit_ssh_tier.
    artifact_root, run_id = _create_debug_ready_run(tmp_path)
    provider = _FakeReadProvider()

    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    assert start.ok is True

    response = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        registers=["rip"],
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert response.ok is True, (
        "debug_read_registers_handler failed without an AdmissionService — "
        "the read path may have accidentally acquired an ssh dependency."
    )
