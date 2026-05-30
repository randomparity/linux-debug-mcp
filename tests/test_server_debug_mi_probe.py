"""Phase-A gdb/MI attach-probe wiring in debug.start_session (#79).

Handler-level tests: inject a real TransportTransaction (over FakeQemuTransport) plus a fake batch
debug provider and a fake gdb/MI engine, and assert the probe runs over the guard-protected
rsp_endpoint, the StopCapableGuard refuses a second stop-capable attach on the no-console
qemu-gdbstub path, and the guaranteed-resume invariant holds on every fault (engine crash, RSP
timeout, raised tool exception): the target is never left HALTED and ssh-tier is unblocked after a
confirmed resume.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _layer4_fakes import FakeQemuTransport, build_txn
from conftest import FakeTestProvider, kernel_provenance_details, rootfs, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile, RootfsProfile
from linux_debug_mcp.coordination.admission import AdmissionService
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.gdb_mi import GdbMiError, MiRecord
from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult, DebugSession
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import debug_start_session_handler, target_run_tests_handler
from linux_debug_mcp.transport.base import ExecutionState, LineRole, TransportRef

RUN_ID = "run-1"
KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID)
GDBSTUB_ENDPOINT = {"host": "127.0.0.1", "port": 1234}
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


class FakeDebugProvider:
    """The legacy batch session-of-record provider (Phase A keeps it; Phase C migrates it)."""

    name = "local-qemu-gdbstub"

    def start_session(self, **kwargs):
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
            started_at="2026-05-23T00:00:00+00:00",
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


class FakeEngine:
    """A GdbMiEngine-shaped fake. ``fail_on`` selects which step raises (``attach``/``probe`` raise
    GdbMiError; ``probe_crash`` raises an unwrapped RuntimeError)."""

    def __init__(self, *, fail_on: str | None = None, resume_confirmed: bool = True) -> None:
        self.fail_on = fail_on
        self._resume_confirmed = resume_confirmed
        self.attached = False
        self.resumed = False
        self.forced = False

    def attach(self, *, rsp_endpoint, vmlinux_path, transcript_path):
        if self.fail_on == "attach":
            raise GdbMiError("attach blew up", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        self.attached = True
        return object()  # opaque attachment handle

    def probe_read(self, attachment) -> MiRecord:
        if self.fail_on == "probe":
            raise GdbMiError("rsp timeout", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        if self.fail_on == "probe_crash":
            raise RuntimeError("unexpected non-GdbMiError engine crash")  # an unwrapped tool exception
        return MiRecord(type="result", message="connected", payload=None)  # the ^connected attach proof

    def resume_and_detach(self, attachment) -> bool:
        self.resumed = True
        return True

    def force_resume(self, attachment) -> bool:
        self.forced = True
        return self._resume_confirmed


def _make_registry(directory: Path) -> SessionRegistry:
    directory.mkdir(parents=True, exist_ok=True)
    return SessionRegistry(directory=directory)


def _build_transaction(
    *, registry: SessionRegistry, generation: int = 1
) -> tuple[TransportTransaction, AdmissionService]:
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
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


def test_probe_success_records_session_and_leaves_record_halted(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine()
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
    )
    assert resp.ok is True
    assert engine.attached and engine.resumed
    # AC#1: the typed MI probe record (the ^connected attach proof) is surfaced in the response data.
    assert resp.data["mi_probe"]["record"]["message"] == "connected"
    record = registry.read_record(KEY)
    assert record is not None and record.execution_state == ExecutionState.HALTED  # batch path owns the kernel


def test_second_stop_capable_attach_refused_on_qemu_gdbstub(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    common = dict(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeEngine(),
    )
    first = debug_start_session_handler(**common)
    assert first.ok is True
    second = debug_start_session_handler(new_session=True, **common)
    assert second.ok is False
    # The StopCapableGuard refuses the second attach on qemu-gdbstub even though that path has no
    # console lease. NB: the issue text says "stop_session_conflict"; the implemented code is
    # "stop_capable_conflict".
    assert second.error.category == ErrorCategory.TRANSPORT_CONFLICT
    assert second.error.details["code"] == "stop_capable_conflict"


@pytest.mark.parametrize("fail_on", ["attach", "probe"])
def test_probe_fault_resumes_and_frees_guard(tmp_path: Path, fail_on: str) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine(fail_on=fail_on, resume_confirmed=True)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    # guaranteed resume + teardown: guard released (record deleted), no recovery tombstone.
    assert registry.read_record(KEY) is None
    assert registry.read_tombstone(KEY) is None
    if fail_on != "attach":
        assert engine.forced is True


def test_non_gdbmi_engine_exception_still_resumes_and_frees_guard(tmp_path: Path) -> None:
    """The 'raised tool exception' fault case: an UNWRAPPED, non-GdbMiError exception from the engine
    must still trigger the guaranteed-resume + teardown (never strand the kernel HALTED) and report
    INFRASTRUCTURE_FAILURE rather than escaping the handler."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine(fail_on="probe_crash", resume_confirmed=True)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert engine.forced is True
    assert registry.read_record(KEY) is None
    assert registry.read_tombstone(KEY) is None


def test_probe_fault_releases_guard_even_if_unhalt_write_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guaranteed-resume robustness: if the durable un-halt write (`_resume_debug_transport`) raises
    (e.g. an OSError on a full disk), the teardown must still run -- the StopCapableGuard is released,
    the kernel is not left HALTED, and the handler returns a failure rather than letting the
    exception escape."""
    import linux_debug_mcp.server as server

    def _boom(**_kwargs):
        raise OSError("disk full while un-halting")

    monkeypatch.setattr(server, "_resume_debug_transport", _boom)
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeEngine(fail_on="probe", resume_confirmed=True),
    )
    assert resp.ok is False  # the exception did not escape the handler
    assert registry.read_record(KEY) is None  # teardown released the guard / deleted the record
    # a fresh attach on the same target is admitted (the guard was freed), via recovery since the
    # un-halt failure left a closed_while_halted tombstone.
    reattach = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        new_session=True,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeEngine(),
        recovery=True,
    )
    assert reattach.ok is True


def test_run_tests_rejected_while_target_halted(tmp_path: Path) -> None:
    """The 'during the stop' half of the §5.6 contract: while a debug session holds the kernel
    (durable record HALTED), a concurrently-issued ssh-tier op is fast-rejected with target_halted."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    ok = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeEngine(),
    )
    assert ok.ok is True
    assert registry.read_record(KEY).execution_state == ExecutionState.HALTED
    rootfs_profile: RootfsProfile = rootfs(tmp_path)
    during = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile},
        admission=admission,
        session_registry=registry,
    )
    assert during.ok is False and during.error.details["code"] == "target_halted"


def test_probe_fault_with_confirmed_resume_unblocks_ssh_tier(tmp_path: Path) -> None:
    """The 'after the guaranteed resume' half, on ONE target/registry timeline: a probe fault with
    confirmed resume un-halts the durable record and leaves no recovery tombstone, so a fresh
    ssh-tier op on the SAME target then succeeds (target back in EXECUTING)."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    faulted = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=FakeEngine(fail_on="probe", resume_confirmed=True),
    )
    assert faulted.ok is False
    # guaranteed-resume teardown: record deleted, no tombstone -> ssh-tier is no longer gated.
    assert registry.read_record(KEY) is None
    assert registry.read_tombstone(KEY) is None
    rootfs_profile: RootfsProfile = rootfs(tmp_path)
    after = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile},
        admission=admission,
        session_registry=registry,
    )
    assert after.ok is True
