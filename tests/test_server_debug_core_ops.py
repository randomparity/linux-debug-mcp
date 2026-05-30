"""Phase C: the live gdb/MI session drives debug.start_session and every debug.* op (#81).

These handler-level tests inject a real TransportTransaction (over FakeQemuTransport), a fake
gdb/MI engine, and a GdbMiSessionRegistry, then assert that start_session keeps the engine
ATTACHED and registered (the durable record stays HALTED for the window), and that each per-op
handler dispatches onto the live attachment. The batch provider is gone — there is no
session-of-record other than the live engine attachment.
"""

from __future__ import annotations

from pathlib import Path

from _layer4_fakes import FakeQemuTransport, build_txn
from conftest import kernel_provenance_details, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.coordination.admission import AdmissionService
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.gdb_mi import (
    CANONICAL_PROBE_SYMBOL,
    BreakpointRef,
    Frame,
    GdbMiAttachment,
    GdbMiError,
    GdbMiSessionRegistry,
    MiRecord,
    ResolvedSymbol,
    StopRecord,
    Variable,
)
from linux_debug_mcp.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
    publish_ready_snapshot,
)
from linux_debug_mcp.server import (
    debug_continue_handler,
    debug_set_breakpoint_handler,
    debug_start_session_handler,
)
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


class FakeMiEngine:
    """A GdbMiEngine-shaped fake covering the attach probe AND the Phase C op surface. Each op
    records its call and returns a canned typed record; the live attachment is opaque."""

    def __init__(self) -> None:
        self.attached = False
        self.resolved: str | None = None
        self.forced = False
        self.detached = False
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    # --- attach probe ---
    def attach(self, *, rsp_endpoint, vmlinux_path, transcript_path) -> GdbMiAttachment:
        self.attached = True
        return GdbMiAttachment(
            controller=_NoopController(), rsp_host="127.0.0.1", rsp_port=1234, transcript_path=transcript_path
        )

    def probe_read(self, attachment) -> MiRecord:
        return MiRecord(type="result", message="connected", payload=None)

    def resolve_symbol(self, attachment, symbol_name: str) -> ResolvedSymbol:
        self.resolved = symbol_name
        return ResolvedSymbol(name=symbol_name, value="0x1234 <linux_banner>")

    def force_resume(self, attachment) -> bool:
        self.forced = True
        return True

    def resume_and_detach(self, attachment) -> bool:
        self.detached = True
        return True

    # --- Phase C ops ---
    def set_breakpoint(self, attachment, location: str) -> BreakpointRef:
        self.calls.append(("set_breakpoint", (location,)))
        return BreakpointRef(number="1", type="breakpoint", func=location, addr="0xffffffff81234560")

    def set_watchpoint(self, attachment, expression: str) -> BreakpointRef:
        self.calls.append(("set_watchpoint", (expression,)))
        return BreakpointRef(number="2", type="hw watchpoint", what=expression)

    def clear_breakpoint(self, attachment, number: str) -> None:
        self.calls.append(("clear_breakpoint", (number,)))

    def clear_watchpoint(self, attachment, number: str) -> None:
        self.calls.append(("clear_watchpoint", (number,)))

    def list_breakpoints(self, attachment) -> list[BreakpointRef]:
        self.calls.append(("list_breakpoints", ()))
        return [BreakpointRef(number="1", type="breakpoint", func="do_sys_open")]

    def continue_(self, attachment, *, timeout_sec: float) -> StopRecord:
        self.calls.append(("continue_", (timeout_sec,)))
        return StopRecord(reason="breakpoint-hit", bkptno="1", frame=Frame(level=0, func="do_sys_open"))

    def step(self, attachment, *, timeout_sec: float) -> StopRecord:
        self.calls.append(("step", (timeout_sec,)))
        return StopRecord(reason="end-stepping-range", frame=Frame(level=0, func="do_sys_open"))

    def next(self, attachment, *, timeout_sec: float) -> StopRecord:
        self.calls.append(("next", (timeout_sec,)))
        return StopRecord(reason="end-stepping-range", frame=Frame(level=0, func="do_sys_open"))

    def finish(self, attachment, *, timeout_sec: float) -> StopRecord:
        self.calls.append(("finish", (timeout_sec,)))
        return StopRecord(reason="function-finished", frame=Frame(level=1, func="__x64_sys_open"))

    def backtrace(self, attachment) -> list[Frame]:
        self.calls.append(("backtrace", ()))
        return [Frame(level=0, func="do_sys_open"), Frame(level=1, func="__x64_sys_open")]

    def list_variables(self, attachment) -> list[Variable]:
        self.calls.append(("list_variables", ()))
        return [Variable(name="fd", value="3")]

    def read_registers(self, attachment, register_names: list[str]) -> dict[str, object]:
        self.calls.append(("read_registers", tuple(register_names)))
        return {"registers": {name: "0x10" for name in register_names}}


class _NoopController:
    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def exit(self) -> None:
        return None


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
                _artifact(str(kernel), "kernel-image"),
                _artifact(str(vmlinux), "vmlinux"),
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


def _artifact(path: str, kind: str):
    from linux_debug_mcp.domain import ArtifactRef

    return ArtifactRef(path=path, kind=kind, sensitive=kind == "vmlinux")


def _profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


def _start(
    artifact_root: Path,
    *,
    registry: SessionRegistry,
    txn: TransportTransaction,
    admission: AdmissionService,
    engine: FakeMiEngine,
    sessions: GdbMiSessionRegistry,
    new_session: bool = False,
):
    return debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
        new_session=new_session,
    )


def test_start_session_keeps_engine_attached_and_registered(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    response = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert response.ok is True, response
    session_id = response.data["debug_session_id"]
    # ADR 0021 decision 1: the live attachment is held across MCP calls under the same session id.
    assert sessions.get(session_id) is not None
    # The engine stayed attached; it was NOT detached on the success path.
    assert engine.attached is True and engine.detached is False
    assert engine.resolved == CANONICAL_PROBE_SYMBOL
    assert response.data["mi_probe"]["record"]["message"] == "connected"
    # The durable transport record stays HALTED for the whole debug window.
    record = registry.read_record(KEY)
    assert record is not None and record.execution_state == ExecutionState.HALTED


def test_start_session_fault_reaps_live_session(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    sessions = GdbMiSessionRegistry()

    class _ResolveFails(FakeMiEngine):
        def resolve_symbol(self, attachment, symbol_name: str) -> ResolvedSymbol:
            raise GdbMiError("no such symbol", category=ErrorCategory.DEBUG_ATTACH_FAILURE)

    engine = _ResolveFails()
    response = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert response.ok is False
    assert response.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert engine.forced is True
    # The guaranteed-resume teardown reaped the live session and freed the durable record.
    assert registry.read_record(KEY) is None
    assert all(sessions.get(sid) is None for sid in [response.data.get("debug_session_id", "")] if sid)


def _debug_step_details(artifact_root: Path) -> dict[str, object]:
    store = ArtifactStore(artifact_root, create_root=False)
    debug = store.load_manifest(RUN_ID).step_results.get("debug")
    assert debug is not None and debug.status is StepStatus.SUCCEEDED
    return debug.details


def _load_persisted_session(artifact_root: Path, session_id: str) -> dict[str, object]:
    import json

    session_path = artifact_root / RUN_ID / "debug" / "sessions" / f"{session_id}.json"
    return json.loads(session_path.read_text(encoding="utf-8"))


def test_set_breakpoint_dispatches_and_refreshes_persisted_ledger(tmp_path: Path) -> None:
    """A stateful mutator runs on the registered live attachment, rebuilds the breakpoint ledger from
    the engine's authoritative -break-list, and persists it to the durable session."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    session_id = start.data["debug_session_id"]

    response = debug_set_breakpoint_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        symbol="do_sys_open",
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is True, response
    # The op dispatched onto the live attachment, then refreshed the ledger via -break-list.
    assert ("set_breakpoint", ("do_sys_open",)) in engine.calls
    assert ("list_breakpoints", ()) in engine.calls
    assert response.data["breakpoint"]["number"] == "1"
    # The authoritative ledger (keyed by gdb breakpoint number) is persisted to the durable session.
    persisted = _load_persisted_session(artifact_root, session_id)
    assert "1" in persisted["breakpoints"]
    assert persisted["breakpoints"]["1"]["func"] == "do_sys_open"


def test_stateful_op_preserves_transport_binding_and_mi_probe(tmp_path: Path) -> None:
    """A persisted op re-records the debug step; it must carry forward start_session's
    transport_session_id and mi_probe, else a later debug.end_session cannot close the transport and
    the attach probe record is lost from the manifest."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    session_id = start.data["debug_session_id"]
    before = _debug_step_details(artifact_root)
    assert "transport_session_id" in before and "mi_probe" in before

    response = debug_set_breakpoint_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        symbol="do_sys_open",
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )
    assert response.ok is True, response

    after = _debug_step_details(artifact_root)
    assert after["transport_session_id"] == before["transport_session_id"]
    assert after["mi_probe"] == before["mi_probe"]


def test_continue_dispatches_onto_live_attachment(tmp_path: Path) -> None:
    """An interactive resume verb (continue) drives the live attachment and surfaces the typed stop
    record; it persists without disturbing the breakpoint ledger."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    session_id = start.data["debug_session_id"]

    response = debug_continue_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        timeout_seconds=5,
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is True, response
    assert ("continue_", (5,)) in engine.calls
    assert response.data["stop"]["reason"] == "breakpoint-hit"
    assert response.data["current_execution_state"] == "stopped"
