"""Phase C: the live gdb/MI session drives debug.start_session and every debug.* op (#81).

These handler-level tests inject a real TransportTransaction (over FakeQemuTransport), a fake
gdb/MI engine, and a GdbMiSessionRegistry, then assert that start_session keeps the engine
ATTACHED and registered (the durable record stays HALTED for the window), and that each per-op
handler dispatches onto the live attachment. The batch provider is gone — there is no
session-of-record other than the live engine attachment.
"""

from __future__ import annotations

from pathlib import Path
from typing import get_type_hints

from _layer4_fakes import FakeQemuTransport, build_txn
from conftest import kernel_provenance_details, write_vmlinux_with_build_id

import kdive.server as server_module
from kdive.artifacts.store import ArtifactStore
from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService, publish_ready_snapshot
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug import handlers as debug_handlers
from kdive.debug import operations as debug_operations
from kdive.debug import tools as debug_tools
from kdive.debug.tools import DebugToolContext, DebugToolHandlers
from kdive.domain import ErrorCategory, RunRequest, StepResult, StepStatus
from kdive.providers.debug import GdbMiSessionRegistry as GdbMiSessionRegistryContract
from kdive.providers.local.gdb_mi import (
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
from kdive.seams.target import (
    BreakHint,
    ConsoleKind,
    PlatformMetadata,
    TargetKey,
)
from kdive.server import (
    _end_mi_debug_session,
    debug_continue_handler,
    debug_list_breakpoints_handler,
    debug_set_breakpoint_handler,
    debug_start_session_handler,
)
from kdive.transport.base import ExecutionState, LineRole, TransportRef

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
    *, registry: SessionRegistry, generation: int = 1, platform: PlatformMetadata = PLATFORM_WITH_SSH
) -> tuple[TransportTransaction, AdmissionService]:
    txn, admission = build_txn(FakeQemuTransport(), registry=registry, generation=generation)
    publish_ready_snapshot(
        admission,
        target_key=KEY,
        generation=generation,
        transports=[RSP_CHANNEL],
        platform=platform,
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
    from kdive.domain import ArtifactRef

    return ArtifactRef(path=path, kind=kind, sensitive=kind == "vmlinux")


def _profiles() -> dict[str, DebugProfile]:
    return {"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")}


def test_debug_operation_handlers_route_directly_to_core_response() -> None:
    """Public debug.* handlers should be the adapter layer; avoid a second pass-through wrapper tier."""
    assert not hasattr(server_module, "_debug_read_response")
    assert not hasattr(server_module, "_debug_stateful_response")


def test_debug_operation_handlers_use_typed_operation_requests() -> None:
    """Handlers should construct typed operation requests instead of string names and kwargs bags."""
    assert not hasattr(debug_handlers, "DEBUG_HANDLER_OPERATION_SPECS")
    assert not hasattr(debug_handlers, "DebugHandlerOperationSpec")
    assert not hasattr(debug_handlers, "debug_operation_arguments")

    request = debug_handlers.DebugReadMemoryRequest(address=0x1000, byte_count=16)
    assert request.profile_operation == "debug.read_memory"
    assert request.summary_name == "read_memory"
    assert request.persist_manifest is False


def test_debug_tool_registration_uses_typed_context_and_handler_protocols() -> None:
    context_hints = get_type_hints(DebugToolContext)
    assert context_hints["transaction"] is TransportTransaction
    assert context_hints["admission"] is AdmissionService
    assert context_hints["session_registry"] is SessionRegistry
    assert context_hints["gdb_mi_sessions"] is GdbMiSessionRegistryContract
    assert not hasattr(DebugToolContext, "common_kwargs")
    assert not hasattr(DebugToolContext, "gated_kwargs")

    handler_hints = get_type_hints(DebugToolHandlers)
    assert handler_hints["start_session"].__name__ == "DebugStartSessionHandler"
    assert handler_hints["read_registers"].__name__ == "DebugReadRegistersHandler"
    assert handler_hints["continue_execution"].__name__ == "DebugExecutionControlHandler"
    assert handler_hints["end_session"].__name__ == "DebugEndSessionHandler"


def test_debug_tool_registration_groups_same_shaped_operations() -> None:
    groups = debug_tools.DEBUG_TOOL_REGISTRATION_GROUPS

    assert groups["ungated_query"] == (
        ("debug.read_registers", "read_registers", "registers"),
        ("debug.read_symbol", "read_symbol", "symbol"),
    )
    assert groups["gated_query"] == (
        ("debug.list_breakpoints", "list_breakpoints"),
        ("debug.backtrace", "backtrace"),
        ("debug.list_variables", "list_variables"),
    )
    assert groups["symbol_control"] == (
        ("debug.set_breakpoint", "set_breakpoint"),
        ("debug.set_watchpoint", "set_watchpoint"),
    )
    assert groups["breakpoint_id_control"] == (
        ("debug.clear_breakpoint", "clear_breakpoint"),
        ("debug.clear_watchpoint", "clear_watchpoint"),
    )
    assert groups["execution_control"] == (
        ("debug.continue", "continue_execution"),
        ("debug.step", "step"),
        ("debug.next", "next"),
        ("debug.finish", "finish"),
        ("debug.interrupt", "interrupt"),
    )
    assert {"debug.evaluate", "debug.read_memory", "debug.end_session"}.isdisjoint(
        {operation for group in groups.values() for operation, *_ in group}
    )


def test_debug_operation_response_uses_runtime_bundle() -> None:
    import inspect

    assert debug_operations._debug_operation_response.__module__ == "kdive.debug.operations"
    assert server_module._debug_operation_response is debug_operations._debug_operation_response
    assert hasattr(debug_handlers, "DebugRuntime")
    params = inspect.signature(debug_handlers.debug_tool_operation_response).parameters
    response_hints = get_type_hints(debug_handlers.debug_tool_operation_response)
    assert response_hints["runtime"] is debug_handlers.DebugRuntime
    assert response_hints["request"] is debug_handlers.DebugOperationRequest
    assert "runtime" in params
    assert "request" in params
    assert "operation_name" not in params
    assert "values" not in params
    for dependency_name in (
        "debug_profiles",
        "admission",
        "transaction",
        "session_registry",
        "session_guard",
        "gdb_mi_engine",
        "gdb_mi_sessions",
    ):
        assert dependency_name not in params


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


def test_list_breakpoints_does_not_rewrite_debug_manifest_step(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    session_id = start.data["debug_session_id"]
    before = _debug_step_details(artifact_root)

    response = debug_list_breakpoints_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is True, response
    assert response.data["breakpoints"][0]["func"] == "do_sys_open"
    assert _debug_step_details(artifact_root) == before


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


def _start_for_end(tmp_path: Path) -> tuple[Path, str, FakeMiEngine, GdbMiSessionRegistry, SessionRegistry]:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    return artifact_root, start.data["debug_session_id"], engine, sessions, registry


def test_end_session_bookkeeping_fault_does_not_resume_before_recording(tmp_path: Path, monkeypatch) -> None:
    """Guaranteed-resume ordering: end_session must durably record ENDED *before* the irreversible
    reap+force_resume. If the persist write faults, the kernel must stay HALTED with the live
    attachment intact (re-runnable) — never resumed-yet-owned, which would strand target.run_tests."""
    artifact_root, session_id, engine, sessions, registry = _start_for_end(tmp_path)

    def _boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(server_module, "_persist_mi_debug_session", _boom)
    response = _end_mi_debug_session(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    # The irreversible reap+resume never ran: the kernel is still HALTED and the session re-runnable.
    assert engine.forced is False
    assert sessions.get(session_id) is not None
    assert registry.read_record(KEY).execution_state == ExecutionState.HALTED


def test_end_session_record_fault_does_not_resume_before_recording(tmp_path: Path, monkeypatch) -> None:
    """Same invariant for the manifest-record write: a ManifestStateError after the (successful)
    persist must still leave the kernel HALTED and the attachment registered, not reaped+resumed."""
    from kdive.artifacts.store import ArtifactStore, ManifestStateError

    artifact_root, session_id, engine, sessions, registry = _start_for_end(tmp_path)
    real_record = ArtifactStore.record_step_result

    def _maybe_fail(self, run_id, result, *args, **kwargs):
        if result.summary == "debug.end_session succeeded":
            raise ManifestStateError("manifest busy", ErrorCategory.INFRASTRUCTURE_FAILURE)
        return real_record(self, run_id, result, *args, **kwargs)

    monkeypatch.setattr(ArtifactStore, "record_step_result", _maybe_fail)
    response = _end_mi_debug_session(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is False
    assert engine.forced is False
    assert sessions.get(session_id) is not None
    assert registry.read_record(KEY).execution_state == ExecutionState.HALTED


def test_op_raw_engine_fault_reaps_and_returns_structured_failure(tmp_path: Path) -> None:
    """A live op that raises a NON-GdbMiError fault (e.g. a dead gdb pipe) must not escape the
    handler. The dead attachment is reaped + best-effort resumed and a redacted INFRASTRUCTURE_FAILURE
    is returned, so the kernel is not stranded HALTED behind an unusable engine."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)

    class _DeadPipeEngine(FakeMiEngine):
        def continue_(self, attachment, *, timeout_sec: float):
            raise BrokenPipeError("gdb is gone")

    engine = _DeadPipeEngine()
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

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    # The unusable attachment was reaped and best-effort resumed (guaranteed-resume defence in depth).
    assert sessions.get(session_id) is None
    assert engine.forced is True
    assert "debug.end_session" in response.suggested_next_actions


def test_op_persist_fault_keeps_healthy_session_registered(tmp_path: Path, monkeypatch) -> None:
    """A persist fault on the stateful op path (engine healthy, op already ran) must surface a
    structured failure WITHOUT reaping the live session — the user can retry. Contrast with a raw
    engine fault, which reaps the dead attachment."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeMiEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    session_id = start.data["debug_session_id"]

    def _boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(debug_operations, "_persist_mi_debug_session", _boom)
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

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    # Engine is healthy; the session stays registered and was NOT resumed.
    assert sessions.get(session_id) is not None
    assert engine.forced is False


def test_mutator_ledger_rebuild_fault_reaps_and_returns_structured_failure(tmp_path: Path) -> None:
    """The breakpoint-ledger rebuild (-break-list) after a mutator is an engine call too: if gdb dies
    between the mutator and the rebuild, it must reap+resume and surface a structured failure, not
    escape the handler with the kernel stranded HALTED."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)

    class _LedgerFaultEngine(FakeMiEngine):
        def list_breakpoints(self, attachment):
            raise RuntimeError("gdb died before -break-list")

    engine = _LedgerFaultEngine()
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

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert sessions.get(session_id) is None
    assert engine.forced is True


# --- Task 3: per-op transport_stall teardown (ADR 0023) -------------------------------------------

from kdive.server import debug_read_registers_handler  # noqa: E402


class _StallEngine(FakeMiEngine):
    def continue_(self, attachment, *, timeout_sec: float):
        raise GdbMiError(
            "gdb/MI RSP went silent; the link stalled",
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            details={"code": "transport_stall"},
        )


def test_transport_stall_reaps_resumes_and_tears_down(tmp_path: Path) -> None:
    """A transport_stall during a stateful op runs the full teardown INSIDE debug_lock: reap the live
    attachment, force_resume the guest, resume the durable record to EXECUTING, and close the
    transport (guard release) so target.run_tests is ungated and re-attach starts clean."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = _StallEngine()
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
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details.get("code") == "transport_stall"
    for action in ("debug.start_session", "debug.kdb", "debug.introspect.run"):
        assert action in response.suggested_next_actions
    # The session was reaped, the guest resumed, and the durable transport record torn down.
    assert sessions.get(session_id) is None
    assert engine.forced is True
    assert registry.read_record(KEY) is None


def test_read_op_transport_stall_also_tears_down(tmp_path: Path) -> None:
    """A read op (debug.read_registers) over a stalled link runs the same reap+resume teardown — a
    dead link is dead regardless of op kind."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)

    class _StallReadEngine(FakeMiEngine):
        def read_registers(self, attachment, register_names: list[str]) -> dict[str, object]:
            raise GdbMiError(
                "RSP write timed out",
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={"code": "transport_stall"},
            )

    engine = _StallReadEngine()
    sessions = GdbMiSessionRegistry()
    start = _start(artifact_root, registry=registry, txn=txn, admission=admission, engine=engine, sessions=sessions)
    assert start.ok is True, start
    session_id = start.data["debug_session_id"]

    response = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        registers=["pc"],
        debug_session_id=session_id,
        debug_profiles=_profiles(),
        transaction=txn,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is False
    assert response.error.category is ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details.get("code") == "transport_stall"
    assert sessions.get(session_id) is None
    assert engine.forced is True


def test_benign_gdbmi_error_keeps_session(tmp_path: Path) -> None:
    """A non-stall GdbMiError (bad symbol) stays contained: the session is kept, not reaped, and the
    guest is not resumed — Phase-C behaviour unchanged."""
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)

    class _BadSymbolEngine(FakeMiEngine):
        def set_breakpoint(self, attachment, location: str):
            raise GdbMiError(
                "no symbol matches", category=ErrorCategory.DEBUG_ATTACH_FAILURE, details={"location": location}
            )

    engine = _BadSymbolEngine()
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
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )

    assert response.ok is False
    assert response.error.category is ErrorCategory.DEBUG_ATTACH_FAILURE
    assert sessions.get(session_id) is not None  # session kept (contained error)
    assert engine.forced is False
