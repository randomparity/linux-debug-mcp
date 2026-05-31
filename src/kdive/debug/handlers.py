from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.providers.local.gdb_mi import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard

DEBUG_METHOD_OPERATIONS = {
    "read_registers": "debug.read_registers",
    "read_symbol": "debug.read_symbol",
    "read_memory": "debug.read_memory",
    "evaluate": "debug.evaluate",
    "set_breakpoint": "debug.set_breakpoint",
    "set_watchpoint": "debug.set_watchpoint",
    "clear_breakpoint": "debug.clear_breakpoint",
    "clear_watchpoint": "debug.clear_watchpoint",
    "list_breakpoints": "debug.list_breakpoints",
    "backtrace": "debug.backtrace",
    "list_variables": "debug.list_variables",
    "continue_execution": "debug.continue",
    "step": "debug.step",
    "next": "debug.next",
    "finish": "debug.finish",
    "interrupt": "debug.interrupt",
    "end_session": "debug.end_session",
}


@dataclass(frozen=True)
class DebugHandlerOperationSpec:
    method_name: str
    persist_manifest: bool
    argument_names: tuple[str, ...] = ()


DEBUG_HANDLER_OPERATION_SPECS = {
    "debug.read_registers": DebugHandlerOperationSpec("read_registers", False, ("registers",)),
    "debug.read_symbol": DebugHandlerOperationSpec("read_symbol", False, ("symbol",)),
    "debug.read_memory": DebugHandlerOperationSpec("read_memory", False, ("address", "byte_count")),
    "debug.evaluate": DebugHandlerOperationSpec("evaluate", False, ("inspector", "arguments")),
    "debug.set_breakpoint": DebugHandlerOperationSpec("set_breakpoint", True, ("symbol",)),
    "debug.set_watchpoint": DebugHandlerOperationSpec("set_watchpoint", True, ("symbol",)),
    "debug.clear_breakpoint": DebugHandlerOperationSpec("clear_breakpoint", True, ("breakpoint_id",)),
    "debug.clear_watchpoint": DebugHandlerOperationSpec("clear_watchpoint", True, ("breakpoint_id",)),
    "debug.list_breakpoints": DebugHandlerOperationSpec("list_breakpoints", False),
    "debug.backtrace": DebugHandlerOperationSpec("backtrace", False),
    "debug.list_variables": DebugHandlerOperationSpec("list_variables", False),
    "debug.continue": DebugHandlerOperationSpec("continue_execution", True, ("timeout_seconds",)),
    "debug.step": DebugHandlerOperationSpec("step", True, ("timeout_seconds",)),
    "debug.next": DebugHandlerOperationSpec("next", True, ("timeout_seconds",)),
    "debug.finish": DebugHandlerOperationSpec("finish", True, ("timeout_seconds",)),
    "debug.interrupt": DebugHandlerOperationSpec("interrupt", True, ("timeout_seconds",)),
}


@dataclass(frozen=True)
class DebugRuntime:
    debug_profiles: dict[str, DebugProfile] | None = None
    admission: AdmissionService | None = None
    transaction: TransportTransaction | None = None
    session_registry: SessionRegistry | None = None
    session_guard: SessionGuard | None = None
    gdb_mi_engine: GdbMiEngine | None = None
    gdb_mi_sessions: GdbMiSessionRegistry | None = None


def debug_runtime_from_handler_args(
    *,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> DebugRuntime:
    return DebugRuntime(
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


class DebugOperationCore(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_session_id: str | None,
        method_name: str,
        kwargs: dict[str, object],
        persist_manifest: bool,
        runtime: DebugRuntime,
    ) -> ToolResponse: ...


_DEBUG_OPERATION_CORE: DebugOperationCore | None = None


def configure_debug_operation_core(operation_core: DebugOperationCore) -> None:
    global _DEBUG_OPERATION_CORE
    _DEBUG_OPERATION_CORE = operation_core


def debug_handler_operation_spec(operation: str) -> DebugHandlerOperationSpec:
    return DEBUG_HANDLER_OPERATION_SPECS[operation]


def debug_operation_arguments(operation: DebugHandlerOperationSpec, values: dict[str, object]) -> dict[str, object]:
    return {name: values[name] for name in operation.argument_names}


def _default_debug_operation_core(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    method_name: str,
    kwargs: dict[str, object],
    persist_manifest: bool,
    runtime: DebugRuntime,
) -> ToolResponse:
    if _DEBUG_OPERATION_CORE is None:
        raise RuntimeError("debug operation core has not been configured")
    return _DEBUG_OPERATION_CORE(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name=method_name,
        kwargs=kwargs,
        persist_manifest=persist_manifest,
        runtime=runtime,
    )


def debug_tool_operation_response(
    *,
    operation_name: str,
    values: dict[str, object],
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    runtime: DebugRuntime,
    operation_core: DebugOperationCore = _default_debug_operation_core,
) -> ToolResponse:
    operation = debug_handler_operation_spec(operation_name)
    return operation_core(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        method_name=operation.method_name,
        kwargs=debug_operation_arguments(operation, values),
        persist_manifest=operation.persist_manifest,
        runtime=runtime,
    )


def _runtime(
    *,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> DebugRuntime:
    return debug_runtime_from_handler_args(
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_read_registers_handler(
    *,
    artifact_root: Path,
    run_id: str,
    registers: list[str],
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return debug_tool_operation_response(
        operation_name="debug.read_registers",
        values={"registers": registers},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        runtime=_runtime(
            debug_profiles=debug_profiles,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
    )


def debug_read_symbol_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return debug_tool_operation_response(
        operation_name="debug.read_symbol",
        values={"symbol": symbol},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        runtime=_runtime(
            debug_profiles=debug_profiles,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
    )


def debug_read_memory_handler(
    *,
    artifact_root: Path,
    run_id: str,
    address: int,
    byte_count: int,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return debug_tool_operation_response(
        operation_name="debug.read_memory",
        values={"address": address, "byte_count": byte_count},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        runtime=_runtime(
            debug_profiles=debug_profiles,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
    )


def debug_evaluate_handler(
    *,
    artifact_root: Path,
    run_id: str,
    inspector: str,
    arguments: dict[str, object] | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return debug_tool_operation_response(
        operation_name="debug.evaluate",
        values={"inspector": inspector, "arguments": arguments or {}},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        runtime=_runtime(
            debug_profiles=debug_profiles,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
    )


def _debug_operation_handler(
    *,
    operation_name: str,
    values: dict[str, object],
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    debug_profiles: dict[str, DebugProfile] | None,
    admission: AdmissionService | None,
    transaction: TransportTransaction | None,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
    gdb_mi_engine: GdbMiEngine | None,
    gdb_mi_sessions: GdbMiSessionRegistry | None,
) -> ToolResponse:
    return debug_tool_operation_response(
        operation_name=operation_name,
        values=values,
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        runtime=_runtime(
            debug_profiles=debug_profiles,
            admission=admission,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
    )


def debug_set_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.set_breakpoint",
        values={"symbol": symbol},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_set_watchpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    symbol: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.set_watchpoint",
        values={"symbol": symbol},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_clear_breakpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.clear_breakpoint",
        values={"breakpoint_id": breakpoint_id},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_clear_watchpoint_handler(
    *,
    artifact_root: Path,
    run_id: str,
    breakpoint_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.clear_watchpoint",
        values={"breakpoint_id": breakpoint_id},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_list_breakpoints_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.list_breakpoints",
        values={},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_backtrace_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.backtrace",
        values={},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_list_variables_handler(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name="debug.list_variables",
        values={},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def _debug_execution_control_handler(
    *,
    operation_name: str,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None,
    debug_session_id: str | None,
    debug_profiles: dict[str, DebugProfile] | None,
    admission: AdmissionService | None,
    transaction: TransportTransaction | None,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
    gdb_mi_engine: GdbMiEngine | None,
    gdb_mi_sessions: GdbMiSessionRegistry | None,
) -> ToolResponse:
    return _debug_operation_handler(
        operation_name=operation_name,
        values={"timeout_seconds": timeout_seconds},
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_continue_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_execution_control_handler(
        operation_name="debug.continue",
        artifact_root=artifact_root,
        run_id=run_id,
        timeout_seconds=timeout_seconds,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_step_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_execution_control_handler(
        operation_name="debug.step",
        artifact_root=artifact_root,
        run_id=run_id,
        timeout_seconds=timeout_seconds,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_next_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_execution_control_handler(
        operation_name="debug.next",
        artifact_root=artifact_root,
        run_id=run_id,
        timeout_seconds=timeout_seconds,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_finish_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_execution_control_handler(
        operation_name="debug.finish",
        artifact_root=artifact_root,
        run_id=run_id,
        timeout_seconds=timeout_seconds,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )


def debug_interrupt_handler(
    *,
    artifact_root: Path,
    run_id: str,
    timeout_seconds: int | None = None,
    debug_session_id: str | None = None,
    debug_profiles: dict[str, DebugProfile] | None = None,
    admission: AdmissionService | None = None,
    transaction: TransportTransaction | None = None,
    session_registry: SessionRegistry | None = None,
    session_guard: SessionGuard | None = None,
    gdb_mi_engine: GdbMiEngine | None = None,
    gdb_mi_sessions: GdbMiSessionRegistry | None = None,
) -> ToolResponse:
    return _debug_execution_control_handler(
        operation_name="debug.interrupt",
        artifact_root=artifact_root,
        run_id=run_id,
        timeout_seconds=timeout_seconds,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=admission,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
