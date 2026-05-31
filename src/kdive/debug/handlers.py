from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol

from kdive.config import DebugProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard


class DebugOperationRequest(Protocol):
    profile_operation: str
    summary_name: str
    persist_manifest: bool


class _DebugOperationMetadata:
    profile_operation: ClassVar[str]
    summary_name: ClassVar[str]
    persist_manifest: ClassVar[bool]


@dataclass(frozen=True)
class DebugReadRegistersRequest(_DebugOperationMetadata):
    registers: list[str]
    profile_operation: ClassVar[str] = "debug.read_registers"
    summary_name: ClassVar[str] = "read_registers"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugReadSymbolRequest(_DebugOperationMetadata):
    symbol: str
    profile_operation: ClassVar[str] = "debug.read_symbol"
    summary_name: ClassVar[str] = "read_symbol"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugReadMemoryRequest(_DebugOperationMetadata):
    address: int
    byte_count: int
    profile_operation: ClassVar[str] = "debug.read_memory"
    summary_name: ClassVar[str] = "read_memory"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugEvaluateRequest(_DebugOperationMetadata):
    inspector: str
    arguments: dict[str, object]
    profile_operation: ClassVar[str] = "debug.evaluate"
    summary_name: ClassVar[str] = "evaluate"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugSetBreakpointRequest(_DebugOperationMetadata):
    symbol: str
    profile_operation: ClassVar[str] = "debug.set_breakpoint"
    summary_name: ClassVar[str] = "set_breakpoint"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugSetWatchpointRequest(_DebugOperationMetadata):
    symbol: str
    profile_operation: ClassVar[str] = "debug.set_watchpoint"
    summary_name: ClassVar[str] = "set_watchpoint"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugClearBreakpointRequest(_DebugOperationMetadata):
    breakpoint_id: str
    profile_operation: ClassVar[str] = "debug.clear_breakpoint"
    summary_name: ClassVar[str] = "clear_breakpoint"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugClearWatchpointRequest(_DebugOperationMetadata):
    breakpoint_id: str
    profile_operation: ClassVar[str] = "debug.clear_watchpoint"
    summary_name: ClassVar[str] = "clear_watchpoint"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugListBreakpointsRequest(_DebugOperationMetadata):
    profile_operation: ClassVar[str] = "debug.list_breakpoints"
    summary_name: ClassVar[str] = "list_breakpoints"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugBacktraceRequest(_DebugOperationMetadata):
    profile_operation: ClassVar[str] = "debug.backtrace"
    summary_name: ClassVar[str] = "backtrace"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugListVariablesRequest(_DebugOperationMetadata):
    profile_operation: ClassVar[str] = "debug.list_variables"
    summary_name: ClassVar[str] = "list_variables"
    persist_manifest: ClassVar[bool] = False


@dataclass(frozen=True)
class DebugContinueRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.continue"
    summary_name: ClassVar[str] = "continue_execution"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugStepRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.step"
    summary_name: ClassVar[str] = "step"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugNextRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.next"
    summary_name: ClassVar[str] = "next"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugFinishRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.finish"
    summary_name: ClassVar[str] = "finish"
    persist_manifest: ClassVar[bool] = True


@dataclass(frozen=True)
class DebugInterruptRequest(_DebugOperationMetadata):
    timeout_seconds: int | None
    profile_operation: ClassVar[str] = "debug.interrupt"
    summary_name: ClassVar[str] = "interrupt"
    persist_manifest: ClassVar[bool] = True


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
        request: DebugOperationRequest,
        runtime: DebugRuntime,
    ) -> ToolResponse: ...


_DEBUG_OPERATION_CORE: DebugOperationCore | None = None


def configure_debug_operation_core(operation_core: DebugOperationCore) -> None:
    global _DEBUG_OPERATION_CORE
    _DEBUG_OPERATION_CORE = operation_core


def _default_debug_operation_core(
    *,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    request: DebugOperationRequest,
    runtime: DebugRuntime,
) -> ToolResponse:
    if _DEBUG_OPERATION_CORE is None:
        raise RuntimeError("debug operation core has not been configured")
    return _DEBUG_OPERATION_CORE(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        request=request,
        runtime=runtime,
    )


def debug_tool_operation_response(
    *,
    request: DebugOperationRequest,
    artifact_root: Path,
    run_id: str,
    debug_session_id: str | None,
    runtime: DebugRuntime,
    operation_core: DebugOperationCore = _default_debug_operation_core,
) -> ToolResponse:
    return operation_core(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        request=request,
        runtime=runtime,
    )


def _runtime_from_operation_args(
    *,
    debug_profiles: dict[str, DebugProfile] | None,
    admission: AdmissionService | None,
    transaction: TransportTransaction | None,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
    gdb_mi_engine: GdbMiEngine | None,
    gdb_mi_sessions: GdbMiSessionRegistry | None,
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


def _debug_operation_handler(
    *,
    request: DebugOperationRequest,
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
    operation_core: DebugOperationCore,
) -> ToolResponse:
    return debug_tool_operation_response(
        request=request,
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        runtime=_runtime_from_operation_args(
            debug_profiles=debug_profiles,
            admission=admission,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
        operation_core=operation_core,
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
    operation_core: DebugOperationCore = _default_debug_operation_core,
) -> ToolResponse:
    return _debug_operation_handler(
        request=DebugReadRegistersRequest(registers=registers),
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=None,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        operation_core=operation_core,
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
    operation_core: DebugOperationCore = _default_debug_operation_core,
) -> ToolResponse:
    return _debug_operation_handler(
        request=DebugReadSymbolRequest(symbol=symbol),
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=None,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        operation_core=operation_core,
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
    operation_core: DebugOperationCore = _default_debug_operation_core,
) -> ToolResponse:
    return _debug_operation_handler(
        request=DebugReadMemoryRequest(address=address, byte_count=byte_count),
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=None,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        operation_core=operation_core,
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
    operation_core: DebugOperationCore = _default_debug_operation_core,
) -> ToolResponse:
    return _debug_operation_handler(
        request=DebugEvaluateRequest(inspector=inspector, arguments=arguments or {}),
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=debug_session_id,
        debug_profiles=debug_profiles,
        admission=None,
        transaction=transaction,
        session_registry=session_registry,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        operation_core=operation_core,
    )


def _make_symbol_control_handler(
    name: str,
    request_factory: Callable[[str], DebugOperationRequest],
) -> Callable[..., ToolResponse]:
    def handler(
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
        operation_core: DebugOperationCore = _default_debug_operation_core,
    ) -> ToolResponse:
        return _debug_operation_handler(
            request=request_factory(symbol),
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
            operation_core=operation_core,
        )

    handler.__name__ = name
    return handler


def _make_breakpoint_id_control_handler(
    name: str,
    request_factory: Callable[[str], DebugOperationRequest],
) -> Callable[..., ToolResponse]:
    def handler(
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
        operation_core: DebugOperationCore = _default_debug_operation_core,
    ) -> ToolResponse:
        return _debug_operation_handler(
            request=request_factory(breakpoint_id),
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
            operation_core=operation_core,
        )

    handler.__name__ = name
    return handler


def _make_debug_session_query_handler(
    name: str,
    request_factory: Callable[[], DebugOperationRequest],
) -> Callable[..., ToolResponse]:
    def handler(
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
        operation_core: DebugOperationCore = _default_debug_operation_core,
    ) -> ToolResponse:
        return _debug_operation_handler(
            request=request_factory(),
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
            operation_core=operation_core,
        )

    handler.__name__ = name
    return handler


def _make_debug_execution_control_handler(
    name: str,
    request_factory: Callable[[int | None], DebugOperationRequest],
) -> Callable[..., ToolResponse]:
    def handler(
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
        operation_core: DebugOperationCore = _default_debug_operation_core,
    ) -> ToolResponse:
        return _debug_operation_handler(
            request=request_factory(timeout_seconds),
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
            operation_core=operation_core,
        )

    handler.__name__ = name
    return handler


debug_set_breakpoint_handler = _make_symbol_control_handler("debug_set_breakpoint_handler", DebugSetBreakpointRequest)
debug_set_watchpoint_handler = _make_symbol_control_handler("debug_set_watchpoint_handler", DebugSetWatchpointRequest)
debug_clear_breakpoint_handler = _make_breakpoint_id_control_handler(
    "debug_clear_breakpoint_handler", DebugClearBreakpointRequest
)
debug_clear_watchpoint_handler = _make_breakpoint_id_control_handler(
    "debug_clear_watchpoint_handler", DebugClearWatchpointRequest
)
debug_list_breakpoints_handler = _make_debug_session_query_handler(
    "debug_list_breakpoints_handler", DebugListBreakpointsRequest
)
debug_backtrace_handler = _make_debug_session_query_handler("debug_backtrace_handler", DebugBacktraceRequest)
debug_list_variables_handler = _make_debug_session_query_handler(
    "debug_list_variables_handler", DebugListVariablesRequest
)
debug_continue_handler = _make_debug_execution_control_handler("debug_continue_handler", DebugContinueRequest)
debug_step_handler = _make_debug_execution_control_handler("debug_step_handler", DebugStepRequest)
debug_next_handler = _make_debug_execution_control_handler("debug_next_handler", DebugNextRequest)
debug_finish_handler = _make_debug_execution_control_handler("debug_finish_handler", DebugFinishRequest)
debug_interrupt_handler = _make_debug_execution_control_handler("debug_interrupt_handler", DebugInterruptRequest)
