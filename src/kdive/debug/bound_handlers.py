from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from kdive.debug.handlers import (
    debug_backtrace_handler as _debug_backtrace_handler,
)
from kdive.debug.handlers import (
    debug_clear_breakpoint_handler as _debug_clear_breakpoint_handler,
)
from kdive.debug.handlers import (
    debug_clear_watchpoint_handler as _debug_clear_watchpoint_handler,
)
from kdive.debug.handlers import (
    debug_continue_handler as _debug_continue_handler,
)
from kdive.debug.handlers import (
    debug_evaluate_handler as _debug_evaluate_handler,
)
from kdive.debug.handlers import (
    debug_finish_handler as _debug_finish_handler,
)
from kdive.debug.handlers import (
    debug_interrupt_handler as _debug_interrupt_handler,
)
from kdive.debug.handlers import (
    debug_list_breakpoints_handler as _debug_list_breakpoints_handler,
)
from kdive.debug.handlers import (
    debug_list_variables_handler as _debug_list_variables_handler,
)
from kdive.debug.handlers import (
    debug_next_handler as _debug_next_handler,
)
from kdive.debug.handlers import (
    debug_read_memory_handler as _debug_read_memory_handler,
)
from kdive.debug.handlers import (
    debug_read_registers_handler as _debug_read_registers_handler,
)
from kdive.debug.handlers import (
    debug_read_symbol_handler as _debug_read_symbol_handler,
)
from kdive.debug.handlers import (
    debug_set_breakpoint_handler as _debug_set_breakpoint_handler,
)
from kdive.debug.handlers import (
    debug_set_watchpoint_handler as _debug_set_watchpoint_handler,
)
from kdive.debug.handlers import (
    debug_step_handler as _debug_step_handler,
)
from kdive.debug.module_symbols import (
    ModuleSymbolLoadOptions,
)
from kdive.debug.module_symbols import (
    debug_load_module_symbols_handler as _debug_load_module_symbols_handler,
)
from kdive.debug.operations import _debug_operation_response
from kdive.debug.session_end import debug_end_session_handler as _debug_end_session_handler
from kdive.debug.session_handlers import debug_start_session_handler as _debug_start_session_handler
from kdive.debug.tools import (
    DebugBreakpointIdRequest,
    DebugEvaluateRequest,
    DebugExecutionRequest,
    DebugLoadModuleSymbolsRequest,
    DebugMemoryRequest,
    DebugRegistersRequest,
    DebugRuntime,
    DebugSessionRequest,
    DebugStartSessionRequest,
    DebugSymbolRequest,
    DebugToolContext,
    DebugToolHandlers,
)
from kdive.domain import ToolResponse

_RequiredT = TypeVar("_RequiredT")
_LeafHandler = Callable[..., ToolResponse]


def _required(value: _RequiredT | None, name: str) -> _RequiredT:
    if value is None:
        raise TypeError(f"{name} is required")
    return value


def debug_start_session_handler(*, request: DebugStartSessionRequest, runtime: DebugToolContext) -> ToolResponse:
    return _debug_start_session_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_profile=request.debug_profile,
        new_session=request.new_session,
        admission=runtime.admission,
        transaction=runtime.transaction,
        session_registry=runtime.session_registry,
        session_guard=runtime.session_guard,
        gdb_mi_engine=runtime.gdb_mi_engine,
        gdb_mi_sessions=runtime.gdb_mi_sessions,
    )


def debug_read_registers_handler(
    *,
    request: DebugRegistersRequest | None = None,
    runtime: DebugRuntime,
    artifact_root: Path | None = None,
    run_id: str | None = None,
    registers: list[str] | None = None,
    debug_session_id: str | None = None,
) -> ToolResponse:
    request = request or DebugRegistersRequest(
        artifact_root=_required(artifact_root, "artifact_root"),
        run_id=_required(run_id, "run_id"),
        registers=_required(registers, "registers"),
        debug_session_id=debug_session_id,
    )
    return _debug_read_registers_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        registers=request.registers,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_debug_operation_response,
    )


def _make_symbol_bound_handler(name: str, leaf_handler: _LeafHandler) -> Callable[..., ToolResponse]:
    def handler(
        *,
        request: DebugSymbolRequest | None = None,
        runtime: DebugRuntime,
        artifact_root: Path | None = None,
        run_id: str | None = None,
        symbol: str | None = None,
        debug_session_id: str | None = None,
    ) -> ToolResponse:
        request = request or DebugSymbolRequest(
            artifact_root=_required(artifact_root, "artifact_root"),
            run_id=_required(run_id, "run_id"),
            symbol=_required(symbol, "symbol"),
            debug_session_id=debug_session_id,
        )
        return leaf_handler(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            symbol=request.symbol,
            debug_session_id=request.debug_session_id,
            runtime=runtime,
            operation_core=_debug_operation_response,
        )

    handler.__name__ = name
    return handler


def _make_breakpoint_id_bound_handler(name: str, leaf_handler: _LeafHandler) -> Callable[..., ToolResponse]:
    def handler(
        *,
        request: DebugBreakpointIdRequest | None = None,
        runtime: DebugRuntime,
        artifact_root: Path | None = None,
        run_id: str | None = None,
        breakpoint_id: str | None = None,
        debug_session_id: str | None = None,
    ) -> ToolResponse:
        request = request or DebugBreakpointIdRequest(
            artifact_root=_required(artifact_root, "artifact_root"),
            run_id=_required(run_id, "run_id"),
            breakpoint_id=_required(breakpoint_id, "breakpoint_id"),
            debug_session_id=debug_session_id,
        )
        return leaf_handler(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            breakpoint_id=request.breakpoint_id,
            debug_session_id=request.debug_session_id,
            runtime=runtime,
            operation_core=_debug_operation_response,
        )

    handler.__name__ = name
    return handler


def _make_session_query_bound_handler(name: str, leaf_handler: _LeafHandler) -> Callable[..., ToolResponse]:
    def handler(
        *,
        request: DebugSessionRequest | None = None,
        runtime: DebugRuntime,
        artifact_root: Path | None = None,
        run_id: str | None = None,
        debug_session_id: str | None = None,
    ) -> ToolResponse:
        request = request or DebugSessionRequest(
            artifact_root=_required(artifact_root, "artifact_root"),
            run_id=_required(run_id, "run_id"),
            debug_session_id=debug_session_id,
        )
        return leaf_handler(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            debug_session_id=request.debug_session_id,
            runtime=runtime,
            operation_core=_debug_operation_response,
        )

    handler.__name__ = name
    return handler


def _make_execution_control_bound_handler(name: str, leaf_handler: _LeafHandler) -> Callable[..., ToolResponse]:
    def handler(
        *,
        request: DebugExecutionRequest | None = None,
        runtime: DebugRuntime,
        artifact_root: Path | None = None,
        run_id: str | None = None,
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> ToolResponse:
        request = request or DebugExecutionRequest(
            artifact_root=_required(artifact_root, "artifact_root"),
            run_id=_required(run_id, "run_id"),
            debug_session_id=debug_session_id,
            timeout_seconds=timeout_seconds,
        )
        return leaf_handler(
            artifact_root=request.artifact_root,
            run_id=request.run_id,
            debug_session_id=request.debug_session_id,
            timeout_seconds=request.timeout_seconds,
            runtime=runtime,
            operation_core=_debug_operation_response,
        )

    handler.__name__ = name
    return handler


debug_read_symbol_handler = _make_symbol_bound_handler("debug_read_symbol_handler", _debug_read_symbol_handler)


def debug_read_memory_handler(
    *,
    request: DebugMemoryRequest | None = None,
    runtime: DebugRuntime,
    artifact_root: Path | None = None,
    run_id: str | None = None,
    address: int | None = None,
    byte_count: int | None = None,
    debug_session_id: str | None = None,
) -> ToolResponse:
    request = request or DebugMemoryRequest(
        artifact_root=_required(artifact_root, "artifact_root"),
        run_id=_required(run_id, "run_id"),
        address=_required(address, "address"),
        byte_count=_required(byte_count, "byte_count"),
        debug_session_id=debug_session_id,
    )
    return _debug_read_memory_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        address=request.address,
        byte_count=request.byte_count,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_debug_operation_response,
    )


def debug_evaluate_handler(
    *,
    request: DebugEvaluateRequest | None = None,
    runtime: DebugRuntime,
    artifact_root: Path | None = None,
    run_id: str | None = None,
    inspector: str | None = None,
    arguments: dict[str, object] | None = None,
    debug_session_id: str | None = None,
) -> ToolResponse:
    request = request or DebugEvaluateRequest(
        artifact_root=_required(artifact_root, "artifact_root"),
        run_id=_required(run_id, "run_id"),
        inspector=_required(inspector, "inspector"),
        arguments=arguments,
        debug_session_id=debug_session_id,
    )
    return _debug_evaluate_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        inspector=request.inspector,
        arguments=request.arguments,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_debug_operation_response,
    )


def debug_load_module_symbols_handler(
    *, request: DebugLoadModuleSymbolsRequest, runtime: DebugToolContext
) -> ToolResponse:
    return _debug_load_module_symbols_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        options=ModuleSymbolLoadOptions(
            module=request.module,
            sections=request.sections,
            ko_path=request.ko_path,
        ),
        debug_session_id=request.debug_session_id,
        runtime=DebugRuntime(
            admission=runtime.admission,
            transaction=runtime.transaction,
            session_registry=runtime.session_registry,
            session_guard=runtime.session_guard,
            gdb_mi_engine=runtime.gdb_mi_engine,
            gdb_mi_sessions=runtime.gdb_mi_sessions,
        ),
    )


debug_set_breakpoint_handler = _make_symbol_bound_handler("debug_set_breakpoint_handler", _debug_set_breakpoint_handler)
debug_set_watchpoint_handler = _make_symbol_bound_handler("debug_set_watchpoint_handler", _debug_set_watchpoint_handler)
debug_clear_breakpoint_handler = _make_breakpoint_id_bound_handler(
    "debug_clear_breakpoint_handler", _debug_clear_breakpoint_handler
)
debug_clear_watchpoint_handler = _make_breakpoint_id_bound_handler(
    "debug_clear_watchpoint_handler", _debug_clear_watchpoint_handler
)
debug_list_breakpoints_handler = _make_session_query_bound_handler(
    "debug_list_breakpoints_handler", _debug_list_breakpoints_handler
)
debug_backtrace_handler = _make_session_query_bound_handler("debug_backtrace_handler", _debug_backtrace_handler)
debug_list_variables_handler = _make_session_query_bound_handler(
    "debug_list_variables_handler", _debug_list_variables_handler
)
debug_continue_handler = _make_execution_control_bound_handler("debug_continue_handler", _debug_continue_handler)
debug_step_handler = _make_execution_control_bound_handler("debug_step_handler", _debug_step_handler)
debug_next_handler = _make_execution_control_bound_handler("debug_next_handler", _debug_next_handler)
debug_finish_handler = _make_execution_control_bound_handler("debug_finish_handler", _debug_finish_handler)
debug_interrupt_handler = _make_execution_control_bound_handler("debug_interrupt_handler", _debug_interrupt_handler)


def debug_end_session_handler(*, request: DebugSessionRequest, runtime: DebugToolContext) -> ToolResponse:
    return _debug_end_session_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_session_id=request.debug_session_id,
        admission=runtime.admission,
        transaction=runtime.transaction,
        session_registry=runtime.session_registry,
        session_guard=runtime.session_guard,
        gdb_mi_engine=runtime.gdb_mi_engine,
        gdb_mi_sessions=runtime.gdb_mi_sessions,
    )


def debug_tool_handlers() -> DebugToolHandlers:
    return DebugToolHandlers(
        start_session=debug_start_session_handler,
        read_registers=debug_read_registers_handler,
        read_symbol=debug_read_symbol_handler,
        read_memory=debug_read_memory_handler,
        evaluate=debug_evaluate_handler,
        load_module_symbols=debug_load_module_symbols_handler,
        set_breakpoint=debug_set_breakpoint_handler,
        set_watchpoint=debug_set_watchpoint_handler,
        clear_breakpoint=debug_clear_breakpoint_handler,
        clear_watchpoint=debug_clear_watchpoint_handler,
        list_breakpoints=debug_list_breakpoints_handler,
        backtrace=debug_backtrace_handler,
        list_variables=debug_list_variables_handler,
        continue_execution=debug_continue_handler,
        step=debug_step_handler,
        next=debug_next_handler,
        finish=debug_finish_handler,
        interrupt=debug_interrupt_handler,
        end_session=debug_end_session_handler,
    )
