from __future__ import annotations

from pathlib import Path
from typing import Protocol

from kdive.debug.contracts import (
    DebugBacktraceRequest,
    DebugClearBreakpointRequest,
    DebugClearWatchpointRequest,
    DebugContinueRequest,
    DebugEvaluateRequest,
    DebugFinishRequest,
    DebugInterruptRequest,
    DebugListBreakpointsRequest,
    DebugListVariablesRequest,
    DebugNextRequest,
    DebugOperationRequest,
    DebugReadMemoryRequest,
    DebugReadRegistersRequest,
    DebugReadSymbolRequest,
    DebugRuntime,
    DebugSetBreakpointRequest,
    DebugSetWatchpointRequest,
    DebugStepRequest,
)
from kdive.debug.operations import _debug_operation_response
from kdive.domain import ToolResponse


class DebugToolSessionRequest(Protocol):
    artifact_root: Path
    run_id: str
    debug_session_id: str | None


class DebugToolRegistersRequest(DebugToolSessionRequest, Protocol):
    registers: list[str]


class DebugToolSymbolRequest(DebugToolSessionRequest, Protocol):
    symbol: str


class DebugToolMemoryRequest(DebugToolSessionRequest, Protocol):
    address: int
    byte_count: int


class DebugToolEvaluateRequest(DebugToolSessionRequest, Protocol):
    inspector: str
    arguments: dict[str, object] | None


class DebugToolBreakpointIdRequest(DebugToolSessionRequest, Protocol):
    breakpoint_id: str


class DebugToolExecutionRequest(DebugToolSessionRequest, Protocol):
    timeout_seconds: int | None


def _debug_response(
    *, request: DebugToolSessionRequest, operation_request: DebugOperationRequest, runtime: DebugRuntime
) -> ToolResponse:
    return _debug_operation_response(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_session_id=request.debug_session_id,
        request=operation_request,
        runtime=runtime,
    )


def debug_read_registers_handler(*, request: DebugToolRegistersRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugReadRegistersRequest(registers=request.registers),
        runtime=runtime,
    )


def debug_read_symbol_handler(*, request: DebugToolSymbolRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugReadSymbolRequest(symbol=request.symbol),
        runtime=runtime,
    )


def debug_read_memory_handler(*, request: DebugToolMemoryRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugReadMemoryRequest(address=request.address, byte_count=request.byte_count),
        runtime=runtime,
    )


def debug_evaluate_handler(*, request: DebugToolEvaluateRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugEvaluateRequest(inspector=request.inspector, arguments=request.arguments or {}),
        runtime=runtime,
    )


def debug_set_breakpoint_handler(*, request: DebugToolSymbolRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugSetBreakpointRequest(symbol=request.symbol),
        runtime=runtime,
    )


def debug_set_watchpoint_handler(*, request: DebugToolSymbolRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugSetWatchpointRequest(symbol=request.symbol),
        runtime=runtime,
    )


def debug_clear_breakpoint_handler(*, request: DebugToolBreakpointIdRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugClearBreakpointRequest(breakpoint_id=request.breakpoint_id),
        runtime=runtime,
    )


def debug_clear_watchpoint_handler(*, request: DebugToolBreakpointIdRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugClearWatchpointRequest(breakpoint_id=request.breakpoint_id),
        runtime=runtime,
    )


def debug_list_breakpoints_handler(*, request: DebugToolSessionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(request=request, operation_request=DebugListBreakpointsRequest(), runtime=runtime)


def debug_backtrace_handler(*, request: DebugToolSessionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(request=request, operation_request=DebugBacktraceRequest(), runtime=runtime)


def debug_list_variables_handler(*, request: DebugToolSessionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(request=request, operation_request=DebugListVariablesRequest(), runtime=runtime)


def debug_continue_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugContinueRequest(timeout_seconds=request.timeout_seconds),
        runtime=runtime,
    )


def debug_step_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugStepRequest(timeout_seconds=request.timeout_seconds),
        runtime=runtime,
    )


def debug_next_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugNextRequest(timeout_seconds=request.timeout_seconds),
        runtime=runtime,
    )


def debug_finish_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugFinishRequest(timeout_seconds=request.timeout_seconds),
        runtime=runtime,
    )


def debug_interrupt_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_response(
        request=request,
        operation_request=DebugInterruptRequest(timeout_seconds=request.timeout_seconds),
        runtime=runtime,
    )
