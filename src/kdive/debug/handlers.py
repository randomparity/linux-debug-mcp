from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol, cast

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


def _pop_required(kwargs: dict[str, object], name: str) -> object:
    try:
        return kwargs.pop(name)
    except KeyError as exc:
        raise TypeError(f"{name} is required") from exc


def _operation_handler_signature(
    request_parameters: tuple[tuple[str, object, object], ...],
) -> inspect.Signature:
    common_parameters: tuple[tuple[str, object, object], ...] = (
        ("artifact_root", "Path", inspect.Parameter.empty),
        ("run_id", "str", inspect.Parameter.empty),
        *request_parameters,
        ("runtime", "DebugRuntime", inspect.Parameter.empty),
        ("debug_session_id", "str | None", None),
        ("operation_core", "DebugOperationCore", inspect.Parameter.empty),
    )
    return inspect.Signature(
        parameters=[
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotation,
            )
            for name, annotation, default in common_parameters
        ],
        return_annotation="ToolResponse",
    )


def _make_operation_request_handler(
    name: str,
    request_factory: Callable[[dict[str, object]], DebugOperationRequest],
    request_parameters: tuple[tuple[str, object, object], ...],
) -> Callable[..., ToolResponse]:
    def handler(**kwargs: object) -> ToolResponse:
        artifact_root = _pop_required(kwargs, "artifact_root")
        run_id = _pop_required(kwargs, "run_id")
        runtime = _pop_required(kwargs, "runtime")
        operation_core = _pop_required(kwargs, "operation_core")
        debug_session_id = kwargs.pop("debug_session_id", None)
        request = request_factory(kwargs)
        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError(f"unexpected argument: {unexpected}")
        if not isinstance(artifact_root, Path):
            raise TypeError("artifact_root must be a Path")
        if not isinstance(run_id, str):
            raise TypeError("run_id must be a string")
        if not isinstance(runtime, DebugRuntime):
            raise TypeError("runtime must be DebugRuntime")
        if not callable(operation_core):
            raise TypeError("operation_core must be callable")
        if debug_session_id is not None and not isinstance(debug_session_id, str):
            raise TypeError("debug_session_id must be a string or None")
        return cast(DebugOperationCore, operation_core)(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            request=request,
            runtime=runtime,
        )

    handler.__name__ = name
    cast(Any, handler).__signature__ = _operation_handler_signature(request_parameters)
    return handler


def _read_registers_request(kwargs: dict[str, object]) -> DebugOperationRequest:
    registers = _pop_required(kwargs, "registers")
    if not isinstance(registers, list) or not all(isinstance(register, str) for register in registers):
        raise TypeError("registers must be a list of strings")
    return DebugReadRegistersRequest(registers=cast(list[str], registers))


def _read_symbol_request(kwargs: dict[str, object]) -> DebugOperationRequest:
    symbol = _pop_required(kwargs, "symbol")
    if not isinstance(symbol, str):
        raise TypeError("symbol must be a string")
    return DebugReadSymbolRequest(symbol=symbol)


def _read_memory_request(kwargs: dict[str, object]) -> DebugOperationRequest:
    address = _pop_required(kwargs, "address")
    byte_count = _pop_required(kwargs, "byte_count")
    if not isinstance(address, int):
        raise TypeError("address must be an integer")
    if not isinstance(byte_count, int):
        raise TypeError("byte_count must be an integer")
    return DebugReadMemoryRequest(address=address, byte_count=byte_count)


def _evaluate_request(kwargs: dict[str, object]) -> DebugOperationRequest:
    inspector = _pop_required(kwargs, "inspector")
    arguments = kwargs.pop("arguments", None)
    if not isinstance(inspector, str):
        raise TypeError("inspector must be a string")
    if arguments is not None and (
        not isinstance(arguments, dict) or not all(isinstance(key, str) for key in arguments)
    ):
        raise TypeError("arguments must be a dict with string keys or None")
    return DebugEvaluateRequest(inspector=inspector, arguments=cast(dict[str, object], arguments or {}))


debug_read_registers_handler = _make_operation_request_handler(
    "debug_read_registers_handler",
    _read_registers_request,
    (("registers", "list[str]", inspect.Parameter.empty),),
)
debug_read_symbol_handler = _make_operation_request_handler(
    "debug_read_symbol_handler",
    _read_symbol_request,
    (("symbol", "str", inspect.Parameter.empty),),
)
debug_read_memory_handler = _make_operation_request_handler(
    "debug_read_memory_handler",
    _read_memory_request,
    (
        ("address", "int", inspect.Parameter.empty),
        ("byte_count", "int", inspect.Parameter.empty),
    ),
)
debug_evaluate_handler = _make_operation_request_handler(
    "debug_evaluate_handler",
    _evaluate_request,
    (
        ("inspector", "str", inspect.Parameter.empty),
        ("arguments", "dict[str, object] | None", None),
    ),
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
        runtime: DebugRuntime,
        debug_session_id: str | None = None,
        operation_core: DebugOperationCore,
    ) -> ToolResponse:
        return operation_core(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            request=request_factory(symbol),
            runtime=runtime,
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
        runtime: DebugRuntime,
        debug_session_id: str | None = None,
        operation_core: DebugOperationCore,
    ) -> ToolResponse:
        return operation_core(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            request=request_factory(breakpoint_id),
            runtime=runtime,
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
        runtime: DebugRuntime,
        debug_session_id: str | None = None,
        operation_core: DebugOperationCore,
    ) -> ToolResponse:
        return operation_core(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            request=request_factory(),
            runtime=runtime,
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
        runtime: DebugRuntime,
        timeout_seconds: int | None = None,
        debug_session_id: str | None = None,
        operation_core: DebugOperationCore,
    ) -> ToolResponse:
        return operation_core(
            artifact_root=artifact_root,
            run_id=run_id,
            debug_session_id=debug_session_id,
            request=request_factory(timeout_seconds),
            runtime=runtime,
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

_debug_read_registers_leaf_handler = debug_read_registers_handler
_debug_read_symbol_leaf_handler = debug_read_symbol_handler
_debug_read_memory_leaf_handler = debug_read_memory_handler
_debug_evaluate_leaf_handler = debug_evaluate_handler
_debug_set_breakpoint_leaf_handler = debug_set_breakpoint_handler
_debug_set_watchpoint_leaf_handler = debug_set_watchpoint_handler
_debug_clear_breakpoint_leaf_handler = debug_clear_breakpoint_handler
_debug_clear_watchpoint_leaf_handler = debug_clear_watchpoint_handler
_debug_list_breakpoints_leaf_handler = debug_list_breakpoints_handler
_debug_backtrace_leaf_handler = debug_backtrace_handler
_debug_list_variables_leaf_handler = debug_list_variables_handler
_debug_continue_leaf_handler = debug_continue_handler
_debug_step_leaf_handler = debug_step_handler
_debug_next_leaf_handler = debug_next_handler
_debug_finish_leaf_handler = debug_finish_handler
_debug_interrupt_leaf_handler = debug_interrupt_handler


def _operation_core() -> DebugOperationCore:
    from kdive.debug.operations import _debug_operation_response

    return _debug_operation_response


def debug_read_registers_handler(*, request: DebugToolRegistersRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_read_registers_leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        registers=request.registers,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def debug_read_symbol_handler(*, request: DebugToolSymbolRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_read_symbol_leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        symbol=request.symbol,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def debug_read_memory_handler(*, request: DebugToolMemoryRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_read_memory_leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        address=request.address,
        byte_count=request.byte_count,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def debug_evaluate_handler(*, request: DebugToolEvaluateRequest, runtime: DebugRuntime) -> ToolResponse:
    return _debug_evaluate_leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        inspector=request.inspector,
        arguments=request.arguments,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def _symbol_control_handler(
    leaf_handler: Callable[..., ToolResponse], *, request: DebugToolSymbolRequest, runtime: DebugRuntime
) -> ToolResponse:
    return leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        symbol=request.symbol,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def _breakpoint_id_control_handler(
    leaf_handler: Callable[..., ToolResponse], *, request: DebugToolBreakpointIdRequest, runtime: DebugRuntime
) -> ToolResponse:
    return leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        breakpoint_id=request.breakpoint_id,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def _session_query_handler(
    leaf_handler: Callable[..., ToolResponse], *, request: DebugToolSessionRequest, runtime: DebugRuntime
) -> ToolResponse:
    return leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_session_id=request.debug_session_id,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def _execution_control_handler(
    leaf_handler: Callable[..., ToolResponse], *, request: DebugToolExecutionRequest, runtime: DebugRuntime
) -> ToolResponse:
    return leaf_handler(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_session_id=request.debug_session_id,
        timeout_seconds=request.timeout_seconds,
        runtime=runtime,
        operation_core=_operation_core(),
    )


def debug_set_breakpoint_handler(*, request: DebugToolSymbolRequest, runtime: DebugRuntime) -> ToolResponse:
    return _symbol_control_handler(_debug_set_breakpoint_leaf_handler, request=request, runtime=runtime)


def debug_set_watchpoint_handler(*, request: DebugToolSymbolRequest, runtime: DebugRuntime) -> ToolResponse:
    return _symbol_control_handler(_debug_set_watchpoint_leaf_handler, request=request, runtime=runtime)


def debug_clear_breakpoint_handler(*, request: DebugToolBreakpointIdRequest, runtime: DebugRuntime) -> ToolResponse:
    return _breakpoint_id_control_handler(_debug_clear_breakpoint_leaf_handler, request=request, runtime=runtime)


def debug_clear_watchpoint_handler(*, request: DebugToolBreakpointIdRequest, runtime: DebugRuntime) -> ToolResponse:
    return _breakpoint_id_control_handler(_debug_clear_watchpoint_leaf_handler, request=request, runtime=runtime)


def debug_list_breakpoints_handler(*, request: DebugToolSessionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _session_query_handler(_debug_list_breakpoints_leaf_handler, request=request, runtime=runtime)


def debug_backtrace_handler(*, request: DebugToolSessionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _session_query_handler(_debug_backtrace_leaf_handler, request=request, runtime=runtime)


def debug_list_variables_handler(*, request: DebugToolSessionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _session_query_handler(_debug_list_variables_leaf_handler, request=request, runtime=runtime)


def debug_continue_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _execution_control_handler(_debug_continue_leaf_handler, request=request, runtime=runtime)


def debug_step_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _execution_control_handler(_debug_step_leaf_handler, request=request, runtime=runtime)


def debug_next_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _execution_control_handler(_debug_next_leaf_handler, request=request, runtime=runtime)


def debug_finish_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _execution_control_handler(_debug_finish_leaf_handler, request=request, runtime=runtime)


def debug_interrupt_handler(*, request: DebugToolExecutionRequest, runtime: DebugRuntime) -> ToolResponse:
    return _execution_control_handler(_debug_interrupt_leaf_handler, request=request, runtime=runtime)
