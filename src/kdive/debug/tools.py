from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.contracts import (
    DebugBacktraceRequest as DebugBacktraceOperationRequest,
)
from kdive.debug.contracts import (
    DebugClearBreakpointRequest as DebugClearBreakpointOperationRequest,
)
from kdive.debug.contracts import (
    DebugClearWatchpointRequest as DebugClearWatchpointOperationRequest,
)
from kdive.debug.contracts import (
    DebugContinueRequest as DebugContinueOperationRequest,
)
from kdive.debug.contracts import (
    DebugEvaluateRequest as DebugEvaluateOperationRequest,
)
from kdive.debug.contracts import (
    DebugFinishRequest as DebugFinishOperationRequest,
)
from kdive.debug.contracts import (
    DebugInterruptRequest as DebugInterruptOperationRequest,
)
from kdive.debug.contracts import (
    DebugListBreakpointsRequest as DebugListBreakpointsOperationRequest,
)
from kdive.debug.contracts import (
    DebugListVariablesRequest as DebugListVariablesOperationRequest,
)
from kdive.debug.contracts import (
    DebugNextRequest as DebugNextOperationRequest,
)
from kdive.debug.contracts import (
    DebugOperationCore,
    DebugOperationRequest,
    DebugRuntime,
)
from kdive.debug.contracts import (
    DebugReadMemoryRequest as DebugReadMemoryOperationRequest,
)
from kdive.debug.contracts import (
    DebugReadRegistersRequest as DebugReadRegistersOperationRequest,
)
from kdive.debug.contracts import (
    DebugReadSymbolRequest as DebugReadSymbolOperationRequest,
)
from kdive.debug.contracts import (
    DebugSetBreakpointRequest as DebugSetBreakpointOperationRequest,
)
from kdive.debug.contracts import (
    DebugSetWatchpointRequest as DebugSetWatchpointOperationRequest,
)
from kdive.debug.contracts import (
    DebugStepRequest as DebugStepOperationRequest,
)
from kdive.domain import Model, ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard
from kdive.tools.adapter_boundary import adapter_validation_failure, optional_model_arg


class DebugStartSessionHandler(Protocol):
    def __call__(self, *, request: DebugStartSessionRequest, runtime: DebugToolContext) -> ToolResponse: ...


class DebugLoadModuleSymbolsHandler(Protocol):
    def __call__(self, *, request: DebugLoadModuleSymbolsRequest, runtime: DebugToolContext) -> ToolResponse: ...


class DebugEndSessionHandler(Protocol):
    def __call__(self, *, request: DebugSessionRequest, runtime: DebugToolContext) -> ToolResponse: ...


class _DebugOperationToolRequest(Protocol):
    artifact_root: Path
    run_id: str
    debug_session_id: str | None


@dataclass(frozen=True)
class DebugToolHandlers:
    start_session: DebugStartSessionHandler
    load_module_symbols: DebugLoadModuleSymbolsHandler
    operation: DebugOperationCore
    end_session: DebugEndSessionHandler


@dataclass(frozen=True)
class DebugToolContext:
    default_artifact_root: Path
    transaction: TransportTransaction
    admission: AdmissionService
    session_registry: SessionRegistry
    session_guard: SessionGuard
    gdb_mi_engine: GdbMiEngine
    gdb_mi_sessions: GdbMiSessionRegistry


@dataclass(frozen=True)
class DebugSessionRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None


@dataclass(frozen=True)
class DebugStartSessionRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    debug_profile: str | None
    new_session: bool


@dataclass(frozen=True)
class DebugRegistersRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    registers: list[str]


@dataclass(frozen=True)
class DebugSymbolRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    symbol: str


@dataclass(frozen=True)
class DebugMemoryRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    address: int
    byte_count: int


@dataclass(frozen=True)
class DebugEvaluateRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    inspector: str
    arguments: dict[str, object] | None


@dataclass(frozen=True)
class DebugLoadModuleSymbolsRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    module: str
    sections: dict[str, str] | None
    ko_path: str | None


@dataclass(frozen=True)
class DebugBreakpointIdRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    breakpoint_id: str


@dataclass(frozen=True)
class DebugExecutionRequest:
    artifact_root: Path
    run_id: str
    debug_session_id: str | None
    timeout_seconds: int | None


class DebugSessionContext(Model):
    run_id: str
    artifact_root: str | None = None
    debug_session_id: str | None = None


class DebugStartSessionOptions(Model):
    debug_profile: str | None = None
    new_session: bool = False


class DebugEvaluateOptions(Model):
    arguments: dict[str, object] | None = None


class DebugLoadModuleSymbolsOptions(Model):
    sections: dict[str, str] | None = None
    ko_path: str | None = None


class DebugExecutionOptions(Model):
    timeout_seconds: int | None = None


def _path(value: str) -> Path:
    return Path(value)


def _dump(response: ToolResponse) -> dict[str, Any]:
    return response.model_dump(mode="json")


def _session_context(
    value: DebugSessionContext | dict[str, Any] | None,
    *,
    default_artifact_root: str,
) -> tuple[Path, str, str | None]:
    context = optional_model_arg(value, DebugSessionContext)
    artifact_root = default_artifact_root if context.artifact_root is None else context.artifact_root
    return _path(artifact_root), context.run_id, context.debug_session_id


def _debug_runtime(context: DebugToolContext) -> DebugRuntime:
    return DebugRuntime(
        admission=context.admission,
        transaction=context.transaction,
        session_registry=context.session_registry,
        session_guard=context.session_guard,
        gdb_mi_engine=context.gdb_mi_engine,
        gdb_mi_sessions=context.gdb_mi_sessions,
    )


def _run_debug_operation(
    *,
    operation: DebugOperationCore,
    request: _DebugOperationToolRequest,
    operation_request: DebugOperationRequest,
    runtime: DebugRuntime,
) -> ToolResponse:
    return operation(
        artifact_root=request.artifact_root,
        run_id=request.run_id,
        debug_session_id=request.debug_session_id,
        request=operation_request,
        runtime=runtime,
    )


def _tool_function_name(tool_name: str) -> str:
    return tool_name.replace(".", "_")


def _register_debug_session_lifecycle_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    @app.tool(name="debug.start_session")
    def debug_start_session(
        context: DebugSessionContext | dict[str, Any],
        options: DebugStartSessionOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, _debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
            start_options = optional_model_arg(options, DebugStartSessionOptions)
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            handlers.start_session(
                request=DebugStartSessionRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=None,
                    debug_profile=start_options.debug_profile,
                    new_session=start_options.new_session,
                ),
                runtime=tool_context,
            )
        )

    @app.tool(name="debug.end_session")
    def debug_end_session(
        context: DebugSessionContext | dict[str, Any],
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            handlers.end_session(
                request=DebugSessionRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                ),
                runtime=tool_context,
            )
        )


def _register_registers_query(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    operation: DebugOperationCore,
) -> None:
    def debug_registers_query(
        context: DebugSessionContext | dict[str, Any],
        registers: list[str],
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=operation,
                request=DebugRegistersRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    registers=registers,
                ),
                operation_request=DebugReadRegistersOperationRequest(registers=registers),
                runtime=_debug_runtime(tool_context),
            )
        )

    debug_registers_query.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_registers_query)


def _register_symbol_query(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    operation: DebugOperationCore,
) -> None:
    def debug_symbol_query(
        context: DebugSessionContext | dict[str, Any],
        symbol: str,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=operation,
                request=DebugSymbolRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    symbol=symbol,
                ),
                operation_request=DebugReadSymbolOperationRequest(symbol=symbol),
                runtime=_debug_runtime(tool_context),
            )
        )

    debug_symbol_query.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_symbol_query)


def _register_debug_read_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    _register_registers_query(
        app,
        tool_context=tool_context,
        default_artifact_root=default_artifact_root,
        tool_name="debug.read_registers",
        operation=handlers.operation,
    )
    _register_symbol_query(
        app,
        tool_context=tool_context,
        default_artifact_root=default_artifact_root,
        tool_name="debug.read_symbol",
        operation=handlers.operation,
    )

    @app.tool(name="debug.read_memory")
    def debug_read_memory(
        context: DebugSessionContext | dict[str, Any],
        address: int,
        byte_count: int,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=handlers.operation,
                request=DebugMemoryRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    address=address,
                    byte_count=byte_count,
                ),
                operation_request=DebugReadMemoryOperationRequest(address=address, byte_count=byte_count),
                runtime=_debug_runtime(tool_context),
            )
        )

    @app.tool(name="debug.evaluate")
    def debug_evaluate(
        context: DebugSessionContext | dict[str, Any],
        inspector: str,
        options: DebugEvaluateOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
            evaluate_options = optional_model_arg(options, DebugEvaluateOptions)
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=handlers.operation,
                request=DebugEvaluateRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    inspector=inspector,
                    arguments=evaluate_options.arguments,
                ),
                operation_request=DebugEvaluateOperationRequest(
                    inspector=inspector,
                    arguments=evaluate_options.arguments or {},
                ),
                runtime=_debug_runtime(tool_context),
            )
        )


def _register_debug_module_symbol_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    @app.tool(name="debug.load_module_symbols")
    def debug_load_module_symbols(
        context: DebugSessionContext | dict[str, Any],
        module: str,
        options: DebugLoadModuleSymbolsOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
            load_options = optional_model_arg(options, DebugLoadModuleSymbolsOptions)
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            handlers.load_module_symbols(
                request=DebugLoadModuleSymbolsRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    module=module,
                    sections=load_options.sections,
                    ko_path=load_options.ko_path,
                ),
                runtime=tool_context,
            )
        )


def _register_symbol_control(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    operation: DebugOperationCore,
    request_factory: Callable[[str], DebugOperationRequest],
) -> None:
    def debug_symbol_control(
        context: DebugSessionContext | dict[str, Any],
        symbol: str,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=operation,
                request=DebugSymbolRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    symbol=symbol,
                ),
                operation_request=request_factory(symbol),
                runtime=_debug_runtime(tool_context),
            )
        )

    debug_symbol_control.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_symbol_control)


def _register_breakpoint_id_control(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    operation: DebugOperationCore,
    request_factory: Callable[[str], DebugOperationRequest],
) -> None:
    def debug_breakpoint_id_control(
        context: DebugSessionContext | dict[str, Any],
        breakpoint_id: str,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=operation,
                request=DebugBreakpointIdRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    breakpoint_id=breakpoint_id,
                ),
                operation_request=request_factory(breakpoint_id),
                runtime=_debug_runtime(tool_context),
            )
        )

    debug_breakpoint_id_control.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_breakpoint_id_control)


def _register_gated_query(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    operation: DebugOperationCore,
    operation_request: DebugOperationRequest,
) -> None:
    def debug_session_query(
        context: DebugSessionContext | dict[str, Any],
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=operation,
                request=DebugSessionRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                ),
                operation_request=operation_request,
                runtime=_debug_runtime(tool_context),
            )
        )

    debug_session_query.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_session_query)


def _register_debug_breakpoint_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    for tool_name, request_factory in (
        ("debug.set_breakpoint", DebugSetBreakpointOperationRequest),
        ("debug.set_watchpoint", DebugSetWatchpointOperationRequest),
    ):
        _register_symbol_control(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            operation=handlers.operation,
            request_factory=request_factory,
        )

    for tool_name, request_factory in (
        ("debug.clear_breakpoint", DebugClearBreakpointOperationRequest),
        ("debug.clear_watchpoint", DebugClearWatchpointOperationRequest),
    ):
        _register_breakpoint_id_control(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            operation=handlers.operation,
            request_factory=request_factory,
        )

    for tool_name, operation_request in (
        ("debug.list_breakpoints", DebugListBreakpointsOperationRequest()),
        ("debug.backtrace", DebugBacktraceOperationRequest()),
        ("debug.list_variables", DebugListVariablesOperationRequest()),
    ):
        _register_gated_query(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            operation=handlers.operation,
            operation_request=operation_request,
        )


def _register_execution_control(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    operation: DebugOperationCore,
    request_factory: Callable[[int | None], DebugOperationRequest],
) -> None:
    def debug_execution_control(
        context: DebugSessionContext | dict[str, Any],
        options: DebugExecutionOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            artifact_root, run_id, debug_session_id = _session_context(
                context,
                default_artifact_root=default_artifact_root,
            )
            execution_options = optional_model_arg(options, DebugExecutionOptions)
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _dump(
            _run_debug_operation(
                operation=operation,
                request=DebugExecutionRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    timeout_seconds=execution_options.timeout_seconds,
                ),
                operation_request=request_factory(execution_options.timeout_seconds),
                runtime=_debug_runtime(tool_context),
            )
        )

    debug_execution_control.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_execution_control)


def _register_debug_execution_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    for tool_name, request_factory in (
        ("debug.continue", DebugContinueOperationRequest),
        ("debug.step", DebugStepOperationRequest),
        ("debug.next", DebugNextOperationRequest),
        ("debug.finish", DebugFinishOperationRequest),
        ("debug.interrupt", DebugInterruptOperationRequest),
    ):
        _register_execution_control(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            operation=handlers.operation,
            request_factory=request_factory,
        )


def register_debug_tools(app: FastMCP, *, context: DebugToolContext, handlers: DebugToolHandlers) -> None:
    default_artifact_root = str(context.default_artifact_root)
    _register_debug_session_lifecycle_tools(
        app, tool_context=context, default_artifact_root=default_artifact_root, handlers=handlers
    )
    _register_debug_read_tools(
        app, tool_context=context, default_artifact_root=default_artifact_root, handlers=handlers
    )
    _register_debug_module_symbol_tools(
        app, tool_context=context, default_artifact_root=default_artifact_root, handlers=handlers
    )
    _register_debug_breakpoint_tools(
        app, tool_context=context, default_artifact_root=default_artifact_root, handlers=handlers
    )
    _register_debug_execution_tools(
        app, tool_context=context, default_artifact_root=default_artifact_root, handlers=handlers
    )
