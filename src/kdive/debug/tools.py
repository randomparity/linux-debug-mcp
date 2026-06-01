from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.handlers import DebugRuntime
from kdive.domain import Model, ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard
from kdive.tools.adapter_boundary import adapter_validation_failure, optional_model_arg


class DebugStartSessionHandler(Protocol):
    def __call__(self, *, request: DebugStartSessionRequest, runtime: DebugToolContext) -> ToolResponse: ...


class DebugReadRegistersHandler(Protocol):
    def __call__(self, *, request: DebugRegistersRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugReadSymbolHandler(Protocol):
    def __call__(self, *, request: DebugSymbolRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugReadMemoryHandler(Protocol):
    def __call__(self, *, request: DebugMemoryRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugEvaluateHandler(Protocol):
    def __call__(self, *, request: DebugEvaluateRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugLoadModuleSymbolsHandler(Protocol):
    def __call__(self, *, request: DebugLoadModuleSymbolsRequest, runtime: DebugToolContext) -> ToolResponse: ...


class DebugSymbolControlHandler(Protocol):
    def __call__(self, *, request: DebugSymbolRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugBreakpointIdControlHandler(Protocol):
    def __call__(self, *, request: DebugBreakpointIdRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugSessionQueryHandler(Protocol):
    def __call__(self, *, request: DebugSessionRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugExecutionControlHandler(Protocol):
    def __call__(self, *, request: DebugExecutionRequest, runtime: DebugRuntime) -> ToolResponse: ...


class DebugEndSessionHandler(Protocol):
    def __call__(self, *, request: DebugSessionRequest, runtime: DebugToolContext) -> ToolResponse: ...


@dataclass(frozen=True)
class DebugToolHandlers:
    start_session: DebugStartSessionHandler
    read_registers: DebugReadRegistersHandler
    read_symbol: DebugReadSymbolHandler
    read_memory: DebugReadMemoryHandler
    evaluate: DebugEvaluateHandler
    load_module_symbols: DebugLoadModuleSymbolsHandler
    set_breakpoint: DebugSymbolControlHandler
    set_watchpoint: DebugSymbolControlHandler
    clear_breakpoint: DebugBreakpointIdControlHandler
    clear_watchpoint: DebugBreakpointIdControlHandler
    list_breakpoints: DebugSessionQueryHandler
    backtrace: DebugSessionQueryHandler
    list_variables: DebugSessionQueryHandler
    continue_execution: DebugExecutionControlHandler
    step: DebugExecutionControlHandler
    next: DebugExecutionControlHandler
    finish: DebugExecutionControlHandler
    interrupt: DebugExecutionControlHandler
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


def _debug_runtime(context: DebugToolContext, *, include_admission: bool) -> DebugRuntime:
    return DebugRuntime(
        admission=(context.admission if include_admission else None),
        transaction=context.transaction,
        session_registry=context.session_registry,
        session_guard=context.session_guard,
        gdb_mi_engine=context.gdb_mi_engine,
        gdb_mi_sessions=context.gdb_mi_sessions,
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
    handler: DebugReadRegistersHandler,
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
            handler(
                request=DebugRegistersRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    registers=registers,
                ),
                runtime=_debug_runtime(tool_context, include_admission=False),
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
    handler: DebugReadSymbolHandler,
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
            handler(
                request=DebugSymbolRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    symbol=symbol,
                ),
                runtime=_debug_runtime(tool_context, include_admission=False),
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
        handler=handlers.read_registers,
    )
    _register_symbol_query(
        app,
        tool_context=tool_context,
        default_artifact_root=default_artifact_root,
        tool_name="debug.read_symbol",
        handler=handlers.read_symbol,
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
            handlers.read_memory(
                request=DebugMemoryRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    address=address,
                    byte_count=byte_count,
                ),
                runtime=_debug_runtime(tool_context, include_admission=False),
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
            handlers.evaluate(
                request=DebugEvaluateRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    inspector=inspector,
                    arguments=evaluate_options.arguments,
                ),
                runtime=_debug_runtime(tool_context, include_admission=False),
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
    handler: DebugSymbolControlHandler,
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
            handler(
                request=DebugSymbolRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    symbol=symbol,
                ),
                runtime=_debug_runtime(tool_context, include_admission=True),
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
    handler: DebugBreakpointIdControlHandler,
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
            handler(
                request=DebugBreakpointIdRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    breakpoint_id=breakpoint_id,
                ),
                runtime=_debug_runtime(tool_context, include_admission=True),
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
    handler: DebugSessionQueryHandler,
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
            handler(
                request=DebugSessionRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                ),
                runtime=_debug_runtime(tool_context, include_admission=True),
            )
        )

    debug_session_query.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_session_query)


def _register_debug_breakpoint_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    for tool_name, handler in (
        ("debug.set_breakpoint", handlers.set_breakpoint),
        ("debug.set_watchpoint", handlers.set_watchpoint),
    ):
        _register_symbol_control(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            handler=handler,
        )

    for tool_name, handler in (
        ("debug.clear_breakpoint", handlers.clear_breakpoint),
        ("debug.clear_watchpoint", handlers.clear_watchpoint),
    ):
        _register_breakpoint_id_control(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            handler=handler,
        )

    for tool_name, handler in (
        ("debug.list_breakpoints", handlers.list_breakpoints),
        ("debug.backtrace", handlers.backtrace),
        ("debug.list_variables", handlers.list_variables),
    ):
        _register_gated_query(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            handler=handler,
        )


def _register_execution_control(
    app: FastMCP,
    *,
    tool_context: DebugToolContext,
    default_artifact_root: str,
    tool_name: str,
    handler: DebugExecutionControlHandler,
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
            handler(
                request=DebugExecutionRequest(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    timeout_seconds=execution_options.timeout_seconds,
                ),
                runtime=_debug_runtime(tool_context, include_admission=True),
            )
        )

    debug_execution_control.__name__ = _tool_function_name(tool_name)
    app.tool(name=tool_name)(debug_execution_control)


def _register_debug_execution_tools(
    app: FastMCP, *, tool_context: DebugToolContext, default_artifact_root: str, handlers: DebugToolHandlers
) -> None:
    for tool_name, handler in (
        ("debug.continue", handlers.continue_execution),
        ("debug.step", handlers.step),
        ("debug.next", handlers.next),
        ("debug.finish", handlers.finish),
        ("debug.interrupt", handlers.interrupt),
    ):
        _register_execution_control(
            app,
            tool_context=tool_context,
            default_artifact_root=default_artifact_root,
            tool_name=tool_name,
            handler=handler,
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
