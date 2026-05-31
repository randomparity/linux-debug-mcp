from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import Model, ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard


class DebugStartSessionHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_profile: str | None,
        new_session: bool,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugReadRegistersHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        registers: list[str],
        debug_session_id: str | None,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugReadSymbolHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        symbol: str,
        debug_session_id: str | None,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugReadMemoryHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        address: int,
        byte_count: int,
        debug_session_id: str | None,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugEvaluateHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        inspector: str,
        arguments: dict[str, object] | None,
        debug_session_id: str | None,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugLoadModuleSymbolsHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        module: str,
        sections: dict[str, str] | None,
        ko_path: str | None,
        debug_session_id: str | None,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugSymbolControlHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        symbol: str,
        debug_session_id: str | None,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugBreakpointIdControlHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        breakpoint_id: str,
        debug_session_id: str | None,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugSessionQueryHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_session_id: str | None,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugExecutionControlHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_session_id: str | None,
        timeout_seconds: int | None,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


class DebugEndSessionHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_session_id: str | None,
        admission: AdmissionService,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
        session_guard: SessionGuard,
        gdb_mi_engine: GdbMiEngine,
        gdb_mi_sessions: GdbMiSessionRegistry,
    ) -> ToolResponse: ...


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


class DebugSessionContext(Model):
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


def _model(value: Model | dict[str, Any] | None, model_type: type[Model]) -> Model:
    if value is None:
        return model_type()
    return value if isinstance(value, model_type) else model_type.model_validate(value)


def _session_context(
    value: DebugSessionContext | dict[str, Any] | None,
    *,
    default_artifact_root: str,
) -> tuple[Path, str | None]:
    context = _model(value, DebugSessionContext)
    assert isinstance(context, DebugSessionContext)
    artifact_root = default_artifact_root if context.artifact_root is None else context.artifact_root
    return _path(artifact_root), context.debug_session_id


def _debug_runtime_kwargs(context: DebugToolContext) -> dict[str, Any]:
    return {
        "transaction": context.transaction,
        "session_registry": context.session_registry,
        "session_guard": context.session_guard,
        "gdb_mi_engine": context.gdb_mi_engine,
        "gdb_mi_sessions": context.gdb_mi_sessions,
    }


def _gated_debug_runtime_kwargs(context: DebugToolContext) -> dict[str, Any]:
    return {"admission": context.admission, **_debug_runtime_kwargs(context)}


def _tool_function_name(tool_name: str) -> str:
    return tool_name.replace(".", "_")


def register_debug_tools(app: FastMCP, *, context: DebugToolContext, handlers: DebugToolHandlers) -> None:
    tool_context = context
    default_artifact_root = str(context.default_artifact_root)

    @app.tool(name="debug.start_session")
    def debug_start_session(
        run_id: str,
        context: DebugSessionContext | None = None,
        options: DebugStartSessionOptions | None = None,
    ) -> dict[str, Any]:
        artifact_root, _debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
        start_options = _model(options, DebugStartSessionOptions)
        assert isinstance(start_options, DebugStartSessionOptions)
        return _dump(
            handlers.start_session(
                artifact_root=artifact_root,
                run_id=run_id,
                debug_profile=start_options.debug_profile,
                new_session=start_options.new_session,
                admission=tool_context.admission,
                **_debug_runtime_kwargs(tool_context),
            )
        )

    def _register_registers_query(tool_name: str, handler: DebugReadRegistersHandler) -> None:
        def debug_registers_query(
            run_id: str,
            registers: list[str],
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                handler(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    registers=registers,
                    debug_session_id=debug_session_id,
                    **_debug_runtime_kwargs(tool_context),
                )
            )

        debug_registers_query.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_registers_query)

    def _register_symbol_query(tool_name: str, handler: DebugReadSymbolHandler) -> None:
        def debug_symbol_query(
            run_id: str,
            symbol: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                handler(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    symbol=symbol,
                    debug_session_id=debug_session_id,
                    **_debug_runtime_kwargs(tool_context),
                )
            )

        debug_symbol_query.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_symbol_query)

    _register_registers_query("debug.read_registers", handlers.read_registers)
    _register_symbol_query("debug.read_symbol", handlers.read_symbol)

    @app.tool(name="debug.read_memory")
    def debug_read_memory(
        run_id: str,
        address: int,
        byte_count: int,
        context: DebugSessionContext | None = None,
    ) -> dict[str, Any]:
        artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
        return _dump(
            handlers.read_memory(
                artifact_root=artifact_root,
                run_id=run_id,
                address=address,
                byte_count=byte_count,
                debug_session_id=debug_session_id,
                **_debug_runtime_kwargs(tool_context),
            )
        )

    @app.tool(name="debug.evaluate")
    def debug_evaluate(
        run_id: str,
        inspector: str,
        context: DebugSessionContext | None = None,
        options: DebugEvaluateOptions | None = None,
    ) -> dict[str, Any]:
        artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
        evaluate_options = _model(options, DebugEvaluateOptions)
        assert isinstance(evaluate_options, DebugEvaluateOptions)
        return _dump(
            handlers.evaluate(
                artifact_root=artifact_root,
                run_id=run_id,
                inspector=inspector,
                arguments=evaluate_options.arguments,
                debug_session_id=debug_session_id,
                **_debug_runtime_kwargs(tool_context),
            )
        )

    @app.tool(name="debug.load_module_symbols")
    def debug_load_module_symbols(
        run_id: str,
        module: str,
        context: DebugSessionContext | None = None,
        options: DebugLoadModuleSymbolsOptions | None = None,
    ) -> dict[str, Any]:
        artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
        load_options = _model(options, DebugLoadModuleSymbolsOptions)
        assert isinstance(load_options, DebugLoadModuleSymbolsOptions)
        return _dump(
            handlers.load_module_symbols(
                artifact_root=artifact_root,
                run_id=run_id,
                module=module,
                sections=load_options.sections,
                ko_path=load_options.ko_path,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(tool_context),
            )
        )

    def _register_symbol_control(tool_name: str, handler: DebugSymbolControlHandler) -> None:
        def debug_symbol_control(
            run_id: str,
            symbol: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                handler(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    symbol=symbol,
                    debug_session_id=debug_session_id,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_symbol_control.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_symbol_control)

    def _register_breakpoint_id_control(tool_name: str, handler: DebugBreakpointIdControlHandler) -> None:
        def debug_breakpoint_id_control(
            run_id: str,
            breakpoint_id: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                handler(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    breakpoint_id=breakpoint_id,
                    debug_session_id=debug_session_id,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_breakpoint_id_control.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_breakpoint_id_control)

    def _register_gated_query(tool_name: str, handler: DebugSessionQueryHandler) -> None:
        def debug_session_query(
            run_id: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                handler(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_session_query.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_session_query)

    def _register_execution_control(tool_name: str, handler: DebugExecutionControlHandler) -> None:
        def debug_execution_control(
            run_id: str,
            context: DebugSessionContext | None = None,
            options: DebugExecutionOptions | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            execution_options = _model(options, DebugExecutionOptions)
            assert isinstance(execution_options, DebugExecutionOptions)
            return _dump(
                handler(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    timeout_seconds=execution_options.timeout_seconds,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_execution_control.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_execution_control)

    for tool_name, handler in (
        ("debug.set_breakpoint", handlers.set_breakpoint),
        ("debug.set_watchpoint", handlers.set_watchpoint),
    ):
        _register_symbol_control(tool_name, handler)

    for tool_name, handler in (
        ("debug.clear_breakpoint", handlers.clear_breakpoint),
        ("debug.clear_watchpoint", handlers.clear_watchpoint),
    ):
        _register_breakpoint_id_control(tool_name, handler)

    for tool_name, handler in (
        ("debug.list_breakpoints", handlers.list_breakpoints),
        ("debug.backtrace", handlers.backtrace),
        ("debug.list_variables", handlers.list_variables),
    ):
        _register_gated_query(tool_name, handler)

    for tool_name, handler in (
        ("debug.continue", handlers.continue_execution),
        ("debug.step", handlers.step),
        ("debug.next", handlers.next),
        ("debug.finish", handlers.finish),
        ("debug.interrupt", handlers.interrupt),
    ):
        _register_execution_control(tool_name, handler)

    @app.tool(name="debug.end_session")
    def debug_end_session(
        run_id: str,
        context: DebugSessionContext | None = None,
    ) -> dict[str, Any]:
        artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
        return _dump(
            handlers.end_session(
                artifact_root=artifact_root,
                run_id=run_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(tool_context),
            )
        )
