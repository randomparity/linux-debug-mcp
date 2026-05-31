from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import Model, ToolResponse
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard

DebugToolHandler = Callable[..., ToolResponse]
DebugUngatedHandler = DebugToolHandler
DebugStatefulHandler = DebugToolHandler
DebugSessionQueryHandler = DebugToolHandler
DebugExecutionControlHandler = DebugToolHandler


@dataclass(frozen=True)
class DebugToolHandlers:
    start_session: DebugStatefulHandler
    read_registers: DebugUngatedHandler
    read_symbol: DebugUngatedHandler
    read_memory: DebugUngatedHandler
    evaluate: DebugUngatedHandler
    load_module_symbols: DebugStatefulHandler
    set_breakpoint: DebugStatefulHandler
    set_watchpoint: DebugStatefulHandler
    clear_breakpoint: DebugStatefulHandler
    clear_watchpoint: DebugStatefulHandler
    list_breakpoints: DebugSessionQueryHandler
    backtrace: DebugSessionQueryHandler
    list_variables: DebugSessionQueryHandler
    continue_execution: DebugExecutionControlHandler
    step: DebugExecutionControlHandler
    next: DebugExecutionControlHandler
    finish: DebugExecutionControlHandler
    interrupt: DebugExecutionControlHandler
    end_session: DebugStatefulHandler


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


UNGATED_QUERY_TOOL_SPECS: tuple[tuple[str, str, str], ...] = (
    ("debug.read_registers", "read_registers", "registers"),
    ("debug.read_symbol", "read_symbol", "symbol"),
)
GATED_QUERY_TOOL_SPECS: tuple[tuple[str, str], ...] = (
    ("debug.list_breakpoints", "list_breakpoints"),
    ("debug.backtrace", "backtrace"),
    ("debug.list_variables", "list_variables"),
)
SYMBOL_CONTROL_TOOL_SPECS: tuple[tuple[str, str], ...] = (
    ("debug.set_breakpoint", "set_breakpoint"),
    ("debug.set_watchpoint", "set_watchpoint"),
)
BREAKPOINT_ID_CONTROL_TOOL_SPECS: tuple[tuple[str, str], ...] = (
    ("debug.clear_breakpoint", "clear_breakpoint"),
    ("debug.clear_watchpoint", "clear_watchpoint"),
)
EXECUTION_CONTROL_TOOL_SPECS: tuple[tuple[str, str], ...] = (
    ("debug.continue", "continue_execution"),
    ("debug.step", "step"),
    ("debug.next", "next"),
    ("debug.finish", "finish"),
    ("debug.interrupt", "interrupt"),
)

DEBUG_TOOL_REGISTRATION_GROUPS: dict[str, tuple[tuple[str, ...], ...]] = {
    "ungated_query": UNGATED_QUERY_TOOL_SPECS,
    "gated_query": GATED_QUERY_TOOL_SPECS,
    "symbol_control": SYMBOL_CONTROL_TOOL_SPECS,
    "breakpoint_id_control": BREAKPOINT_ID_CONTROL_TOOL_SPECS,
    "execution_control": EXECUTION_CONTROL_TOOL_SPECS,
}


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

    def _register_registers_query(tool_name: str, handler_name: str) -> None:
        def debug_registers_query(
            run_id: str,
            registers: list[str],
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                getattr(handlers, handler_name)(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    registers=registers,
                    debug_session_id=debug_session_id,
                    **_debug_runtime_kwargs(tool_context),
                )
            )

        debug_registers_query.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_registers_query)

    def _register_symbol_query(tool_name: str, handler_name: str) -> None:
        def debug_symbol_query(
            run_id: str,
            symbol: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                getattr(handlers, handler_name)(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    symbol=symbol,
                    debug_session_id=debug_session_id,
                    **_debug_runtime_kwargs(tool_context),
                )
            )

        debug_symbol_query.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_symbol_query)

    for tool_name, handler_name, value_name in UNGATED_QUERY_TOOL_SPECS:
        if value_name == "registers":
            _register_registers_query(tool_name, handler_name)
        elif value_name == "symbol":
            _register_symbol_query(tool_name, handler_name)
        else:
            raise ValueError(f"unknown ungated debug query shape: {value_name}")

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

    def _register_symbol_control(tool_name: str, handler_name: str) -> None:
        def debug_symbol_control(
            run_id: str,
            symbol: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                getattr(handlers, handler_name)(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    symbol=symbol,
                    debug_session_id=debug_session_id,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_symbol_control.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_symbol_control)

    def _register_breakpoint_id_control(tool_name: str, handler_name: str) -> None:
        def debug_breakpoint_id_control(
            run_id: str,
            breakpoint_id: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                getattr(handlers, handler_name)(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    breakpoint_id=breakpoint_id,
                    debug_session_id=debug_session_id,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_breakpoint_id_control.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_breakpoint_id_control)

    def _register_gated_query(tool_name: str, handler_name: str) -> None:
        def debug_session_query(
            run_id: str,
            context: DebugSessionContext | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            return _dump(
                getattr(handlers, handler_name)(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_session_query.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_session_query)

    def _register_execution_control(tool_name: str, handler_name: str) -> None:
        def debug_execution_control(
            run_id: str,
            context: DebugSessionContext | None = None,
            options: DebugExecutionOptions | None = None,
        ) -> dict[str, Any]:
            artifact_root, debug_session_id = _session_context(context, default_artifact_root=default_artifact_root)
            execution_options = _model(options, DebugExecutionOptions)
            assert isinstance(execution_options, DebugExecutionOptions)
            return _dump(
                getattr(handlers, handler_name)(
                    artifact_root=artifact_root,
                    run_id=run_id,
                    debug_session_id=debug_session_id,
                    timeout_seconds=execution_options.timeout_seconds,
                    **_gated_debug_runtime_kwargs(tool_context),
                )
            )

        debug_execution_control.__name__ = _tool_function_name(tool_name)
        app.tool(name=tool_name)(debug_execution_control)

    for tool_name, handler_name in SYMBOL_CONTROL_TOOL_SPECS:
        _register_symbol_control(tool_name, handler_name)

    for tool_name, handler_name in BREAKPOINT_ID_CONTROL_TOOL_SPECS:
        _register_breakpoint_id_control(tool_name, handler_name)

    for tool_name, handler_name in GATED_QUERY_TOOL_SPECS:
        _register_gated_query(tool_name, handler_name)

    for tool_name, handler_name in EXECUTION_CONTROL_TOOL_SPECS:
        _register_execution_control(tool_name, handler_name)

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
