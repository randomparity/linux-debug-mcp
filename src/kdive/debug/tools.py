from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.providers.local.gdb_mi import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard


class DebugStartSessionHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        debug_profile: str | None,
        new_session: bool,
        transaction: TransportTransaction,
        admission: AdmissionService,
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


def _path(value: str) -> Path:
    return Path(value)


def _dump(response: ToolResponse) -> dict[str, Any]:
    return response.model_dump(mode="json")


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


def register_debug_tools(app: FastMCP, *, context: DebugToolContext, handlers: DebugToolHandlers) -> None:
    @app.tool(name="debug.start_session")
    def debug_start_session(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_profile: str | None = None,
        new_session: bool = False,
    ) -> dict[str, Any]:
        return _dump(
            handlers.start_session(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_profile=debug_profile,
                new_session=new_session,
                admission=context.admission,
                **_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.read_registers")
    def debug_read_registers(
        run_id: str,
        registers: list[str],
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.read_registers(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                registers=registers,
                debug_session_id=debug_session_id,
                **_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.read_symbol")
    def debug_read_symbol(
        run_id: str,
        symbol: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.read_symbol(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                symbol=symbol,
                debug_session_id=debug_session_id,
                **_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.read_memory")
    def debug_read_memory(
        run_id: str,
        address: int,
        byte_count: int,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.read_memory(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                address=address,
                byte_count=byte_count,
                debug_session_id=debug_session_id,
                **_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.evaluate")
    def debug_evaluate(
        run_id: str,
        inspector: str,
        arguments: dict[str, object] | None = None,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.evaluate(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                inspector=inspector,
                arguments=arguments,
                debug_session_id=debug_session_id,
                **_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.load_module_symbols")
    def debug_load_module_symbols(
        run_id: str,
        module: str,
        sections: dict[str, str] | None = None,
        ko_path: str | None = None,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.load_module_symbols(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                module=module,
                sections=sections,
                ko_path=ko_path,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.set_breakpoint")
    def debug_set_breakpoint(
        run_id: str,
        symbol: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.set_breakpoint(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                symbol=symbol,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.set_watchpoint")
    def debug_set_watchpoint(
        run_id: str,
        symbol: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.set_watchpoint(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                symbol=symbol,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.clear_breakpoint")
    def debug_clear_breakpoint(
        run_id: str,
        breakpoint_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.clear_breakpoint(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                breakpoint_id=breakpoint_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.clear_watchpoint")
    def debug_clear_watchpoint(
        run_id: str,
        breakpoint_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.clear_watchpoint(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                breakpoint_id=breakpoint_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.list_breakpoints")
    def debug_list_breakpoints(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.list_breakpoints(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.backtrace")
    def debug_backtrace(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.backtrace(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.list_variables")
    def debug_list_variables(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.list_variables(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.continue")
    def debug_continue(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.continue_execution(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                timeout_seconds=timeout_seconds,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.step")
    def debug_step(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.step(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                timeout_seconds=timeout_seconds,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.next")
    def debug_next(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.next(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                timeout_seconds=timeout_seconds,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.finish")
    def debug_finish(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.finish(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                timeout_seconds=timeout_seconds,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.interrupt")
    def debug_interrupt(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.interrupt(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                timeout_seconds=timeout_seconds,
                **_gated_debug_runtime_kwargs(context),
            )
        )

    @app.tool(name="debug.end_session")
    def debug_end_session(
        run_id: str,
        artifact_root: str = str(context.default_artifact_root),
        debug_session_id: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            handlers.end_session(
                artifact_root=_path(artifact_root),
                run_id=run_id,
                debug_session_id=debug_session_id,
                **_gated_debug_runtime_kwargs(context),
            )
        )
