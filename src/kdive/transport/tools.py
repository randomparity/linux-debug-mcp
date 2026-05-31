from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse


class TransportOpenHandler(Protocol):
    def __call__(
        self,
        *,
        run_id: str,
        recovery: bool,
        transaction: TransportTransaction,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class TransportCloseHandler(Protocol):
    def __call__(
        self,
        *,
        run_id: str,
        session_id: str,
        transaction: TransportTransaction,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class TransportInjectBreakHandler(Protocol):
    def __call__(
        self,
        *,
        run_id: str,
        session_id: str,
        acknowledged_permissions: list[str] | None,
        artifact_root: Path,
        transaction: TransportTransaction,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


@dataclass(frozen=True)
class TransportToolHandlers:
    open: TransportOpenHandler
    close: TransportCloseHandler
    inject_break: TransportInjectBreakHandler


@dataclass(frozen=True)
class TransportToolContext:
    default_artifact_root: Path
    transaction: TransportTransaction
    admission: AdmissionService
    session_registry: SessionRegistry


def register_transport_tools(
    app: FastMCP,
    *,
    context: TransportToolContext,
    handlers: TransportToolHandlers,
) -> None:
    @app.tool(name="transport.open")
    def transport_open(run_id: str, recovery: bool = False) -> dict[str, Any]:
        return handlers.open(
            run_id=run_id,
            recovery=recovery,
            transaction=context.transaction,
            admission=context.admission,
            session_registry=context.session_registry,
        ).model_dump(mode="json")

    @app.tool(name="transport.close")
    def transport_close(run_id: str, session_id: str) -> dict[str, Any]:
        return handlers.close(
            run_id=run_id,
            session_id=session_id,
            transaction=context.transaction,
            session_registry=context.session_registry,
        ).model_dump(mode="json")

    @app.tool(name="transport.inject_break")
    def transport_inject_break(
        run_id: str,
        session_id: str,
        acknowledged_permissions: list[str] | None = None,
        artifact_root: str = str(context.default_artifact_root),
    ) -> dict[str, Any]:
        return handlers.inject_break(
            run_id=run_id,
            session_id=session_id,
            acknowledged_permissions=acknowledged_permissions,
            artifact_root=Path(artifact_root),
            transaction=context.transaction,
            admission=context.admission,
            session_registry=context.session_registry,
        ).model_dump(mode="json")
