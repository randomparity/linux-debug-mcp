from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


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


class TransportTargetContext(Model):
    run_id: str
    artifact_root: str | None = None


class TransportOpenOptions(Model):
    recovery: bool = False


class TransportBreakOptions(Model):
    acknowledged_permissions: list[str] | None = None


def register_transport_tools(
    app: FastMCP,
    *,
    context: TransportToolContext,
    handlers: TransportToolHandlers,
) -> None:
    tool_context = context

    @app.tool(name="transport.open")
    def transport_open(
        context: TransportTargetContext | dict[str, Any],
        options: TransportOpenOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            context_model = model_arg(context, TransportTargetContext)
            options_model = optional_model_arg(options, TransportOpenOptions)
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return handlers.open(
            run_id=context_model.run_id,
            recovery=options_model.recovery,
            transaction=tool_context.transaction,
            admission=tool_context.admission,
            session_registry=tool_context.session_registry,
        ).model_dump(mode="json")

    @app.tool(name="transport.close")
    def transport_close(context: TransportTargetContext | dict[str, Any], session_id: str) -> dict[str, Any]:
        try:
            context_model = model_arg(context, TransportTargetContext)
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return handlers.close(
            run_id=context_model.run_id,
            session_id=session_id,
            transaction=tool_context.transaction,
            session_registry=tool_context.session_registry,
        ).model_dump(mode="json")

    @app.tool(name="transport.inject_break")
    def transport_inject_break(
        context: TransportTargetContext | dict[str, Any],
        session_id: str,
        options: TransportBreakOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            context_model = model_arg(context, TransportTargetContext)
            options_model = optional_model_arg(options, TransportBreakOptions)
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return handlers.inject_break(
            run_id=context_model.run_id,
            session_id=session_id,
            acknowledged_permissions=options_model.acknowledged_permissions,
            artifact_root=Path(context_model.artifact_root or str(tool_context.default_artifact_root)),
            transaction=tool_context.transaction,
            admission=tool_context.admission,
            session_registry=tool_context.session_registry,
        ).model_dump(mode="json")
