from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from kdive.domain import ErrorCategory, ToolResponse
from kdive.providers.contracts.models import (
    ConsoleReadRequest,
    ConsoleSessionRequest,
    ConsoleWriteRequest,
    HardwareControlRequest,
    ProviderRequest,
    ProvisioningRequest,
    RealBootRequest,
    RemoteArtifactSyncRequest,
    RemoteBuildRequest,
    ReservationReleaseRequest,
    ReservationRequest,
    ReserveProvisionBootRequest,
)
from kdive.providers.registry import ProviderRegistry
from kdive.providers.stubs import future_not_implemented_response, select_future_provider
from kdive.safety.redaction import Redactor


def list_providers_handler() -> ToolResponse:
    registry = ProviderRegistry.with_defaults()
    providers = []
    for provider in registry.list_capabilities():
        provider_payload = provider.model_dump(mode="json")
        plugin_metadata = registry.provider_plugin_metadata(provider.provider_name)
        if plugin_metadata is not None:
            provider_payload["plugin"] = plugin_metadata.model_dump(mode="json")
            provider_payload["documentation_paths"] = list(plugin_metadata.documentation_paths)
        providers.append(provider_payload)
    return ToolResponse.success(
        summary="listed provider capabilities",
        data={"providers": providers},
    )


def _validation_error_details(exc: ValidationError) -> dict[str, Any]:
    return {
        "validation_errors": [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())),
                "type": error.get("type", "validation_error"),
            }
            for error in exc.errors(include_input=False)
        ]
    }


def _future_request_validation_failure(exc: ValidationError) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message="future provider request failed validation",
        details=redactor.redact_value(_validation_error_details(exc)),
        suggested_next_actions=["providers.list"],
    )


def future_request_validation_failure_response(exc: ValidationError) -> dict[str, Any]:
    return _future_request_validation_failure(exc).model_dump(mode="json")


def _future_stub_handler(
    *,
    request: ProviderRequest,
    operation: str,
    registry: ProviderRegistry | None = None,
) -> ToolResponse:
    registry = registry or ProviderRegistry.with_defaults()
    provider = select_future_provider(
        registry,
        operation=operation,
        architecture=request.architecture,
        provider_name=request.provider_name,
    )
    if isinstance(provider, ToolResponse):
        return provider

    plugin_metadata = registry.provider_plugin_metadata(provider.provider_name)
    documentation_paths = (
        list(plugin_metadata.documentation_paths) if plugin_metadata is not None else list(provider.documentation_paths)
    )
    return future_not_implemented_response(
        provider=provider,
        operation=operation,
        architecture=request.architecture,
        documentation_paths=documentation_paths,
    )


FutureProviderHandler = Callable[..., ToolResponse]


@dataclass(frozen=True)
class FutureProviderOperationSpec:
    operation: str
    request_type: type[ProviderRequest]
    handler: FutureProviderHandler


def _make_future_provider_handler(
    *,
    operation: str,
    request_type: type[ProviderRequest],
    handler_name: str,
) -> FutureProviderHandler:
    def handler(*, request: ProviderRequest, registry: ProviderRegistry | None = None) -> ToolResponse:
        return _future_stub_handler(
            request=request,
            operation=operation,
            registry=registry,
        )

    handler.__name__ = handler_name
    handler.__annotations__ = {
        "request": request_type,
        "registry": ProviderRegistry | None,
        "return": ToolResponse,
    }
    return handler


_FUTURE_PROVIDER_HANDLER_ROWS: tuple[tuple[str, type[ProviderRequest], str], ...] = (
    ("remote.build_kernel", RemoteBuildRequest, "remote_build_kernel_handler"),
    ("remote.sync_artifacts", RemoteArtifactSyncRequest, "remote_sync_artifacts_handler"),
    ("reservation.request_host", ReservationRequest, "reservation_request_host_handler"),
    ("reservation.release_host", ReservationReleaseRequest, "reservation_release_host_handler"),
    ("provision.prepare_target", ProvisioningRequest, "provision_prepare_target_handler"),
    ("hardware.power_control", HardwareControlRequest, "hardware_power_control_handler"),
    ("hardware.boot_kernel", RealBootRequest, "hardware_boot_kernel_handler"),
    ("console.open_session", ConsoleSessionRequest, "console_open_session_handler"),
    ("console.read", ConsoleReadRequest, "console_read_handler"),
    ("console.write", ConsoleWriteRequest, "console_write_handler"),
    ("workflow.reserve_provision_boot", ReserveProvisionBootRequest, "workflow_reserve_provision_boot_handler"),
)

FUTURE_PROVIDER_OPERATIONS: dict[str, FutureProviderOperationSpec] = {}
for _operation, _request_type, _handler_name in _FUTURE_PROVIDER_HANDLER_ROWS:
    _handler = _make_future_provider_handler(
        operation=_operation,
        request_type=_request_type,
        handler_name=_handler_name,
    )
    globals()[_handler_name] = _handler
    FUTURE_PROVIDER_OPERATIONS[_operation] = FutureProviderOperationSpec(
        operation=_operation,
        request_type=_request_type,
        handler=_handler,
    )
