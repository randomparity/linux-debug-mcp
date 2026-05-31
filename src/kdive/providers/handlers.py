from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, Protocol, TypeVar

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


_RequestT = TypeVar("_RequestT", bound=ProviderRequest)


class FutureProviderHandler(Protocol[_RequestT]):
    def __call__(
        self,
        *,
        request: _RequestT,
        registry: ProviderRegistry | None = None,
    ) -> ToolResponse: ...


@dataclass(frozen=True)
class FutureProviderOperationSpec(Generic[_RequestT]):
    operation: str
    request_type: type[_RequestT]
    handler: FutureProviderHandler[_RequestT]


def _future_typed_stub_handler(
    *,
    request: ProviderRequest,
    operation: str,
    request_type: type[_RequestT],
    registry: ProviderRegistry | None = None,
) -> ToolResponse:
    if not isinstance(request, request_type):
        try:
            request = request_type.model_validate(request.model_dump(mode="python"))
        except ValidationError as exc:
            return _future_request_validation_failure(exc)
    return _future_stub_handler(
        request=request,
        operation=operation,
        registry=registry,
    )


def remote_build_kernel_handler(
    *, request: RemoteBuildRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="remote.build_kernel",
        request_type=RemoteBuildRequest,
        registry=registry,
    )


def remote_sync_artifacts_handler(
    *, request: RemoteArtifactSyncRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="remote.sync_artifacts",
        request_type=RemoteArtifactSyncRequest,
        registry=registry,
    )


def reservation_request_host_handler(
    *, request: ReservationRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="reservation.request_host",
        request_type=ReservationRequest,
        registry=registry,
    )


def reservation_release_host_handler(
    *, request: ReservationReleaseRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="reservation.release_host",
        request_type=ReservationReleaseRequest,
        registry=registry,
    )


def provision_prepare_target_handler(
    *, request: ProvisioningRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="provision.prepare_target",
        request_type=ProvisioningRequest,
        registry=registry,
    )


def hardware_power_control_handler(
    *, request: HardwareControlRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="hardware.power_control",
        request_type=HardwareControlRequest,
        registry=registry,
    )


def hardware_boot_kernel_handler(*, request: RealBootRequest, registry: ProviderRegistry | None = None) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="hardware.boot_kernel",
        request_type=RealBootRequest,
        registry=registry,
    )


def console_open_session_handler(
    *, request: ConsoleSessionRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="console.open_session",
        request_type=ConsoleSessionRequest,
        registry=registry,
    )


def console_read_handler(*, request: ConsoleReadRequest, registry: ProviderRegistry | None = None) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="console.read",
        request_type=ConsoleReadRequest,
        registry=registry,
    )


def console_write_handler(*, request: ConsoleWriteRequest, registry: ProviderRegistry | None = None) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="console.write",
        request_type=ConsoleWriteRequest,
        registry=registry,
    )


def workflow_reserve_provision_boot_handler(
    *, request: ReserveProvisionBootRequest, registry: ProviderRegistry | None = None
) -> ToolResponse:
    return _future_typed_stub_handler(
        request=request,
        operation="workflow.reserve_provision_boot",
        request_type=ReserveProvisionBootRequest,
        registry=registry,
    )


FUTURE_PROVIDER_OPERATIONS: dict[str, FutureProviderOperationSpec[Any]] = {
    "remote.build_kernel": FutureProviderOperationSpec(
        operation="remote.build_kernel",
        request_type=RemoteBuildRequest,
        handler=remote_build_kernel_handler,
    ),
    "remote.sync_artifacts": FutureProviderOperationSpec(
        operation="remote.sync_artifacts",
        request_type=RemoteArtifactSyncRequest,
        handler=remote_sync_artifacts_handler,
    ),
    "reservation.request_host": FutureProviderOperationSpec(
        operation="reservation.request_host",
        request_type=ReservationRequest,
        handler=reservation_request_host_handler,
    ),
    "reservation.release_host": FutureProviderOperationSpec(
        operation="reservation.release_host",
        request_type=ReservationReleaseRequest,
        handler=reservation_release_host_handler,
    ),
    "provision.prepare_target": FutureProviderOperationSpec(
        operation="provision.prepare_target",
        request_type=ProvisioningRequest,
        handler=provision_prepare_target_handler,
    ),
    "hardware.power_control": FutureProviderOperationSpec(
        operation="hardware.power_control",
        request_type=HardwareControlRequest,
        handler=hardware_power_control_handler,
    ),
    "hardware.boot_kernel": FutureProviderOperationSpec(
        operation="hardware.boot_kernel",
        request_type=RealBootRequest,
        handler=hardware_boot_kernel_handler,
    ),
    "console.open_session": FutureProviderOperationSpec(
        operation="console.open_session",
        request_type=ConsoleSessionRequest,
        handler=console_open_session_handler,
    ),
    "console.read": FutureProviderOperationSpec(
        operation="console.read",
        request_type=ConsoleReadRequest,
        handler=console_read_handler,
    ),
    "console.write": FutureProviderOperationSpec(
        operation="console.write",
        request_type=ConsoleWriteRequest,
        handler=console_write_handler,
    ),
    "workflow.reserve_provision_boot": FutureProviderOperationSpec(
        operation="workflow.reserve_provision_boot",
        request_type=ReserveProvisionBootRequest,
        handler=workflow_reserve_provision_boot_handler,
    ),
}
