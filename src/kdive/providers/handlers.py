from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from kdive.domain import ErrorCategory, ToolResponse
from kdive.providers.contracts.models import (
    BootOrchestrationRequest,
    ConsoleReadRequest,
    ConsoleSessionRequest,
    ConsoleWriteRequest,
    HardwareControlRequest,
    ProviderRequest,
    ProvisioningRequest,
    RemoteArtifactSyncRequest,
    RemoteBuildRequest,
    ReservationReleaseRequest,
    ReservationRequest,
    ReserveProvisionBootRequest,
)
from kdive.providers.registry import ProviderRegistry
from kdive.providers.stubs import select_stub_provider, stub_not_implemented_response
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


def _stub_request_validation_failure(exc: ValidationError) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message="stub provider request failed validation",
        details=redactor.redact_value(_validation_error_details(exc)),
        suggested_next_actions=["providers.list"],
    )


def stub_request_validation_failure_response(exc: ValidationError) -> dict[str, Any]:
    return _stub_request_validation_failure(exc).model_dump(mode="json")


def _stub_provider_handler(
    *,
    request: ProviderRequest,
    operation: str,
    registry: ProviderRegistry | None = None,
) -> ToolResponse:
    registry = registry or ProviderRegistry.with_defaults()
    provider = select_stub_provider(
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
    return stub_not_implemented_response(
        provider=provider,
        operation=operation,
        architecture=request.architecture,
        documentation_paths=documentation_paths,
    )


@dataclass(frozen=True)
class StubProviderOperationSpec:
    operation: str
    request_type: type[ProviderRequest]


def stub_provider_operation_handler(
    *,
    request: ProviderRequest,
    spec: StubProviderOperationSpec,
    registry: ProviderRegistry | None = None,
) -> ToolResponse:
    if not isinstance(request, spec.request_type):
        try:
            request = spec.request_type.model_validate(request.model_dump(mode="python"))
        except ValidationError as exc:
            return _stub_request_validation_failure(exc)
    return _stub_provider_handler(
        request=request,
        operation=spec.operation,
        registry=registry,
    )


STUB_PROVIDER_OPERATIONS: dict[str, StubProviderOperationSpec] = {
    "remote.build_kernel": StubProviderOperationSpec(
        operation="remote.build_kernel",
        request_type=RemoteBuildRequest,
    ),
    "remote.sync_artifacts": StubProviderOperationSpec(
        operation="remote.sync_artifacts",
        request_type=RemoteArtifactSyncRequest,
    ),
    "reservation.request_host": StubProviderOperationSpec(
        operation="reservation.request_host",
        request_type=ReservationRequest,
    ),
    "reservation.release_host": StubProviderOperationSpec(
        operation="reservation.release_host",
        request_type=ReservationReleaseRequest,
    ),
    "provision.prepare_target": StubProviderOperationSpec(
        operation="provision.prepare_target",
        request_type=ProvisioningRequest,
    ),
    "hardware.power_control": StubProviderOperationSpec(
        operation="hardware.power_control",
        request_type=HardwareControlRequest,
    ),
    "hardware.boot_kernel": StubProviderOperationSpec(
        operation="hardware.boot_kernel",
        request_type=BootOrchestrationRequest,
    ),
    "console.open_session": StubProviderOperationSpec(
        operation="console.open_session",
        request_type=ConsoleSessionRequest,
    ),
    "console.read": StubProviderOperationSpec(
        operation="console.read",
        request_type=ConsoleReadRequest,
    ),
    "console.write": StubProviderOperationSpec(
        operation="console.write",
        request_type=ConsoleWriteRequest,
    ),
    "workflow.reserve_provision_boot": StubProviderOperationSpec(
        operation="workflow.reserve_provision_boot",
        request_type=ReserveProvisionBootRequest,
    ),
}
