from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, Protocol, cast, get_type_hints

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.config import PROVIDER_DESTRUCTIVE_PERMISSIONS, missing_destructive_permissions
from kdive.domain import ErrorCategory, Model, ToolResponse
from kdive.providers.contracts.models import (
    ConsoleAccessMethod,
    ConsoleReadRequest,
    ConsoleSessionRequest,
    ConsoleWriteRequest,
    HardwareControlRequest,
    PowerAction,
    ProviderRequest,
    ProvisioningRequest,
    RealBootRequest,
    RemoteArtifactSyncRequest,
    RemoteBuildRequest,
    ReservationReleaseRequest,
    ReservationRequest,
    ReserveProvisionBootRequest,
)
from kdive.providers.handlers import (
    STUB_PROVIDER_OPERATIONS,
    list_providers_handler,
    stub_provider_operation_handler,
    stub_request_validation_failure_response,
)


class _StubProviderRequestFactory(Protocol):
    __name__: str
    __doc__: str | None
    __annotations__: dict[str, Any]

    def __call__(self, *args: Any, **kwargs: Any) -> ProviderRequest: ...


class ProviderToolContext(Model):
    provider_name: str | None = None
    operation_label: str | None = None
    run_id: str | None = None


class ProviderExecutionOptions(Model):
    timeout_seconds: int = 300
    acknowledged_permissions: list[str] | None = None


class RemoteBuildArtifactOptions(Model):
    output_artifact_ref: str | None = None


class RemoteSyncArtifactOptions(Model):
    destination_artifact_ref: str | None = None


class ReservationRequestOptions(Model):
    reservation_token_ref: str | None = None


class ProvisioningOptions(Model):
    reservation_id: str | None = None
    credential_ref: str | None = None


class HardwarePowerOptions(Model):
    bmc_credential_ref: str | None = None


class HardwareBootOptions(Model):
    boot_profile: str | None = None
    reservation_id: str | None = None


class ConsoleOpenOptions(Model):
    credential_ref: str | None = None
    ipmi_cipher_suite: int | None = None


class WorkflowReserveProvisionBootOptions(Model):
    reservation_token_ref: str | None = None
    credential_ref: str | None = None
    bmc_credential_ref: str | None = None


def _model_payload(value: Model | dict[str, Any] | None, model_type: type[Model]) -> dict[str, Any]:
    if value is None:
        return {}
    model = value if isinstance(value, model_type) else model_type.model_validate(value)
    return model.model_dump(exclude_none=True)


def _provider_fields(
    *,
    architecture: str,
    provider_context: ProviderToolContext | dict[str, Any] | None,
    execution_options: ProviderExecutionOptions | dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "architecture": architecture,
        **_model_payload(provider_context, ProviderToolContext),
        **_model_payload(execution_options, ProviderExecutionOptions),
    }


def _evaluated_signature(request_factory: _StubProviderRequestFactory) -> inspect.Signature:
    hints = get_type_hints(request_factory)
    signature = inspect.signature(request_factory)
    parameters = [
        parameter.replace(annotation=hints.get(name, parameter.annotation))
        for name, parameter in signature.parameters.items()
    ]
    return signature.replace(
        parameters=parameters,
        return_annotation=hints.get("return", signature.return_annotation),
    )


def _register_stub_provider_tool(
    app: FastMCP,
    *,
    tool_name: str,
) -> Callable[[_StubProviderRequestFactory], Callable[..., dict[str, Any]]]:
    provider_operation = STUB_PROVIDER_OPERATIONS[tool_name]

    def decorate(request_factory: _StubProviderRequestFactory) -> Callable[..., dict[str, Any]]:
        def tool_wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            try:
                request = request_factory(*args, **kwargs)
            except ValidationError as exc:
                return stub_request_validation_failure_response(exc)
            missing_permissions = missing_destructive_permissions(
                provider_operation.operation,
                request.acknowledged_permissions,
                registry=PROVIDER_DESTRUCTIVE_PERMISSIONS,
            )
            if missing_permissions:
                return ToolResponse.failure(
                    category=ErrorCategory.CONFIGURATION_ERROR,
                    message=f"{provider_operation.operation} is destructive; acknowledge its required permissions",
                    details={"code": "permission_required", "required_permissions": missing_permissions},
                    suggested_next_actions=["providers.list"],
                ).model_dump(mode="json")
            return stub_provider_operation_handler(request=request, spec=provider_operation).model_dump(mode="json")

        tool_wrapper.__name__ = request_factory.__name__
        tool_wrapper.__doc__ = request_factory.__doc__
        tool_wrapper.__annotations__ = get_type_hints(request_factory)
        # FastMCP inspects ``__signature__`` on the registered callable; copy the adapter signature
        # so the public tool schema exposes explicit parameters instead of ``*args, **kwargs``.
        cast(Any, tool_wrapper).__signature__ = _evaluated_signature(request_factory)
        return app.tool(name=tool_name)(tool_wrapper)

    return decorate


def remote_build_kernel(
    architecture: str,
    source_ref: str,
    build_profile: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    artifact_options: RemoteBuildArtifactOptions | None = None,
) -> RemoteBuildRequest:
    return RemoteBuildRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        source_ref=source_ref,
        build_profile=build_profile,
        **_model_payload(artifact_options, RemoteBuildArtifactOptions),
    )


def remote_sync_artifacts(
    architecture: str,
    external_artifact_ref: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    artifact_options: RemoteSyncArtifactOptions | None = None,
) -> RemoteArtifactSyncRequest:
    return RemoteArtifactSyncRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        external_artifact_ref=external_artifact_ref,
        **_model_payload(artifact_options, RemoteSyncArtifactOptions),
    )


def reservation_request_host(
    architecture: str,
    reservation_pool: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    reservation_options: ReservationRequestOptions | None = None,
) -> ReservationRequest:
    return ReservationRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        reservation_pool=reservation_pool,
        **_model_payload(reservation_options, ReservationRequestOptions),
    )


def reservation_release_host(
    architecture: str,
    reservation_id: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
) -> ReservationReleaseRequest:
    return ReservationReleaseRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        reservation_id=reservation_id,
    )


def provision_prepare_target(
    architecture: str,
    target_name: str,
    provisioning_profile: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    provisioning_options: ProvisioningOptions | None = None,
) -> ProvisioningRequest:
    return ProvisioningRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        target_name=target_name,
        provisioning_profile=provisioning_profile,
        **_model_payload(provisioning_options, ProvisioningOptions),
    )


def hardware_power_control(
    architecture: str,
    target_name: str,
    action: PowerAction,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    power_options: HardwarePowerOptions | None = None,
) -> HardwareControlRequest:
    return HardwareControlRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        target_name=target_name,
        action=action,
        **_model_payload(power_options, HardwarePowerOptions),
    )


def hardware_boot_kernel(
    architecture: str,
    target_name: str,
    kernel_artifact_ref: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    boot_options: HardwareBootOptions | None = None,
) -> RealBootRequest:
    return RealBootRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        target_name=target_name,
        kernel_artifact_ref=kernel_artifact_ref,
        **_model_payload(boot_options, HardwareBootOptions),
    )


def console_open_session(
    architecture: str,
    target_name: str,
    access_method: ConsoleAccessMethod,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    console_options: ConsoleOpenOptions | None = None,
) -> ConsoleSessionRequest:
    return ConsoleSessionRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        target_name=target_name,
        access_method=access_method,
        **_model_payload(console_options, ConsoleOpenOptions),
    )


def console_read(
    architecture: str,
    console_session_id: str,
    max_bytes: int = 4096,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
) -> ConsoleReadRequest:
    return ConsoleReadRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        console_session_id=console_session_id,
        max_bytes=max_bytes,
    )


def console_write(
    architecture: str,
    console_session_id: str,
    data: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
) -> ConsoleWriteRequest:
    return ConsoleWriteRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        console_session_id=console_session_id,
        data=data,
    )


def workflow_reserve_provision_boot(
    architecture: str,
    reservation_pool: str,
    target_name: str,
    provisioning_profile: str,
    kernel_artifact_ref: str,
    provider_context: ProviderToolContext | None = None,
    execution_options: ProviderExecutionOptions | None = None,
    workflow_options: WorkflowReserveProvisionBootOptions | None = None,
) -> ReserveProvisionBootRequest:
    return ReserveProvisionBootRequest(
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        reservation_pool=reservation_pool,
        target_name=target_name,
        provisioning_profile=provisioning_profile,
        kernel_artifact_ref=kernel_artifact_ref,
        **_model_payload(workflow_options, WorkflowReserveProvisionBootOptions),
    )


PROVIDER_TOOL_REQUEST_FACTORIES: tuple[tuple[str, _StubProviderRequestFactory], ...] = (
    ("remote.build_kernel", remote_build_kernel),
    ("remote.sync_artifacts", remote_sync_artifacts),
    ("reservation.request_host", reservation_request_host),
    ("reservation.release_host", reservation_release_host),
    ("provision.prepare_target", provision_prepare_target),
    ("hardware.power_control", hardware_power_control),
    ("hardware.boot_kernel", hardware_boot_kernel),
    ("console.open_session", console_open_session),
    ("console.read", console_read),
    ("console.write", console_write),
    ("workflow.reserve_provision_boot", workflow_reserve_provision_boot),
)


def register_provider_tools(app: FastMCP) -> None:
    @app.tool(name="providers.list")
    def providers_list() -> dict[str, Any]:
        return list_providers_handler().model_dump(mode="json")

    for tool_name, request_factory in PROVIDER_TOOL_REQUEST_FACTORIES:
        _register_stub_provider_tool(app, tool_name=tool_name)(request_factory)
