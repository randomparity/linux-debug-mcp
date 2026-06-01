from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, Protocol, cast, get_type_hints

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.domain import Model
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
            return stub_provider_operation_handler(request=request, spec=provider_operation).model_dump(mode="json")

        tool_wrapper.__name__ = request_factory.__name__
        tool_wrapper.__doc__ = request_factory.__doc__
        tool_wrapper.__annotations__ = get_type_hints(request_factory)
        # FastMCP inspects ``__signature__`` on the registered callable; copy the adapter signature
        # so the public tool schema exposes explicit parameters instead of ``*args, **kwargs``.
        cast(Any, tool_wrapper).__signature__ = _evaluated_signature(request_factory)
        return app.tool(name=tool_name)(tool_wrapper)

    return decorate


def register_provider_tools(app: FastMCP) -> None:
    @app.tool(name="providers.list")
    def providers_list() -> dict[str, Any]:
        return list_providers_handler().model_dump(mode="json")

    @_register_stub_provider_tool(
        app,
        tool_name="remote.build_kernel",
    )
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

    @_register_stub_provider_tool(
        app,
        tool_name="remote.sync_artifacts",
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

    @_register_stub_provider_tool(
        app,
        tool_name="reservation.request_host",
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

    @_register_stub_provider_tool(
        app,
        tool_name="reservation.release_host",
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

    @_register_stub_provider_tool(
        app,
        tool_name="provision.prepare_target",
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

    @_register_stub_provider_tool(
        app,
        tool_name="hardware.power_control",
    )
    def hardware_power_control(
        architecture: str,
        target_name: str,
        action: str,
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

    @_register_stub_provider_tool(
        app,
        tool_name="hardware.boot_kernel",
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

    @_register_stub_provider_tool(
        app,
        tool_name="console.open_session",
    )
    def console_open_session(
        architecture: str,
        target_name: str,
        access_method: str,
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

    @_register_stub_provider_tool(
        app,
        tool_name="console.read",
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

    @_register_stub_provider_tool(
        app,
        tool_name="console.write",
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

    @_register_stub_provider_tool(
        app,
        tool_name="workflow.reserve_provision_boot",
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
