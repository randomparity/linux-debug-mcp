from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
    FUTURE_PROVIDER_OPERATIONS,
    future_request_validation_failure_response,
    list_providers_handler,
)


class _FutureProviderRequestFactory(Protocol):
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


@dataclass(frozen=True)
class FutureProviderToolRequestSpec:
    request_type: type[ProviderRequest]
    operation_fields: tuple[str, ...]
    options_model: type[Model] | None = None
    common_fields: tuple[str, ...] = ("architecture", "provider_context", "execution_options")


FUTURE_PROVIDER_TOOL_REQUEST_SPECS: dict[str, FutureProviderToolRequestSpec] = {
    "remote.build_kernel": FutureProviderToolRequestSpec(
        request_type=RemoteBuildRequest,
        operation_fields=("source_ref", "build_profile"),
        options_model=RemoteBuildArtifactOptions,
    ),
    "remote.sync_artifacts": FutureProviderToolRequestSpec(
        request_type=RemoteArtifactSyncRequest,
        operation_fields=("external_artifact_ref",),
        options_model=RemoteSyncArtifactOptions,
    ),
    "reservation.request_host": FutureProviderToolRequestSpec(
        request_type=ReservationRequest,
        operation_fields=("reservation_pool",),
        options_model=ReservationRequestOptions,
    ),
    "reservation.release_host": FutureProviderToolRequestSpec(
        request_type=ReservationReleaseRequest,
        operation_fields=("reservation_id",),
    ),
    "provision.prepare_target": FutureProviderToolRequestSpec(
        request_type=ProvisioningRequest,
        operation_fields=("target_name", "provisioning_profile"),
        options_model=ProvisioningOptions,
    ),
    "hardware.power_control": FutureProviderToolRequestSpec(
        request_type=HardwareControlRequest,
        operation_fields=("target_name", "action"),
        options_model=HardwarePowerOptions,
    ),
    "hardware.boot_kernel": FutureProviderToolRequestSpec(
        request_type=RealBootRequest,
        operation_fields=("target_name", "kernel_artifact_ref"),
        options_model=HardwareBootOptions,
    ),
    "console.open_session": FutureProviderToolRequestSpec(
        request_type=ConsoleSessionRequest,
        operation_fields=("target_name", "access_method"),
        options_model=ConsoleOpenOptions,
    ),
    "console.read": FutureProviderToolRequestSpec(
        request_type=ConsoleReadRequest,
        operation_fields=("console_session_id", "max_bytes"),
    ),
    "console.write": FutureProviderToolRequestSpec(
        request_type=ConsoleWriteRequest,
        operation_fields=("console_session_id", "data"),
    ),
    "workflow.reserve_provision_boot": FutureProviderToolRequestSpec(
        request_type=ReserveProvisionBootRequest,
        operation_fields=("reservation_pool", "target_name", "provisioning_profile", "kernel_artifact_ref"),
        options_model=WorkflowReserveProvisionBootOptions,
    ),
}


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


def _future_provider_request(
    tool_name: str,
    *,
    architecture: str,
    provider_context: ProviderToolContext | dict[str, Any] | None,
    execution_options: ProviderExecutionOptions | dict[str, Any] | None,
    operation_values: Mapping[str, Any],
    options: Model | dict[str, Any] | None = None,
) -> ProviderRequest:
    spec = FUTURE_PROVIDER_TOOL_REQUEST_SPECS[tool_name]
    payload = {
        **_provider_fields(
            architecture=architecture,
            provider_context=provider_context,
            execution_options=execution_options,
        ),
        **{field: operation_values[field] for field in spec.operation_fields},
    }
    if spec.options_model is not None:
        payload.update(_model_payload(options, spec.options_model))
    return spec.request_type(**payload)


def _evaluated_signature(request_factory: _FutureProviderRequestFactory) -> inspect.Signature:
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


def _register_future_provider_tool(
    app: FastMCP,
    *,
    tool_name: str,
) -> Callable[[_FutureProviderRequestFactory], Callable[..., dict[str, Any]]]:
    provider_operation = FUTURE_PROVIDER_OPERATIONS[tool_name]

    def decorate(request_factory: _FutureProviderRequestFactory) -> Callable[..., dict[str, Any]]:
        def tool_wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            try:
                request = request_factory(*args, **kwargs)
            except ValidationError as exc:
                return future_request_validation_failure_response(exc)
            return provider_operation.handler(request=request).model_dump(mode="json")

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

    @_register_future_provider_tool(
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
        return cast(
            RemoteBuildRequest,
            _future_provider_request(
                "remote.build_kernel",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=artifact_options,
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            RemoteArtifactSyncRequest,
            _future_provider_request(
                "remote.sync_artifacts",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=artifact_options,
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            ReservationRequest,
            _future_provider_request(
                "reservation.request_host",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=reservation_options,
            ),
        )

    @_register_future_provider_tool(
        app,
        tool_name="reservation.release_host",
    )
    def reservation_release_host(
        architecture: str,
        reservation_id: str,
        provider_context: ProviderToolContext | None = None,
        execution_options: ProviderExecutionOptions | None = None,
    ) -> ReservationReleaseRequest:
        return cast(
            ReservationReleaseRequest,
            _future_provider_request(
                "reservation.release_host",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            ProvisioningRequest,
            _future_provider_request(
                "provision.prepare_target",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=provisioning_options,
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            HardwareControlRequest,
            _future_provider_request(
                "hardware.power_control",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=power_options,
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            RealBootRequest,
            _future_provider_request(
                "hardware.boot_kernel",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=boot_options,
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            ConsoleSessionRequest,
            _future_provider_request(
                "console.open_session",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=console_options,
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            ConsoleReadRequest,
            _future_provider_request(
                "console.read",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            ConsoleWriteRequest,
            _future_provider_request(
                "console.write",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
            ),
        )

    @_register_future_provider_tool(
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
        return cast(
            ReserveProvisionBootRequest,
            _future_provider_request(
                "workflow.reserve_provision_boot",
                architecture=architecture,
                provider_context=provider_context,
                execution_options=execution_options,
                operation_values=locals(),
                options=workflow_options,
            ),
        )
