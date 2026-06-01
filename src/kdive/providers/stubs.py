from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kdive.config import PROVIDER_DESTRUCTIVE_PERMISSIONS
from kdive.domain import (
    ErrorCategory,
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
    ToolResponse,
)

STUB_ARCHITECTURES = ["x86_64", "ppc64le"]
STUB_AVAILABILITY_LIMITATION = "Stub provider only: advertises future capability and performs no external side effects."


def _semantics(*, destructive: bool, idempotent: bool = False, retryable: bool = True) -> OperationSemantics:
    return OperationSemantics(
        idempotent=idempotent,
        retryable=retryable,
        destructive=destructive,
        cancelable=False,
        concurrent_safe=False,
    )


def _operation(
    operation: str,
    *,
    destructive: bool,
    required_host_tools: list[str],
    destructive_permissions: list[str] | None = None,
) -> ProviderOperationCapability:
    return ProviderOperationCapability(
        operation=operation,
        semantics=_semantics(destructive=destructive, idempotent=not destructive),
        implementation_state=ImplementationState.STUB,
        required_host_tools=required_host_tools,
        destructive_permissions=destructive_permissions or [],
        limitations=[STUB_AVAILABILITY_LIMITATION],
    )


def _stub_capability(
    *,
    name: str,
    family: str,
    target_kinds: list[TargetKind],
    transports: list[str],
    operations: list[ProviderOperationCapability],
    required_host_tools: list[str],
    destructive_permissions: list[str] | None = None,
) -> ProviderCapability:
    return ProviderCapability(
        provider_name=name,
        provider_version="0.1.0",
        provider_family=family,
        implementation_state=ImplementationState.STUB,
        architectures=list(STUB_ARCHITECTURES),
        target_kinds=target_kinds,
        transports=transports,
        limitations=[STUB_AVAILABILITY_LIMITATION],
        operations=[operation.operation for operation in operations],
        operation_capabilities=operations,
        required_host_tools=required_host_tools,
        destructive_permissions=destructive_permissions or [],
        access_methods=transports,
        semantics=_semantics(
            destructive=any(operation.semantics.destructive for operation in operations),
            idempotent=all(operation.semantics.idempotent for operation in operations),
        ),
    )


def remote_build_stub_capability() -> ProviderCapability:
    tools = ["ssh", "rsync", "remote-build-api-client"]
    return _stub_capability(
        name="remote-build-stub",
        family="build",
        target_kinds=[TargetKind.REMOTE],
        transports=["ssh", "https-api", "filesystem"],
        required_host_tools=tools,
        operations=[
            _operation("remote.build_kernel", destructive=False, required_host_tools=tools),
        ],
    )


def remote_artifact_sync_stub_capability() -> ProviderCapability:
    tools = ["rsync", "ssh", "artifact-sync-client"]
    return _stub_capability(
        name="remote-artifact-sync-stub",
        family="artifacts",
        target_kinds=[TargetKind.REMOTE],
        transports=["rsync", "ssh", "https-api"],
        required_host_tools=tools,
        operations=[
            _operation("remote.sync_artifacts", destructive=False, required_host_tools=tools),
        ],
    )


def reservation_stub_capability() -> ProviderCapability:
    tools = ["reservation-api-client"]
    permissions = [
        *PROVIDER_DESTRUCTIVE_PERMISSIONS["reservation.request_host"],
        *PROVIDER_DESTRUCTIVE_PERMISSIONS["reservation.release_host"],
    ]
    return _stub_capability(
        name="reservation-stub",
        family="reservation",
        target_kinds=[TargetKind.REMOTE, TargetKind.PHYSICAL],
        transports=["https-api"],
        required_host_tools=tools,
        destructive_permissions=permissions,
        operations=[
            _operation(
                "reservation.request_host",
                destructive=True,
                required_host_tools=tools,
                destructive_permissions=PROVIDER_DESTRUCTIVE_PERMISSIONS["reservation.request_host"],
            ),
            _operation(
                "reservation.release_host",
                destructive=True,
                required_host_tools=tools,
                destructive_permissions=PROVIDER_DESTRUCTIVE_PERMISSIONS["reservation.release_host"],
            ),
        ],
    )


def provisioning_stub_capability() -> ProviderCapability:
    tools = ["provisioning-cli", "ssh"]
    permissions = PROVIDER_DESTRUCTIVE_PERMISSIONS["provision.prepare_target"]
    return _stub_capability(
        name="provisioning-stub",
        family="provisioning",
        target_kinds=[TargetKind.REMOTE, TargetKind.PHYSICAL],
        transports=["ssh", "https-api", "filesystem"],
        required_host_tools=tools,
        destructive_permissions=permissions,
        operations=[
            _operation(
                "provision.prepare_target",
                destructive=True,
                required_host_tools=tools,
                destructive_permissions=permissions,
            ),
        ],
    )


def hardware_control_stub_capability() -> ProviderCapability:
    tools = ["power-control-cli", "bmc-api-client"]
    permissions = PROVIDER_DESTRUCTIVE_PERMISSIONS["hardware.power_control"]
    return _stub_capability(
        name="hardware-control-stub",
        family="hardware",
        target_kinds=[TargetKind.PHYSICAL],
        transports=["bmc", "https-api"],
        required_host_tools=tools,
        destructive_permissions=permissions,
        operations=[
            _operation(
                "hardware.power_control",
                destructive=True,
                required_host_tools=tools,
                destructive_permissions=permissions,
            ),
        ],
    )


def console_access_stub_capability() -> ProviderCapability:
    tools = ["console-client"]
    return _stub_capability(
        name="console-access-stub",
        family="console",
        target_kinds=[TargetKind.REMOTE, TargetKind.PHYSICAL],
        transports=["serial-console", "ssh", "websocket"],
        required_host_tools=tools,
        operations=[
            _operation("console.open_session", destructive=False, required_host_tools=tools),
            _operation("console.read", destructive=False, required_host_tools=tools),
            _operation("console.write", destructive=False, required_host_tools=tools),
        ],
    )


def real_boot_stub_capability() -> ProviderCapability:
    tools = ["boot-orchestrator", "reservation-api-client", "provisioning-cli", "power-control-cli"]
    permissions = [
        *PROVIDER_DESTRUCTIVE_PERMISSIONS["hardware.boot_kernel"],
        *PROVIDER_DESTRUCTIVE_PERMISSIONS["workflow.reserve_provision_boot"],
    ]
    return _stub_capability(
        name="real-boot-stub",
        family="boot",
        target_kinds=[TargetKind.REMOTE, TargetKind.PHYSICAL],
        transports=["ssh", "bmc", "serial-console", "https-api"],
        required_host_tools=tools,
        destructive_permissions=permissions,
        operations=[
            _operation(
                "hardware.boot_kernel",
                destructive=True,
                required_host_tools=tools,
                destructive_permissions=PROVIDER_DESTRUCTIVE_PERMISSIONS["hardware.boot_kernel"],
            ),
            _operation(
                "workflow.reserve_provision_boot",
                destructive=True,
                required_host_tools=tools,
                destructive_permissions=PROVIDER_DESTRUCTIVE_PERMISSIONS["workflow.reserve_provision_boot"],
            ),
        ],
    )


def stub_provider_capability_factories() -> list[Callable[[], ProviderCapability]]:
    return [
        remote_build_stub_capability,
        remote_artifact_sync_stub_capability,
        reservation_stub_capability,
        provisioning_stub_capability,
        hardware_control_stub_capability,
        console_access_stub_capability,
        real_boot_stub_capability,
    ]


def stub_configuration_error_response(message: str, details: dict[str, object] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        details=details,
        suggested_next_actions=["providers.list"],
    )


def select_stub_provider(
    registry: Any,
    *,
    operation: str,
    architecture: str,
    provider_name: str | None = None,
) -> ProviderCapability | ToolResponse:
    if provider_name is not None:
        try:
            provider = registry.get(provider_name)
        except KeyError:
            return stub_configuration_error_response(
                "unknown provider",
                {"provider_name": provider_name, "operation": operation, "architecture": architecture},
            )
        if operation not in provider.operations:
            return stub_configuration_error_response(
                "provider does not advertise requested operation",
                {"provider_name": provider_name, "operation": operation, "architecture": architecture},
            )
        if architecture not in provider.architectures:
            return stub_configuration_error_response(
                "provider does not advertise requested architecture",
                {"provider_name": provider_name, "operation": operation, "architecture": architecture},
            )
        return provider

    candidates = registry.find_by_operation_and_architecture(operation=operation, architecture=architecture)
    if not candidates:
        return stub_configuration_error_response(
            "no provider advertises requested operation and architecture",
            {"operation": operation, "architecture": architecture},
        )
    if len(candidates) > 1:
        return stub_configuration_error_response(
            "multiple providers advertise requested operation and architecture",
            {
                "operation": operation,
                "architecture": architecture,
                "candidate_provider_names": [candidate.provider_name for candidate in candidates],
            },
        )
    return candidates[0]


def stub_not_implemented_response(
    *,
    provider: ProviderCapability,
    operation: str,
    architecture: str,
    documentation_paths: list[str] | None = None,
) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.NOT_IMPLEMENTED,
        message=f"{provider.provider_name} advertises stub operation {operation} but is not implemented",
        details={
            "provider_name": provider.provider_name,
            "operation": operation,
            "architecture": architecture,
            "implementation_state": provider.implementation_state,
            "documentation_paths": documentation_paths or [],
            "side_effects": "none",
        },
        suggested_next_actions=["providers.list"],
    )
