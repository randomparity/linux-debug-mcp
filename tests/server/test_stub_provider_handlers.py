from __future__ import annotations

import inspect
import socket
import subprocess
from pathlib import Path
from typing import get_type_hints

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.domain import ToolResponse
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
    console_open_session_handler,
    console_read_handler,
    console_write_handler,
    hardware_boot_kernel_handler,
    hardware_power_control_handler,
    provision_prepare_target_handler,
    remote_build_kernel_handler,
    remote_sync_artifacts_handler,
    reservation_release_host_handler,
    reservation_request_host_handler,
    workflow_reserve_provision_boot_handler,
)
from kdive.providers.local.build.local_kernel_build import LocalKernelBuildProvider
from kdive.providers.local.local_ssh_tests import LocalSshTestProvider
from kdive.providers.local.target.libvirt_qemu import LibvirtQemuProvider
from kdive.providers.registry import ProviderRegistry
from kdive.providers.stubs import remote_build_stub_capability
from kdive.server import create_app
from kdive.tools import providers as provider_tools

VALID_CALLS = [
    (
        remote_build_kernel_handler,
        {
            "architecture": "ppc64le",
            "source_ref": "linux-src",
            "build_profile": "defconfig",
        },
        "remote-build-stub",
        "remote.build_kernel",
    ),
    (
        remote_sync_artifacts_handler,
        {
            "architecture": "ppc64le",
            "external_artifact_ref": "kernel-image",
        },
        "remote-artifact-sync-stub",
        "remote.sync_artifacts",
    ),
    (
        reservation_request_host_handler,
        {
            "architecture": "ppc64le",
            "reservation_pool": "lab-a",
        },
        "reservation-stub",
        "reservation.request_host",
    ),
    (
        reservation_release_host_handler,
        {
            "architecture": "ppc64le",
            "reservation_id": "reservation-1",
        },
        "reservation-stub",
        "reservation.release_host",
    ),
    (
        provision_prepare_target_handler,
        {
            "architecture": "ppc64le",
            "target_name": "host-01",
            "provisioning_profile": "fedora",
        },
        "provisioning-stub",
        "provision.prepare_target",
    ),
    (
        hardware_power_control_handler,
        {
            "architecture": "ppc64le",
            "target_name": "host-01",
            "action": "cycle",
        },
        "hardware-control-stub",
        "hardware.power_control",
    ),
    (
        hardware_boot_kernel_handler,
        {
            "architecture": "ppc64le",
            "target_name": "host-01",
            "kernel_artifact_ref": "kernel-image",
        },
        "real-boot-stub",
        "hardware.boot_kernel",
    ),
    (
        console_open_session_handler,
        {
            "architecture": "ppc64le",
            "target_name": "host-01",
            "access_method": "serial",
        },
        "console-access-stub",
        "console.open_session",
    ),
    (
        console_read_handler,
        {
            "architecture": "ppc64le",
            "console_session_id": "console-1",
            "max_bytes": 128,
        },
        "console-access-stub",
        "console.read",
    ),
    (
        console_write_handler,
        {
            "architecture": "ppc64le",
            "console_session_id": "console-1",
            "data": "help\n",
        },
        "console-access-stub",
        "console.write",
    ),
    (
        workflow_reserve_provision_boot_handler,
        {
            "architecture": "ppc64le",
            "reservation_pool": "lab-a",
            "target_name": "host-01",
            "provisioning_profile": "fedora",
            "kernel_artifact_ref": "kernel-image",
        },
        "real-boot-stub",
        "workflow.reserve_provision_boot",
    ),
]

REQUEST_BY_HANDLER = {
    remote_build_kernel_handler: RemoteBuildRequest,
    remote_sync_artifacts_handler: RemoteArtifactSyncRequest,
    reservation_request_host_handler: ReservationRequest,
    reservation_release_host_handler: ReservationReleaseRequest,
    provision_prepare_target_handler: ProvisioningRequest,
    hardware_power_control_handler: HardwareControlRequest,
    hardware_boot_kernel_handler: RealBootRequest,
    console_open_session_handler: ConsoleSessionRequest,
    console_read_handler: ConsoleReadRequest,
    console_write_handler: ConsoleWriteRequest,
    workflow_reserve_provision_boot_handler: ReserveProvisionBootRequest,
}


def _request_for(handler, payload):
    return REQUEST_BY_HANDLER[handler](**payload)


def _tool_response(tool_name: str, **payload) -> ToolResponse:
    raw = create_app()._tool_manager._tools[tool_name].fn(**payload)
    return ToolResponse.model_validate(raw)


def test_stub_provider_handlers_take_typed_request_models() -> None:
    signature = inspect.signature(remote_build_kernel_handler)
    assert "kwargs" not in signature.parameters
    assert get_type_hints(remote_build_kernel_handler)["request"] is RemoteBuildRequest
    assert remote_build_kernel_handler.__module__ == "kdive.providers.handlers"


def test_stub_provider_handlers_are_real_static_functions() -> None:
    from kdive.providers import handlers

    source = inspect.getsource(handlers)

    assert "globals()[" not in source
    assert ".__annotations__" not in source


def test_stub_provider_runtime_vocabulary_does_not_use_future_terms() -> None:
    from kdive.providers import handlers

    provider_handler_names = {name for name in vars(handlers) if "future" in name.lower() or "Future" in name}
    provider_tool_names = {name for name in vars(provider_tools) if "future" in name.lower() or "Future" in name}

    assert provider_handler_names == set()
    assert provider_tool_names == set()


def test_stub_provider_handler_validates_direct_call_request_type() -> None:
    response = remote_build_kernel_handler(request=ProviderRequest(architecture="ppc64le"))

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert response.error.message == "stub provider request failed validation"
    assert response.error.details == {
        "validation_errors": [
            {"field": "source_ref", "type": "missing"},
            {"field": "build_profile", "type": "missing"},
        ]
    }


def test_stub_provider_handlers_are_generated_from_operation_table() -> None:
    for handler, _, _, operation in VALID_CALLS:
        spec = STUB_PROVIDER_OPERATIONS[operation]
        assert spec.handler is handler
        assert spec.request_type is REQUEST_BY_HANDLER[handler]


def test_create_app_registers_stub_provider_tools_through_shared_helper() -> None:
    app = create_app()

    assert not hasattr(provider_tools, "_StubProviderPayloadAdapter")
    assert not hasattr(provider_tools, "_provider_payload")

    for _, _, _, operation in VALID_CALLS:
        tool = app._tool_manager._tools[operation]
        assert tool.fn.__module__ == "kdive.tools.providers"


def test_provider_tools_registration_uses_stub_operation_table() -> None:
    for handler, _, _, operation in VALID_CALLS:
        spec = STUB_PROVIDER_OPERATIONS[operation]
        assert spec.handler is handler
        assert spec.request_type is REQUEST_BY_HANDLER[handler]


def test_stub_provider_tool_schema_groups_repeated_provider_metadata() -> None:
    signature = inspect.signature(create_app()._tool_manager._tools["remote.build_kernel"].fn)
    assert "architecture" in signature.parameters
    assert "source_ref" in signature.parameters
    assert "build_profile" in signature.parameters
    assert "provider_context" in signature.parameters
    assert "execution_options" in signature.parameters
    assert "artifact_options" in signature.parameters
    for repeated in ("provider_name", "timeout_seconds", "operation_label", "run_id", "output_artifact_ref"):
        assert repeated not in signature.parameters


def test_stub_provider_tool_request_variation_is_table_driven() -> None:
    specs = provider_tools.STUB_PROVIDER_TOOL_REQUEST_SPECS

    assert set(specs) == {operation for _, _, _, operation in VALID_CALLS}
    assert specs["remote.build_kernel"].request_type is RemoteBuildRequest
    assert specs["remote.build_kernel"].operation_fields == ("source_ref", "build_profile")
    assert specs["remote.build_kernel"].options_model is provider_tools.RemoteBuildArtifactOptions
    assert specs["console.write"].request_type is ConsoleWriteRequest
    assert specs["console.write"].operation_fields == ("console_session_id", "data")
    assert specs["console.write"].options_model is None
    assert all(
        spec.common_fields == ("architecture", "provider_context", "execution_options") for spec in specs.values()
    )


def test_stub_provider_tool_grouped_metadata_reaches_request_validation() -> None:
    response = _tool_response(
        "remote.build_kernel",
        architecture="ppc64le",
        source_ref="linux-src",
        build_profile="defconfig",
        provider_context={"provider_name": "missing-provider", "operation_label": "remote-build", "run_id": "run-1"},
        execution_options={"timeout_seconds": 60},
        artifact_options={"output_artifact_ref": "kernel-image"},
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


@pytest.mark.parametrize(("handler", "payload", "provider_name", "operation"), VALID_CALLS)
def test_stub_provider_handlers_return_not_implemented(handler, payload, provider_name: str, operation: str) -> None:
    response = handler(request=_request_for(handler, payload))

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == provider_name
    assert response.error.details["operation"] == operation
    assert response.error.details["architecture"] == payload["architecture"]
    assert response.error.details["implementation_state"] == "stub"
    assert response.error.details["documentation_paths"] == ["docs/ppc64le-provider-spike.md"]
    assert response.suggested_next_actions == ["providers.list"]


def test_stub_provider_handler_maps_malformed_requests_to_configuration_error() -> None:
    response = _tool_response(
        "hardware.power_control",
        architecture="ppc64le",
        target_name="host-01",
        action="restart",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert response.error.details["validation_errors"]


def test_explicit_provider_selection_never_falls_back() -> None:
    response = remote_build_kernel_handler(
        request=RemoteBuildRequest(
            architecture="ppc64le",
            source_ref="linux-src",
            build_profile="defconfig",
            provider_name="reservation-stub",
        )
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "does not advertise" in response.error.message


def test_unknown_explicit_provider_returns_configuration_error() -> None:
    response = remote_build_kernel_handler(
        request=RemoteBuildRequest(
            architecture="ppc64le",
            source_ref="linux-src",
            build_profile="defconfig",
            provider_name="missing-provider",
        )
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


@pytest.mark.parametrize("reservation_id", ["", "../reservation", "bad id"])
def test_reservation_release_rejects_unsafe_reservation_ids(reservation_id: str) -> None:
    response = _tool_response(
        "reservation.release_host",
        architecture="ppc64le",
        reservation_id=reservation_id,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_unsupported_architecture_returns_configuration_error() -> None:
    response = _tool_response(
        "remote.build_kernel",
        architecture="aarch64",
        source_ref="linux-src",
        build_profile="defconfig",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_ambiguous_implicit_provider_selection_includes_candidate_names() -> None:
    registry = ProviderRegistry()
    first = remote_build_stub_capability()
    registry.register(first)
    registry.register(first.model_copy(update={"provider_name": "remote-build-stub-2"}))

    response = remote_build_kernel_handler(
        request=RemoteBuildRequest(
            architecture="ppc64le",
            source_ref="linux-src",
            build_profile="defconfig",
        ),
        registry=registry,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert response.error.details["candidate_provider_names"] == [
        "remote-build-stub",
        "remote-build-stub-2",
    ]


def test_console_write_validation_does_not_accept_credential_ref_or_echo_payload() -> None:
    signature = inspect.signature(create_app()._tool_manager._tools["console.write"].fn)
    assert "credential_ref" not in signature.parameters

    response = _tool_response(
        "console.write",
        architecture="ppc64le",
        console_session_id="console-1",
        data="x" * 4097,
    )

    dumped = str(response.model_dump(mode="json"))
    assert response.ok is False
    assert "x" * 100 not in dumped


@pytest.mark.parametrize(("handler", "payload", "provider_name", "operation"), VALID_CALLS)
def test_stub_provider_handlers_do_not_create_run_workspace_or_touch_forbidden_dependencies(
    handler,
    payload,
    provider_name: str,
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_forbidden_dependency(*args: object, **kwargs: object) -> object:
        raise AssertionError("stub providers must not touch forbidden dependencies")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", fail_forbidden_dependency)
    monkeypatch.setattr(subprocess, "Popen", fail_forbidden_dependency)
    monkeypatch.setattr(socket, "socket", fail_forbidden_dependency)
    monkeypatch.setattr(socket, "create_connection", fail_forbidden_dependency)
    monkeypatch.setattr(Path, "read_text", fail_forbidden_dependency)
    monkeypatch.setattr(Path, "read_bytes", fail_forbidden_dependency)
    monkeypatch.setattr(ArtifactStore, "create_run", fail_forbidden_dependency)
    monkeypatch.setattr(ArtifactStore, "record_step_result", fail_forbidden_dependency)
    monkeypatch.setattr(LocalKernelBuildProvider, "plan_build", fail_forbidden_dependency)
    monkeypatch.setattr(LocalSshTestProvider, "plan_tests", fail_forbidden_dependency)
    monkeypatch.setattr(LibvirtQemuProvider, "plan_boot", fail_forbidden_dependency)

    response = handler(request=_request_for(handler, payload))

    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == provider_name
    assert response.error.details["operation"] == operation
    assert not (tmp_path / ".kdive" / "runs").exists()


def test_console_open_ipmi_cipher_zero_is_configuration_error() -> None:
    response = _tool_response(
        "console.open_session",
        architecture="x86_64",
        target_name="host-01",
        access_method="ipmi-sol",
        console_options={"ipmi_cipher_suite": 0},
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    fields = [item["field"] for item in response.error.details["validation_errors"]]
    assert any("ipmi_cipher_suite" in field for field in fields)
    assert response.suggested_next_actions == ["providers.list"]


def test_console_open_ipmi_default_cipher_reaches_not_implemented() -> None:
    response = console_open_session_handler(
        request=ConsoleSessionRequest(
            architecture="x86_64",
            target_name="host-01",
            access_method="ipmi-sol",
        )
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == "console-access-stub"
    assert response.error.details["operation"] == "console.open_session"


def test_console_open_cipher_on_ssh_is_configuration_error() -> None:
    response = _tool_response(
        "console.open_session",
        architecture="x86_64",
        target_name="host-01",
        access_method="ssh",
        console_options={"ipmi_cipher_suite": 3},
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
