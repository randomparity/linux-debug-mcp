from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from kdive.artifacts.store import ArtifactStore
from kdive.providers.libvirt_qemu import LibvirtQemuProvider
from kdive.providers.local_kernel_build import LocalKernelBuildProvider
from kdive.providers.local_ssh_tests import LocalSshTestProvider
from kdive.providers.registry import ProviderRegistry
from kdive.providers.stubs import remote_build_stub_capability
from kdive.server import (
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


@pytest.mark.parametrize(("handler", "payload", "provider_name", "operation"), VALID_CALLS)
def test_future_stub_handlers_return_not_implemented(handler, payload, provider_name: str, operation: str) -> None:
    response = handler(**payload)

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == provider_name
    assert response.error.details["operation"] == operation
    assert response.error.details["architecture"] == payload["architecture"]
    assert response.error.details["implementation_state"] == "stub"
    assert response.error.details["documentation_paths"] == ["docs/ppc64le-provider-spike.md"]
    assert response.suggested_next_actions == ["providers.list"]


def test_future_stub_handler_maps_malformed_requests_to_configuration_error() -> None:
    response = hardware_power_control_handler(
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
        architecture="ppc64le",
        source_ref="linux-src",
        build_profile="defconfig",
        provider_name="reservation-stub",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "does not advertise" in response.error.message


def test_unknown_explicit_provider_returns_configuration_error() -> None:
    response = remote_build_kernel_handler(
        architecture="ppc64le",
        source_ref="linux-src",
        build_profile="defconfig",
        provider_name="missing-provider",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


@pytest.mark.parametrize("reservation_id", ["", "../reservation", "bad id"])
def test_reservation_release_rejects_unsafe_reservation_ids(reservation_id: str) -> None:
    response = reservation_release_host_handler(
        architecture="ppc64le",
        reservation_id=reservation_id,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_unsupported_architecture_returns_configuration_error() -> None:
    response = remote_build_kernel_handler(
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
        architecture="ppc64le",
        source_ref="linux-src",
        build_profile="defconfig",
        registry=registry,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert response.error.details["candidate_provider_names"] == [
        "remote-build-stub",
        "remote-build-stub-2",
    ]


def test_console_write_validation_does_not_echo_payload_or_credential_refs() -> None:
    response = console_write_handler(
        architecture="ppc64le",
        console_session_id="console-1",
        data="x" * 4097,
        credential_ref="credential-ref-1",
    )

    dumped = str(response.model_dump(mode="json"))
    assert response.ok is False
    assert "x" * 100 not in dumped
    assert "credential-ref-1" not in dumped


@pytest.mark.parametrize(("handler", "payload", "provider_name", "operation"), VALID_CALLS)
def test_future_stub_handlers_do_not_create_run_workspace_or_touch_forbidden_dependencies(
    handler,
    payload,
    provider_name: str,
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_forbidden_dependency(*args: object, **kwargs: object) -> object:
        raise AssertionError("future stubs must not touch forbidden dependencies")

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

    response = handler(**payload)

    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == provider_name
    assert response.error.details["operation"] == operation
    assert not (tmp_path / ".kdive" / "runs").exists()


def test_console_open_ipmi_cipher_zero_is_configuration_error() -> None:
    response = console_open_session_handler(
        architecture="x86_64",
        target_name="host-01",
        access_method="ipmi-sol",
        ipmi_cipher_suite=0,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    fields = [item["field"] for item in response.error.details["validation_errors"]]
    assert any("ipmi_cipher_suite" in field for field in fields)
    assert response.suggested_next_actions == ["providers.list"]


def test_console_open_ipmi_default_cipher_reaches_not_implemented() -> None:
    response = console_open_session_handler(
        architecture="x86_64",
        target_name="host-01",
        access_method="ipmi-sol",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["provider_name"] == "console-access-stub"
    assert response.error.details["operation"] == "console.open_session"


def test_console_open_cipher_on_ssh_is_configuration_error() -> None:
    response = console_open_session_handler(
        architecture="x86_64",
        target_name="host-01",
        access_method="ssh",
        ipmi_cipher_suite=3,
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
