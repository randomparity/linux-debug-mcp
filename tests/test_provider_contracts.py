from __future__ import annotations

import pytest
from pydantic import ValidationError

from kdive.providers.contracts.models import (
    ConsoleReadRequest,
    ConsoleReadResult,
    ConsoleSessionRequest,
    ConsoleWriteRequest,
    ConsoleWriteResult,
    HardwareControlRequest,
    HardwareControlResult,
    ProvisioningRequest,
    ProvisioningResult,
    RealBootRequest,
    RealBootResult,
    RemoteArtifactSyncRequest,
    RemoteArtifactSyncResult,
    RemoteBuildRequest,
    RemoteBuildResult,
    ReservationReleaseRequest,
    ReservationRequest,
    ReservationResult,
    ReserveProvisionBootRequest,
)


def assert_rejects(model: type, payload: dict, *, hidden: str | None = None) -> None:
    with pytest.raises(ValidationError) as exc_info:
        model(**payload)
    if hidden:
        assert hidden not in str(exc_info.value)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            RemoteBuildRequest,
            {
                "architecture": "x86_64",
                "source_ref": "linux-src",
                "build_profile": "defconfig",
                "provider_name": "remote-build-stub",
                "timeout_seconds": 3600,
                "operation_label": "nightly.build",
                "run_id": "run-abc123",
                "output_artifact_ref": "kernel-image",
            },
        ),
        (
            RemoteArtifactSyncRequest,
            {
                "architecture": "ppc64le",
                "external_artifact_ref": "remote-vmlinux",
                "provider_name": "remote-artifact-sync-stub",
                "timeout_seconds": 60,
                "operation_label": "sync.vmlinux",
                "run_id": "run-abc123",
                "destination_artifact_ref": "local-vmlinux",
            },
        ),
        (
            ReservationRequest,
            {
                "architecture": "ppc64le",
                "reservation_pool": "lab-a",
                "provider_name": "reservation-stub",
                "timeout_seconds": 120,
                "operation_label": "reserve.lab-a",
                "run_id": "run-abc123",
                "reservation_token_ref": "pool-token",
            },
        ),
        (
            ReservationReleaseRequest,
            {
                "architecture": "ppc64le",
                "reservation_id": "reservation-1",
                "provider_name": "reservation-stub",
                "timeout_seconds": 120,
                "operation_label": "release.lab-a",
                "run_id": "run-abc123",
            },
        ),
        (
            ProvisioningRequest,
            {
                "architecture": "ppc64le",
                "target_name": "host-01",
                "provisioning_profile": "fedora-rawhide",
                "provider_name": "provisioning-stub",
                "timeout_seconds": 1800,
                "operation_label": "provision.host-01",
                "run_id": "run-abc123",
                "reservation_id": "reservation-1",
                "credential_ref": "provision-creds",
            },
        ),
        (
            HardwareControlRequest,
            {
                "architecture": "ppc64le",
                "target_name": "host-01",
                "action": "cycle",
                "provider_name": "hardware-control-stub",
                "timeout_seconds": 120,
                "operation_label": "power-cycle",
                "run_id": "run-abc123",
                "bmc_credential_ref": "bmc-creds",
            },
        ),
        (
            ConsoleSessionRequest,
            {
                "architecture": "x86_64",
                "target_name": "vm-01",
                "access_method": "serial",
                "provider_name": "console-access-stub",
                "timeout_seconds": 30,
                "operation_label": "console-open",
                "run_id": "run-abc123",
                "credential_ref": "console-creds",
            },
        ),
        (
            ConsoleReadRequest,
            {
                "architecture": "x86_64",
                "console_session_id": "console-1",
                "max_bytes": 4096,
                "provider_name": "console-access-stub",
                "timeout_seconds": 30,
                "operation_label": "console-read",
                "run_id": "run-abc123",
            },
        ),
        (
            ConsoleWriteRequest,
            {
                "architecture": "x86_64",
                "console_session_id": "console-1",
                "data": "reboot\n",
                "provider_name": "console-access-stub",
                "timeout_seconds": 30,
                "operation_label": "console-write",
                "run_id": "run-abc123",
            },
        ),
        (
            RealBootRequest,
            {
                "architecture": "ppc64le",
                "target_name": "host-01",
                "kernel_artifact_ref": "kernel-image",
                "provider_name": "real-boot-stub",
                "timeout_seconds": 600,
                "operation_label": "boot-real-target",
                "run_id": "run-abc123",
                "boot_profile": "serial-console",
                "reservation_id": "reservation-1",
            },
        ),
        (
            ReserveProvisionBootRequest,
            {
                "architecture": "ppc64le",
                "reservation_pool": "lab-a",
                "target_name": "host-01",
                "provisioning_profile": "fedora-rawhide",
                "kernel_artifact_ref": "kernel-image",
                "provider_name": "real-boot-stub",
                "timeout_seconds": 3600,
                "operation_label": "reserve-provision-boot",
                "run_id": "run-abc123",
                "reservation_token_ref": "pool-token",
                "credential_ref": "provision-creds",
                "bmc_credential_ref": "bmc-creds",
            },
        ),
    ],
)
def test_request_models_accept_safe_common_fields(model: type, payload: dict) -> None:
    request = model(**payload)

    assert request.provider_name == payload["provider_name"]
    assert request.architecture == payload["architecture"]
    assert request.timeout_seconds == payload["timeout_seconds"]
    assert request.operation_label == payload["operation_label"]
    assert request.run_id == payload["run_id"]


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            RemoteBuildResult,
            {
                "provider_name": "remote-build-stub",
                "architecture": "x86_64",
                "build_id": "build-1",
                "kernel_artifact_ref": "kernel-image",
            },
        ),
        (
            RemoteArtifactSyncResult,
            {
                "provider_name": "remote-artifact-sync-stub",
                "architecture": "ppc64le",
                "sync_id": "sync-1",
                "artifact_ref": "vmlinux",
                "byte_count": 42,
            },
        ),
        (
            ReservationResult,
            {
                "provider_name": "reservation-stub",
                "architecture": "ppc64le",
                "reservation_id": "reservation-1",
                "target_name": "host-01",
            },
        ),
        (
            ProvisioningResult,
            {
                "provider_name": "provisioning-stub",
                "architecture": "ppc64le",
                "provisioning_id": "provision-1",
                "target_name": "host-01",
            },
        ),
        (
            HardwareControlResult,
            {
                "provider_name": "hardware-control-stub",
                "architecture": "ppc64le",
                "target_name": "host-01",
                "action": "cycle",
                "power_state": "on",
            },
        ),
        (
            ConsoleReadResult,
            {
                "provider_name": "console-access-stub",
                "architecture": "x86_64",
                "console_session_id": "console-1",
                "data": "booted\n",
                "byte_count": 7,
            },
        ),
        (
            ConsoleWriteResult,
            {
                "provider_name": "console-access-stub",
                "architecture": "x86_64",
                "console_session_id": "console-1",
                "byte_count": 7,
            },
        ),
        (
            RealBootResult,
            {
                "provider_name": "real-boot-stub",
                "architecture": "ppc64le",
                "boot_id": "boot-1",
                "target_name": "host-01",
                "console_session_id": "console-1",
            },
        ),
    ],
)
def test_result_models_accept_minimal_safe_results(model: type, payload: dict) -> None:
    result = model(**payload)

    assert result.provider_name == payload["provider_name"]
    assert result.architecture == payload["architecture"]
    assert result.status == "not_implemented"


@pytest.mark.parametrize("model", [RemoteBuildRequest, ConsoleReadRequest, HardwareControlRequest])
def test_requests_reject_missing_architecture(model: type) -> None:
    payloads = {
        RemoteBuildRequest: {"source_ref": "linux-src", "build_profile": "defconfig"},
        ConsoleReadRequest: {"console_session_id": "console-1"},
        HardwareControlRequest: {"target_name": "host-01", "action": "on"},
    }

    assert_rejects(model, payloads[model])


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            RemoteBuildRequest,
            {
                "architecture": "x86_64",
                "source_ref": "linux-src",
                "build_profile": "defconfig",
                "provider_name": "",
            },
        ),
        (
            ReservationRequest,
            {
                "architecture": "x86_64",
                "reservation_pool": "bad pool",
            },
        ),
        (
            ConsoleReadRequest,
            {
                "architecture": "x86_64",
                "console_session_id": "",
            },
        ),
        (
            ReservationReleaseRequest,
            {
                "architecture": "x86_64",
                "reservation_id": "../reservation",
            },
        ),
        (
            RealBootRequest,
            {
                "architecture": "x86_64",
                "target_name": "../host",
                "kernel_artifact_ref": "kernel-image",
            },
        ),
    ],
)
def test_requests_reject_unsafe_labels(model: type, payload: dict) -> None:
    assert_rejects(model, payload)


@pytest.mark.parametrize("architecture", ["aarch64", "powerpc", ""])
def test_requests_reject_unknown_architectures(architecture: str) -> None:
    assert_rejects(
        RemoteBuildRequest,
        {"architecture": architecture, "source_ref": "linux-src", "build_profile": "defconfig"},
        hidden=architecture,
    )


@pytest.mark.parametrize("timeout_seconds", [0, -1, 86401])
def test_requests_reject_invalid_timeouts(timeout_seconds: int) -> None:
    assert_rejects(
        ReservationRequest,
        {"architecture": "x86_64", "reservation_pool": "lab-a", "timeout_seconds": timeout_seconds},
    )


@pytest.mark.parametrize("action", ["restart", "shell", ""])
def test_hardware_control_rejects_invalid_power_actions(action: str) -> None:
    assert_rejects(
        HardwareControlRequest,
        {"architecture": "x86_64", "target_name": "host-01", "action": action},
        hidden=action,
    )


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            ConsoleReadRequest,
            {"architecture": "x86_64", "console_session_id": "console-1", "max_bytes": 0},
        ),
        (
            ConsoleReadRequest,
            {"architecture": "x86_64", "console_session_id": "console-1", "max_bytes": 1048577},
        ),
        (
            ConsoleReadResult,
            {
                "provider_name": "console-access-stub",
                "architecture": "x86_64",
                "console_session_id": "console-1",
                "byte_count": -1,
            },
        ),
        (
            ConsoleWriteResult,
            {
                "provider_name": "console-access-stub",
                "architecture": "x86_64",
                "console_session_id": "console-1",
                "byte_count": 4097,
            },
        ),
        (
            RemoteArtifactSyncResult,
            {
                "provider_name": "remote-artifact-sync-stub",
                "architecture": "x86_64",
                "byte_count": -1,
            },
        ),
    ],
)
def test_models_reject_invalid_byte_counts(model: type, payload: dict) -> None:
    assert_rejects(model, payload)


@pytest.mark.parametrize(
    ("payload", "hidden"),
    [
        ({"architecture": "x86_64", "console_session_id": "console-1", "data": ""}, ""),
        (
            {"architecture": "x86_64", "console_session_id": "console-1", "data": "x" * 4097},
            "x" * 4097,
        ),
        (
            {"architecture": "x86_64", "console_session_id": "console-1", "data": "TOKEN=super-secret"},
            "super-secret",
        ),
    ],
)
def test_console_write_rejects_empty_oversized_or_raw_secret_payloads(payload: dict, hidden: str) -> None:
    if payload["data"].startswith("TOKEN="):
        payload = {**payload, "token": payload["data"]}
    assert_rejects(ConsoleWriteRequest, payload, hidden=hidden)


@pytest.mark.parametrize(
    ("model", "payload", "hidden"),
    [
        (
            ProvisioningRequest,
            {
                "architecture": "x86_64",
                "target_name": "host-01",
                "provisioning_profile": "default",
                "password": "plain-value",  # pragma: allowlist secret
            },
            "plain-value",
        ),
        (
            ReservationRequest,
            {
                "architecture": "x86_64",
                "reservation_pool": "lab-a",
                "reservation_token": "raw-token",
            },
            "raw-token",
        ),
        (
            HardwareControlRequest,
            {
                "architecture": "x86_64",
                "target_name": "host-01",
                "action": "on",
                "bmc_credentials": "raw-creds",
            },
            "raw-creds",
        ),
    ],
)
def test_models_reject_raw_credential_token_or_password_fields(model: type, payload: dict, hidden: str) -> None:
    assert_rejects(model, payload, hidden=hidden)


def _ipmi_request(**overrides: object) -> dict:
    payload = {
        "architecture": "x86_64",
        "target_name": "vm-01",
        "access_method": "ipmi-sol",
    }
    payload.update(overrides)
    return payload


def test_ipmi_sol_defaults_cipher_to_three() -> None:
    request = ConsoleSessionRequest(**_ipmi_request())
    assert request.ipmi_cipher_suite == 3


def test_ipmi_sol_accepts_explicit_cipher_three() -> None:
    request = ConsoleSessionRequest(**_ipmi_request(ipmi_cipher_suite=3))
    assert request.ipmi_cipher_suite == 3


def test_ipmi_sol_rejects_cipher_zero() -> None:
    with pytest.raises(ValidationError) as exc:
        ConsoleSessionRequest(**_ipmi_request(ipmi_cipher_suite=0))
    assert "ipmi_cipher_suite" in str(exc.value)


@pytest.mark.parametrize("suite", [1, 2, 17])
def test_ipmi_sol_rejects_non_allowlisted_cipher(suite: int) -> None:
    assert_rejects(ConsoleSessionRequest, _ipmi_request(ipmi_cipher_suite=suite))


def test_cipher_rejected_for_non_ipmi_method() -> None:
    payload = {
        "architecture": "x86_64",
        "target_name": "vm-01",
        "access_method": "ssh",
        "ipmi_cipher_suite": 3,
    }
    assert_rejects(ConsoleSessionRequest, payload)


def test_serial_method_without_cipher_is_accepted() -> None:
    request = ConsoleSessionRequest(architecture="x86_64", target_name="vm-01", access_method="serial")
    assert request.ipmi_cipher_suite is None


def test_legacy_ipmi_access_method_rejected() -> None:
    payload = {"architecture": "x86_64", "target_name": "vm-01", "access_method": "ipmi"}
    assert_rejects(ConsoleSessionRequest, payload)
