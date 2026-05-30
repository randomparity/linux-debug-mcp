from __future__ import annotations

import re
import unicodedata
from typing import Any, ClassVar

from pydantic import ConfigDict, Field, field_validator, model_validator

from kdive.domain import Model
from kdive.safety.ipmi import check_ipmi_cipher_value, validate_ipmi_cipher_suite

KNOWN_ARCHITECTURES = {"x86_64", "ppc64le"}
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_CONSOLE_READ_BYTES = 1024 * 1024
MAX_CONSOLE_WRITE_BYTES = 4096

_SAFE_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_RAW_SECRET_MARKERS = ("password", "secret", "token", "credential")
_ALLOWED_SECRET_REFERENCE_FIELDS = {
    "credential_ref",
    "ssh_key_ref",
    "bmc_credential_ref",
    "reservation_token_ref",
}
_POWER_ACTIONS = {"on", "off", "cycle", "reset"}
_CONSOLE_ACCESS_METHODS = {"serial", "ssh", "ipmi-sol"}


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def _validate_safe_label(value: str, *, field_name: str) -> str:
    if not _SAFE_LABEL_PATTERN.match(value) or _has_control_character(value):
        raise ValueError(f"{field_name} must be a safe label")
    return value


def _safe_fields(base: frozenset[str], *field_names: str) -> frozenset[str]:
    return base | frozenset(field_names)


def _reject_raw_secret_fields(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    for key in data:
        normalized = str(key).lower()
        if normalized in _ALLOWED_SECRET_REFERENCE_FIELDS or normalized.endswith("_ref"):
            continue
        if any(marker in normalized for marker in _RAW_SECRET_MARKERS):
            raise ValueError("raw secret fields are not allowed; use reference fields")
    return data


class ProviderContractModel(Model):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, hide_input_in_errors=True)

    _safe_label_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def reject_raw_secret_fields(cls, data: Any) -> Any:
        return _reject_raw_secret_fields(data)

    @field_validator("*")
    @classmethod
    def validate_common_safe_labels(cls, value: Any, info: Any) -> Any:
        if value is None or info.field_name not in cls._safe_label_fields:
            return value
        if not isinstance(value, str):
            raise ValueError(f"{info.field_name} must be a safe label")
        return _validate_safe_label(value, field_name=info.field_name)

    @field_validator("architecture", check_fields=False)
    @classmethod
    def validate_architecture(cls, value: str) -> str:
        if value not in KNOWN_ARCHITECTURES:
            raise ValueError("architecture is not supported")
        return value

    @field_validator("timeout_seconds", check_fields=False)
    @classmethod
    def validate_timeout_seconds(cls, value: int) -> int:
        if value < 1 or value > MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds must be within the allowed range")
        return value


class ProviderRequest(ProviderContractModel):
    provider_name: str | None = None
    architecture: str
    timeout_seconds: int = Field(default=300)
    operation_label: str | None = None
    run_id: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = frozenset(
        {"provider_name", "architecture", "operation_label", "run_id"}
    )


class ProviderResult(ProviderContractModel):
    provider_name: str
    architecture: str
    operation_label: str | None = None
    run_id: str | None = None
    status: str = "not_implemented"
    message: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = frozenset(
        {"provider_name", "architecture", "operation_label", "run_id", "status"}
    )


class RemoteBuildRequest(ProviderRequest):
    source_ref: str
    build_profile: str
    output_artifact_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "source_ref",
        "build_profile",
        "output_artifact_ref",
    )


class RemoteBuildResult(ProviderResult):
    build_id: str | None = None
    kernel_artifact_ref: str | None = None
    log_artifact_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "build_id",
        "kernel_artifact_ref",
        "log_artifact_ref",
    )


class RemoteArtifactSyncRequest(ProviderRequest):
    external_artifact_ref: str
    destination_artifact_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "external_artifact_ref",
        "destination_artifact_ref",
    )


class RemoteArtifactSyncResult(ProviderResult):
    sync_id: str | None = None
    artifact_ref: str | None = None
    byte_count: int | None = Field(default=None, ge=0)

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "sync_id",
        "artifact_ref",
    )


class ReservationRequest(ProviderRequest):
    reservation_pool: str
    reservation_token_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "reservation_pool",
        "reservation_token_ref",
    )


class ReservationReleaseRequest(ProviderRequest):
    reservation_id: str

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(ProviderRequest._safe_label_fields, "reservation_id")


class ReservationResult(ProviderResult):
    reservation_id: str | None = None
    target_name: str | None = None
    expires_at: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "reservation_id",
        "target_name",
    )


class ProvisioningRequest(ProviderRequest):
    target_name: str
    provisioning_profile: str
    reservation_id: str | None = None
    credential_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "target_name",
        "provisioning_profile",
        "reservation_id",
        "credential_ref",
    )


class ProvisioningResult(ProviderResult):
    provisioning_id: str | None = None
    target_name: str | None = None
    image_artifact_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "provisioning_id",
        "target_name",
        "image_artifact_ref",
    )


class HardwareControlRequest(ProviderRequest):
    target_name: str
    action: str
    bmc_credential_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "target_name",
        "bmc_credential_ref",
    )

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        if value not in _POWER_ACTIONS:
            raise ValueError("power action is not supported")
        return value


class HardwareControlResult(ProviderResult):
    target_name: str | None = None
    action: str | None = None
    power_state: str | None = None
    external_task_id: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "target_name",
        "action",
        "power_state",
        "external_task_id",
    )


class ConsoleSessionRequest(ProviderRequest):
    target_name: str
    access_method: str
    credential_ref: str | None = None
    ipmi_cipher_suite: int | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "target_name",
        "access_method",
        "credential_ref",
    )

    @field_validator("access_method")
    @classmethod
    def validate_access_method(cls, value: str) -> str:
        if value not in _CONSOLE_ACCESS_METHODS:
            raise ValueError("console access method is not supported")
        return value

    @field_validator("ipmi_cipher_suite")
    @classmethod
    def validate_cipher_value(cls, value: int | None) -> int | None:
        if value is None:
            return value
        return check_ipmi_cipher_value(value)

    @model_validator(mode="after")
    def enforce_ipmi_cipher_policy(self) -> ConsoleSessionRequest:
        if self.access_method == "ipmi-sol":
            normalized = validate_ipmi_cipher_suite(self.ipmi_cipher_suite)
            if normalized != self.ipmi_cipher_suite:
                object.__setattr__(self, "ipmi_cipher_suite", normalized)
        elif self.ipmi_cipher_suite is not None:
            raise ValueError("ipmi_cipher_suite is only valid for access_method 'ipmi-sol'")
        return self


class ConsoleReadRequest(ProviderRequest):
    console_session_id: str
    max_bytes: int = Field(default=4096, ge=1, le=MAX_CONSOLE_READ_BYTES)

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "console_session_id",
    )


class ConsoleReadResult(ProviderResult):
    console_session_id: str
    data: str = ""
    byte_count: int = Field(default=0, ge=0, le=MAX_CONSOLE_READ_BYTES)
    truncated: bool = False

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "console_session_id",
    )


class ConsoleWriteRequest(ProviderRequest):
    console_session_id: str
    data: str

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "console_session_id",
    )

    @field_validator("data")
    @classmethod
    def validate_data(cls, value: str) -> str:
        encoded_length = len(value.encode("utf-8"))
        if encoded_length < 1 or encoded_length > MAX_CONSOLE_WRITE_BYTES:
            raise ValueError("console write payload length is not allowed")
        return value


class ConsoleWriteResult(ProviderResult):
    console_session_id: str
    byte_count: int = Field(default=0, ge=0, le=MAX_CONSOLE_WRITE_BYTES)

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "console_session_id",
    )


class RealBootRequest(ProviderRequest):
    target_name: str
    kernel_artifact_ref: str
    boot_profile: str | None = None
    reservation_id: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "target_name",
        "kernel_artifact_ref",
        "boot_profile",
        "reservation_id",
    )


class RealBootResult(ProviderResult):
    boot_id: str | None = None
    target_name: str | None = None
    console_session_id: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderResult._safe_label_fields,
        "boot_id",
        "target_name",
        "console_session_id",
    )


class ReserveProvisionBootRequest(ProviderRequest):
    reservation_pool: str
    target_name: str
    provisioning_profile: str
    kernel_artifact_ref: str
    reservation_token_ref: str | None = None
    credential_ref: str | None = None
    bmc_credential_ref: str | None = None

    _safe_label_fields: ClassVar[frozenset[str]] = _safe_fields(
        ProviderRequest._safe_label_fields,
        "reservation_pool",
        "target_name",
        "provisioning_profile",
        "kernel_artifact_ref",
        "reservation_token_ref",
        "credential_ref",
        "bmc_credential_ref",
    )
