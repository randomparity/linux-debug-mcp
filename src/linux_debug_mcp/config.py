from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from linux_debug_mcp.safety.secrets import SecretReference

_SAFE_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_ALLOWED_SSH_OPTIONS = {
    "ConnectTimeout": {"validator": "timeout"},
    "IdentitiesOnly": {"values": {"yes", "no"}},
    "LogLevel": {"values": {"ERROR", "QUIET", "VERBOSE"}},
    "StrictHostKeyChecking": {"values": {"accept-new", "yes"}},
}
SPRINT_4_DEBUG_OPERATIONS = [
    "debug.start_session",
    "debug.interrupt",
    "debug.continue",
    "debug.set_breakpoint",
    "debug.clear_breakpoint",
    "debug.list_breakpoints",
    "debug.read_registers",
    "debug.read_symbol",
    "debug.read_memory",
    "debug.evaluate",
    "debug.end_session",
]


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class BuildProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str = "local-kernel-build"
    output_policy: Literal["per_run", "shared"] = "per_run"
    targets: list[str] = Field(default_factory=lambda: ["bzImage"], min_length=1)
    command_timeout_seconds: int = Field(default=3600, ge=1)
    required_tools: list[str] = Field(default_factory=list)
    jobs: int | None = Field(default=None, ge=1)
    make_variables: dict[str, str] = Field(default_factory=dict)
    config_fragments: list[Path] = Field(default_factory=list)

    def effective_required_tools(self) -> list[str]:
        tools = ["make"]
        for tool in self.required_tools:
            if tool != "make":
                tools.append(tool)
        return tools

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, value: list[str]) -> list[str]:
        target_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./+-]*$")
        for target in value:
            if not target_pattern.match(target):
                raise ValueError(f"target {target!r} is not a simple make target")
        return value

    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        reserved = {"O", "ARCH", "KBUILD_OUTPUT"}
        name_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
        for key, item in value.items():
            if key in reserved:
                raise ValueError(f"make variable {key} is provider-owned")
            if not name_pattern.match(key):
                raise ValueError(f"make variable {key} is not a simple make variable name")
            if any(unicodedata.category(char) == "Cc" for char in item):
                raise ValueError(f"make variable {key} contains a control character")
        return value


class TestCommand(ConfigModel):
    name: str
    argv: list[str] = Field(min_length=1)
    timeout_seconds: int | None = Field(default=None, ge=1)
    required: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _SAFE_LABEL_PATTERN.match(value):
            raise ValueError("test command name must be filesystem safe")
        return value

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item:
                raise ValueError("test command argv entries must be non-empty")
            if _has_control_character(item):
                raise ValueError("test command argv entries must not contain control characters")
        return value


class TestSuiteProfile(ConfigModel):
    name: str
    commands: list[TestCommand] = Field(min_length=1)
    timeout_seconds: int = Field(default=30, ge=1)
    stop_on_failure: bool = True
    collect_dmesg: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _SAFE_LABEL_PATTERN.match(value):
            raise ValueError("test suite name must be filesystem safe")
        return value


class RootfsProfile(ConfigModel):
    name: str
    source: str
    source_type: Literal["disk_image", "directory"] = "disk_image"
    mutability: Literal["read_only", "copy_on_write", "mutable"] = "copy_on_write"
    access_method: Literal["ssh", "serial", "ssh_and_serial", "none"] = "ssh"
    credential_refs: list[SecretReference] = Field(default_factory=list)
    readiness_marker: str | None = None
    guest_writable_paths: list[str] = Field(default_factory=list)
    ssh_host: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str | None = None
    ssh_key_ref: str | None = None
    ssh_options: dict[str, str] = Field(default_factory=dict)

    @field_validator("ssh_host", "ssh_user", "ssh_key_ref")
    @classmethod
    def validate_optional_ssh_text(cls, value: str | None) -> str | None:
        if value is not None and (not value or _has_control_character(value)):
            raise ValueError("SSH profile fields must be non-empty and must not contain control characters")
        return value

    @field_validator("ssh_options")
    @classmethod
    def validate_ssh_options(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if key not in _ALLOWED_SSH_OPTIONS:
                raise ValueError(f"unsupported SSH option: {key}")
            if not key or any(char.isspace() or unicodedata.category(char) == "Cc" for char in key):
                raise ValueError("SSH option names must be simple names")
            if not item or _has_control_character(item):
                raise ValueError(f"invalid SSH option value for {key}")
            rule = _ALLOWED_SSH_OPTIONS[key]
            if rule.get("validator") == "timeout":
                try:
                    parsed = int(item)
                except ValueError as exc:
                    raise ValueError("ConnectTimeout must be an integer") from exc
                if parsed < 1 or parsed > 3600:
                    raise ValueError("ConnectTimeout must be between 1 and 3600 seconds")
            elif item not in rule["values"]:
                raise ValueError(f"invalid SSH option value for {key}")
        return value


class TargetProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str = "local-libvirt-qemu"
    target_ref: str | None = None
    kernel_args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    cleanup_policy: Literal["preserve_on_failure", "stop_on_failure"] = "preserve_on_failure"
    debug_gdbstub: bool = False
    gdbstub_endpoint: str = "127.0.0.1:1234"
    libvirt_uri: str | None = None
    managed_domain: bool = False
    managed_domain_prefix: str | None = None


class DebugProfile(ConfigModel):
    name: str
    enabled_operations: list[str] = Field(default_factory=lambda: list(SPRINT_4_DEBUG_OPERATIONS))
    kaslr_policy: Literal["disabled"] = "disabled"
    symbol_identity_required: bool = True
    evaluation_mode: Literal["predefined_inspectors"] = "predefined_inspectors"

    @field_validator("enabled_operations")
    @classmethod
    def validate_enabled_operations(cls, value: list[str]) -> list[str]:
        supported = set(SPRINT_4_DEBUG_OPERATIONS)
        for operation in value:
            if operation not in supported:
                raise ValueError(f"unsupported debug operation: {operation}")
        return value


class ArtifactPolicy(ConfigModel):
    retention_days: int = Field(default=14, ge=1)
    raw_logs_enabled: bool = False
    redact_responses: bool = True
    preserve_failed_runs: bool = True


class ServerConfig(ConfigModel):
    artifact_root: Path
    build_profiles: dict[str, BuildProfile] = Field(default_factory=dict)
    rootfs_profiles: dict[str, RootfsProfile] = Field(default_factory=dict)
    target_profiles: dict[str, TargetProfile] = Field(default_factory=dict)
    debug_profiles: dict[str, DebugProfile] = Field(default_factory=dict)
    test_suites: dict[str, TestSuiteProfile] = Field(default_factory=dict)
    artifact_policy: ArtifactPolicy = Field(default_factory=ArtifactPolicy)
    logging_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    sensitive_paths: list[Path] = Field(default_factory=list)

    @field_validator("build_profiles", "rootfs_profiles", "target_profiles", "debug_profiles", "test_suites")
    @classmethod
    def profile_keys_match_names(cls, value: dict[str, ConfigModel], info: ValidationInfo) -> dict[str, ConfigModel]:
        for key, profile in value.items():
            if key != profile.name:
                raise ValueError(f"{info.field_name} profile key must match profile name")
        return value
