from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from linux_debug_mcp.safety.secrets import SecretReference


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


class RootfsProfile(ConfigModel):
    name: str
    source: str
    mutability: Literal["read_only", "copy_on_write", "mutable"] = "copy_on_write"
    access_method: Literal["ssh", "serial", "ssh_and_serial", "none"] = "ssh"
    credential_refs: list[SecretReference] = Field(default_factory=list)
    readiness_marker: str | None = None
    guest_writable_paths: list[str] = Field(default_factory=list)


class TargetProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str
    target_ref: str | None = None
    kernel_args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    cleanup_policy: Literal["preserve_all", "preserve_failed", "stop_failed", "remove_temporary"] = "preserve_failed"
    debug_gdbstub: bool = False


class DebugProfile(ConfigModel):
    name: str
    enabled_operations: list[str] = Field(default_factory=list)
    gdbstub_endpoint: str | None = None
    kaslr_policy: Literal["disabled", "known", "unknown"] = "disabled"
    symbol_identity_required: bool = True
    evaluation_mode: Literal["disabled", "predefined_inspectors", "limited_expressions"] = "predefined_inspectors"


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
    artifact_policy: ArtifactPolicy = Field(default_factory=ArtifactPolicy)
    logging_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    sensitive_paths: list[Path] = Field(default_factory=list)

    @field_validator("build_profiles", "rootfs_profiles", "target_profiles", "debug_profiles")
    @classmethod
    def profile_keys_match_names(cls, value: dict[str, ConfigModel], info: ValidationInfo) -> dict[str, ConfigModel]:
        for key, profile in value.items():
            if key != profile.name:
                raise ValueError(f"{info.field_name} profile key must match profile name")
        return value
