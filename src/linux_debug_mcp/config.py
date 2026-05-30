from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from linux_debug_mcp.safety.secrets import SecretReference

_SAFE_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
# Unquoted kernel-arg token: no whitespace (would split the cmdline), no XML- or
# shell-special characters. + % @ are safe additions (not special to the kernel cmdline
# parser, XML text, or — there is no shell — the host).
_KERNEL_ARG_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:=,/+%@-]*\Z")
# Quoted kernel-arg token: key="value". The kernel cmdline parser groups a double-quoted
# value (embedded spaces become part of the single parameter). The value is restricted to
# printable ASCII except " — excluding " (which would close the quote early and split the
# cmdline) and all control characters (C0, DEL, and C1) to match the codebase's control-char
# hygiene. ElementTree escapes the surrounding XML text, and there is no shell, so no
# host-side injection results.
_KERNEL_ARG_QUOTED_PATTERN = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.:/+%@-]*="[\x20-\x21\x23-\x7e]*"\Z')
_MAKE_VAR_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
_CONFIG_LINE_PATTERN = re.compile(
    r'^(?:CONFIG_[A-Z0-9_]+=(?:[ymn]|-?\d+|0x[0-9A-Fa-f]+|"[^"\n\r]*")|# CONFIG_[A-Z0-9_]+ is not set)\Z'
)


def validate_kernel_arg_tokens(value: list[str]) -> list[str]:
    seen_keys: set[str] = set()
    for token in value:
        if not (_KERNEL_ARG_PATTERN.match(token) or _KERNEL_ARG_QUOTED_PATTERN.match(token)):
            raise ValueError(f"unsafe kernel argument token: {token!r}")
        key = token.split("=", 1)[0] if "=" in token else token
        if key in seen_keys:
            raise ValueError(f"duplicate kernel argument key: {key!r}")
        seen_keys.add(key)
    return value


def merge_kernel_args(base: list[str], override: list[str]) -> list[str]:
    def key_of(token: str) -> str:
        return token.split("=", 1)[0] if "=" in token else token

    override_keys = {key_of(token) for token in override}
    merged = [token for token in base if key_of(token) not in override_keys]
    merged.extend(override)
    return merged


def validate_config_line_tokens(value: list[str]) -> list[str]:
    seen_symbols: set[str] = set()
    for line in value:
        if not _CONFIG_LINE_PATTERN.match(line):
            raise ValueError(f"invalid kernel config line: {line!r}")
        symbol = _config_symbol(line)
        if symbol in seen_symbols:
            raise ValueError(f"duplicate kernel config symbol: {symbol!r}")
        seen_symbols.add(symbol)
    return value


def _config_symbol(line: str) -> str:
    if line.startswith("# CONFIG_"):
        return line[len("# ") :].split(" ", 1)[0]
    return line.split("=", 1)[0]


def merge_config_lines(base: list[str], override: list[str]) -> list[str]:
    override_symbols = {_config_symbol(line) for line in override}
    merged = [line for line in base if _config_symbol(line) not in override_symbols]
    merged.extend(override)
    return merged


def validate_make_variable_map(value: dict[str, str]) -> dict[str, str]:
    reserved = {"O", "ARCH", "KBUILD_OUTPUT"}
    for key, item in value.items():
        if key in reserved:
            raise ValueError(f"make variable {key} is provider-owned")
        if not _MAKE_VAR_NAME_PATTERN.match(key):
            raise ValueError(f"make variable {key} is not a simple make variable name")
        if any(unicodedata.category(char) == "Cc" for char in item):
            raise ValueError(f"make variable {key} contains a control character")
    return value


_ALLOWED_SSH_OPTIONS = {
    "ConnectTimeout": {"validator": "timeout"},
    "IdentitiesOnly": {"values": {"yes", "no"}},
    "LogLevel": {"values": {"ERROR", "QUIET", "VERBOSE"}},
    "StrictHostKeyChecking": {"values": {"accept-new", "yes"}},
}
ALLOWED_DEBUG_OPERATIONS = [
    "debug.start_session",
    "debug.interrupt",
    "debug.continue",
    "debug.set_breakpoint",
    "debug.clear_breakpoint",
    "debug.list_breakpoints",
    # Phase C (#81): structured execution-control + stack inspection on the MI engine.
    "debug.step",
    "debug.next",
    "debug.finish",
    "debug.backtrace",
    "debug.list_variables",
    "debug.set_watchpoint",
    "debug.clear_watchpoint",
    "debug.read_registers",
    "debug.read_symbol",
    "debug.read_memory",
    "debug.evaluate",
    # Phase D (#82): load a loadable module's symbols at runtime addresses (sysfs sections +
    # add-symbol-file) so a breakpoint in the module resolves.
    "debug.load_module_symbols",
    "debug.end_session",
    # Finding F14: transport.inject_break is destructive (halts the kernel) — gate it through the
    # same DebugProfile.enabled_operations contract as every other halting/mutating debug op so a
    # read-only profile can refuse it. Kept in this list (not a transport-only list) because the
    # gate is per-DebugProfile and the existing `_ensure_debug_operation_enabled` consumes it.
    "transport.inject_break",
    "debug.introspect.run",
    "debug.introspect.helper",
    # Offline vmcore introspection (#55). Listed for enumerability/consistency;
    # the vmcore path does not call `_ensure_debug_operation_enabled` (no
    # DebugProfile in the request) — it is never gated (§5.6 rule 3).
    "debug.introspect.from_vmcore",
    "debug.introspect.from_vmcore_helper",
    # ADR 0011 / #56: capability token (NOT an MCP tool) gating allow_write=true on the live
    # introspect path. Only ever passed to `_ensure_debug_operation_enabled`, never registered
    # as a tool. A read-only profile narrows `enabled_operations` to exclude it to refuse writes.
    "debug.introspect.write",
]

# Spec §5.2 step 4a: soft cap on introspect step records per run. The handler enforces this
# once, without holding the manifest lock — see spec §5.3 "Soft-cap semantics".
MAX_INTROSPECT_CALLS_PER_RUN = 1000

# Spec §11 open risk 4a: integer-percent threshold for the host-side prelude-cost warning;
# fires when `prelude_ms * 100 >= PRELUDE_WARNING_FRACTION_PCT * timeout_seconds * 1000`.
PRELUDE_WARNING_FRACTION_PCT = 40
TRANSPORT_OPERATIONS = [
    "transport.open",
    "transport.status",
    "transport.health",
    "transport.inject_break",
    "transport.close",
]
TRANSPORT_DESTRUCTIVE_PERMISSIONS = {
    "transport.inject_break": ["drop target kernel into the debugger"],
}
# ADR 0011 / #56: per-call ack required for live introspect write mode (allow_write=true),
# mirroring TRANSPORT_DESTRUCTIVE_PERMISSIONS. Only the live `debug.introspect.run` path has a
# writable target; the vmcore path rejects allow_write upstream and so has no entry here.
INTROSPECT_DESTRUCTIVE_PERMISSIONS = {
    "debug.introspect.run": ["mutate live kernel state via drgn write APIs"],
}


def validate_transport_operation(operation: str) -> str:
    if operation not in TRANSPORT_OPERATIONS:
        raise ValueError(f"unsupported transport operation: {operation}")
    return operation


def missing_destructive_permissions(
    operation: str,
    acknowledged: list[str],
    *,
    registry: dict[str, list[str]] | None = None,
) -> list[str]:
    """Return the destructive permissions an operation requires that the caller has not
    acknowledged. A non-destructive (or unknown) operation requires nothing, so the list is empty.
    The tool layer refuses the call when this is non-empty so an agent never performs a destructive
    operation (drop a kernel into the debugger, mutate live kernel state) without explicit
    acknowledgement. ``registry`` selects the permission table (defaults to
    ``TRANSPORT_DESTRUCTIVE_PERMISSIONS``; introspect passes ``INTROSPECT_DESTRUCTIVE_PERMISSIONS``)."""
    table = registry if registry is not None else TRANSPORT_DESTRUCTIVE_PERMISSIONS
    required = table.get(operation, [])
    acknowledged_set = set(acknowledged)
    return [permission for permission in required if permission not in acknowledged_set]


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def validate_optional_ssh_text(value: str | None) -> str | None:
    if value is not None and (not value or _has_control_character(value)):
        raise ValueError("SSH profile fields must be non-empty and must not contain control characters")
    return value


def validate_ssh_options_map(value: dict[str, str]) -> dict[str, str]:
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
    config_lines: list[str] = Field(default_factory=list)

    def effective_required_tools(self) -> list[str]:
        tools = ["make"]
        for tool in self.required_tools:
            if tool != "make":
                tools.append(tool)
        return tools

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, value: list[str]) -> list[str]:
        target_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./+-]*\Z")
        for target in value:
            if not target_pattern.match(target):
                raise ValueError(f"target {target!r} is not a simple make target")
        return value

    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_make_variable_map(value)

    @field_validator("config_lines")
    @classmethod
    def validate_config_lines(cls, value: list[str]) -> list[str]:
        return validate_config_line_tokens(value)


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
        return validate_optional_ssh_text(value)

    @field_validator("ssh_options")
    @classmethod
    def validate_ssh_options(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_ssh_options_map(value)


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

    @field_validator("kernel_args")
    @classmethod
    def validate_kernel_args(cls, value: list[str]) -> list[str]:
        return validate_kernel_arg_tokens(value)


class BuildOverrides(ConfigModel):
    make_variables: dict[str, str] = Field(default_factory=dict)
    config_lines: list[str] = Field(default_factory=list)

    @field_validator("make_variables")
    @classmethod
    def validate_make_variables(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_make_variable_map(value)

    @field_validator("config_lines")
    @classmethod
    def validate_config_lines(cls, value: list[str]) -> list[str]:
        return validate_config_line_tokens(value)


class RootfsOverrides(ConfigModel):
    """Per-run overrides for RootfsProfile fields other than `source` (handled by rootfs_source).

    Each field is None when not overridden. Validation mirrors the corresponding RootfsProfile
    field so an override cannot produce an invalid profile.
    """

    mutability: Literal["read_only", "copy_on_write", "mutable"] | None = None
    access_method: Literal["ssh", "serial", "ssh_and_serial", "none"] | None = None
    readiness_marker: str | None = None
    ssh_host: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_user: str | None = None
    ssh_key_ref: str | None = None
    ssh_options: dict[str, str] | None = None

    @field_validator("ssh_host", "ssh_user", "ssh_key_ref")
    @classmethod
    def validate_optional_ssh_text(cls, value: str | None) -> str | None:
        return validate_optional_ssh_text(value)

    @field_validator("readiness_marker")
    @classmethod
    def validate_readiness_marker(cls, value: str | None) -> str | None:
        if value is not None and (not value or _has_control_character(value)):
            raise ValueError("readiness_marker must be non-empty and free of control characters")
        return value

    @field_validator("ssh_options")
    @classmethod
    def validate_ssh_options(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return value if value is None else validate_ssh_options_map(value)

    def as_profile_update(self) -> dict[str, object]:
        """Return the set overrides as a RootfsProfile.model_copy update mapping."""
        return self.model_dump(exclude_none=True)


class BootOverrides(ConfigModel):
    kernel_args: list[str] = Field(default_factory=list)
    rootfs_source: str | None = None
    rootfs: RootfsOverrides | None = None

    @field_validator("kernel_args")
    @classmethod
    def validate_kernel_args(cls, value: list[str]) -> list[str]:
        return validate_kernel_arg_tokens(value)

    @field_validator("rootfs_source")
    @classmethod
    def validate_rootfs_source(cls, value: str | None) -> str | None:
        # Structural check only; path-safety (existence, overlap, metacharacters) is enforced at handler time.
        if value is not None and (not value or _has_control_character(value)):
            raise ValueError("rootfs_source must be non-empty and free of control characters")
        return value

    def has_rootfs_field_overrides(self) -> bool:
        return self.rootfs is not None and bool(self.rootfs.as_profile_update())


class DebugProfile(ConfigModel):
    name: str
    enabled_operations: list[str] = Field(default_factory=lambda: list(ALLOWED_DEBUG_OPERATIONS))
    kaslr_policy: Literal["disabled"] = "disabled"
    symbol_identity_required: bool = True
    evaluation_mode: Literal["predefined_inspectors"] = "predefined_inspectors"

    @field_validator("enabled_operations")
    @classmethod
    def validate_enabled_operations(cls, value: list[str]) -> list[str]:
        supported = set(ALLOWED_DEBUG_OPERATIONS)
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
    def profile_keys_match_names(
        cls,
        value: dict[str, BuildProfile | RootfsProfile | TargetProfile | DebugProfile | TestSuiteProfile],
        info: ValidationInfo,
    ) -> dict[str, BuildProfile | RootfsProfile | TargetProfile | DebugProfile | TestSuiteProfile]:
        for key, profile in value.items():
            if key != profile.name:
                raise ValueError(f"{info.field_name} profile key must match profile name")
        return value
