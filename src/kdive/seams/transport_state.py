from __future__ import annotations

import ipaddress
import math
import unicodedata
import uuid
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, field_serializer, field_validator

from kdive.domain import ArtifactRef, Model
from kdive.seams.target import (
    Arch,
    KernelProvenance,
    LeaseInfo,
    PlatformMetadata,
    SshEndpoint,
    TargetKey,
    TargetState,
)

DEFAULT_MIN_LEASE_TTL_SECONDS = 300


def _deep_freeze(value: Any) -> Any:
    """Validate JSON-compatible routing data and convert it to read-only containers."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"routing data floats must be finite (no nan/inf), got {value!r}")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"routing data mapping keys must be strings, got {type(key).__name__}")
            frozen[key] = _deep_freeze(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    raise ValueError(f"routing data must be JSON-compatible, got non-JSON value of type {type(value).__name__}")


def _deep_thaw(value: Any) -> Any:
    """Convert frozen routing containers back to plain JSON containers."""
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_deep_thaw(item) for item in value]
    return value


class LineRole(StrEnum):
    SHARED_CONSOLE = "shared_console"
    DEDICATED_DEBUG = "dedicated_debug"
    RSP = "rsp"


class BreakMethod(StrEnum):
    GDBSTUB_NATIVE = "gdbstub_native"
    UART_BREAK = "uart_break"
    AGENT_PROXY_BREAK = "agent_proxy_break"
    SYSRQ_G = "sysrq_g"


class EndpointExposure(StrEnum):
    LOOPBACK_LOCAL = "loopback_local"
    BROKERED_REQUIRED = "brokered_required"


class TransportLocality(StrEnum):
    """Where a transport's backing source lives."""

    LOCAL = "local"
    REMOTE = "remote"


class RecordState(StrEnum):
    PENDING = "pending"
    OPENING = "opening"
    READY = "ready"
    DEGRADED = "degraded"
    CLOSING = "closing"
    ABANDONED = "abandoned"
    CLOSED = "closed"


class ExecutionState(StrEnum):
    EXECUTING = "executing"
    HALTED = "halted"
    UNKNOWN = "unknown"


class TcpEndpoint(Model):
    """Loopback-pinned TCP endpoint."""

    kind: Literal["tcp"] = "tcp"
    host: str
    port: int = Field(ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _host_must_be_loopback(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"TCP endpoint host must be a loopback IP literal (e.g. 127.0.0.1, ::1), got {value!r}"
            ) from exc
        if not address.is_loopback:
            raise ValueError(f"TCP endpoint host must be loopback (127.0.0.0/8 or ::1), got {value!r}")
        return value


class UnixSocketEndpoint(Model):
    """Per-session unix-domain socket owned by the server user."""

    kind: Literal["unix"] = "unix"
    path: str
    mode: int = 0o600

    @field_validator("path")
    @classmethod
    def _path_must_be_safe(cls, value: str) -> str:
        if not value:
            raise ValueError("unix socket path must not be empty")
        if any(unicodedata.category(char) == "Cc" for char in value):
            raise ValueError("unix socket path must not contain control characters")
        if not value.startswith("/"):
            raise ValueError(f"unix socket path must be absolute, got {value!r}")
        if ".." in value.split("/"):
            raise ValueError(f"unix socket path must not contain '..' traversal segments, got {value!r}")
        return value

    @field_validator("mode")
    @classmethod
    def _mode_must_be_owner_only(cls, value: int) -> int:
        if not 0 <= value <= 0o777:
            raise ValueError(f"unix socket mode must be within 0..0o777, got {value:#o}")
        if value & 0o077:
            raise ValueError(f"unix socket mode must not grant group/other access, got {value:#o}")
        return value


Endpoint = Annotated[TcpEndpoint | UnixSocketEndpoint, Field(discriminator="kind")]


class TransportRef(Model):
    """The settled-contract channel descriptor."""

    model_config = ConfigDict(frozen=True)

    provider: str
    channel_id: str
    line_role: LineRole
    caps: tuple[str, ...] = ()
    target_ref: Mapping[str, Any] = Field(default_factory=dict, validate_default=True)
    opts: Mapping[str, Any] = Field(default_factory=dict, validate_default=True)
    secret_refs: tuple[str, ...] = ()

    @field_validator("target_ref", "opts", mode="after")
    @classmethod
    def _freeze_routing_data(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return _deep_freeze(value)

    @field_serializer("target_ref", "opts")
    def _serialize_routing_data(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return _deep_thaw(value)


class OpenRequest(Model):
    """The settled-contract argument to transport.open()."""

    target_key: TargetKey
    generation: int = Field(ge=0)
    transport_ref: TransportRef
    required_caps: list[str] = Field(default_factory=list)
    platform: PlatformMetadata
    lease: LeaseInfo | None = None
    min_lease_ttl: int | None = Field(default=None, ge=1)


class BreakPlan(Model):
    method: BreakMethod
    channel_id: str
    rationale: str


class TargetAccess(Model):
    ssh: SshEndpoint | None = None
    transports: list[TransportRef] = Field(default_factory=list)


class TargetHandle(Model):
    target_id: str
    provisioner: str
    generation: int = Field(ge=0)
    arch: Arch
    native: bool
    state: TargetState
    access: TargetAccess
    platform: PlatformMetadata
    kernel: KernelProvenance
    lease: LeaseInfo | None = None


class TransportSession(Model):
    """Write-ahead durable ownership record persisted as JSON."""

    session_id: str = Field(pattern=r"^transport-[0-9a-f]{32}$")
    target_key: TargetKey
    generation: int = Field(ge=0)
    provider: str
    channel_id: str
    console_endpoint: Endpoint | None = None
    rsp_endpoint: Endpoint | None = None
    record_state: RecordState = RecordState.PENDING
    console_lease_token: str | None = None
    stop_guard_token: str | None = None
    attach_epoch: int = Field(default=0, ge=0)
    break_plan: BreakPlan | None = None
    execution_state: ExecutionState = ExecutionState.UNKNOWN
    backend_pid: int | None = Field(default=None, ge=1)
    backend_start_time: str | None = None
    created_at: datetime
    ended_at: datetime | None = None
    artifacts: list[ArtifactRef] = Field(default_factory=list)


def new_session_id() -> str:
    return f"transport-{uuid.uuid4().hex}"


__all__ = (
    "DEFAULT_MIN_LEASE_TTL_SECONDS",
    "BreakMethod",
    "BreakPlan",
    "Endpoint",
    "EndpointExposure",
    "ExecutionState",
    "LineRole",
    "OpenRequest",
    "RecordState",
    "TargetAccess",
    "TargetHandle",
    "TcpEndpoint",
    "TransportLocality",
    "TransportRef",
    "TransportSession",
    "UnixSocketEndpoint",
    "new_session_id",
)
