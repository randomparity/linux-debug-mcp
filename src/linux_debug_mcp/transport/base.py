from __future__ import annotations

import ipaddress
import threading
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from linux_debug_mcp.domain import ArtifactRef, Model
from linux_debug_mcp.seams.target import (
    KernelProvenance,
    LeaseInfo,
    PlatformMetadata,
    SshEndpoint,
    TargetKey,
    TargetState,
)

DEFAULT_MIN_LEASE_TTL_SECONDS = 300


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
    """Where a transport's backing source lives. Trusted registry metadata: a `REMOTE`
    or out-of-band transport is structurally `brokered_required` and may never declare
    `loopback_local` (§3.2, §8.4)."""

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
    """Loopback-pinned TCP endpoint (spec §3.2, §8.4). `host` is constrained to a
    loopback IP literal at the schema boundary so a provider bug or a stale persisted
    record can never mint a routable RSP/console endpoint that bypasses the §8.4 trust
    boundary; loopback is a reachability bound, not access control (§8.4)."""

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
    """Per-session unix-domain socket owned by the server user (spec §3.2, §8.4). OS
    file permissions are the console access-control boundary, so `mode` is constrained
    to owner-only (no group/other bits): a socket reachable by another uid would defeat
    that guarantee."""

    kind: Literal["unix"] = "unix"
    path: str
    mode: int = 0o600

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
    """The settled-contract channel descriptor (contract §3.2). Shape is frozen —
    this layer adds no field.

    Frozen, with `caps`/`secret_refs` as tuples, because these are authority-bearing:
    `caps` drives break-plan candidate selection (§4.1) and `secret_refs` drives secret
    resolution (§3.4). A caller or provider that retains a validated ref must not be
    able to mutate it in place to add a break candidate or a secret ref after the
    snapshot/authority check. `target_ref`/`opts` are opaque provisioning routing data,
    not authority inputs; freezing blocks whole-field replacement."""

    model_config = ConfigDict(frozen=True)

    provider: str
    channel_id: str
    line_role: LineRole
    caps: tuple[str, ...] = ()
    target_ref: dict[str, Any] = Field(default_factory=dict)
    opts: dict[str, Any] = Field(default_factory=dict)
    secret_refs: tuple[str, ...] = ()


class OpenRequest(Model):
    """The settled-contract argument to transport.open() (contract §3.2). Shape is
    frozen — recovery-mode attach is a tool arg, not a field here (spec §3.2)."""

    target_key: TargetKey
    generation: int = Field(ge=0)
    transport_ref: TransportRef
    required_caps: list[str] = Field(default_factory=list)
    platform: PlatformMetadata
    lease: LeaseInfo | None = None
    min_lease_ttl: int | None = Field(default=None, ge=1)


class TransportCapability(Model):
    """01-owned capability surfaced in providers.list. `endpoint_exposure` drives the
    §8.4 endpoint-safety gate and is trusted registry metadata, never caller-supplied.

    `locality` makes the §8.4 endpoint-exposure rule structurally verifiable rather than
    a provider-name convention: a `REMOTE` transport that declares `loopback_local` is
    rejected at construction (and therefore at registration), so a misregistered remote
    provider can never present trusted metadata that would authorize a raw TCP endpoint.
    `locality` defaults to `REMOTE`, the safe value — a provider must opt in to `LOCAL`
    to be eligible for `loopback_local`. `TcpEndpoint`'s loopback-only constraint is the
    independent second line of defense.

    Frozen and tuple-valued so the registry can hold a capability the gate trusts: once
    registered, no caller-retained reference can flip `endpoint_exposure`/`locality` or
    widen the `operations`/`architectures` surface."""

    model_config = ConfigDict(frozen=True)

    provider_name: str
    provider_family: Literal["transport"] = "transport"
    locality: TransportLocality = TransportLocality.REMOTE
    architectures: tuple[str, ...] = ()
    provides_console: bool
    provides_rsp: bool
    supports_uart_break: bool
    endpoint_exposure: EndpointExposure
    operations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _remote_must_be_brokered(self) -> TransportCapability:
        if self.locality is TransportLocality.REMOTE and self.endpoint_exposure is EndpointExposure.LOOPBACK_LOCAL:
            raise ValueError(
                f"remote transport {self.provider_name!r} cannot declare loopback_local "
                "endpoint exposure; remote/out-of-band transports are structurally "
                "brokered_required (§3.2, §8.4)"
            )
        return self


class BreakPlan(Model):
    method: BreakMethod
    channel_id: str
    rationale: str


class TargetAccess(Model):
    ssh: SshEndpoint | None = None
    transports: list[TransportRef] = Field(default_factory=list)


class TargetHandle(Model):
    """Provisioning-owned handle (contract §3.1). Defined here, beside `TransportRef`,
    to close the TransportRef<->TargetHandle type cycle; shape matches the contract."""

    target_id: str
    provisioner: str
    generation: int = Field(ge=0)
    arch: str
    native: bool
    state: TargetState
    access: TargetAccess
    platform: PlatformMetadata
    kernel: KernelProvenance
    lease: LeaseInfo | None = None


class TransportSession(Model):
    """Write-ahead durable ownership record (spec §3.2, §4.7). Persisted as JSON;
    liveness is owned by the in-process registry (Layer 4) while the server runs.

    `rsp_endpoint` is the `Endpoint` union: a loopback `TcpEndpoint` for `loopback_local`
    providers (gdb/agent-proxy are TCP-only, §6.1) and the brokered `UnixSocketEndpoint`
    that a `brokered_required` transport must use (the #08 broker, §8.4). Carrying both
    shapes now means the #08 broker is an endpoint-construction swap, not a wire-schema
    change downstream layers or schema consumers would reject. Which shape is admissible
    per provider is enforced by the §8.4 runtime gate, not by narrowing this field."""

    session_id: str
    target_key: TargetKey
    generation: int = Field(ge=0)
    provider: str
    channel_id: str
    console_endpoint: Endpoint | None = None
    rsp_endpoint: Endpoint | None = None
    record_state: RecordState = RecordState.PENDING
    console_lease_token: str | None = None
    stop_guard_token: str | None = None
    attach_epoch: int = 0
    break_plan: BreakPlan | None = None
    execution_state: ExecutionState = ExecutionState.UNKNOWN
    backend_pid: int | None = None
    backend_start_time: str | None = None
    created_at: datetime
    ended_at: datetime | None = None
    artifacts: list[ArtifactRef] = Field(default_factory=list)


def new_session_id() -> str:
    return f"transport-{uuid.uuid4().hex}"


class Transport(ABC):
    """Abstract transport provider. Concrete transports (serial-local, qemu-gdbstub)
    land in Layer 3; the open() transaction (Layer 4) drives attach/close/health."""

    @property
    @abstractmethod
    def capability(self) -> TransportCapability: ...

    @abstractmethod
    def attach(
        self,
        request: OpenRequest,
        *,
        cancel: threading.Event,
        deadline: float,
        on_partial: Callable[[str, object], None],
    ) -> TransportSession: ...

    @abstractmethod
    def close(self, session: TransportSession) -> None: ...

    @abstractmethod
    def health(self, session: TransportSession) -> str: ...


class TransportRegistry:
    """In-process registry of transport capabilities, keyed by provider name. The
    §8.4 gate reads `endpoint_exposure` from here (trusted metadata)."""

    def __init__(self) -> None:
        self._capabilities: dict[str, TransportCapability] = {}

    def register(self, capability: TransportCapability) -> None:
        if capability.provider_name in self._capabilities:
            raise ValueError(f"transport already registered: {capability.provider_name}")
        self._capabilities[capability.provider_name] = capability

    def get(self, provider_name: str) -> TransportCapability:
        try:
            return self._capabilities[provider_name]
        except KeyError as exc:
            raise KeyError(f"unknown transport provider: {provider_name}") from exc

    def endpoint_exposure(self, provider_name: str) -> EndpointExposure:
        return self.get(provider_name).endpoint_exposure

    def list_capabilities(self) -> list[TransportCapability]:
        return list(self._capabilities.values())
