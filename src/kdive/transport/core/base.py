from __future__ import annotations

import ipaddress
import math
import threading
import unicodedata
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, field_serializer, field_validator, model_validator

from kdive.config import validate_transport_operation
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
from kdive.transport.core.break_types import BreakProxy, BreakSshRunner

DEFAULT_MIN_LEASE_TTL_SECONDS = 300

# Closed allowlist of transport providers trusted to bind a loopback endpoint against a
# local source (spec §3.2). `endpoint_exposure`/`locality` are provider-declared, so the
# trust bottoms out here: a provider not in this set may never register `loopback_local`,
# which keeps every unknown/remote transport `brokered_required` (default-deny, §8.4).
LOCAL_TRANSPORT_PROVIDERS: frozenset[str] = frozenset({"qemu-gdbstub", "serial-local"})


def _deep_freeze(value: Any) -> Any:
    """Recursively validate that a structure is JSON-compatible and convert it to a
    read-only form (mappings → read-only views, sequences → tuples) so it can be neither
    mutated in place nor fail JSON persistence later. Rejects non-JSON leaves such as
    `set`, `bytearray`, or custom objects, and non-string mapping keys."""
    if value is None or isinstance(value, (str, bool, int)):
        # bool is a subclass of int; both are valid JSON scalars.
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
    """Inverse of `_deep_freeze` for serialization back to plain JSON containers."""
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
    """The settled-contract channel descriptor (contract §3.2). Shape is frozen —
    this layer adds no field.

    Frozen and deeply immutable because every field is authority-bearing: `caps` drives
    break-plan candidate selection (§4.1), `secret_refs` drives secret resolution (§3.4),
    and `target_ref` is the provider attach-routing/path-safety input that admission
    re-binds from the authoritative snapshot. A caller or provider that retains a
    validated ref must not be able to mutate it in place — to add a break candidate or
    secret ref, or redirect attach to a different device/host — after the authority
    check. `target_ref`/`opts` are stored as read-only mappings; the wire shape is
    unchanged (still JSON objects)."""

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
    architectures: tuple[Arch, ...] = ()
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

    @field_validator("operations")
    @classmethod
    def _operations_are_allowlisted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for operation in value:
            validate_transport_operation(operation)
        return value


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
    arch: Arch
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


@dataclass(frozen=True)
class BackendAttachment:
    """A Layer-3 backend's terminal success value (ADR 0003): only fields the wire work
    discovers. Layer 4 owns TransportSession and assembles it from its durable record +
    this attachment. Backends never mint session_id, tokens, or record_state."""

    console_endpoint: Endpoint | None
    rsp_endpoint: Endpoint | None
    backend_pid: int | None
    backend_start_time: str | None
    console_artifact: ArtifactRef | None = None


@dataclass(frozen=True)
class BreakResources:
    """The live resources a transport hands the break-inject mechanism (#82 / ADR 0024): the
    agent-proxy and its handle for a UART/agent break, and the ssh prefix/runner for a sysrq-g
    write. A transport that injects no out-of-band break (gdbstub-native) returns None instead."""

    proxy: BreakProxy | None
    proxy_handle: Any
    ssh_runner: BreakSshRunner | None = None
    ssh_argv_prefix: tuple[str, ...] = ()
    work_dir: Path | None = None


class Transport(ABC):
    """Abstract transport provider. Concrete transports (serial-local, qemu-gdbstub)
    land in Layer 3; the open() transaction (Layer 4) drives attach/close/health."""

    @property
    @abstractmethod
    def capability(self) -> TransportCapability: ...

    def break_resources(self, session: TransportSession) -> BreakResources | None:
        """Resolve the live proxy/ssh resources needed to inject a break over this session's
        console, or None when the transport exposes no out-of-band break handle (the gdbstub
        interrupts natively, or the proxy handle is gone). Default: None — a transport opts in by
        overriding. ``inject_break_for_session`` maps None to ``break_inject_unavailable``."""
        return None

    @abstractmethod
    def attach(
        self,
        request: OpenRequest,
        *,
        cancel: threading.Event,
        deadline: float,
        on_partial: Callable[[str, object], None],
        secrets: Mapping[str, str] = MappingProxyType({}),
    ) -> BackendAttachment:
        """Wire-level attach: connect to the target channel and return the discovered
        endpoint(s) and process identity as a BackendAttachment (ADR 0003). Layer 4
        owns the durable TransportSession and assembles it from its existing record
        plus this attachment; backends never mint session_id, tokens, or record_state."""
        ...

    @abstractmethod
    def close(self, session: TransportSession) -> None: ...

    @abstractmethod
    def health(self, session: TransportSession) -> str: ...

    def reap_backend(self, pid: int, start_time: str | None) -> None:
        """Best-effort kill of a supervised backend process by its (pid, start-time) fingerprint.

        Layer-4 teardown (`_SessionSubscriber.invalidate`) and open-failure unwind
        (`TransportTransaction._rollback`) both call this to reap an orphaned backend; it is the
        single hook that replaces the previous private `transport._proxy` reach (ADR 0004 / TD-07).
        Default: no-op — a transport with no supervised backend process (e.g. qemu-gdbstub, whose
        `backend_pid` is always None) needs no reap. An overriding transport MUST start-time-fence
        the kill so it never signals a recycled PID, and MAY raise; the caller suppresses so a reap
        failure never masks the original teardown error.
        """
        return


class TransportRegistry:
    """In-process registry of transport capabilities, keyed by provider name. The
    §8.4 gate reads `endpoint_exposure` from here (trusted metadata)."""

    def __init__(self) -> None:
        self._capabilities: dict[str, TransportCapability] = {}

    def register(self, capability: TransportCapability) -> None:
        if capability.provider_name in self._capabilities:
            raise ValueError(f"transport already registered: {capability.provider_name}")
        if (
            capability.endpoint_exposure is EndpointExposure.LOOPBACK_LOCAL
            and capability.provider_name not in LOCAL_TRANSPORT_PROVIDERS
        ):
            raise ValueError(
                f"transport {capability.provider_name!r} is not an allowlisted local provider "
                "and may not register loopback_local exposure; unknown/remote transports are "
                "brokered_required (§3.2, §8.4)"
            )
        self._capabilities[capability.provider_name] = capability

    def get(self, provider_name: str) -> TransportCapability | None:
        return self._capabilities.get(provider_name)

    def require(self, provider_name: str) -> TransportCapability:
        try:
            return self._capabilities[provider_name]
        except KeyError as exc:
            raise KeyError(f"unknown transport provider: {provider_name}") from exc

    def endpoint_exposure(self, provider_name: str) -> EndpointExposure:
        return self.require(provider_name).endpoint_exposure

    def list_capabilities(self) -> list[TransportCapability]:
        return list(self._capabilities.values())
