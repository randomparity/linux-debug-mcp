from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from pydantic import ConfigDict, field_validator, model_validator

from kdive.config import validate_transport_operation
from kdive.domain import ArtifactRef, Model
from kdive.seams.target import Arch
from kdive.seams.transport_state import (
    DEFAULT_MIN_LEASE_TTL_SECONDS,
    BreakMethod,
    BreakPlan,
    Endpoint,
    EndpointExposure,
    ExecutionState,
    LineRole,
    OpenRequest,
    RecordState,
    TargetAccess,
    TargetHandle,
    TcpEndpoint,
    TransportLocality,
    TransportRef,
    TransportSession,
    UnixSocketEndpoint,
    new_session_id,
)
from kdive.transport.core.bounded import Deadline
from kdive.transport.core.break_types import BreakProxy, BreakSshRunner

__all__ = (
    "DEFAULT_MIN_LEASE_TTL_SECONDS",
    "LOCAL_TRANSPORT_PROVIDERS",
    "BackendAttachment",
    "BreakMethod",
    "BreakPlan",
    "BreakResources",
    "Endpoint",
    "EndpointExposure",
    "ExecutionState",
    "LineRole",
    "OpenRequest",
    "RecordState",
    "TargetAccess",
    "TargetHandle",
    "TcpEndpoint",
    "Transport",
    "TransportCapability",
    "TransportLocality",
    "TransportRef",
    "TransportRegistry",
    "TransportSession",
    "UnixSocketEndpoint",
    "new_session_id",
)

# Closed allowlist of transport providers trusted to bind a loopback endpoint against a
# local source (spec §3.2). `endpoint_exposure`/`locality` are provider-declared, so the
# trust bottoms out here: a provider not in this set may never register `loopback_local`,
# which keeps every unknown/remote transport `brokered_required` (default-deny, §8.4).
LOCAL_TRANSPORT_PROVIDERS: frozenset[str] = frozenset({"qemu-gdbstub", "serial-local"})


class TransportCapability(Model):
    """Provider capability metadata surfaced in providers.list."""

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
        deadline: Deadline,
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
