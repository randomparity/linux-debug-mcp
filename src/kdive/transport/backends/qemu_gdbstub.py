from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable, Mapping
from types import MappingProxyType

from kdive.domain import ErrorCategory
from kdive.transport.core.base import (
    BackendAttachment,
    EndpointExposure,
    OpenRequest,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportLocality,
    TransportSession,
)
from kdive.transport.core.bounded import Deadline
from kdive.transport.core.rsp_probe import rsp_reachable


class QemuGdbstubAttachError(Exception):
    def __init__(self, message: str, *, category: ErrorCategory) -> None:
        super().__init__(message)
        self.category = category


class QemuGdbstubTransport(Transport):
    """RSP passthrough to QEMU's gdbstub (§6.3). No agent-proxy, no console, no halt.
    This transport only exposes bounded RSP connectivity; gdb/MI session ownership lives
    in the MCP handlers and ``kdive.providers.local.debug.gdb_mi``."""

    @property
    def capability(self) -> TransportCapability:
        return TransportCapability(
            provider_name="qemu-gdbstub",
            locality=TransportLocality.LOCAL,
            architectures=(),
            provides_console=False,
            provides_rsp=True,
            supports_uart_break=False,
            endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
            operations=(),
        )

    def attach(
        self,
        request: OpenRequest,
        *,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: Callable[[str, object], None],
        secrets: Mapping[str, str] = MappingProxyType({}),
    ) -> BackendAttachment:
        opts = request.transport_ref.opts
        host = str(opts.get("host", "127.0.0.1"))
        try:
            port = int(opts["port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise QemuGdbstubAttachError(
                f"qemu-gdbstub transport_ref.opts['port'] must be an integer, got {opts.get('port')!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            ) from exc
        if not 1 <= port <= 65535:
            raise QemuGdbstubAttachError(
                f"qemu-gdbstub port out of range (1-65535), got {port}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        # F2: enforce loopback BEFORE any network IO. A loopback_local provider must never
        # initiate an outbound RSP connect to a caller-supplied remote host (SSRF-like from
        # target metadata). A non-loopback/hostname value is a CONFIGURATION_ERROR here, not
        # a late TcpEndpoint schema ValueError after the connect already happened.
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False  # a hostname is not an IP literal → reject without DNS/IO
        if not is_loopback:
            raise QemuGdbstubAttachError(
                f"qemu-gdbstub host must be a loopback IP literal, got {host!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        # Decision 5: a minimal bounded RSP-framing exchange, not a bare connect — a stale
        # or non-RSP listener on the port must not be accepted as a healthy gdbstub.
        if not rsp_reachable(host, port, deadline=deadline, cancel=cancel):
            raise QemuGdbstubAttachError(
                f"qemu gdbstub at {host}:{port} did not answer RSP framing",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
            )
        return BackendAttachment(
            console_endpoint=None,
            rsp_endpoint=TcpEndpoint(host=host, port=port),
            backend_pid=None,
            backend_start_time=None,
        )

    def close(self, session: TransportSession) -> None:
        return None

    def health(self, session: TransportSession) -> str:
        endpoint = session.rsp_endpoint
        if not isinstance(endpoint, TcpEndpoint):
            return "degraded"
        ok = rsp_reachable(endpoint.host, endpoint.port, deadline=Deadline.after(2.0), cancel=threading.Event())
        return "ready" if ok else "degraded"
