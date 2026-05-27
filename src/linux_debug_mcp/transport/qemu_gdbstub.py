from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.transport.base import (
    BackendAttachment,
    EndpointExposure,
    OpenRequest,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportLocality,
)
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.rsp_probe import rsp_reachable


class QemuGdbstubAttachError(Exception):
    def __init__(self, message: str, *, category: ErrorCategory) -> None:
        super().__init__(message)
        self.category = category


class QemuGdbstubTransport(Transport):
    """RSP passthrough to QEMU's gdbstub (§6.3). No agent-proxy, no console, no halt.
    The existing QemuGdbstubProvider batch-gdb engine is untouched in Layer 3."""

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
        deadline: float,
        on_partial: Callable[[str, object], None],
    ) -> BackendAttachment:
        opts = request.transport_ref.opts
        host = str(opts.get("host", "127.0.0.1"))
        port = int(opts["port"])
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
        bounded = deadline if isinstance(deadline, Deadline) else Deadline.after(float(deadline))
        # Decision 5: a minimal bounded RSP-framing exchange, not a bare connect — a stale
        # or non-RSP listener on the port must not be accepted as a healthy gdbstub.
        if not rsp_reachable(host, port, deadline=bounded, cancel=cancel):
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

    def close(self, session: object) -> None:
        return None

    def health(self, session: object) -> str:
        endpoint = getattr(session, "rsp_endpoint", None)
        if endpoint is None:
            return "degraded"
        ok = rsp_reachable(endpoint.host, endpoint.port, deadline=Deadline.after(2.0), cancel=threading.Event())
        return "ready" if ok else "degraded"
