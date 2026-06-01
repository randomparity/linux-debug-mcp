from __future__ import annotations

import ipaddress

from kdive.seams.transport_state import Endpoint, EndpointExposure, TcpEndpoint, UnixSocketEndpoint
from kdive.transport.core.base import (
    TransportCapability,
)

# Ops that return / depend on a live stop-capable endpoint. A brokered_required transport
# may not satisfy these with a raw endpoint (spec §8.4).
_ENDPOINT_RETURNING_OPS = frozenset({"transport.open", "transport.inject_break"})


class EndpointSafetyError(RuntimeError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def refuse_unsafe_exposure(capability: TransportCapability, *, op: str) -> None:
    """Pre-attach §8.4 gate: decided from TRUSTED registry metadata BEFORE any guard, lease,
    secret resolution, or provider attach. A `brokered_required` transport's endpoint-returning
    open is refused `endpoint_unsafe` — it never reaches attach (ADR 0005 / roadmap Layer 4)."""
    if op in _ENDPOINT_RETURNING_OPS and capability.endpoint_exposure is EndpointExposure.BROKERED_REQUIRED:
        raise EndpointSafetyError(
            f"transport {capability.provider_name!r} is brokered_required; a raw endpoint open is "
            "refused until the #08 broker exists",
            code="endpoint_unsafe",
        )


def assert_loopback_endpoint(endpoint: Endpoint) -> None:
    """Return-path belt: the bound address must be loopback (TcpEndpoint already enforces this
    at the schema boundary; this re-asserts at assembly so a future Endpoint variant can't slip
    a routable address through). UnixSocketEndpoint is local by construction."""
    if isinstance(endpoint, TcpEndpoint):
        if not ipaddress.ip_address(endpoint.host).is_loopback:
            raise EndpointSafetyError(f"bound RSP endpoint is not loopback: {endpoint.host}", code="endpoint_unsafe")
    elif not isinstance(endpoint, UnixSocketEndpoint):
        raise EndpointSafetyError(f"unrecognized endpoint type {type(endpoint).__name__}", code="endpoint_unsafe")
