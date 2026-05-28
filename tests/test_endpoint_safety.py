import pytest

from linux_debug_mcp.coordination.endpoint_safety import (
    EndpointSafetyError,
    assert_loopback_endpoint,
    refuse_unsafe_exposure,
)
from linux_debug_mcp.transport.base import (
    EndpointExposure,
    TcpEndpoint,
    TransportCapability,
    TransportLocality,
    UnixSocketEndpoint,
)


def _cap(exposure: EndpointExposure, locality: TransportLocality) -> TransportCapability:
    return TransportCapability(
        provider_name="x",
        locality=locality,
        provides_console=True,
        provides_rsp=True,
        supports_uart_break=False,
        endpoint_exposure=exposure,
    )


def test_loopback_local_rsp_open_is_allowed():
    refuse_unsafe_exposure(_cap(EndpointExposure.LOOPBACK_LOCAL, TransportLocality.LOCAL), op="transport.open")


def test_brokered_required_rsp_open_is_refused_before_attach():
    with pytest.raises(EndpointSafetyError) as exc:
        refuse_unsafe_exposure(_cap(EndpointExposure.BROKERED_REQUIRED, TransportLocality.REMOTE), op="transport.open")
    assert exc.value.code == "endpoint_unsafe"


def test_loopback_tcp_endpoint_passes_return_path_assert():
    assert_loopback_endpoint(TcpEndpoint(host="127.0.0.1", port=5551))


def test_unix_socket_endpoint_passes_return_path_assert():
    assert_loopback_endpoint(UnixSocketEndpoint(path="/run/x.sock", mode=0o600))
