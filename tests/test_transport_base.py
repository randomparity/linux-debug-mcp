from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from linux_debug_mcp.seams.target import ConsoleKind, LeaseInfo, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import (
    DEFAULT_MIN_LEASE_TTL_SECONDS,
    BreakMethod,
    BreakPlan,
    Endpoint,
    EndpointExposure,
    ExecutionState,
    LineRole,
    OpenRequest,
    RecordState,
    TargetHandle,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportRef,
    TransportRegistry,
    TransportSession,
    UnixSocketEndpoint,
    new_session_id,
)


def _platform() -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=True,
    )


def _ref() -> TransportRef:
    return TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp-0",
        line_role=LineRole.RSP,
        caps=["provides_rsp"],
    )


def test_endpoint_discriminated_union_round_trips():
    adapter = TypeAdapter(Endpoint)
    tcp = adapter.validate_python({"kind": "tcp", "host": "127.0.0.1", "port": 1234})
    assert isinstance(tcp, TcpEndpoint)
    unix = adapter.validate_python({"kind": "unix", "path": "/tmp/c.sock", "mode": 0o600})
    assert isinstance(unix, UnixSocketEndpoint)
    assert adapter.validate_python(adapter.dump_python(tcp)) == tcp


def test_tcp_endpoint_port_bounds():
    TcpEndpoint(host="127.0.0.1", port=1)
    with pytest.raises(ValidationError):
        TcpEndpoint(host="127.0.0.1", port=0)


def test_unix_socket_mode_defaults_to_0600():
    assert UnixSocketEndpoint(path="/tmp/c.sock").mode == 0o600


def test_open_request_default_ttl_and_optional_lease():
    req = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=0,
        transport_ref=_ref(),
        required_caps=["provides_rsp"],
        platform=_platform(),
    )
    assert req.lease is None
    assert req.min_lease_ttl is None
    assert DEFAULT_MIN_LEASE_TTL_SECONDS == 300


def test_transport_ref_and_open_request_forbid_extra_fields():
    with pytest.raises(ValidationError):
        TransportRef(provider="p", channel_id="c", line_role=LineRole.RSP, bogus=1)


def test_open_request_requires_transport_ref():
    # transport_ref is mandatory: admission must re-bind/validate the selected channel.
    with pytest.raises(ValidationError):
        OpenRequest(
            target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
            generation=0,
            required_caps=["provides_rsp"],
            platform=_platform(),
        )


def test_open_request_has_no_recovery_field():
    # recovery is a transport.open tool arg (routes to admit_recovery), never a wire
    # field on the settled-contract OpenRequest (spec §3.2).
    with pytest.raises(ValidationError):
        OpenRequest(
            target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
            generation=0,
            transport_ref=_ref(),
            required_caps=["provides_rsp"],
            platform=_platform(),
            recovery=True,
        )


def test_transport_capability_family_is_fixed():
    cap = TransportCapability(
        provider_name="qemu-gdbstub",
        architectures=["x86_64"],
        provides_console=False,
        provides_rsp=True,
        supports_uart_break=False,
        endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
    )
    assert cap.provider_family == "transport"
    with pytest.raises(ValidationError):
        TransportCapability(
            provider_name="x",
            provider_family="provisioning",
            provides_console=False,
            provides_rsp=True,
            supports_uart_break=False,
            endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
        )


def test_target_handle_holds_transport_refs():
    # Proves the TransportRef <-> TargetHandle cycle is resolved at import time.
    handle = TargetHandle(
        target_id="run-1",
        provisioner="local-qemu",
        generation=0,
        arch="x86_64",
        native=True,
        state="ready",
        access={"ssh": None, "transports": [_ref()]},
        platform=_platform(),
        kernel={
            "build_id": "bid",
            "release": "6.9.0",
            "vmlinux_ref": "ref",
            "cmdline": "ro",
        },
        lease=None,
    )
    assert handle.access.transports[0].channel_id == "rsp-0"


def test_new_session_id_is_prefixed_and_unique():
    a, b = new_session_id(), new_session_id()
    assert a.startswith("transport-") and b.startswith("transport-")
    assert a != b


def test_transport_session_defaults():
    session = TransportSession(
        session_id=new_session_id(),
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=0,
        provider="qemu-gdbstub",
        channel_id="rsp-0",
        created_at=datetime.now(UTC),
    )
    assert session.record_state is RecordState.PENDING
    assert session.execution_state is ExecutionState.UNKNOWN
    assert session.attach_epoch == 0
    assert session.rsp_endpoint is None


def test_break_plan_method_enum():
    plan = BreakPlan(method=BreakMethod.GDBSTUB_NATIVE, channel_id="rsp-0", rationale="rsp")
    assert plan.method == "gdbstub_native"


def test_transport_registry_register_lookup_and_duplicate():
    registry = TransportRegistry()
    cap = TransportCapability(
        provider_name="qemu-gdbstub",
        provides_console=False,
        provides_rsp=True,
        supports_uart_break=False,
        endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
    )
    registry.register(cap)
    assert registry.get("qemu-gdbstub") is cap
    assert registry.endpoint_exposure("qemu-gdbstub") is EndpointExposure.LOOPBACK_LOCAL
    assert registry.list_capabilities() == [cap]
    with pytest.raises(ValueError):
        registry.register(cap)
    with pytest.raises(KeyError):
        registry.get("missing")


def test_transport_abc_cannot_be_instantiated_without_methods():
    with pytest.raises(TypeError):
        Transport()  # abstract
