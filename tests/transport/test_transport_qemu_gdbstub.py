import socket
import threading
from typing import get_type_hints

import pytest

from kdive.domain import ErrorCategory
from kdive.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from kdive.transport.base import (
    BackendAttachment,
    EndpointExposure,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    TransportLocality,
    TransportRef,
    TransportSession,
)
from kdive.transport.bounded import Deadline
from kdive.transport.qemu_gdbstub import QemuGdbstubAttachError, QemuGdbstubTransport


def _request(port: int) -> OpenRequest:
    return OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(
            provider="qemu-gdbstub",
            channel_id="rsp0",
            line_role=LineRole.RSP,
            opts={"host": "127.0.0.1", "port": port},
        ),
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART,
            console_count=1,
            dedicated_debug_line=False,
            ssh_reachable=True,
        ),
        required_caps=["rsp"],
    )


def test_capability_flags():
    cap = QemuGdbstubTransport().capability
    assert cap.provider_name == "qemu-gdbstub"
    assert cap.provides_rsp and not cap.provides_console and not cap.supports_uart_break
    assert cap.locality is TransportLocality.LOCAL
    assert cap.endpoint_exposure is EndpointExposure.LOOPBACK_LOCAL


def test_close_and_health_match_transport_session_protocol() -> None:
    assert get_type_hints(QemuGdbstubTransport.close)["session"] is TransportSession
    assert get_type_hints(QemuGdbstubTransport.health)["session"] is TransportSession


def _serve(handler):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _run():
        conn, _ = listener.accept()
        handler(conn)
        conn.close()

    threading.Thread(target=_run, daemon=True).start()
    return listener, port


def test_attach_returns_loopback_tcp_endpoint_when_the_stub_answers_rsp():
    listener, port = _serve(lambda conn: conn.sendall(b"+$T05#b9"))  # valid RSP stop reply (sum 'T05'=0xb9)
    try:
        result = QemuGdbstubTransport().attach(
            _request(port),
            cancel=threading.Event(),
            deadline=Deadline.after(2.0),
            on_partial=lambda *_: None,
        )
        assert isinstance(result, BackendAttachment)
        assert isinstance(result.rsp_endpoint, TcpEndpoint)
        assert result.rsp_endpoint.port == port
        assert result.backend_pid is None  # nothing spawned
    finally:
        listener.close()


def test_attach_rejects_a_plain_tcp_listener_that_does_not_speak_rsp():
    listener, port = _serve(lambda conn: None)  # accepts but never answers RSP
    try:
        with pytest.raises(QemuGdbstubAttachError) as exc:
            QemuGdbstubTransport().attach(
                _request(port),
                cancel=threading.Event(),
                deadline=Deadline.after(0.4),
                on_partial=lambda *_: None,
            )
        assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    finally:
        listener.close()


def test_attach_rejects_an_unreachable_stub():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(QemuGdbstubAttachError) as exc:
        QemuGdbstubTransport().attach(
            _request(port),
            cancel=threading.Event(),
            deadline=Deadline.after(0.3),
            on_partial=lambda *_: None,
        )
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE


@pytest.mark.parametrize("bad_port", ["not-a-number", None, 0, -1, 70000])
def test_attach_rejects_invalid_port_with_configuration_error(monkeypatch, bad_port):
    # TD-03: a malformed/out-of-range opts['port'] must surface as CONFIGURATION_ERROR before
    # any network IO, not as a raw ValueError/TypeError from int().
    called = []
    monkeypatch.setattr(
        "kdive.transport.qemu_gdbstub.rsp_reachable",
        lambda *a, **k: (called.append(True), True)[1],
    )
    request = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(
            provider="qemu-gdbstub",
            channel_id="rsp0",
            line_role=LineRole.RSP,
            opts={"host": "127.0.0.1", "port": bad_port},
        ),
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART,
            console_count=1,
            dedicated_debug_line=False,
            ssh_reachable=True,
        ),
        required_caps=["rsp"],
    )
    with pytest.raises(QemuGdbstubAttachError) as exc:
        QemuGdbstubTransport().attach(
            request,
            cancel=threading.Event(),
            deadline=Deadline.after(1.0),
            on_partial=lambda *_: None,
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert called == []  # rejected before any RSP probe


def test_attach_rejects_a_non_loopback_host_without_any_network_io(monkeypatch):
    """A loopback_local provider must never connect out to a caller-supplied remote host
    (round-3 review F2): loopback is enforced before rsp_reachable is ever called."""
    called = []
    monkeypatch.setattr(
        "kdive.transport.qemu_gdbstub.rsp_reachable",
        lambda *a, **k: (called.append(True), True)[1],
    )
    for host in ("10.0.0.5", "192.168.1.10", "8.8.8.8", "evil.example.com"):
        request = OpenRequest(
            target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
            generation=0,
            transport_ref=TransportRef(
                provider="qemu-gdbstub",
                channel_id="rsp0",
                line_role=LineRole.RSP,
                opts={"host": host, "port": 1234},
            ),
            platform=PlatformMetadata(
                console_kind=ConsoleKind.UART,
                console_count=1,
                dedicated_debug_line=False,
                ssh_reachable=True,
            ),
            required_caps=["rsp"],
        )
        with pytest.raises(QemuGdbstubAttachError) as exc:
            QemuGdbstubTransport().attach(
                request,
                cancel=threading.Event(),
                deadline=Deadline.after(1.0),
                on_partial=lambda *_: None,
            )
        assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert called == []  # loopback rejected before any outbound connection
