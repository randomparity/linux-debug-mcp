import socket
import threading

from kdive.transport.core.bounded import Deadline
from kdive.transport.core.rsp_probe import rsp_frame, rsp_reachable


def _serve_once(handler) -> tuple[socket.socket, int]:
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


def test_rsp_frame_computes_checksum():
    # checksum of "?" is 0x3f.
    assert rsp_frame("?") == b"$?#3f"


def test_valid_rsp_frame_accepts_well_formed_and_rejects_malformed():
    from kdive.transport.core.rsp_probe import valid_rsp_frame

    assert valid_rsp_frame(b"+" + rsp_frame("T05")) is True
    assert valid_rsp_frame(b"+") is False  # bare ack, no packet
    assert valid_rsp_frame(b"$T05#zz") is False  # non-hex checksum
    assert valid_rsp_frame(b"$T05#00") is False  # checksum does not match payload
    assert valid_rsp_frame(b"$hello") is False  # no terminator


def test_rsp_reachable_true_for_a_peer_that_answers_a_valid_frame():
    listener, port = _serve_once(lambda conn: conn.sendall(b"+" + rsp_frame("T05")))
    try:
        assert rsp_reachable("127.0.0.1", port, deadline=Deadline.after(2.0), cancel=threading.Event()) is True
    finally:
        listener.close()


def test_rsp_reachable_false_for_an_ack_only_or_bad_checksum_peer():
    ack_only, port_a = _serve_once(lambda conn: conn.sendall(b"+"))
    bad_sum, port_b = _serve_once(lambda conn: conn.sendall(b"$T05#00"))
    try:
        assert rsp_reachable("127.0.0.1", port_a, deadline=Deadline.after(0.5), cancel=threading.Event()) is False
        assert rsp_reachable("127.0.0.1", port_b, deadline=Deadline.after(0.5), cancel=threading.Event()) is False
    finally:
        ack_only.close()
        bad_sum.close()


def test_rsp_reachable_false_for_a_plain_tcp_listener_that_never_speaks_rsp():
    listener, port = _serve_once(lambda conn: None)  # accepts, says nothing
    try:
        assert rsp_reachable("127.0.0.1", port, deadline=Deadline.after(0.4), cancel=threading.Event()) is False
    finally:
        listener.close()


def test_rsp_reachable_false_when_nothing_listens():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    assert rsp_reachable("127.0.0.1", dead_port, deadline=Deadline.after(0.3), cancel=threading.Event()) is False
