import socket
import sys
import threading
import time

import pytest

from linux_debug_mcp.transport.bounded import (
    BoundedIOCancelled,
    BoundedIOTimeout,
    Deadline,
    allocate_loopback_ports,
    await_accept,
    check_not_cancelled,
    connect_tcp,
    open_device,
    spawn,
)


def test_deadline_remaining_decreases_and_expires():
    deadline = Deadline.after(0.05)
    assert deadline.remaining() > 0
    assert not deadline.expired()
    time.sleep(0.06)
    assert deadline.remaining() == 0.0
    assert deadline.expired()


def test_check_not_cancelled_raises_when_event_set():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BoundedIOCancelled):
        check_not_cancelled(cancel)


def test_connect_tcp_succeeds_to_a_live_loopback_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    cancel = threading.Event()
    try:
        conn = connect_tcp("127.0.0.1", port, deadline=Deadline.after(1.0), cancel=cancel)
        conn.close()
    finally:
        listener.close()


def test_connect_tcp_raises_on_refused_or_dead_port():
    # Bind+close to obtain a port nothing is listening on.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises((BoundedIOTimeout, ConnectionError, OSError)):
        connect_tcp("127.0.0.1", port, deadline=Deadline.after(0.2), cancel=threading.Event())


def test_connect_tcp_raises_when_cancelled_before_start():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BoundedIOCancelled):
        connect_tcp("127.0.0.1", 9, deadline=Deadline.after(1.0), cancel=cancel)


def test_allocate_loopback_ports_returns_distinct_held_ports():
    holders = allocate_loopback_ports(2)
    try:
        ports = [port for port, _sock in holders]
        assert len(set(ports)) == 2
        assert all(1 <= port <= 65535 for port in ports)
    finally:
        for _port, sock in holders:
            sock.close()


def test_await_accept_returns_a_connection_then_times_out():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        conn = await_accept(listener, deadline=Deadline.after(1.0), cancel=threading.Event())
        conn.close()
        client.close()
        with pytest.raises(BoundedIOTimeout):
            await_accept(listener, deadline=Deadline.after(0.1), cancel=threading.Event())
    finally:
        listener.close()


def test_open_device_rejects_a_fifo(tmp_path):
    import os as _os

    fifo = tmp_path / "fifo"
    _os.mkfifo(fifo)
    # A FIFO is not a serial source; open_device rejects non-character devices (F3).
    with pytest.raises(OSError):
        open_device(str(fifo), deadline=Deadline.after(0.2), cancel=threading.Event())


def test_open_device_opens_a_pty_slave():
    import os as _os
    import pty

    master, slave = pty.openpty()
    name = _os.ttyname(slave)
    try:
        fd = open_device(name, deadline=Deadline.after(1.0), cancel=threading.Event())
        assert fd >= 0
        _os.close(fd)
    finally:
        _os.close(master)
        _os.close(slave)


def test_spawn_raises_when_cancelled_and_never_spawns():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BoundedIOCancelled):
        spawn([sys.executable, "-c", "pass"], deadline=Deadline.after(1.0), cancel=cancel)


def test_spawn_starts_a_subprocess_to_completion():
    proc = spawn([sys.executable, "-c", "pass"], deadline=Deadline.after(5.0), cancel=threading.Event())
    proc.wait(timeout=5)
    assert proc.returncode == 0


def test_await_accept_raises_when_cancelled_before_start():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    cancel = threading.Event()
    cancel.set()
    try:
        with pytest.raises(BoundedIOCancelled):
            await_accept(listener, deadline=Deadline.after(1.0), cancel=cancel)
    finally:
        listener.close()


def test_open_device_raises_when_cancelled_before_start():
    import os as _os
    import pty

    master, slave = pty.openpty()
    name = _os.ttyname(slave)
    cancel = threading.Event()
    cancel.set()
    try:
        with pytest.raises(BoundedIOCancelled):
            open_device(name, deadline=Deadline.after(1.0), cancel=cancel)
    finally:
        _os.close(master)
        _os.close(slave)
