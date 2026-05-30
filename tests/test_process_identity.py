import dataclasses
import os
import sys

import pytest

from kdive.seams.process_identity import (
    ProcessIdentity,
    ProcessIdentityProbe,
    ProcProcessIdentityProbe,
)


def test_process_identity_is_frozen():
    identity = ProcessIdentity(pid=1234, start_time="999", argv0="agent-proxy")
    with pytest.raises(dataclasses.FrozenInstanceError):
        identity.pid = 5  # type: ignore[misc]


def test_proc_probe_reports_self_alive():
    probe = ProcProcessIdentityProbe()
    assert probe.is_alive(os.getpid()) is True


def test_proc_probe_reports_unused_pid_dead():
    probe = ProcProcessIdentityProbe()
    # PID 2**31-1 is not a running process on any supported platform.
    assert probe.is_alive(2_147_483_646) is False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc identity is Linux-only")
def test_proc_probe_identity_has_start_time_on_linux():
    probe = ProcProcessIdentityProbe()
    identity = probe.identity(os.getpid())
    assert identity is not None
    assert identity.pid == os.getpid()
    assert identity.start_time is not None


def test_probe_protocol_accepts_a_fake():
    class _Fake:
        def identity(self, pid: int) -> ProcessIdentity | None:
            return ProcessIdentity(pid=pid, start_time="42", argv0="fake")

        def is_alive(self, pid: int) -> bool:
            return True

        def looks_like(self, pid: int, name_substr: str) -> bool:
            return True

        def owns_listener(self, pid: int, host: str, port: int) -> bool | None:
            return True

    probe: ProcessIdentityProbe = _Fake()
    assert probe.identity(7).start_time == "42"
    assert probe.owns_listener(7, "127.0.0.1", 1234) is True


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc/net is Linux-only")
def test_proc_probe_owns_listener_matches_our_own_listening_socket():
    import socket
    import subprocess

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    # A foreign PID we own: same UID, so /proc/<pid>/fd is readable (unlike
    # PID 1, which is root-owned and would make owns_listener return None
    # "indeterminable" rather than False on an unprivileged runner).
    foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        probe = ProcProcessIdentityProbe()
        assert probe.owns_listener(os.getpid(), "127.0.0.1", port) is True
        assert probe.owns_listener(foreign.pid, "127.0.0.1", port) is False
    finally:
        foreign.terminate()
        foreign.wait(timeout=5)
        listener.close()


def test_proc_probe_owns_listener_is_none_when_proc_net_absent(monkeypatch):
    from pathlib import Path as _Path

    probe = ProcProcessIdentityProbe()
    # Simulate a host without /proc/net (e.g. macOS): ownership is unknown, not 'foreign'.
    monkeypatch.setattr(_Path, "exists", lambda self: False)
    assert probe.owns_listener(os.getpid(), "127.0.0.1", 65000) is None


def test_expected_addr_hex():
    probe = ProcProcessIdentityProbe()
    assert probe._expected_addr_hex("127.0.0.1") == "0100007F"
    assert probe._expected_addr_hex("127.0.1.1") == "0101007F"
    assert probe._expected_addr_hex("0.0.0.0") == "00000000"
    assert probe._expected_addr_hex("::1") == "00000000000000000000000001000000"


def test_listen_inode_matches_the_exact_address_not_any_loopback(monkeypatch):
    """Two LISTEN rows share the port: 127.0.0.1 (inode A) and 127.0.1.1 (inode B). The
    advertised 127.0.0.1 must select inode A only — never B (round-5 F2). A 0.0.0.0 row is
    never matched for 127.0.0.1 (F3)."""
    from pathlib import Path as _Path

    port = 5555
    ph = f"{port:04X}"
    tcp = (
        "  sl  local_address rem_address   st ... inode\n"
        f"   0: 0100007F:{ph} 00000000:0000 0A 0 0 0 0 0 1001\n"  # 127.0.0.1 → inode 1001
        f"   1: 0101007F:{ph} 00000000:0000 0A 0 0 0 0 0 2002\n"  # 127.0.1.1 → inode 2002
        f"   2: 00000000:{ph} 00000000:0000 0A 0 0 0 0 0 3003\n"  # 0.0.0.0   → inode 3003
    )

    def _read(self, **_):
        if self.name == "tcp":
            return tcp
        raise OSError

    monkeypatch.setattr(_Path, "read_text", _read)
    probe = ProcProcessIdentityProbe()
    assert probe._listen_inode("127.0.0.1", port) == "1001"
    assert probe._listen_inode("127.0.1.1", port) == "2002"


def test_listen_inode_does_not_match_a_wildcard_row_for_a_specific_address(monkeypatch):
    from pathlib import Path as _Path

    port = 5556
    ph = f"{port:04X}"
    tcp = (
        "  sl  local_address rem_address   st ... inode\n"
        f"   0: 00000000:{ph} 00000000:0000 0A 0 0 0 0 0 4004\n"  # 0.0.0.0 only
    )

    def _read(self, **_):
        if self.name == "tcp":
            return tcp
        raise OSError

    monkeypatch.setattr(_Path, "read_text", _read)
    probe = ProcProcessIdentityProbe()
    assert probe._listen_inode("127.0.0.1", port) is None
