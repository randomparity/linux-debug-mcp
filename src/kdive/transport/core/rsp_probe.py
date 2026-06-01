from __future__ import annotations

import threading

from kdive.transport.core.bounded import BoundedIOTimeout, Deadline, connect_tcp

# Cap on bytes buffered while waiting for a complete RSP frame from an unauthenticated peer. A
# valid `$...#xx` halt-reason reply is a few dozen bytes; the bound stops a hostile or broken peer
# that streams data without ever sending `#` from pinning CPU/memory in the accumulation loop.
RSP_MAX_ACCUMULATE_BYTES = 4096


def rsp_frame(payload: str) -> bytes:
    """Wrap an RSP payload as `$<payload>#<checksum>` (mod-256 sum, 2 hex digits)."""
    checksum = sum(payload.encode("ascii")) % 256
    return b"$" + payload.encode("ascii") + b"#" + f"{checksum:02x}".encode("ascii")


def valid_rsp_frame(buffer: bytes) -> bool:
    """True iff `buffer` contains a complete, checksum-valid RSP packet
    `$<payload>#<2 hex>` (leading `+`/`-` acks ignored). A bare `+`, a frame with a
    non-hex checksum, or a checksum that does not equal `sum(payload) % 256` is False —
    so a non-RSP listener that merely writes `+` or `$hello` is rejected."""
    start = buffer.find(b"$")
    if start == -1:
        return False
    hash_idx = buffer.find(b"#", start)
    if hash_idx == -1 or hash_idx + 2 >= len(buffer):
        return False
    payload = buffer[start + 1 : hash_idx]
    checksum_hex = buffer[hash_idx + 1 : hash_idx + 3]
    try:
        expected = int(checksum_hex, 16)
    except ValueError:
        return False
    return (sum(payload) % 256) == expected


def rsp_reachable(host: str, port: int, *, deadline: Deadline, cancel: threading.Event) -> bool:
    """Connect and exchange one READ-ONLY RSP packet (`?`, the halt-reason query — no side
    effects) and confirm the peer answers a complete, checksum-valid `$...#xx` frame. A
    plain TCP listener that accepts but never answers (or answers garbage) returns False."""
    try:
        sock = connect_tcp(host, port, deadline=deadline, cancel=cancel)
    except (BoundedIOTimeout, OSError):
        return False
    buffer = b""
    try:
        sock.sendall(b"+" + rsp_frame("?"))
        while not deadline.expired() and not cancel.is_set():
            sock.settimeout(max(0.05, min(0.5, deadline.remaining())))
            try:
                chunk = sock.recv(256)
            except TimeoutError:
                continue
            if not chunk:
                break
            buffer += chunk
            if valid_rsp_frame(buffer):
                return True
            if len(buffer) > RSP_MAX_ACCUMULATE_BYTES:
                break
    except OSError:
        return False
    finally:
        sock.close()
    return False
