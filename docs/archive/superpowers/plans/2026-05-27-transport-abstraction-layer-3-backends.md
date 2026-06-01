# Transport Abstraction — Layer 3 (Backends & Transports) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the wire-level transport backends — agent-proxy supervision, the `serial-local` and `qemu-gdbstub` transports, the `inject_break` mechanism, and the agent-proxy prerequisite check — with no MCP surface and no end-to-end kernel halt.

**Architecture:** Layer 3 produces *bytes on the wire*. Each concrete `Transport.attach()` returns a `BackendAttachment` (wire-discovered fields only); Layer 4 later assembles the durable `TransportSession` from it (ADR 0003). Every blocking attach step is bounded + cancellable through one shared `transport/bounded.py` module, so a hung attach is force-reapable. Process/listener identity is an injectable `ProcessIdentityProbe` seam with a `/proc` default, shared with the existing qemu-gdbstub provider (ADR 0004). No kernel is halted here — `send_break` is exercised against PTY/fakes; the end-to-end halt is gated to Layer 4.

**Tech Stack:** Python 3.11+, threading (no asyncio), Pydantic v2 (`Model`/`ConfigModel`, `extra="forbid"`), stdlib `socket`/`os`/`pty`/`select`/`subprocess`, pytest. Ruff is the only linter/formatter (line length 120, selects `E,F,I,UP,B,SIM`). No new runtime dependency.

---

## Decisions & rejected alternatives (feed verbatim to each adversarial-review round)

These are SETTLED. A reviewer must treat them as decided and block only on (a) a contract/ADR violation citable by section, or (b) a concrete interleaving with named steps → wrong result. Do not relitigate.

1. **`attach()` returns `BackendAttachment`; Layer 4 owns `TransportSession` ([ADR 0003]).** Backends populate only `console_endpoint`/`rsp_endpoint`/`backend_pid`/`backend_start_time`/`console_artifact`. They never mint `session_id`, tokens, or `record_state`. *Rejected:* carrier+merge (two identities, convention-only split) and threading `session_id` into `attach` (still a partial record). Structural split > prose invariant.
2. **Process/listener identity is an injectable `ProcessIdentityProbe` seam, `/proc` default ([ADR 0004]).** Unit tests inject a fake → host-independent. **Listener identity is per-transport (see decision 7) — there is no single "RSP-primary" rule:** qemu-gdbstub uses RSP framing for *reachability only*; agent-proxy does **not** use RSP framing and instead **fails closed on address-specific `owns_listener(pid, "127.0.0.1", port)` for both ports** (`False`/`None` rejects). Reap-safety rests on the start-time fingerprint of *our own* spawned pid (`Popen` reap live; `stop_by_identity` for crash recovery). The qemu provider is refactored onto the same seam. *Rejected:* `/proc`-only (per-OS divergence), `psutil` (unjustified dependency), Linux-gating tests (skipping ≠ fixing), and any RSP-framing-as-listener-identity for agent-proxy (a live kernel is not in kgdb, so its gdb port is silent — round-1..9 review).
3. **One shared `transport/bounded.py` for bounded+cancellable IO.** The "no unbounded syscall, honor cancel+deadline" invariant lives in one fake-tested place. Only primitives with a real call site are included. *Rejected:* per-transport inline (duplicates the safety-critical code), share-only-Deadline (leaves the risky syscalls copied).
4. **Layer 3 never halts a real kernel.** `send_break` dispatch is unit-tested against fakes; a Linux+agent-proxy-gated PTY integration test pins the real BREAK escape bytes and endpoint liveness. The end-to-end "drops a kgdb target into the debugger" assertion is **Layer 4**. *Rejected:* a richer in-process fake kgdb/RSP server (tests the fake, YAGNI), thin integration (loses the escape-byte pin).
5. **The qemu-gdbstub adapter sources its RSP host/port from the channel `transport_ref` and does a bounded RSP-framing reachability probe at attach.** The existing 52KB `QemuGdbstubProvider` batch-gdb engine is **untouched** in Layer 3 (its rewire onto the transaction is Layer 4). Listener-*identity* verification does not apply (QEMU owns the stub; we did not race-allocate it). *Rejected:* pure passthrough with no probe (returns a dead endpoint as healthy).
6. **(Plan-level) Port allocation is internal to `AgentProxyBackend.start`; the bound `console_port`/`gdb_port` are *outputs* on `ProxyHandle`, not inputs.** This is the necessary consequence of "retry the whole allocation on a bind conflict" (§6.1) — fixed input ports cannot be re-allocated on conflict. This deviates from the §6.1 signature *sketch* (which listed them as params); the behavior (race-minimized, identity-verified) is unchanged. If a reviewer prefers caller-supplied ports, that is a non-blocking note.
7. **(Plan-level) Two distinct identity signals, by transport.** For **qemu-gdbstub** the load-bearing reachability signal is a minimal **RSP-framing probe** that parses a complete checksum-valid `$...#xx` frame (`rsp_probe.rsp_reachable`/`valid_rsp_frame`) — QEMU's stub always answers the read-only `?` query, and a bare `+`/`$hello`/bad-checksum peer is rejected. For **agent-proxy** fronting a live kernel, RSP framing is **not** usable (the kernel is not in kgdb until broken in), so the load-bearing signal is **address-specific listener ownership** (`ProcessIdentityProbe.owns_listener(pid, "127.0.0.1", port)`: our spawned child owns the LISTEN socket on the **exact advertised `127.0.0.1:port`** — not any 127/8 address), with a TCP connect proving a listener exists and `is_alive`+`looks_like` as supporting checks. Verification **fails closed**: it requires `owns_listener is True` for **both** ports; `None` (ownership unverifiable — no `/proc/net`, or unreadable) is a **reject**, never a pass, so a foreign listener cannot slip through on an indeterminable host. agent-proxy is Linux-only in prod (ownership determinable); unit tests inject the verdict via a fake probe. On a verification failure `start` reaps **our** child via `Popen.terminate/wait/kill/wait` (no zombie) and reallocates — a foreign listener is **never** signalled (we only ever act on our own `Popen`). *Rejected:* a single uniform "RSP framing or connect" check for both (blesses a foreign listener on the agent-proxy path, accepts any TCP listener as a gdbstub on the qemu path — round-1 F1/F3); treating `owns_listener=None` as a pass (round-2 F2); signal-only stop without `wait()` (zombies — round-2 F4).

[ADR 0003]: ../../adr/0003-layer3-backend-attachment-vs-transport-session-ownership.md
[ADR 0004]: ../../adr/0004-process-identity-is-an-injectable-seam.md

---

## File structure

| File | New/Edit | Responsibility |
|------|----------|----------------|
| `src/linux_debug_mcp/transport/bounded.py` | Create | `Deadline` + bounded, cancellable IO primitives (`connect_tcp`, `open_device`, `spawn`, `await_accept`, `allocate_loopback_ports`) and `BoundedIOTimeout`/`BoundedIOCancelled`. |
| `src/linux_debug_mcp/transport/rsp_probe.py` | Create | `rsp_frame` + `rsp_reachable` — a minimal bounded read-only RSP-framing probe (used by the qemu-gdbstub adapter). |
| `src/linux_debug_mcp/seams/process_identity.py` | Create | `ProcessIdentity` value + `ProcessIdentityProbe` Protocol (`identity`/`is_alive`/`looks_like`/`owns_listener`) + `ProcProcessIdentityProbe` (`/proc` default). |
| `src/linux_debug_mcp/transport/base.py` | Edit | Add `BackendAttachment`; change `Transport.attach(...) -> BackendAttachment`. |
| `src/linux_debug_mcp/transport/proxy.py` | Create | `ProxyHandle`, `ProxyBackend` Protocol, `AgentProxyBackend` (argv, `-s003`, race-minimized ports, on_partial, identity verification, health, reap, send_break). |
| `src/linux_debug_mcp/transport/qemu_gdbstub.py` | Create | `QemuGdbstubTransport` adapter (RSP passthrough from the channel ref + bounded framing probe). |
| `src/linux_debug_mcp/transport/serial_local.py` | Create | `SerialLocalTransport`: console-only → mode-`0600` unix socket; console+gdb → `AgentProxyBackend` demux. |
| `src/linux_debug_mcp/transport/break_inject.py` | Create | `inject_break` dispatch over an admitted `BreakPlan` (`uart_break`/`agent_proxy_break` → proxy `send_break`; `sysrq_g` → ssh write). |
| `src/linux_debug_mcp/providers/qemu_gdbstub.py` | Edit | Refactor identity checks onto `ProcessIdentityProbe` (constructor seam, `/proc` default). |
| `src/linux_debug_mcp/prereqs/checks.py` | Edit | Add the `agent-proxy` availability check (WARNING when absent). |
| `tests/test_transport_bounded.py` | Create | Bounded-IO primitive tests against slow fakes. |
| `tests/test_process_identity.py` | Create | Probe seam tests (fake + `/proc` impl where available). |
| `tests/test_transport_proxy.py` | Create | AgentProxyBackend unit tests against fakes. |
| `tests/test_transport_qemu_gdbstub.py` | Create | qemu-gdbstub adapter tests. |
| `tests/test_transport_serial_local.py` | Create | serial-local both-paths tests. |
| `tests/test_break_inject.py` | Create | inject_break dispatch tests. |
| `tests/test_prereqs_agent_proxy.py` | Create | agent-proxy prereq check tests. |
| `tests/test_serial_local_transport_integration.py` | Create | Gated PTY + real agent-proxy integration (skips without `agent-proxy` unless `LDM_REQUIRE_AGENT_PROXY=1`). |
| `.github/workflows/transport-integration.yml` | Create | First CI workflow: build pinned agent-proxy, run the integration test un-skipped. |

Test files: `tests/test_rsp_probe.py` accompanies `rsp_probe.py`; the rest are listed per task.

**Dependency order (topological):** `bounded` → `rsp_probe` → `process_identity` → `base` edit → `proxy` → `qemu_gdbstub` → `serial_local` → `break_inject` → qemu provider refactor → prereqs → integration test.

---

## Task 1: `transport/bounded.py` — Deadline + bounded IO primitives

**Files:**
- Create: `src/linux_debug_mcp/transport/bounded.py`
- Test: `tests/test_transport_bounded.py`

- [ ] **Step 1: Write the failing test for `Deadline` + cancel/timeout guard**

```python
# tests/test_transport_bounded.py
import socket
import threading
import time

import pytest

from linux_debug_mcp.transport.bounded import (
    BoundedIOCancelled,
    BoundedIOTimeout,
    Deadline,
    check_not_cancelled,
    connect_tcp,
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
```

- [ ] **Step 2: Run the tests, verify they fail**

Run: `uv run python -m pytest tests/test_transport_bounded.py -q`
Expected: FAIL with `ModuleNotFoundError` / import error.

- [ ] **Step 3: Implement `Deadline` and the guards**

```python
# src/linux_debug_mcp/transport/bounded.py
from __future__ import annotations

import os
import select
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass


class BoundedIOTimeout(TimeoutError):
    """A bounded IO step did not complete before its deadline."""


class BoundedIOCancelled(Exception):
    """A bounded IO step observed its cancel event set."""


@dataclass(frozen=True)
class Deadline:
    """A monotonic deadline. `remaining()` never goes negative."""

    at: float

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        return cls(time.monotonic() + seconds)

    def remaining(self) -> float:
        return max(0.0, self.at - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0


def check_not_cancelled(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise BoundedIOCancelled("operation cancelled")


def _slice(deadline: Deadline, cancel: threading.Event) -> float:
    check_not_cancelled(cancel)
    remaining = deadline.remaining()
    if remaining <= 0.0:
        raise BoundedIOTimeout("deadline exceeded")
    return remaining
```

- [ ] **Step 4: Run the tests, verify they pass**

Run: `uv run python -m pytest tests/test_transport_bounded.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Write failing tests for `connect_tcp`, `open_device`, `await_accept`, `allocate_loopback_ports`**

```python
# tests/test_transport_bounded.py  (append)
from linux_debug_mcp.transport.bounded import (
    allocate_loopback_ports,
    await_accept,
    open_device,
)


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


def test_connect_tcp_times_out_against_a_dead_port():
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
```

- [ ] **Step 6: Run them, verify they fail**

Run: `uv run python -m pytest tests/test_transport_bounded.py -q`
Expected: FAIL (functions not defined).

- [ ] **Step 7: Implement the IO primitives**

```python
# src/linux_debug_mcp/transport/bounded.py  (append)
def connect_tcp(host: str, port: int, *, deadline: Deadline, cancel: threading.Event) -> socket.socket:
    remaining = _slice(deadline, cancel)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(remaining)
        sock.connect((host, port))
    except (TimeoutError, socket.timeout) as exc:
        sock.close()
        raise BoundedIOTimeout(f"connect to {host}:{port} timed out") from exc
    except OSError:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


def allocate_loopback_ports(count: int) -> list[tuple[int, socket.socket]]:
    """Bind `count` ephemeral 127.0.0.1 ports and return (port, held_socket) pairs.
    The caller keeps each socket bound until immediately before exec, then closes it
    (race-minimized allocation, §6.1). On any failure, all sockets are closed."""
    holders: list[tuple[int, socket.socket]] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            holders.append((sock.getsockname()[1], sock))
    except OSError:
        for _port, sock in holders:
            sock.close()
        raise
    return holders


def await_accept(listener: socket.socket, *, deadline: Deadline, cancel: threading.Event) -> socket.socket:
    while True:
        remaining = _slice(deadline, cancel)
        readable, _, _ = select.select([listener], [], [], min(remaining, 0.2))
        if readable:
            conn, _addr = listener.accept()
            return conn


def open_device(path: str, *, deadline: Deadline, cancel: threading.Event) -> int:
    """Open a serial **character device** / PTY slave non-blocking and return an fd.
    `O_NONBLOCK` ensures the open does not block waiting on carrier (DCD) on a real serial
    line. Rejects non-character-special paths (FIFOs, regular files): serial sources are
    ttys/PTYs, and a unix-socket source is connected elsewhere — so a FIFO/regular path is
    a configuration error, not a thing to wait on. (`O_RDWR|O_NONBLOCK` on a FIFO would
    return immediately without proving any peer, which is why this rejects rather than
    polls for writability.)"""
    check_not_cancelled(cancel)
    if deadline.expired():
        raise BoundedIOTimeout("deadline exceeded")
    mode = os.stat(path).st_mode
    if not stat.S_ISCHR(mode):
        raise OSError(f"{path!r} is not a character device (expected a serial port or PTY slave)")
    return os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)


def spawn(argv: list[str], *, deadline: Deadline, cancel: threading.Event, **popen_kwargs: object) -> subprocess.Popen:
    """Start a subprocess with no shell. Spawn itself is non-blocking; the deadline/cancel
    are checked before exec so a cancelled attach never spawns."""
    _slice(deadline, cancel)
    return subprocess.Popen(argv, shell=False, **popen_kwargs)  # noqa: S603 - list argv, never a shell
```

- [ ] **Step 8: Run all bounded tests, verify pass; lint**

Run: `uv run python -m pytest tests/test_transport_bounded.py -q && uv run ruff check src/linux_debug_mcp/transport/bounded.py tests/test_transport_bounded.py && uv run ruff format --check src/linux_debug_mcp/transport/bounded.py tests/test_transport_bounded.py`
Expected: all pass, no lint errors.

- [ ] **Step 9: Commit**

```bash
git add src/linux_debug_mcp/transport/bounded.py tests/test_transport_bounded.py
git commit -m "feat: add bounded, cancellable transport IO primitives (#10)"
```

---

## Task 1b: `transport/rsp_probe.py` — minimal RSP-framing reachability probe

A connect-only probe accepts any TCP listener as a gdbstub (round-1 review F3). A real probe must exchange one read-only RSP packet and confirm the peer speaks `$...#xx` framing. This module is shared by the qemu-gdbstub adapter (Task 6, where QEMU's stub always answers the read-only `?` query) and is **not** used for agent-proxy's gdb port (a live kernel is not in kgdb until broken in, so it would not answer RSP — agent-proxy identity rests on listener ownership instead, Task 5).

**Files:**
- Create: `src/linux_debug_mcp/transport/rsp_probe.py`
- Test: `tests/test_rsp_probe.py`

- [ ] **Step 1: Write failing tests (live RSP responder accepted; plain TCP listener rejected)**

```python
# tests/test_rsp_probe.py
import socket
import threading

from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.rsp_probe import rsp_frame, rsp_reachable


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
    from linux_debug_mcp.transport.rsp_probe import valid_rsp_frame

    assert valid_rsp_frame(b"+" + rsp_frame("T05")) is True
    assert valid_rsp_frame(b"+") is False              # bare ack, no packet
    assert valid_rsp_frame(b"$T05#zz") is False        # non-hex checksum
    assert valid_rsp_frame(b"$T05#00") is False        # checksum does not match payload
    assert valid_rsp_frame(b"$hello") is False         # no terminator


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
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_rsp_probe.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement the probe**

```python
# src/linux_debug_mcp/transport/rsp_probe.py
from __future__ import annotations

import socket
import threading

from linux_debug_mcp.transport.bounded import BoundedIOTimeout, Deadline, connect_tcp


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
            except (TimeoutError, socket.timeout):
                continue
            if not chunk:
                break
            buffer += chunk
            if valid_rsp_frame(buffer):
                return True
            if len(buffer) > 4096:  # bounded: do not accumulate unboundedly
                break
    except OSError:
        return False
    finally:
        sock.close()
    return False
```

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_rsp_probe.py -q && uv run ruff check src/linux_debug_mcp/transport/rsp_probe.py tests/test_rsp_probe.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/rsp_probe.py tests/test_rsp_probe.py
git commit -m "feat: add minimal RSP-framing reachability probe (#10)"
```

---

## Task 2: `seams/process_identity.py` — `ProcessIdentityProbe` seam (ADR 0004)

**Files:**
- Create: `src/linux_debug_mcp/seams/process_identity.py`
- Test: `tests/test_process_identity.py`

- [ ] **Step 1: Write the failing tests (fake + value type + /proc on self)**

```python
# tests/test_process_identity.py
import os
import sys

import pytest

from linux_debug_mcp.seams.process_identity import (
    ProcessIdentity,
    ProcessIdentityProbe,
    ProcProcessIdentityProbe,
)


def test_process_identity_is_frozen():
    identity = ProcessIdentity(pid=1234, start_time="999", argv0="agent-proxy")
    with pytest.raises(Exception):
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

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        probe = ProcProcessIdentityProbe()
        assert probe.owns_listener(os.getpid(), "127.0.0.1", port) is True
        # A pid that is not us does not own our listener.
        assert probe.owns_listener(1, "127.0.0.1", port) is False
    finally:
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
        f"   0: 0100007F:{ph} 00000000:0000 0A 0 0 0 0 0 1001\n"   # 127.0.0.1 → inode 1001
        f"   1: 0101007F:{ph} 00000000:0000 0A 0 0 0 0 0 2002\n"   # 127.0.1.1 → inode 2002
        f"   2: 00000000:{ph} 00000000:0000 0A 0 0 0 0 0 3003\n"   # 0.0.0.0   → inode 3003
    )

    def _read(self, **_):
        if self.name == "tcp":
            return tcp
        raise OSError

    monkeypatch.setattr(_Path, "read_text", _read)
    probe = ProcProcessIdentityProbe()
    assert probe._listen_inode("127.0.0.1", port) == "1001"
    assert probe._listen_inode("127.0.1.1", port) == "2002"
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_process_identity.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement the seam (port the /proc logic from `providers/qemu_gdbstub.py`)**

```python
# src/linux_debug_mcp/seams/process_identity.py
from __future__ import annotations

import errno
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ProcessIdentity:
    """A pid plus a start-time fingerprint so pid reuse cannot cause a foreign match.
    `start_time` is an opaque string token (Linux: /proc stat field 19); None when the
    platform cannot supply one (e.g. macOS), which callers treat as 'unverifiable'."""

    pid: int
    start_time: str | None
    argv0: str | None


class ProcessIdentityProbe(Protocol):
    def identity(self, pid: int) -> ProcessIdentity | None: ...

    def is_alive(self, pid: int) -> bool: ...

    def looks_like(self, pid: int, name_substr: str) -> bool: ...

    def owns_listener(self, pid: int, host: str, port: int) -> bool | None: ...


class ProcProcessIdentityProbe:
    """Default Linux `/proc` implementation. The single home for the start-time
    fingerprint technique (ADR 0004); the qemu-gdbstub provider and the agent-proxy
    backend both consume this seam rather than re-reading /proc."""

    def identity(self, pid: int) -> ProcessIdentity | None:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            stat_text = stat_path.read_text(encoding="utf-8")
        except OSError:
            return None
        _prefix, separator, suffix = stat_text.rpartition(") ")
        start_time: str | None = None
        if separator:
            fields = suffix.split()
            if len(fields) >= 20:
                start_time = fields[19]
        argv0 = self._argv0(pid)
        return ProcessIdentity(pid=pid, start_time=start_time, argv0=argv0)

    def is_alive(self, pid: int) -> bool:
        if self._is_zombie(pid):
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError as exc:
            return exc.errno != errno.ESRCH
        return True

    def looks_like(self, pid: int, name_substr: str) -> bool:
        argv0 = self._argv0(pid)
        if argv0 is None:
            return False
        return name_substr in Path(argv0).name

    def owns_listener(self, pid: int, host: str, port: int) -> bool | None:
        """True iff `pid` owns the LISTEN socket bound to the **exact** `host:port` we
        advertise. Returns None when ownership cannot be determined (no /proc/net, e.g.
        macOS, or our own fds are unreadable) so callers fail closed rather than treat
        'unknown' as proven. Matching is address-specific (round-5 F2): a foreign listener
        on 127.0.0.1:port while our child holds 127.0.1.1:port must NOT pass."""
        if not Path("/proc/net/tcp").exists():
            return None  # indeterminable (no /proc/net)
        inode = self._listen_inode(host, port)
        if inode is None:
            return False  # no LISTEN socket on the exact advertised host:port
        fd_dir = Path("/proc") / str(pid) / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            return None  # cannot read our own fds → indeterminable, fail closed
        target = f"socket:[{inode}]"
        for entry in entries:
            try:
                if os.readlink(entry) == target:
                    return True
            except OSError:
                continue
        return False

    @staticmethod
    def _expected_addr_hex(host: str) -> str | None:
        """The /proc/net local-address hex (little-endian per 32-bit word) for `host`."""
        try:
            return f"{int.from_bytes(socket.inet_aton(host), 'little'):08X}"
        except OSError:
            pass
        try:
            packed = socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            return None
        return "".join(f"{int.from_bytes(packed[i : i + 4], 'little'):08X}" for i in range(0, 16, 4))

    def _listen_inode(self, host: str, port: int) -> str | None:
        expected = self._expected_addr_hex(host)
        if expected is None:
            return None
        proc_net = "/proc/net/tcp6" if len(expected) == 32 else "/proc/net/tcp"
        try:
            lines = Path(proc_net).read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            return None
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            addr_hex, _sep, port_hex = fields[1].rpartition(":")
            if fields[3] != "0A" or int(port_hex, 16) != port:
                continue
            if addr_hex.upper() != expected:
                continue  # exact advertised address only (F2: 127.0.0.1 ≠ 127.0.1.1, ≠ 0.0.0.0)
            return fields[9]
        return None

    def _argv0(self, pid: int) -> str | None:
        cmdline_path = Path("/proc") / str(pid) / "cmdline"
        try:
            cmdline = cmdline_path.read_bytes()
        except OSError:
            return None
        if not cmdline:
            return None
        return cmdline.split(b"\0", 1)[0].decode("utf-8", errors="ignore")

    def _is_zombie(self, pid: int) -> bool:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            stat_text = stat_path.read_text(encoding="utf-8")
        except OSError:
            return False
        _prefix, separator, suffix = stat_text.rpartition(") ")
        if not separator:
            return False
        fields = suffix.split()
        return bool(fields and fields[0] == "Z")
```

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_process_identity.py -q && uv run ruff check src/linux_debug_mcp/seams/process_identity.py tests/test_process_identity.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/process_identity.py tests/test_process_identity.py
git commit -m "feat: add injectable ProcessIdentityProbe seam with /proc default (#10)"
```

---

## Task 3: `transport/base.py` — add `BackendAttachment`, narrow `attach()` (ADR 0003)

**Files:**
- Modify: `src/linux_debug_mcp/transport/base.py` (the `Transport` ABC at base.py:328 and a new value type)
- Test: `tests/test_transport_base.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_transport_base.py  (append; BackendAttachment to the existing import block)
import threading

from linux_debug_mcp.transport.base import BackendAttachment


def test_backend_attachment_is_frozen_and_carries_only_wire_fields():
    attachment = BackendAttachment(
        console_endpoint=None,
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=1234),
        backend_pid=4321,
        backend_start_time="999",
        console_artifact=None,
    )
    assert attachment.rsp_endpoint.port == 1234
    assert attachment.backend_pid == 4321
    with pytest.raises(Exception):
        attachment.backend_pid = 1  # type: ignore[misc]
    # BackendAttachment must not carry identity/token/record_state fields (ADR 0003).
    for forbidden in ("session_id", "console_lease_token", "stop_guard_token", "record_state"):
        assert not hasattr(attachment, forbidden)


def test_concrete_transport_attach_returns_backend_attachment():
    class _StubTransport(Transport):
        @property
        def capability(self) -> TransportCapability:
            return TransportCapability(
                provider_name="qemu-gdbstub",
                locality=TransportLocality.LOCAL,
                provides_console=False,
                provides_rsp=True,
                supports_uart_break=False,
                endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
            )

        def attach(self, request, *, cancel, deadline, on_partial) -> BackendAttachment:
            return BackendAttachment(
                console_endpoint=None,
                rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=request.transport_ref.opts["port"]),
                backend_pid=None,
                backend_start_time=None,
                console_artifact=None,
            )

        def close(self, session) -> None: ...

        def health(self, session) -> str:
            return "ready"

    transport = _StubTransport()
    request = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(
            provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, opts={"port": 7000}
        ),
        platform=_platform(),
    )
    result = transport.attach(request, cancel=threading.Event(), deadline=1.0, on_partial=lambda *_: None)
    assert isinstance(result, BackendAttachment)
    assert result.rsp_endpoint.port == 7000
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_transport_base.py -q`
Expected: FAIL (`ImportError: BackendAttachment`).

- [ ] **Step 3: Add `BackendAttachment` and narrow the ABC return type**

In `src/linux_debug_mcp/transport/base.py`, add a dataclass import (`from dataclasses import dataclass`) and, immediately before `class Transport(ABC):`, insert:

```python
@dataclass(frozen=True)
class BackendAttachment:
    """A Layer-3 backend's terminal success value (ADR 0003): only fields the wire work
    discovers. Layer 4 owns TransportSession and assembles it from its durable record +
    this attachment. Backends never mint session_id, tokens, or record_state."""

    console_endpoint: Endpoint | None
    rsp_endpoint: Endpoint | None
    backend_pid: int | None
    backend_start_time: str | None
    console_artifact: ArtifactRef | None = None
```

Then change the `Transport.attach` return annotation from `-> TransportSession` to `-> BackendAttachment`, and update its docstring to cite ADR 0003.

- [ ] **Step 4: Run, verify pass; full base-schema suite stays green; lint**

Run: `uv run python -m pytest tests/test_transport_base.py -q && uv run ruff check src/linux_debug_mcp/transport/base.py`
Expected: PASS (existing tests unaffected — `attach` has no production callers).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/base.py tests/test_transport_base.py
git commit -m "feat: add BackendAttachment; backends return it, Layer 4 owns TransportSession (#10)"
```

---

## Task 4: `transport/proxy.py` — `ProxyBackend` Protocol + `AgentProxyBackend` argv/spawn/on_partial

**Files:**
- Create: `src/linux_debug_mcp/transport/proxy.py`
- Test: `tests/test_transport_proxy.py`

This task builds argv construction, race-minimized allocation, the spawn, and on_partial reporting. Task 5 adds identity verification, health, reap, and send_break.

- [ ] **Step 1: Write failing tests for argv + `-s003` + a fake spawner recording partials**

```python
# tests/test_transport_proxy.py
import subprocess
import threading

from linux_debug_mcp.seams.process_identity import ProcessIdentity
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.proxy import (
    AgentProxyBackend,
    LocalDeviceSource,
    RemoteTerminalServerSource,
)


class _FakeProc:
    """Stand-in Popen: records lifecycle calls; `wait` raises TimeoutExpired while
    returncode is None so reap escalates terminate→kill like a real child."""

    def __init__(self, pid, *, dies_on_term=True):
        self.pid = pid
        self.returncode = None
        self._dies_on_term = dies_on_term
        self.events: list[str] = []

    def terminate(self):
        self.events.append("terminate")
        if self._dies_on_term:
            self.returncode = 0

    def kill(self):
        self.events.append("kill")
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(cmd="agent-proxy", timeout=timeout)
        return self.returncode

    def poll(self):
        self.events.append("poll")
        return self.returncode


class _FakeSpawner:
    """Records argv; returns a _FakeProc per call (tracked in self.procs). If `_pids` is an
    iterator, hands out a distinct pid per call (retry tests), else the fixed `pid`."""

    def __init__(self, pid: int = 5000):
        self.calls: list[list[str]] = []
        self.pid = pid
        self._pids = None
        self.procs: list[_FakeProc] = []

    def __call__(self, argv, *, deadline, cancel, **kwargs):
        self.calls.append(list(argv))
        pid = next(self._pids) if self._pids is not None else self.pid
        proc = _FakeProc(pid=pid, dies_on_term=True)
        self.procs.append(proc)
        return proc


def _ok_probe(start_time="t"):
    class _P:
        def identity(self, pid):
            return ProcessIdentity(pid=pid, start_time=start_time, argv0="agent-proxy")

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            return True

    return _P()


def test_local_device_argv_includes_s003_when_no_uart_break():
    spawner = _FakeSpawner()
    backend = AgentProxyBackend(spawner=spawner, identity_probe=_ok_probe())
    partials: list[tuple[str, object]] = []
    backend.start(
        LocalDeviceSource(device="/dev/ttyS0", baud=115200),
        supports_uart_break=False,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda kind, value: partials.append((kind, value)),
        _verify=False,  # identity verification covered in Task 5
    )
    argv = spawner.calls[0]
    assert argv[0] == "agent-proxy"
    assert "-s003" in argv
    assert "0" in argv and "/dev/ttyS0,115200" in argv
    # Ports are loopback-bind-pinned so agent-proxy does not listen on 0.0.0.0 (F1).
    assert argv[1].startswith("127.0.0.1:") and "^127.0.0.1:" in argv[1]
    # cleanup authority is published atomically as pid + start-time fingerprint (F1, round 5)
    assert partials == [("backend_process", {"pid": 5000, "start_time": "t"})]


def test_local_device_argv_omits_s003_when_uart_break_supported():
    spawner = _FakeSpawner()
    backend = AgentProxyBackend(spawner=spawner, identity_probe=_ok_probe())
    backend.start(
        LocalDeviceSource(device="/dev/ttyS0", baud=115200),
        supports_uart_break=True,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
        _verify=False,
    )
    assert "-s003" not in spawner.calls[0]


def test_remote_terminal_server_argv_uses_ip_and_port():
    spawner = _FakeSpawner()
    backend = AgentProxyBackend(spawner=spawner, identity_probe=_ok_probe())
    backend.start(
        RemoteTerminalServerSource(host="10.0.0.5", port=4001),
        supports_uart_break=True,
        cancel=threading.Event(),
        deadline=Deadline.after(2.0),
        on_partial=lambda *_: None,
        _verify=False,
    )
    argv = spawner.calls[0]
    assert "10.0.0.5" in argv and "4001" in argv
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_transport_proxy.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement sources, `ProxyHandle`, the Protocol, and `start` (argv + allocation + spawn + on_partial)**

```python
# src/linux_debug_mcp/transport/proxy.py
from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from linux_debug_mcp.seams.process_identity import ProcessIdentityProbe, ProcProcessIdentityProbe
from linux_debug_mcp.transport.bounded import Deadline, allocate_loopback_ports, spawn

AGENT_PROXY = "agent-proxy"
ON_PARTIAL = Callable[[str, object], None]


@dataclass(frozen=True)
class LocalDeviceSource:
    device: str
    baud: int = 115200


@dataclass(frozen=True)
class RemoteTerminalServerSource:
    host: str
    port: int


ProxySource = LocalDeviceSource | RemoteTerminalServerSource


@dataclass
class ProxyHandle:
    process: object
    backend_pid: int
    backend_start_time: str | None
    console_port: int
    gdb_port: int
    sockets: list[socket.socket] = field(default_factory=list)


class ProxyBackend(Protocol):
    def start(
        self,
        source: ProxySource,
        *,
        supports_uart_break: bool,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: ON_PARTIAL,
        inherit_fds: tuple[int, ...] = (),
    ) -> ProxyHandle: ...

    def health(self, handle: ProxyHandle) -> str: ...

    def send_break(self, handle: ProxyHandle) -> None: ...

    def stop(self, handle: ProxyHandle) -> None: ...

    def stop_by_identity(self, pid: int, start_time: str | None) -> None: ...


def _source_argv(source: ProxySource) -> list[str]:
    if isinstance(source, LocalDeviceSource):
        return ["0", f"{source.device},{source.baud}"]
    return [source.host, str(source.port)]


class AgentProxyBackend:
    """Supervises an agent-proxy child that demuxes a console^gdb port pair (§6.1).
    No shell: argv is a list, ports are ints, endpoints are loopback-only."""

    def __init__(
        self,
        *,
        spawner: Callable[..., object] = spawn,
        identity_probe: ProcessIdentityProbe | None = None,
    ) -> None:
        self._spawn = spawner
        self._identity = identity_probe or ProcProcessIdentityProbe()

    MAX_ATTEMPTS = 5

    def start(
        self,
        source: ProxySource,
        *,
        supports_uart_break: bool,
        cancel: threading.Event,
        deadline: Deadline,
        on_partial: ON_PARTIAL,
        inherit_fds: tuple[int, ...] = (),
        _verify: bool = True,
    ) -> ProxyHandle:
        """Spawn agent-proxy and verify our child owns the allocated listeners. On a
        verification failure (a foreign process won the bind race, §6.1), reap OUR child
        — never the foreigner — and retry on fresh ports until verified, the deadline
        passes, or MAX_ATTEMPTS is reached."""
        last_error: ProxyIdentityError | None = None
        for _attempt in range(self.MAX_ATTEMPTS):
            check_not_cancelled(cancel)
            if deadline.expired():
                break
            handle = self._spawn_once(source, supports_uart_break=supports_uart_break,
                                      cancel=cancel, deadline=deadline, on_partial=on_partial,
                                      inherit_fds=inherit_fds)
            try:
                if handle.backend_start_time is None:
                    # No start-time fingerprint ⇒ the fenced close path could never reap this
                    # child later (F2). Fail closed now, while we still hold the Popen.
                    raise ProxyIdentityError("spawned agent-proxy has no start-time fingerprint")
                if _verify:
                    self._verify_identity(handle, deadline=deadline, cancel=cancel)
            except ProxyIdentityError as exc:
                last_error = exc
                self._reap(handle.process)  # reap OUR fresh child directly; foreign listener untouched
                continue
            except BaseException:
                # cancel (BoundedIOCancelled) / deadline / unexpected: reap before propagating (F1).
                self._reap(handle.process)
                raise
            return handle
        raise last_error or ProxyIdentityError("agent-proxy attach did not verify before the deadline")

    def _spawn_once(self, source, *, supports_uart_break, cancel, deadline, on_partial,
                    inherit_fds=()) -> ProxyHandle:
        holders = allocate_loopback_ports(2)
        console_port, gdb_port = holders[0][0], holders[1][0]
        # Force LOOPBACK binding (round-7 F1): agent-proxy defaults to INADDR_ANY (0.0.0.0),
        # which would expose console/RSP off-host AND fail the exact-127.0.0.1 ownership check.
        # agent-proxy's native `virt_IP:port` syntax binds the given address (setup_local_port).
        argv = [AGENT_PROXY, f"127.0.0.1:{console_port}^127.0.0.1:{gdb_port}", *_source_argv(source)]
        if not supports_uart_break:
            argv.append("-s003")
        # Release the held ports immediately before exec (race-minimized window, §6.1).
        for _port, sock in holders:
            sock.close()
        # pass_fds keeps the source-exclusivity lock fd open in the child so the lock tracks
        # the device-holder's lifetime, surviving a parent crash (round-10 F1).
        process = self._spawn(argv, deadline=deadline, cancel=cancel, pass_fds=inherit_fds)
        # Everything after the Popen exists must reap the child on ANY failure (round-8 F1):
        # `identity()` or `on_partial()` (which may fsync the durable record in Layer 4) can
        # raise, and the handle has not been returned yet, so start()'s cleanup would never
        # see it. Reap here before re-raising.
        try:
            pid = int(process.pid)
            # Capture the start-time fingerprint BEFORE publishing cleanup authority (round-5
            # F1): a crash after this partial must leave reconciliation with pid+start_time,
            # never pid-only. Emit both atomically as one partial.
            identity = self._identity.identity(pid)
            start_time = identity.start_time if identity else None
            on_partial("backend_process", {"pid": pid, "start_time": start_time})
            return ProxyHandle(process=process, backend_pid=pid, backend_start_time=start_time,
                               console_port=console_port, gdb_port=gdb_port)
        except BaseException:
            self._reap(process)
            raise
```

Import `check_not_cancelled` from `transport.bounded`. `_verify_identity`, `health`, `send_break`, `stop` are stubbed to `raise NotImplementedError` for now and filled in Task 5 — except `stop`, which Task 5 must implement before this retry path is exercised end-to-end (the Task 5 tests cover both). Define them all so the class is importable.

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_transport_proxy.py -q && uv run ruff check src/linux_debug_mcp/transport/proxy.py tests/test_transport_proxy.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/proxy.py tests/test_transport_proxy.py
git commit -m "feat: add AgentProxyBackend argv, port allocation, and partial reporting (#10)"
```

---

## Task 5: `transport/proxy.py` — listener-identity verification, health, reap, send_break

**Files:**
- Modify: `src/linux_debug_mcp/transport/proxy.py`
- Test: `tests/test_transport_proxy.py` (append)

- [ ] **Step 1: Write failing tests**

```python
# tests/test_transport_proxy.py  (append; subprocess/threading/Deadline/ProcessIdentity/
# AgentProxyBackend/LocalDeviceSource/_FakeProc/_FakeSpawner are in the Task 4 header above)
import socket
import sys

import pytest

from linux_debug_mcp.seams.process_identity import ProcProcessIdentityProbe
from linux_debug_mcp.transport.proxy import ProxyHandle, ProxyIdentityError


class _Probe:
    """Configurable identity probe. `owns` may be a bool or a callable(pid, port)->bool|None.
    `is_alive` consults `killed` so stop() returns promptly once SIGTERM is recorded."""

    def __init__(self, *, start_time="t", looks=True, owns=True, killed=None):
        self.start_time, self._looks, self._owns, self._killed = start_time, looks, owns, killed if killed is not None else set()

    def identity(self, pid):
        return ProcessIdentity(pid=pid, start_time=self.start_time, argv0="agent-proxy")

    def is_alive(self, pid):
        return pid not in self._killed

    def looks_like(self, pid, name_substr):
        return self._looks

    def owns_listener(self, pid, host, port):
        return self._owns(pid, host, port) if callable(self._owns) else self._owns


def _live_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    return sock, sock.getsockname()[1]


def test_verify_rejects_a_foreign_owner_and_does_not_kill_anything(monkeypatch):
    """A real listener answers TCP, but our child does NOT own it (owns_listener False).
    _verify_identity raises and signals nothing — killing is start()'s job, on OUR child."""
    killed = []
    monkeypatch.setattr("os.kill", lambda pid, sig: killed.append(pid))
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(pid=6000), identity_probe=_Probe(owns=False))
    handle = ProxyHandle(process=object(), backend_pid=6000, backend_start_time="t",
                         console_port=port, gdb_port=port)
    try:
        with pytest.raises(ProxyIdentityError):
            backend._verify_identity(handle, deadline=Deadline.after(0.5), cancel=threading.Event())
        assert killed == []
    finally:
        listener.close()


def test_verify_fails_closed_when_ownership_is_unknown_even_with_a_live_listener():
    """owns_listener None (e.g. /proc unreadable) while a listener answers and our child
    is alive+named: verification must REJECT (fail closed), not pass (round-2 review F2)."""
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(pid=6000), identity_probe=_Probe(owns=lambda pid, host, port: None))
    handle = ProxyHandle(process=object(), backend_pid=6000, backend_start_time="t",
                         console_port=port, gdb_port=port)
    try:
        with pytest.raises(ProxyIdentityError):
            backend._verify_identity(handle, deadline=Deadline.after(0.5), cancel=threading.Event())
    finally:
        listener.close()


def test_start_retries_after_a_foreign_bind_and_reaps_only_our_own_child(monkeypatch):
    """First attempt loses the bind race (verify raises); start() reaps OUR first child via
    its owned Popen, reallocates, and the second attempt verifies. We only ever act on our
    own _FakeProc objects, so a foreign listener's owner can never be signalled."""
    spawner = _FakeSpawner()
    spawner._pids = iter([6000, 6001])  # distinct pid per attempt

    calls = {"n": 0}

    def _verify(handle, *, deadline, cancel):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ProxyIdentityError("foreign bind on first attempt")

    backend = AgentProxyBackend(spawner=spawner, identity_probe=_Probe())
    monkeypatch.setattr(backend, "_verify_identity", _verify)
    handle = backend.start(LocalDeviceSource(device="/dev/ttyS0"), supports_uart_break=True,
                           cancel=threading.Event(), deadline=Deadline.after(5.0),
                           on_partial=lambda *_: None)
    assert handle.backend_pid == 6001
    assert "terminate" in spawner.procs[0].events     # first child reaped
    assert "terminate" not in spawner.procs[1].events  # second child kept


def test_start_fails_closed_and_reaps_when_no_start_time_fingerprint():
    """identity()/start_time is None ⇒ the handle would be unreapable later (F2). start()
    must reject and reap the spawned child rather than return an unreapable handle."""

    class _NoFingerprint:
        def identity(self, pid):
            return None  # no start-time fingerprint

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            return True

    proc = _FakeProc(pid=8100, dies_on_term=True)
    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_NoFingerprint())
    with pytest.raises(ProxyIdentityError):
        backend.start(LocalDeviceSource(device="/dev/ttyS0"), supports_uart_break=True,
                      cancel=threading.Event(), deadline=Deadline.after(1.0), on_partial=lambda *_: None)
    assert "terminate" in proc.events  # reaped despite the missing fingerprint


def test_start_reaps_the_spawned_child_when_verification_is_cancelled(monkeypatch):
    """cancel during verification raises BoundedIOCancelled out of _verify_identity; start()
    must reap the already-spawned child before propagating (round-3 review F1)."""
    from linux_debug_mcp.transport.bounded import BoundedIOCancelled

    proc = _FakeProc(pid=8000, dies_on_term=True)
    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_Probe(start_time="t"))

    def _cancelled(handle, *, deadline, cancel):
        raise BoundedIOCancelled("cancelled mid-verify")

    monkeypatch.setattr(backend, "_verify_identity", _cancelled)
    with pytest.raises(BoundedIOCancelled):
        backend.start(LocalDeviceSource(device="/dev/ttyS0"), supports_uart_break=True,
                      cancel=threading.Event(), deadline=Deadline.after(5.0), on_partial=lambda *_: None)
    assert "terminate" in proc.events  # spawned child reaped, not leaked


def test_stop_terminates_and_reaps_our_child():
    proc = _FakeProc(pid=7000, dies_on_term=True)
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="77"))
    handle = ProxyHandle(process=proc, backend_pid=7000, backend_start_time="77",
                         console_port=1, gdb_port=2)
    backend.stop(handle)
    assert "terminate" in proc.events
    assert proc.returncode is not None  # actually reaped, not a zombie


def test_stop_escalates_to_kill_when_terminate_does_not_reap():
    proc = _FakeProc(pid=7000, dies_on_term=False)
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="77"))
    handle = ProxyHandle(process=proc, backend_pid=7000, backend_start_time="77",
                         console_port=1, gdb_port=2)
    backend.stop(handle)
    assert proc.events[0] == "terminate" and "kill" in proc.events


def test_stop_does_not_signal_a_pid_whose_start_time_no_longer_matches():
    """pid reuse: a different process now holds backend_pid; start-time mismatch ⇒ never
    terminate/kill — only poll() to reap our own exited child."""
    proc = _FakeProc(pid=7000)
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="DIFFERENT"))
    handle = ProxyHandle(process=proc, backend_pid=7000, backend_start_time="77",
                         console_port=1, gdb_port=2)
    backend.stop(handle)
    assert "terminate" not in proc.events and "kill" not in proc.events


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="default /proc identity probe")
def test_stop_reaps_a_real_subprocess():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    probe = ProcProcessIdentityProbe()
    identity = probe.identity(proc.pid)
    backend = AgentProxyBackend()  # default ProcProcessIdentityProbe
    handle = ProxyHandle(process=proc, backend_pid=proc.pid,
                         backend_start_time=identity.start_time, console_port=1, gdb_port=2)
    backend.stop(handle)
    assert proc.poll() is not None  # the real child was reaped


def test_stop_by_identity_signals_only_on_a_fingerprint_match(monkeypatch):
    """Crash-recovery reaper (no Popen): signals by pid only when the live start-time
    matches the durable record (round-6 F1)."""
    signalled = []
    monkeypatch.setattr("os.kill", lambda pid, sig: signalled.append(pid))
    # is_alive False for 9000 so the post-SIGTERM wait loop returns promptly.
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="77", killed={9000}))
    backend.stop_by_identity(9000, "77")
    assert 9000 in signalled


def test_stop_by_identity_refuses_without_or_on_mismatched_fingerprint(monkeypatch):
    signalled = []
    monkeypatch.setattr("os.kill", lambda pid, sig: signalled.append(pid))
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="DIFFERENT"))
    backend.stop_by_identity(9000, None)   # no fingerprint → unfenceable → refuse
    backend.stop_by_identity(9000, "77")   # live start_time "DIFFERENT" ≠ recorded "77"
    assert signalled == []


def test_spawn_reaps_the_child_if_on_partial_raises():
    """on_partial may fsync the durable record (Layer 4) and fail; the just-spawned child
    must be reaped before the error propagates (round-8 F1)."""
    proc = _FakeProc(pid=8200, dies_on_term=True)

    def _boom(kind, value):
        raise RuntimeError("durable record fsync failed")

    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_Probe(start_time="t"))
    with pytest.raises(RuntimeError):
        backend.start(LocalDeviceSource(device="/dev/ttyS0"), supports_uart_break=True,
                      cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=_boom)
    assert "terminate" in proc.events


def test_spawn_reaps_the_child_if_identity_raises():
    """An identity-probe failure after spawn must also reap the child (round-8 F1)."""
    proc = _FakeProc(pid=8300, dies_on_term=True)

    class _BoomProbe:
        def identity(self, pid):
            raise RuntimeError("identity probe failed")

        def is_alive(self, pid):
            return True

        def looks_like(self, pid, name_substr):
            return True

        def owns_listener(self, pid, host, port):
            return True

    backend = AgentProxyBackend(spawner=lambda *a, **k: proc, identity_probe=_BoomProbe())
    with pytest.raises(RuntimeError):
        backend.start(LocalDeviceSource(device="/dev/ttyS0"), supports_uart_break=True,
                      cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    assert "terminate" in proc.events


def test_health_is_degraded_when_a_foreign_process_owns_the_port():
    """The child is alive but no longer owns the loopback port (a foreign process bound it);
    health must report degraded, not bless the stolen endpoint (round-8 F2)."""
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="t", owns=False))
    handle = ProxyHandle(process=_FakeProc(pid=9500), backend_pid=9500, backend_start_time="t",
                         console_port=port, gdb_port=port)
    try:
        assert backend.health(handle) == "degraded"
    finally:
        listener.close()
```

Update `_FakeSpawner` (Task 4) to draw its pid from an optional `self._pids` iterator when present (so a retry test can hand out distinct pids), else the fixed `self.pid`.

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_transport_proxy.py -q`
Expected: FAIL (`ProxyIdentityError` undefined / NotImplementedError).

- [ ] **Step 3: Implement verification + health + reap + send_break**

```python
# src/linux_debug_mcp/transport/proxy.py  (additions)
import os
import signal
import subprocess
import time

from linux_debug_mcp.transport.bounded import Deadline, connect_tcp


class ProxyIdentityError(Exception):
    """A listener on an allocated port could not be verified as the spawned child."""


# inside AgentProxyBackend:

    def _verify_identity(self, handle, *, deadline, cancel) -> None:
        # Confirm OUR spawned child is the listener on BOTH allocated ports. A foreign
        # process that won the bind race (§6.1) answers TCP but does NOT own the socket,
        # so listener ownership — not mere reachability — is the discriminator. (RSP
        # framing is NOT a usable signal here: a live kernel behind agent-proxy is not in
        # kgdb until broken in, so the gdb port stays silent.) FAIL CLOSED: require
        # `owns_listener is True` for both ports. `None` (ownership unverifiable — no
        # /proc/net, or /proc/<pid>/fd unreadable) is a REJECT, not a pass, so a foreign
        # listener can never slip through on an indeterminable host. In prod agent-proxy
        # is Linux-only (ownership is determinable); unit tests inject the verdict via a
        # fake probe. A failure raises; start() reaps OUR child and retries on fresh ports.
        if not self._identity.is_alive(handle.backend_pid):
            raise ProxyIdentityError("spawned agent-proxy child is not alive")
        if not self._identity.looks_like(handle.backend_pid, "agent-proxy"):
            raise ProxyIdentityError("spawned child is not agent-proxy")
        for port in (handle.console_port, handle.gdb_port):
            try:
                conn = connect_tcp("127.0.0.1", port, deadline=deadline, cancel=cancel)
            except (BoundedIOTimeout, OSError) as exc:
                raise ProxyIdentityError(f"allocated port {port} has no listener") from exc
            conn.close()
            # Address-specific (F2): prove ownership of the exact 127.0.0.1:port we advertise.
            if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", port) is not True:
                raise ProxyIdentityError(
                    f"cannot positively confirm our child owns 127.0.0.1:{port} "
                    "(foreign bind or ownership unverifiable) — failing closed"
                )

    def health(self, handle: ProxyHandle) -> str:
        if not self._identity_current(handle):
            return "degraded"
        for port in (handle.console_port, handle.gdb_port):
            # Re-run the SAME address-specific ownership check as attach (round-8 F2): the
            # child may still be alive but a foreign process may now own the loopback port.
            # False/None ⇒ degraded, so health never blesses a stolen endpoint.
            if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", port) is not True:
                return "degraded"
            try:
                conn = connect_tcp("127.0.0.1", port, deadline=Deadline.after(2.0),
                                   cancel=threading.Event())
                conn.close()
            except (BoundedIOTimeout, OSError):
                return "degraded"
        return "ready"

    def send_break(self, handle: ProxyHandle) -> None:
        # Revalidate ownership at SEND time (round-9 F1): never write BREAK control bytes to
        # a recycled/foreign listener. Fail closed if our child is no longer current or no
        # longer owns the console port. The exact escape is pinned by the PTY test (§6.4).
        if not self._identity_current(handle):
            raise ProxyIdentityError("send_break: agent-proxy child is no longer current")
        if self._identity.owns_listener(handle.backend_pid, "127.0.0.1", handle.console_port) is not True:
            raise ProxyIdentityError(
                f"send_break: child no longer owns console 127.0.0.1:{handle.console_port}"
            )
        conn = connect_tcp("127.0.0.1", handle.console_port, deadline=Deadline.after(2.0),
                           cancel=threading.Event())
        try:
            conn.sendall(_BREAK_ESCAPE)
        finally:
            conn.close()

    TERM_GRACE = 5.0
    KILL_GRACE = 2.0

    def _reap(self, process) -> None:
        # Terminate → wait → kill → wait an OWNED Popen (no fingerprint gate — the caller
        # holds this exact Popen, so it is unambiguously ours). Reaps the child: no zombie,
        # no CPU-spinning poll loop, and a foreign pid can never be signalled.
        try:
            process.terminate()
            process.wait(timeout=self.TERM_GRACE)
            return
        except subprocess.TimeoutExpired:
            pass
        except (ProcessLookupError, OSError):
            return
        try:
            process.kill()
            process.wait(timeout=self.KILL_GRACE)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass

    def stop(self, handle: ProxyHandle) -> None:
        # Public close path (called much later, when pid reuse is possible): gate on the
        # start-time fingerprint so a REUSED pid is never signalled, then reap. If this is
        # no longer our child (exited / pid reused), just poll() to reap our own exited
        # child if present. Idempotent.
        if not self._identity_current(handle):
            handle.process.poll()
            return
        self._reap(handle.process)

    def stop_by_identity(self, pid: int, start_time: str | None) -> None:
        # Stateless fenced reaper for crash recovery (round-6 F1): used by Layer-4
        # reconciliation when the in-memory ProxyHandle/Popen is gone and only the durable
        # (pid, start_time) survives. Signal by pid ONLY when the live start-time fingerprint
        # matches — a reused pid is never signalled; a None fingerprint is unfenceable and
        # refuses to signal (leak > kill-wrong-process). os.kill is safe here precisely
        # because the fingerprint match proves it is still our old child.
        if start_time is None:
            return
        observed = self._identity.identity(pid)
        if observed is None or observed.start_time != start_time:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return
        deadline = Deadline.after(self.TERM_GRACE)
        while not deadline.expired():
            if not self._identity.is_alive(pid):
                return
            time.sleep(0.05)
        recheck = self._identity.identity(pid)
        if recheck is not None and recheck.start_time == start_time:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                return

    def _identity_current(self, handle: ProxyHandle) -> bool:
        if not self._identity.is_alive(handle.backend_pid):
            return False
        observed = self._identity.identity(handle.backend_pid)
        if observed is None or observed.start_time is None:
            return False
        return observed.start_time == handle.backend_start_time
```

**Pin `_BREAK_ESCAPE` to the exact agent-proxy console escape (round-1 F4 / round-3 F4).** agent-proxy detects a break on the console connection as the **telnet IAC BREAK** `0xFF 0xF3` and translates it into a real serial line break — or, under `-s003`, the alternate single byte `0x03` to the target line. (Source: `agent-proxy.c` `processIACoptions()`; `defaultBrkStr[2] = { 0xff, 0xf3 }`; README "if your hardware does not support the line break sequence … add `-s003`".) So what `send_break` writes **to the console port** is fixed:

```python
# src/linux_debug_mcp/transport/proxy.py  (near the top)
# Telnet IAC BREAK — what a client sends agent-proxy's console port to request a target
# break. agent-proxy.c defaultBrkStr = {0xff, 0xf3}. Under -s003 agent-proxy emits the
# alternate byte 0x03 to the *target* line instead of a real serial break.
_BREAK_ESCAPE = b"\xff\xf3"
_S003_TARGET_ALTERNATE = b"\x03"
```

The unit guard asserts the **exact** literal (not "non-empty") so a wrong edit fails locally without agent-proxy:

```python
# tests/test_transport_proxy.py  (append)
def test_break_escape_is_the_pinned_telnet_iac_break():
    from linux_debug_mcp.transport.proxy import _BREAK_ESCAPE
    assert _BREAK_ESCAPE == b"\xff\xf3"  # agent-proxy.c defaultBrkStr {0xff,0xf3}


def test_send_break_writes_the_pinned_escape_to_the_console_port():
    from linux_debug_mcp.transport.proxy import _BREAK_ESCAPE
    listener, port = _live_listener()
    received = []

    def _accept():
        conn, _ = listener.accept()
        received.append(conn.recv(64))
        conn.close()

    threading.Thread(target=_accept, daemon=True).start()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe())
    handle = ProxyHandle(process=object(), backend_pid=1, backend_start_time="t",
                         console_port=port, gdb_port=port)
    backend.send_break(handle)
    listener.close()
    assert received and _BREAK_ESCAPE in received[0]


def test_send_break_refuses_when_child_no_longer_owns_the_console_port():
    """A live listener answers, but our child no longer owns the port (owns_listener False):
    send_break must refuse rather than write BREAK bytes to a foreign listener (round-9 F1)."""
    listener, port = _live_listener()
    backend = AgentProxyBackend(spawner=_FakeSpawner(), identity_probe=_Probe(start_time="t", owns=False))
    handle = ProxyHandle(process=_FakeProc(pid=1), backend_pid=1, backend_start_time="t",
                         console_port=port, gdb_port=port)
    try:
        with pytest.raises(ProxyIdentityError):
            backend.send_break(handle)
    finally:
        listener.close()
```

(The unit test pins what we *send to agent-proxy*; the **target-side** effect — `0x03` under `-s003`, or a real line break otherwise — is only observable end-to-end, so the gated integration test (Task 11) is the real exactness gate and **must run in CI**, see Task 11.)

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_transport_proxy.py -q && uv run ruff check src/linux_debug_mcp/transport/proxy.py tests/test_transport_proxy.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/proxy.py tests/test_transport_proxy.py
git commit -m "feat: verify listener identity and reap agent-proxy safely by start-time (#10)"
```

---

## Task 6: `transport/qemu_gdbstub.py` — RSP-passthrough adapter (Decision 5)

**Files:**
- Create: `src/linux_debug_mcp/transport/qemu_gdbstub.py`
- Test: `tests/test_transport_qemu_gdbstub.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_transport_qemu_gdbstub.py
import socket
import threading

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.target import Arch, ConsoleKind, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import (
    BackendAttachment,
    EndpointExposure,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    TransportLocality,
    TransportRef,
)
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.qemu_gdbstub import QemuGdbstubTransport, QemuGdbstubAttachError


def _request(port: int) -> OpenRequest:
    return OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(provider="qemu-gdbstub", channel_id="rsp0",
                                   line_role=LineRole.RSP, opts={"host": "127.0.0.1", "port": port}),
        platform=PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                                  dedicated_debug_line=False, ssh_reachable=True),
        required_caps=["rsp"],
    )


def test_capability_flags():
    cap = QemuGdbstubTransport().capability
    assert cap.provider_name == "qemu-gdbstub"
    assert cap.provides_rsp and not cap.provides_console and not cap.supports_uart_break
    assert cap.locality is TransportLocality.LOCAL
    assert cap.endpoint_exposure is EndpointExposure.LOOPBACK_LOCAL


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
        result = QemuGdbstubTransport().attach(_request(port), cancel=threading.Event(),
                                               deadline=Deadline.after(2.0), on_partial=lambda *_: None)
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
            QemuGdbstubTransport().attach(_request(port), cancel=threading.Event(),
                                          deadline=Deadline.after(0.4), on_partial=lambda *_: None)
        assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    finally:
        listener.close()


def test_attach_rejects_an_unreachable_stub():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(QemuGdbstubAttachError) as exc:
        QemuGdbstubTransport().attach(_request(port), cancel=threading.Event(),
                                      deadline=Deadline.after(0.3), on_partial=lambda *_: None)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE


def test_attach_rejects_a_non_loopback_host_without_any_network_io(monkeypatch):
    """A loopback_local provider must never connect out to a caller-supplied remote host
    (round-3 review F2): loopback is enforced before rsp_reachable is ever called."""
    called = []
    monkeypatch.setattr("linux_debug_mcp.transport.qemu_gdbstub.rsp_reachable",
                        lambda *a, **k: (called.append(True), True)[1])
    for host in ("10.0.0.5", "192.168.1.10", "8.8.8.8", "evil.example.com"):
        request = OpenRequest(
            target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
            generation=0,
            transport_ref=TransportRef(provider="qemu-gdbstub", channel_id="rsp0",
                                       line_role=LineRole.RSP, opts={"host": host, "port": 1234}),
            platform=PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                                      dedicated_debug_line=False, ssh_reachable=True),
            required_caps=["rsp"],
        )
        with pytest.raises(QemuGdbstubAttachError) as exc:
            QemuGdbstubTransport().attach(request, cancel=threading.Event(),
                                          deadline=Deadline.after(1.0), on_partial=lambda *_: None)
        assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert called == []  # loopback rejected before any outbound connection
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_transport_qemu_gdbstub.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement the adapter**

```python
# src/linux_debug_mcp/transport/qemu_gdbstub.py
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

    def attach(self, request: OpenRequest, *, cancel: threading.Event, deadline: float,
               on_partial: Callable[[str, object], None]) -> BackendAttachment:
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
        ok = rsp_reachable(endpoint.host, endpoint.port, deadline=Deadline.after(2.0),
                           cancel=threading.Event())
        return "ready" if ok else "degraded"
```

(Note: the `deadline` parameter type on `Transport.attach` is `float` in the frozen ABC; the adapter accepts either a `Deadline` or a float and normalizes — keep this tolerant until Layer 4 settles the call convention.)

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_transport_qemu_gdbstub.py -q && uv run ruff check src/linux_debug_mcp/transport/qemu_gdbstub.py tests/test_transport_qemu_gdbstub.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/qemu_gdbstub.py tests/test_transport_qemu_gdbstub.py
git commit -m "feat: add qemu-gdbstub RSP-passthrough transport adapter (#10)"
```

---

## Task 7: `transport/serial_local.py` — `serial-local` transport (Decision 4)

**Files:**
- Create: `src/linux_debug_mcp/transport/serial_local.py`
- Test: `tests/test_transport_serial_local.py`

- [ ] **Step 1: Write failing tests (console-only unix socket at mode 0600; console+gdb delegates to proxy)**

```python
# tests/test_transport_serial_local.py
import os
import stat
import threading

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import (
    BackendAttachment, LineRole, OpenRequest, TransportRef, UnixSocketEndpoint, TcpEndpoint,
)
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.serial_local import SerialLocalTransport, SerialLocalConfigError


def _platform() -> PlatformMetadata:
    return PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                            dedicated_debug_line=False, ssh_reachable=False)


def _request(line_role, target_ref, tmp_path) -> OpenRequest:
    return OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(provider="serial-local", channel_id="con0",
                                   line_role=line_role, target_ref=target_ref),
        platform=_platform(),
    )


class _StubSession:
    def __init__(self, console_endpoint=None, rsp_endpoint=None, backend_pid=None, backend_start_time=None):
        self.console_endpoint = console_endpoint
        self.rsp_endpoint = rsp_endpoint
        self.backend_pid = backend_pid
        self.backend_start_time = backend_start_time


def test_console_only_path_bridges_a_pty_device_to_an_owner_only_unix_socket(tmp_path):
    import pty

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)
    transport = SerialLocalTransport(socket_dir=tmp_path)
    request = _request(LineRole.SHARED_CONSOLE, {"device": peripheral_name}, tmp_path)
    result = transport.attach(request, cancel=threading.Event(),
                              deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    try:
        assert isinstance(result, BackendAttachment)
        assert isinstance(result.console_endpoint, UnixSocketEndpoint)
        assert result.rsp_endpoint is None
        mode = stat.S_IMODE(os.stat(result.console_endpoint.path).st_mode)
        assert mode == 0o600  # OS perms are the access-control boundary (§8.4)
        # The per-session parent dir is owner-only, closing the pre-chmod window (F3).
        parent_mode = stat.S_IMODE(os.stat(os.path.dirname(result.console_endpoint.path)).st_mode)
        assert parent_mode == 0o700

        # Bytes on the wire (round-1 review F2): a client gets device output and vice versa.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(result.console_endpoint.path)
        client.settimeout(2.0)
        os.write(controller_fd, b"from-device\n")
        assert b"from-device" in client.recv(64)
        client.sendall(b"to-device\n")
        assert b"to-device" in os.read(controller_fd, 64)
        client.close()
    finally:
        transport.close(_StubSession(result.console_endpoint))  # bounded stop + unlink
        assert not os.path.exists(result.console_endpoint.path)
        os.close(controller_fd)
        os.close(peripheral_fd)


class _RecordingProxy:
    def __init__(self):
        from linux_debug_mcp.transport.proxy import ProxyHandle
        self.handle = ProxyHandle(process=object(), backend_pid=9100, backend_start_time="3",
                                  console_port=5001, gdb_port=5002)
        self.stopped = []
        self.stopped_by_identity = []

    def start(self, source, *, supports_uart_break, cancel, deadline, on_partial):
        on_partial("backend_pid", self.handle.backend_pid)
        return self.handle

    def health(self, handle): return "ready"
    def send_break(self, handle): ...
    def stop(self, handle): self.stopped.append(handle)
    def stop_by_identity(self, pid, start_time): self.stopped_by_identity.append((pid, start_time))


def test_console_plus_gdb_path_delegates_to_proxy_and_returns_tcp_endpoints(tmp_path):
    transport = SerialLocalTransport(socket_dir=tmp_path, proxy=_RecordingProxy())
    request = _request(LineRole.DEDICATED_DEBUG, {"device": "/dev/ttyUSB0", "baud": 115200}, tmp_path)
    result = transport.attach(request, cancel=threading.Event(),
                              deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    assert isinstance(result.console_endpoint, TcpEndpoint)
    assert isinstance(result.rsp_endpoint, TcpEndpoint)
    assert result.backend_pid == 9100


def test_demux_close_stops_the_exact_proxy_handle_and_is_idempotent(tmp_path):
    """The demux ProxyHandle must be retained at attach so close() can reap agent-proxy
    (round-2 review F3). close() passes the SAME handle start() returned, and is idempotent."""
    proxy = _RecordingProxy()
    transport = SerialLocalTransport(socket_dir=tmp_path, proxy=proxy)
    request = _request(LineRole.DEDICATED_DEBUG, {"device": "/dev/ttyUSB0", "baud": 115200}, tmp_path)
    result = transport.attach(request, cancel=threading.Event(),
                              deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    session = _StubSession(console_endpoint=result.console_endpoint, rsp_endpoint=result.rsp_endpoint,
                           backend_pid=result.backend_pid, backend_start_time=result.backend_start_time)
    transport.close(session)
    transport.close(session)  # idempotent: no second stop, no error
    assert proxy.stopped == [proxy.handle]


def test_close_for_a_reused_pid_does_not_stop_a_different_live_session(tmp_path):
    """Session A (pid P, start_time sA) closed and removed; session B reuses pid P with a
    different start_time. A stale close for A must NOT pop/stop B (round-9 F2)."""
    proxy = _RecordingProxy()
    transport = SerialLocalTransport(socket_dir=tmp_path, proxy=proxy)
    # B is the only live handle: same pid, different start_time.
    transport._proxy_handles[(proxy.handle.backend_pid, "B-start")] = proxy.handle
    stale_a = _StubSession(rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5002),
                           backend_pid=proxy.handle.backend_pid, backend_start_time="A-start")
    transport.close(stale_a)  # different (pid, start_time) key ⇒ no match
    assert proxy.stopped == []  # B was not stopped
    assert (proxy.handle.backend_pid, "B-start") in transport._proxy_handles


def test_rejects_target_ref_with_control_characters(tmp_path):
    transport = SerialLocalTransport(socket_dir=tmp_path)
    request = _request(LineRole.SHARED_CONSOLE, {"device": "/dev/tty\n0"}, tmp_path)
    with pytest.raises(SerialLocalConfigError) as exc:
        transport.attach(request, cancel=threading.Event(),
                         deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_concurrent_attach_to_the_same_source_is_refused(tmp_path):
    """Two attaches against the same physical line ⇒ the second is refused with
    TRANSPORT_CONFLICT, never double-driven (spec §4.7, round-7 F2)."""
    import pty

    from linux_debug_mcp.transport.serial_local import SerialLocalConflictError

    master, slave = pty.openpty()
    name = os.ttyname(slave)
    t1 = SerialLocalTransport(socket_dir=tmp_path)
    r1 = t1.attach(_request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
                   cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None)
    try:
        t2 = SerialLocalTransport(socket_dir=tmp_path)
        with pytest.raises(SerialLocalConflictError) as exc:
            t2.attach(_request(LineRole.SHARED_CONSOLE, {"device": name}, tmp_path),
                      cancel=threading.Event(), deadline=Deadline.after(2.0), on_partial=lambda *_: None)
        assert exc.value.category == ErrorCategory.TRANSPORT_CONFLICT
    finally:
        t1.close(_StubSession(r1.console_endpoint))
        os.close(master)
        os.close(slave)


def test_demux_health_is_degraded_when_the_in_memory_handle_is_lost(tmp_path):
    """A durable demux session with backend_pid but an empty handle map (post-restart)
    reports 'degraded', it does not raise KeyError (round-7 F3)."""
    transport = SerialLocalTransport(socket_dir=tmp_path, proxy=_RecordingProxy())
    session = _StubSession(console_endpoint=TcpEndpoint(host="127.0.0.1", port=5001),
                           rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5002), backend_pid=9100)
    assert transport.health(session) == "degraded"
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_transport_serial_local.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement the transport**

Implement `SerialLocalTransport(Transport)`:
- `__init__(self, *, socket_dir, proxy=None, identity_probe=None)`; default `proxy=AgentProxyBackend(...)`. Keep `self._bridges: dict[str, SerialConsoleBridge]` keyed by the exposed socket path **and** `self._proxy_handles: dict[tuple[int, str | None], ProxyHandle]` keyed by **`(backend_pid, backend_start_time)`** — never `backend_pid` alone (round-9 F2: a reused pid must not let a stale close select a *different* session's handle; round-2 F3: so `close()` can reap the demux child).
- `capability`: `provider_name="serial-local"`, `locality=LOCAL`, `provides_console=True`, `provides_rsp=True`, `supports_uart_break=True`, `endpoint_exposure=LOOPBACK_LOCAL`.
- `attach`: validate the `target_ref` device/socket path (control-character + absolute-path checks, raising `SerialLocalConfigError(category=CONFIGURATION_ERROR)`; reuse `UnixSocketEndpoint`'s path rules / `safety/paths` style).
  - **Source exclusivity lock (spec §4.7; round-7 F2, round-10 F1)** — the lock's lifetime must track the **device-holder**, not the server: a server-only `flock` is freed by the OS on a hard crash, and combined with the pre-`backend_process` spawn window a restart could acquire the freed lock and start a *second* agent-proxy while the orphaned first still holds the serial line (double-drive). Steps, *before* attach proceeds:
    1. **Write-ahead source record:** emit `on_partial("source_open", {"path": <abs path>})` so Layer 4 persists that this source is being opened **before** any child exists — a crash before `backend_process` still leaves a record reconciliation can act on.
    2. **Acquire the lock:** open the char device `O_RDONLY | O_NONBLOCK` (or a `<path>.lock` sidecar for a unix-socket source) and `fcntl.flock(fd, LOCK_EX | LOCK_NB)`. On contention (`BlockingIOError`/`OSError`) raise `SerialLocalConflictError(category=TRANSPORT_CONFLICT)`.
    3. **Make the lock child-lived:** `os.set_inheritable(lock_fd, True)` and pass it to the agent-proxy child via `proxy.start(..., inherit_fds=(lock_fd,))`. Because the orphaned child inherits and holds the flocked fd, the lock survives a parent crash for as long as the orphan holds the serial device — so a restart's `flock` **fails** (`TRANSPORT_CONFLICT`) and **cannot** double-drive. The lock frees only when every holder (server *and* child) is gone.
    4. Keep the lock fd in the bridge/`_proxy_handles` entry, report it via `on_partial`, and `os.close` it on **every** rollback and on `close()`.
    (`flock` is advisory — it serializes MCP-mediated attaches; a hostile non-`flock` process is the documented §8.4 residual. **Layer-4 obligation:** reconciliation uses the write-ahead `source_open` record to find and reap an orphan that crashed before recording a `backend_pid`; the child-inherited lock prevents double-drive until it does.)
  - **RSP path** (`line_role` is `DEDICATED_DEBUG` or `RSP` — a gdb line present) → build a `LocalDeviceSource`/`RemoteTerminalServerSource`, call `proxy.start(..., supports_uart_break=request.transport_ref.opts.get("supports_uart_break", True), inherit_fds=(lock_fd,))` (so the agent-proxy child inherits the source lock — round-10 F1), report `on_partial`, **store the returned `ProxyHandle` in `self._proxy_handles[(handle.backend_pid, handle.backend_start_time)]`**, and return a `BackendAttachment` with loopback `TcpEndpoint`s from the handle's `console_port`/`gdb_port` and `backend_pid`/`backend_start_time` from the handle. (If higher-layer assembly later fails, Layer 4 still has `backend_pid` on the attachment to drive reconciliation.)
  - **Console-only path** (no RSP) → build and start a `SerialConsoleBridge` (below); return a `BackendAttachment` with a `UnixSocketEndpoint` (mode `0600`), `rsp_endpoint=None`.
- **`SerialConsoleBridge` (the byte pump — round-1 review F2):** a console socket that does not move bytes is inert, so this is mandatory, not optional. It must:
  1. Open the source with `bounded.open_device(device, deadline, cancel)` (the source is a `/dev/tty*`, PTY slave, or — for a source unix socket — a connected fd). The attach `deadline` bounds device open + socket setup only.
  2. Create a **per-session directory** `os.mkdir(<socket_dir>/<session-id>, 0o700)` and verify it is owner-only `0o700` (round-8 F3 — this closes the pre-`chmod` connect window: even before the socket's own mode lands, a `0700` parent denies any other uid from reaching it, regardless of umask). Then create an `AF_UNIX` `SOCK_STREAM` socket and `bind()` it to a path **inside** that directory, `os.chmod(path, 0o600)` after bind, `listen(1)`; assert the resulting socket mode is `0o600`. (Layer 4 owns `socket_dir` under `<run>/debug/`; this layer additionally guarantees the per-session dir is private.)
  3. Start one **supervised daemon thread** that `await_accept`s a client (this wait is **not** bounded by the attach deadline — a client may connect much later; it ends on the bridge's `stop` event), then runs a `select`-based bidirectional copy loop between the source fd and the accepted connection until EOF, peer close, or the `stop` event. The pump is the session-lifetime worker, not an attach step.
  4. Expose `stop()`: set the stop event, close the connection/listener/source fd, `os.unlink` the socket path, and `join(timeout=teardown_deadline)` the thread (force-abandon on timeout, never block unbounded). Store the bridge in `self._bridges[path]`.
- `close(self, session)`: **demux path** (session has a `backend_pid`) → pop `self._proxy_handles.pop((session.backend_pid, session.backend_start_time), None)` (the `(pid, start_time)` key, so a reused-pid stale close cannot select a different live session — round-9 F2); if the in-memory handle is present, `proxy.stop(handle)` (the **exact** handle `start` returned is reaped). **If the handle is gone** (a server restart lost the in-memory map but the durable record survives — round-6 F1), fall back to `proxy.stop_by_identity(session.backend_pid, session.backend_start_time)` — the stateless fenced reaper. **Console-only path** (a `UnixSocketEndpoint` console) → pop `self._bridges.pop(session.console_endpoint.path, None)`; if present, `bridge.stop()`. In both paths also release the source-exclusivity lock fd (`os.close`) and drop it from the map. Idempotent — a second `close()` finds nothing and `stop_by_identity` no-ops once the child is gone. (Layer-4 crash reconciliation calls `stop_by_identity` directly from the durable record's `(backend_pid, backend_start_time)`.)
- `health(self, session)`: demux path → `handle = self._proxy_handles.get((session.backend_pid, session.backend_start_time))`; if the in-memory handle is **missing** (map lost after a restart — round-7 F3) return `"degraded"` (do **not** `KeyError`), else `proxy.health(handle)`. Console-only path → `"ready"` while the bridge thread is alive and the socket path exists, else `"degraded"`.

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_transport_serial_local.py -q && uv run ruff check src/linux_debug_mcp/transport/serial_local.py tests/test_transport_serial_local.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/serial_local.py tests/test_transport_serial_local.py
git commit -m "feat: add serial-local transport (unix-socket console + agent-proxy demux) (#10)"
```

---

## Task 8: `transport/break_inject.py` — `inject_break` dispatch (Decision 4, §6.4)

**Files:**
- Create: `src/linux_debug_mcp/transport/break_inject.py`
- Test: `tests/test_break_inject.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_break_inject.py
import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan
from linux_debug_mcp.transport.break_inject import InjectBreakError, inject_break


class _RecordingProxy:
    def __init__(self): self.breaks = 0
    def send_break(self, handle): self.breaks += 1


class _RecordingSsh:
    def __init__(self): self.argv = None
    def run(self, argv, *, timeout, stdout_path, stderr_path):
        self.argv = argv
        class _R: returncode = 0
        return _R()


def _plan(method): return BreakPlan(method=method, channel_id="c0", rationale="test")


def test_auto_dispatches_uart_break_to_proxy_send_break():
    proxy = _RecordingProxy()
    inject_break(method="auto", break_plan=_plan(BreakMethod.UART_BREAK),
                 proxy=proxy, proxy_handle=object(), ssh_runner=None, ssh_argv_prefix=None)
    assert proxy.breaks == 1


def test_agent_proxy_break_also_uses_send_break():
    proxy = _RecordingProxy()
    inject_break(method="agent_proxy_break", break_plan=_plan(BreakMethod.AGENT_PROXY_BREAK),
                 proxy=proxy, proxy_handle=object(), ssh_runner=None, ssh_argv_prefix=None)
    assert proxy.breaks == 1


def test_sysrq_g_writes_g_to_sysrq_trigger_over_ssh(tmp_path):
    ssh = _RecordingSsh()
    inject_break(method="sysrq_g", break_plan=_plan(BreakMethod.SYSRQ_G),
                 proxy=None, proxy_handle=None, ssh_runner=ssh,
                 ssh_argv_prefix=["ssh", "vm1"], work_dir=tmp_path)
    assert any("/proc/sysrq-trigger" in part for part in ssh.argv)
    assert any(part == "g" or part.endswith("g") for part in ssh.argv)


def test_requested_method_not_in_admitted_plan_is_rejected():
    with pytest.raises(InjectBreakError) as exc:
        inject_break(method="sysrq_g", break_plan=_plan(BreakMethod.UART_BREAK),
                     proxy=_RecordingProxy(), proxy_handle=object(),
                     ssh_runner=_RecordingSsh(), ssh_argv_prefix=["ssh", "vm1"])
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_gdbstub_native_is_not_an_inject_break_argument():
    with pytest.raises(InjectBreakError):
        inject_break(method="gdbstub_native", break_plan=_plan(BreakMethod.GDBSTUB_NATIVE),
                     proxy=None, proxy_handle=None, ssh_runner=None, ssh_argv_prefix=None)
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_break_inject.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement dispatch**

```python
# src/linux_debug_mcp/transport/break_inject.py
from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan


class InjectBreakError(Exception):
    def __init__(self, message: str, *, category: ErrorCategory) -> None:
        super().__init__(message)
        self.category = category


_REQUESTABLE = {"auto", "uart_break", "agent_proxy_break", "sysrq_g"}


def inject_break(*, method: str, break_plan: BreakPlan, proxy, proxy_handle, ssh_runner,
                 ssh_argv_prefix, work_dir: Path | None = None) -> None:
    """Execute the admitted break plan (§6.4). gdbstub_native is not a valid argument
    (gdb interrupts directly). A requested method not equal to the admitted plan's method
    is rejected, not attempted. No kernel is halted in tests — proxy/ssh are fakes."""
    if method == "gdbstub_native" or break_plan.method is BreakMethod.GDBSTUB_NATIVE:
        raise InjectBreakError("gdbstub_native needs no break injection",
                               category=ErrorCategory.CONFIGURATION_ERROR)
    if method not in _REQUESTABLE:
        raise InjectBreakError(f"unknown break method: {method}",
                               category=ErrorCategory.CONFIGURATION_ERROR)
    resolved = break_plan.method if method == "auto" else BreakMethod(method)
    if resolved is not break_plan.method:
        raise InjectBreakError(
            f"requested {resolved.value} is not the admitted plan method {break_plan.method.value}",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    if resolved in (BreakMethod.UART_BREAK, BreakMethod.AGENT_PROXY_BREAK):
        proxy.send_break(proxy_handle)
        return
    if resolved is BreakMethod.SYSRQ_G:
        base = work_dir or Path(".")
        argv = [*ssh_argv_prefix, "sh", "-c", "echo g > /proc/sysrq-trigger"]
        result = ssh_runner.run(argv, timeout=10, stdout_path=base / "sysrq.out",
                                stderr_path=base / "sysrq.err")
        if getattr(result, "returncode", 0) != 0:
            raise InjectBreakError("sysrq-g write failed",
                                   category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        return
    raise InjectBreakError(f"unsupported method {resolved.value}",
                           category=ErrorCategory.CONFIGURATION_ERROR)
```

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_break_inject.py -q && uv run ruff check src/linux_debug_mcp/transport/break_inject.py tests/test_break_inject.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/break_inject.py tests/test_break_inject.py
git commit -m "feat: add inject_break dispatch over an admitted break plan (#10)"
```

---

## Task 9: Refactor `providers/qemu_gdbstub.py` onto `ProcessIdentityProbe` (ADR 0004)

**Files:**
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py` (`__init__`, `_controller_identity`, `_controller_identity_matches`, `_pid_is_alive`, `_pid_is_zombie`, `_pid_looks_like_controller`, `_terminate_controller_if_safe`)
- Modify: `tests/test_qemu_gdbstub_provider.py` (the 2 failing tests inject a fake probe)

- [ ] **Step 1: Make the 2 failing tests pass deterministically by injecting a fake probe**

In `tests/test_qemu_gdbstub_provider.py`, locate `test_end_session_terminates_recorded_live_controller_pid` and `test_end_session_rejects_live_pid_that_is_not_controller_process`. Construct the provider with an injected fake `ProcessIdentityProbe`:
- For the "terminates recorded live controller" test: fake returns `is_alive=True`, `identity().start_time` equal to the recorded value, `looks_like(...,"gdb")=True` → `_terminate_controller_if_safe` proceeds to SIGTERM.
- For the "rejects live pid that is not controller" test: fake returns `is_alive=True`, matching `start_time`, but `looks_like(...,"gdb")=False` → returns `alive_not_controller` on every OS (the macOS divergence is gone).

```python
# representative fake
class _FakeIdentityProbe:
    def __init__(self, *, alive=True, start_time="match", looks_like=True):
        self._alive, self._start, self._looks = alive, start_time, looks_like
    def identity(self, pid):
        from linux_debug_mcp.seams.process_identity import ProcessIdentity
        return ProcessIdentity(pid=pid, start_time=self._start, argv0="gdb")
    def is_alive(self, pid): return self._alive
    def looks_like(self, pid, name_substr): return self._looks
```

- [ ] **Step 2: Run the 2 tests, verify they still fail (provider has no probe seam yet)**

Run: `uv run python -m pytest tests/test_qemu_gdbstub_provider.py::test_end_session_rejects_live_pid_that_is_not_controller_process -q`
Expected: FAIL (constructor does not accept `identity_probe`).

- [ ] **Step 3: Add the constructor seam and route identity through it**

- Add `identity_probe: ProcessIdentityProbe | None = None` to `QemuGdbstubProvider.__init__`; store `self._identity = identity_probe or ProcProcessIdentityProbe()`.
- Replace `_controller_identity_matches(session)` body to compare `self._identity.identity(pid)` start-time against the recorded identity.
- Replace `_pid_is_alive` → `self._identity.is_alive(pid)`; `_pid_looks_like_controller` → `self._identity.looks_like(pid, "gdb")`.
- Keep `_controller_identity` only if other call sites need the raw recording; otherwise record `self._identity.identity(pid)` at attach time. Preserve the recorded-identity shape persisted on `DebugSession.active_controller_identity`.
- Leave `_terminate_controller_if_safe`'s ordering (`exited` → `alive_unverified` → `alive_not_controller` → SIGTERM) intact, but its predicates now come from the seam.

- [ ] **Step 4: Run the full provider suite, verify all pass on this host (macOS)**

Run: `uv run python -m pytest tests/test_qemu_gdbstub_provider.py -q`
Expected: PASS (67 passed — the 2 prior macOS failures fixed).

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check src/linux_debug_mcp/providers/qemu_gdbstub.py tests/test_qemu_gdbstub_provider.py`

```bash
git add src/linux_debug_mcp/providers/qemu_gdbstub.py tests/test_qemu_gdbstub_provider.py
git commit -m "refactor: route qemu-gdbstub controller identity through the probe seam (#10)"
```

---

## Task 10: `prereqs/checks.py` — agent-proxy availability check (§7.4)

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/checks.py`
- Test: `tests/test_prereqs_agent_proxy.py`

- [ ] **Step 1: Write failing tests (present → PASSED; absent → WARNING with remediation)**

```python
# tests/test_prereqs_agent_proxy.py
from pathlib import Path

from linux_debug_mcp.domain import PrerequisiteStatus
from linux_debug_mcp.prereqs.checks import check_prerequisites


class _Runner:
    def __init__(self, present): self._present = present
    def which(self, command): return "/usr/local/bin/agent-proxy" if (command == "agent-proxy" and self._present) else ("/bin/" + command if self._present else None)
    def run(self, command, timeout): return (0, "", "")


def _check(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_agent_proxy_present_passes(tmp_path):
    checks = check_prerequisites(artifact_root=tmp_path, source_path=None,
                                 enable_libvirt_check=False, runner=_Runner(present=True))
    assert _check(checks, "tool.agent-proxy").status is PrerequisiteStatus.PASSED


def test_agent_proxy_absent_warns_with_remediation(tmp_path):
    checks = check_prerequisites(artifact_root=tmp_path, source_path=None,
                                 enable_libvirt_check=False, runner=_Runner(present=False))
    check = _check(checks, "tool.agent-proxy")
    assert check.status is PrerequisiteStatus.WARNING
    assert "agent-proxy" in (check.suggested_fix or "")
```

- [ ] **Step 2: Run, verify fail**

Run: `uv run python -m pytest tests/test_prereqs_agent_proxy.py -q`
Expected: FAIL (no `tool.agent-proxy` check).

- [ ] **Step 3: Add `_agent_proxy_check` and wire it in**

```python
# src/linux_debug_mcp/prereqs/checks.py  (add a function, call it from check_prerequisites)
AGENT_PROXY_REMEDIATION = (
    "agent-proxy is optional (needed only for serial/console transports). Build it from the "
    "pinned source: git clone https://git.kernel.org/pub/scm/utils/kernel/kgdb/agent-proxy.git "
    "&& make -C agent-proxy, then put it on PATH."
)


def _agent_proxy_check(runner: PrerequisiteRunner) -> PrerequisiteCheck:
    path = runner.which("agent-proxy")
    if path:
        return PrerequisiteCheck(check_id="tool.agent-proxy", status=PrerequisiteStatus.PASSED,
                                 message="agent-proxy found", details={"path": path})
    return PrerequisiteCheck(check_id="tool.agent-proxy", status=PrerequisiteStatus.WARNING,
                             message="agent-proxy was not found", suggested_fix=AGENT_PROXY_REMEDIATION)
```

Call `checks.append(_agent_proxy_check(runner))` in `check_prerequisites` (after the `_tool_check` loop). Do **not** add `agent-proxy` to the existing FAILED-on-absent `_tool_check` loop — it is a WARNING, not a hard requirement.

- [ ] **Step 4: Run, verify pass; lint**

Run: `uv run python -m pytest tests/test_prereqs_agent_proxy.py -q && uv run ruff check src/linux_debug_mcp/prereqs/checks.py tests/test_prereqs_agent_proxy.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/checks.py tests/test_prereqs_agent_proxy.py
git commit -m "feat: add agent-proxy availability prerequisite check (warning) (#10)"
```

---

## Task 11: Gated PTY + agent-proxy integration test (Decision 4)

**Files:**
- Create: `tests/test_serial_local_transport_integration.py`

- [ ] **Step 1: Write the gated integration test**

```python
# tests/test_serial_local_transport_integration.py
import os
import pty
import select
import shutil
import socket
import threading

import pytest

from linux_debug_mcp.seams.process_identity import ProcProcessIdentityProbe
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import LineRole, OpenRequest, TcpEndpoint, TransportRef
from linux_debug_mcp.transport.bounded import Deadline
from linux_debug_mcp.transport.proxy import AgentProxyBackend, _S003_TARGET_ALTERNATE
from linux_debug_mcp.transport.serial_local import SerialLocalTransport

# Require agent-proxy in CI (LDM_REQUIRE_AGENT_PROXY=1) so the break path is a real merge
# gate; skip only on a dev host that did NOT opt in. When required-but-absent the test runs
# and fails (it does not skip), which is what makes CI enforce it (Task 12).
pytestmark = pytest.mark.skipif(
    shutil.which("agent-proxy") is None and os.environ.get("LDM_REQUIRE_AGENT_PROXY") != "1",
    reason="agent-proxy not installed (set LDM_REQUIRE_AGENT_PROXY=1 to require it in CI)",
)


class _Sess:
    def __init__(self, console_endpoint, rsp_endpoint, backend_pid, backend_start_time):
        self.console_endpoint = console_endpoint
        self.rsp_endpoint = rsp_endpoint
        self.backend_pid = backend_pid
        self.backend_start_time = backend_start_time


def test_serial_local_demux_over_pty_yields_endpoints_emits_break_and_reaps(tmp_path):
    """Drive SerialLocalTransport.attach (demux path) over a PTY + real agent-proxy: live
    console/rsp TCP endpoints, send_break surfaces the -s003 alternate on the target line,
    and close() reaps agent-proxy. NO kernel halt here — Layer 4 owns the end-to-end halt."""
    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)

    backend = AgentProxyBackend()
    transport = SerialLocalTransport(socket_dir=tmp_path, proxy=backend)
    request = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
        generation=0,
        transport_ref=TransportRef(
            provider="serial-local", channel_id="dbg0", line_role=LineRole.DEDICATED_DEBUG,
            target_ref={"device": peripheral_name}, opts={"supports_uart_break": False},
        ),
        platform=PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                                  dedicated_debug_line=True, ssh_reachable=False),
    )
    result = transport.attach(request, cancel=threading.Event(),
                              deadline=Deadline.after(10.0), on_partial=lambda *_: None)
    session = _Sess(result.console_endpoint, result.rsp_endpoint, result.backend_pid, result.backend_start_time)
    try:
        assert isinstance(result.console_endpoint, TcpEndpoint)
        assert isinstance(result.rsp_endpoint, TcpEndpoint)
        socket.create_connection((result.console_endpoint.host, result.console_endpoint.port),
                                 timeout=2.0).close()  # console TCP endpoint is live
        # Break via the stored proxy handle; under -s003 the 0x03 alternate hits the line.
        backend.send_break(transport._proxy_handles[(result.backend_pid, result.backend_start_time)])
        deadline = Deadline.after(5.0)
        seen = b""
        os.set_blocking(controller_fd, False)
        while not deadline.expired() and _S003_TARGET_ALTERNATE not in seen:
            readable, _, _ = select.select([controller_fd], [], [], 0.2)
            if readable:
                seen += os.read(controller_fd, 256)
        assert _S003_TARGET_ALTERNATE in seen, f"expected -s003 alternate on the line, saw {seen!r}"
    finally:
        transport.close(session)
        os.close(controller_fd)
        os.close(peripheral_fd)
    # close() dropped the tuple-keyed handle AND reaped the real child (round-10 F2: the old
    # get(backend_pid) lookup was always None and could not catch a leak).
    assert (result.backend_pid, result.backend_start_time) not in transport._proxy_handles
    assert ProcProcessIdentityProbe().is_alive(result.backend_pid) is False
```

- [ ] **Step 2: Run (skips on a dev host without agent-proxy; CI requires it — Task 12)**

Run: `uv run python -m pytest tests/test_serial_local_transport_integration.py -q`
Expected: SKIPPED on a host without `agent-proxy` and without `LDM_REQUIRE_AGENT_PROXY=1`; runs and passes on a Linux+agent-proxy host; runs and FAILS (does not skip) if `LDM_REQUIRE_AGENT_PROXY=1` but agent-proxy is missing.

- [ ] **Step 3: Commit**

```bash
git add tests/test_serial_local_transport_integration.py
git commit -m "test: add gated PTY + agent-proxy serial-local integration test (#10)"
```

---

## Task 12: CI workflow that runs the gated integration test un-skipped (round-4 review F1)

The break-escape and serial-local demux correctness are only proven end-to-end, so CI MUST run Task 11 with `agent-proxy` installed and `LDM_REQUIRE_AGENT_PROXY=1`. The repo has **no** `.github/` yet, so this creates the first workflow.

**Files:**
- Create: `.github/workflows/transport-integration.yml`

- [ ] **Step 1: Write the workflow (pin every action to a current SHA per CLAUDE.md; scan with `zizmor` before committing)**

```yaml
name: transport-integration
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  serial-local-integration:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<full-sha>  # v4.x — pin to current SHA
        with:
          persist-credentials: false
      - name: Build agent-proxy pinned to an immutable commit
        env:
          # Full commit SHA (NOT the mutable `agent-proxy-1.96` tag — round-5 review F3).
          # Pin from upstream at implementation time and verify after checkout.
          AGENT_PROXY_SHA: "<full-commit-sha>"
        run: |
          set -euo pipefail
          git clone https://git.kernel.org/pub/scm/utils/kernel/kgdb/agent-proxy.git
          git -C agent-proxy checkout "$AGENT_PROXY_SHA"
          test "$(git -C agent-proxy rev-parse HEAD)" = "$AGENT_PROXY_SHA"  # fail if the SHA moved
          make -C agent-proxy
          echo "$PWD/agent-proxy" >> "$GITHUB_PATH"
      - uses: astral-sh/setup-uv@<full-sha>  # v6.x — pin to current SHA
      - name: Run the gated integration test (must not skip)
        env:
          LDM_REQUIRE_AGENT_PROXY: "1"
        run: |
          set -euo pipefail
          uv venv --allow-existing            # repo standard (justfile sync-dev) — create the env first
          uv pip install -e '.[dev,test]'
          uv run python -m pytest tests/test_serial_local_transport_integration.py -q
```

- [ ] **Step 2: Validate the workflow**

Run: `actionlint .github/workflows/transport-integration.yml && zizmor .github/workflows/transport-integration.yml`
Expected: no findings. Confirm every pin is a real immutable SHA: `actions/checkout` and `astral-sh/setup-uv` (current releases), and `AGENT_PROXY_SHA` (the full commit SHA upstream `agent-proxy-1.96` points to — resolve with `git ls-remote https://git.kernel.org/pub/scm/utils/kernel/kgdb/agent-proxy.git refs/tags/agent-proxy-1.96`).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/transport-integration.yml
git commit -m "ci: run the gated serial-local agent-proxy integration test un-skipped (#10)"
```

---

## Final verification

- [ ] **Full suite + lint + docs guard green**

Run: `uv run python -m pytest -q && uv run ruff check . && uv run ruff format --check . && just check-docs`
Expected: all pass; the 2 prior macOS identity failures are gone; integration tests skip cleanly without tools.

- [ ] **Confirm the Task 12 CI job is green and did not skip.** The BREAK-escape and serial-local demux correctness are only proven end-to-end; Task 12's workflow runs Task 11 with `LDM_REQUIRE_AGENT_PROXY=1` so a skip is impossible there. "All green on the dev host" (where Task 11 skips) is **not** the merge bar for the break path — the Task 12 Linux+agent-proxy run is.

- [ ] **Dispatch a final whole-layer code review** (subagent-driven-development final reviewer), then run the `/codex:adversarial-review --base main` loop, feeding the "Decisions & rejected alternatives" section above as the SETTLED preamble each round.

---

## Self-review notes

- **Spec coverage:** Task 4/5 = §6.1 (agent-proxy, ports, identity, reap); Task 6 = §6.3; Task 7 = §6.2 + §8.4 console socket; Task 8 = §6.4; Task 10 = §7.4; Task 11 = §9.2. The §10.2 blocking invariants that need the `open()` transaction (crash recovery, endpoint-safety gate, execution-state gate, end-to-end halt) are **Layer 4**, not regressions here.
- **No placeholders:** every code step has real code; the one deliberately-deferred literal is `_BREAK_ESCAPE`, which the spec says is pinned by the PTY integration test (Task 11) — flagged, not a gap.
- **Type consistency:** `BackendAttachment` fields, `ProcessIdentity` fields, `ProxyHandle` fields, and `BreakMethod` values are used identically across tasks.
- **Layering:** no Layer-3 module imports `coordination/registry.py` or constructs a `TransportSession` (ADR 0003); `server.py` is untouched (no MCP surface until Layer 5).
