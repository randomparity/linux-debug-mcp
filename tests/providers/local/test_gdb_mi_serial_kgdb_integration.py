# tests/test_gdb_mi_serial_kgdb_integration.py
"""Phase D (#82), ADR 0024 decision 3: gated serial-KGDB break integration. Drives the real
``serial-local`` demux over a PTY + agent-proxy and injects the admitted break plan through
``TransportTransaction.inject_break_for_session`` — the same handle-resolution path
``debug.interrupt`` takes for a non-native break method — asserting the break reaches the target
line. Skipped (never passing) on a dev host without agent-proxy, so a local-only run can never
show a false green for the serial-KGDB criterion.

The MI continue/``*stopped`` round-trip needs a live KGDB-speaking kernel on the serial line and is
covered by the live-gdbstub gated test (``test_gdb_mi_integration.py``); this test's job is the real
break-injection resolution over the live transport, which agent-proxy alone can exercise."""

import os
import pty
import select
import shutil
import threading
from datetime import UTC, datetime

import pytest

from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.seams.process_identity import ProcProcessIdentityProbe
from kdive.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from kdive.transport.backends.proxy import _S003_TARGET_ALTERNATE, AgentProxyBackend
from kdive.transport.backends.serial_local import SerialLocalTransport
from kdive.transport.core.base import (
    BreakMethod,
    BreakPlan,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    TransportRef,
    TransportSession,
    new_session_id,
)
from kdive.transport.core.bounded import Deadline

# Require agent-proxy in CI (KDIVE_REQUIRE_AGENT_PROXY=1) so the serial-KGDB break/continue
# prerequisite is a real merge gate; skip only on a dev host that did NOT opt in. The skip reason
# names the missing prerequisite so a local-only run shows it skipped, never passing.
pytestmark = pytest.mark.skipif(
    shutil.which("agent-proxy") is None and os.environ.get("KDIVE_REQUIRE_AGENT_PROXY") != "1",
    reason=(
        "agent-proxy not installed (set KDIVE_REQUIRE_AGENT_PROXY=1 to require it in CI) "
        "— serial-KGDB break/continue prerequisite"
    ),
)


def _bare_transaction(registry: SessionRegistry, transport: SerialLocalTransport) -> TransportTransaction:
    """inject_break_for_session reads only `_registry` and `_transports`; build a transaction with
    those two wired and the rest of the open()/close() machinery left unset (this test never opens
    or closes through the transaction — the serial-local transport owns the live demux directly)."""
    txn = object.__new__(TransportTransaction)
    txn._registry = registry  # type: ignore[attr-defined]
    txn._transports = {"serial-local": transport}  # type: ignore[attr-defined]
    return txn


class _Sess:
    def __init__(self, console_endpoint, rsp_endpoint, backend_pid, backend_start_time):
        self.console_endpoint = console_endpoint
        self.rsp_endpoint = rsp_endpoint
        self.backend_pid = backend_pid
        self.backend_start_time = backend_start_time


def test_serial_kgdb_inject_break_for_session_reaches_target_line(tmp_path):
    """Attach the serial-local demux over a PTY + real agent-proxy, then inject the admitted
    agent-proxy break through the transaction's inject_break_for_session seam (resolving the live
    proxy handle off the durable record) and assert the -s003 alternate hits the target line."""
    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)

    backend = AgentProxyBackend()
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=backend)
    target_key = TargetKey(provisioner="local-qemu", target_id="vm1")
    request = OpenRequest(
        target_key=target_key,
        generation=0,
        transport_ref=TransportRef(
            provider="serial-local",
            channel_id="dbg0",
            line_role=LineRole.DEDICATED_DEBUG,
            target_ref={"device": peripheral_name},
            opts={"supports_uart_break": False},
        ),
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=True, ssh_reachable=False
        ),
    )
    result = transport.attach(
        request, cancel=threading.Event(), deadline=Deadline.after(10.0), on_partial=lambda *_: None
    )
    session = _Sess(result.console_endpoint, result.rsp_endpoint, result.backend_pid, result.backend_start_time)
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()
    registry = SessionRegistry(directory=registry_dir)
    session_id = new_session_id()
    record = TransportSession(
        session_id=session_id,
        target_key=target_key,
        generation=0,
        provider="serial-local",
        channel_id="dbg0",
        break_plan=BreakPlan(method=BreakMethod.AGENT_PROXY_BREAK, channel_id="dbg0", rationale="serial KGDB"),
        backend_pid=result.backend_pid,
        backend_start_time=result.backend_start_time,
        created_at=datetime.now(UTC),
    )
    registry.write_record(record)
    transaction = _bare_transaction(registry, transport)
    try:
        assert isinstance(result.rsp_endpoint, TcpEndpoint)
        # The admitted plan's method, resolved off the durable record and injected over the live
        # agent-proxy handle — the exact path debug.interrupt takes for a non-native break.
        transaction.inject_break_for_session(session_id, BreakMethod.AGENT_PROXY_BREAK.value)
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
    assert (result.backend_pid, result.backend_start_time) not in transport._proxy_handles
    assert ProcProcessIdentityProbe().is_alive(result.backend_pid) is False
