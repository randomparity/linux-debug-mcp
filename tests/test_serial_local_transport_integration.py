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
from linux_debug_mcp.transport.proxy import _S003_TARGET_ALTERNATE, AgentProxyBackend
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
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=backend)
    request = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm1"),
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
    try:
        assert isinstance(result.console_endpoint, TcpEndpoint)
        assert isinstance(result.rsp_endpoint, TcpEndpoint)
        socket.create_connection(
            (result.console_endpoint.host, result.console_endpoint.port), timeout=2.0
        ).close()  # console TCP endpoint is live
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
