# tests/test_transport_open_close_integration.py
"""Gated end-to-end transport integration tests (Task C3).

Test 1 — inject_break over a PTY+agent-proxy channel
    Gate: agent-proxy binary present OR KDIVE_REQUIRE_AGENT_PROXY=1.
    Reuses the PTY + SerialLocalTransport fixture from the sibling integration module.
    Drives attach, calls send_break, and asserts the -s003 alternate reaches the controller fd.
    No kgdb-enabled guest needed; the PTY simulates the serial line.

Test 2 — migrated debug.start_session transaction wiring against a live QEMU gdbstub
    Gate: KDIVE_LIVE_GDBSTUB=1 + companion envs + virsh + gdb.
    Runs the complete build→boot→debug.start_session flow with transaction/admission/
    session_registry explicitly injected from _build_transport_machinery, then reads
    registers and verifies ok=True.  Proves the B3 migration is behaviour-preserving
    against a real guest.
"""

from __future__ import annotations

import os
import pty
import select
import shutil
import threading
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Gate helpers
# ---------------------------------------------------------------------------

_AGENT_PROXY_REQUIRED = os.environ.get("KDIVE_REQUIRE_AGENT_PROXY") == "1"
_AGENT_PROXY_PRESENT = shutil.which("agent-proxy") is not None

_GDBSTUB_REQUIRED_ENV = [
    "KDIVE_LIVE_GDBSTUB",
    "KDIVE_SOURCE",
    "KDIVE_ROOTFS",
    "KDIVE_DOMAIN",
    "KDIVE_LIBVIRT_URI",
    "KDIVE_READINESS_MARKER",
]
_MANAGED_DOMAIN_PREFIX = "kdive-"


def _live_gdbstub_active() -> bool:
    """Return True only when every required env var is set and LIVE_GDBSTUB==1."""
    if os.environ.get("KDIVE_LIVE_GDBSTUB") != "1":
        return False
    return all(os.environ.get(name) for name in _GDBSTUB_REQUIRED_ENV)


def _gdbstub_skip_reason() -> str:
    missing = [name for name in _GDBSTUB_REQUIRED_ENV if not os.environ.get(name)]
    return (
        "live gdbstub integration test skipped; set "
        f"{', '.join(missing) if missing else 'KDIVE_LIVE_GDBSTUB=1'} to run it. "
        "Example: KDIVE_LIVE_GDBSTUB=1 "
        "KDIVE_SOURCE=/path/to/linux "
        "KDIVE_ROOTFS=/var/lib/kdive/rootfs/minimal.qcow2 "
        "KDIVE_DOMAIN=kdive-dev-debug "
        "KDIVE_LIBVIRT_URI=qemu:///system "
        "KDIVE_READINESS_MARKER=kdive-ready "
        "pytest tests/test_transport_open_close_integration.py -q"
    )


def _gdbstub_env() -> dict[str, str]:
    """Return the required gdbstub env vars (call only after the skipif guard has passed)."""
    return {name: os.environ[name] for name in _GDBSTUB_REQUIRED_ENV}


# ---------------------------------------------------------------------------
# Test 1: inject_break over PTY + agent-proxy
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _AGENT_PROXY_PRESENT and not _AGENT_PROXY_REQUIRED,
    reason="agent-proxy not installed (set KDIVE_REQUIRE_AGENT_PROXY=1 to require it in CI)",
)
def test_inject_break_drops_kgdb_target_into_debugger(tmp_path: Path) -> None:
    """Drive SerialLocalTransport.attach over a PTY + real agent-proxy, call send_break,
    and assert the -s003 KGDB alternate reaches the controller fd.  The PTY plays the
    role of the serial line; no kgdb-enabled guest is required."""
    from kdive.seams.process_identity import ProcProcessIdentityProbe
    from kdive.seams.target import ConsoleKind, PlatformMetadata, TargetKey
    from kdive.transport.backends.proxy import _S003_TARGET_ALTERNATE, AgentProxyBackend
    from kdive.transport.backends.serial_local import SerialLocalTransport
    from kdive.transport.core.base import LineRole, OpenRequest, TcpEndpoint, TransportRef
    from kdive.transport.core.bounded import Deadline

    controller_fd, peripheral_fd = pty.openpty()
    peripheral_name = os.ttyname(peripheral_fd)

    backend = AgentProxyBackend()
    transport = SerialLocalTransport(socket_dir=tmp_path, lock_dir=tmp_path / "locks", proxy=backend)
    request = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="vm-c3"),
        generation=0,
        transport_ref=TransportRef(
            provider="serial-local",
            channel_id="dbg0",
            line_role=LineRole.DEDICATED_DEBUG,
            target_ref={"device": peripheral_name},
            opts={"supports_uart_break": False},
        ),
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART,
            console_count=1,
            dedicated_debug_line=True,
            ssh_reachable=False,
        ),
    )

    result = transport.attach(
        request,
        cancel=threading.Event(),
        deadline=Deadline.after(10.0),
        on_partial=lambda *_: None,
    )
    try:
        assert isinstance(result.console_endpoint, TcpEndpoint), "attach must return a live TCP console endpoint"
        assert isinstance(result.rsp_endpoint, TcpEndpoint), "attach must return a live TCP RSP endpoint"

        # Send the break via the admitted proxy handle — the -s003 alternate is the KGDB entry
        # signal that would halt a live kernel's kgdb stub.
        proxy_handle = transport._proxy_handles[(result.backend_pid, result.backend_start_time)]
        backend.send_break(proxy_handle)

        # Drain the controller fd until the -s003 alternate appears or the deadline expires.
        deadline = Deadline.after(5.0)
        seen = b""
        os.set_blocking(controller_fd, False)
        while not deadline.expired() and _S003_TARGET_ALTERNATE not in seen:
            readable, _, _ = select.select([controller_fd], [], [], 0.2)
            if readable:
                seen += os.read(controller_fd, 256)

        assert _S003_TARGET_ALTERNATE in seen, f"expected -s003 KGDB entry alternate on the serial line, got {seen!r}"
    finally:
        # _Sess-compatible minimal session object with just the fields close() reads.
        class _MinSession:
            def __init__(self, pid, start_time):
                self.backend_pid = pid
                self.backend_start_time = start_time
                self.console_endpoint = result.console_endpoint
                self.rsp_endpoint = result.rsp_endpoint

        transport.close(_MinSession(result.backend_pid, result.backend_start_time))
        os.close(controller_fd)
        os.close(peripheral_fd)

    # Verify close() reaped the proxy handle and the child process is gone.
    assert (result.backend_pid, result.backend_start_time) not in transport._proxy_handles
    assert ProcProcessIdentityProbe().is_alive(result.backend_pid) is False


# ---------------------------------------------------------------------------
# Test 2: migrated debug.start_session → read_registers over a live gdbstub
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _live_gdbstub_active(),
    reason=_gdbstub_skip_reason(),
)
def test_qemu_gdbstub_flow_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Drive the full build→boot→debug.start_session flow with transaction/admission/
    session_registry explicitly injected from _build_transport_machinery.

    The test proves the B3 migration is behaviour-preserving: the migrated handler returns
    ok=True and reads register values from the same live QEMU guest the legacy path used.
    A durable HALTED record must exist in the session registry after start_session, and
    debug.read_registers must return non-empty register data.
    """
    env = _gdbstub_env()
    source = Path(env["KDIVE_SOURCE"]).expanduser()
    rootfs_path = Path(env["KDIVE_ROOTFS"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    vmlinux = source / "vmlinux"
    gdbstub_endpoint = os.environ.get("KDIVE_GDBSTUB_ENDPOINT", "127.0.0.1:1234")

    assert source.is_dir(), f"KDIVE_SOURCE must be a Linux source directory: {source}"
    assert rootfs_path.is_file(), f"KDIVE_ROOTFS must be a disk image file: {rootfs_path}"
    assert kernel_image.is_file(), f"built kernel image is required at {kernel_image}"
    assert vmlinux.is_file(), f"unstripped vmlinux is required at {vmlinux}"
    assert env["KDIVE_DOMAIN"].startswith(_MANAGED_DOMAIN_PREFIX), (
        "KDIVE_DOMAIN must be a dedicated managed domain starting with "
        f"{_MANAGED_DOMAIN_PREFIX!r}: {env['KDIVE_DOMAIN']}"
    )

    from kdive import server
    from kdive.config import RootfsProfile, TargetProfile
    from kdive.debug.contracts import DebugRuntime
    from kdive.providers.local.debug.gdb_mi import GdbMiEngine, GdbMiSessionRegistry
    from kdive.server import (
        _build_transport_machinery,
        create_run_handler,
        debug_read_registers_handler,
        debug_start_session_handler,
        kernel_build_handler,
        target_boot_handler,
    )
    from kdive.transport.core.base import ExecutionState

    # Register the live profiles into the server's DEFAULT_* dicts so the handlers can resolve them.
    monkeypatch.setitem(
        server.DEFAULT_TARGET_PROFILES,
        "live-qemu-debug",
        TargetProfile(
            name="live-qemu-debug",
            architecture="x86_64",
            target_ref=env["KDIVE_DOMAIN"],
            managed_domain=True,
            managed_domain_prefix=_MANAGED_DOMAIN_PREFIX,
            libvirt_uri=env["KDIVE_LIBVIRT_URI"],
            timeout_seconds=300,
            debug_gdbstub=True,
            gdbstub_endpoint=gdbstub_endpoint,
        ),
    )
    monkeypatch.setitem(
        server.DEFAULT_ROOTFS_PROFILES,
        "live-rootfs",
        RootfsProfile(
            name="live-rootfs",
            source=str(rootfs_path),
            source_type="disk_image",
            mutability="read_only",
            readiness_marker=env["KDIVE_READINESS_MARKER"],
        ),
    )

    # Build the Layer-4 machinery with a fresh (per-test) session registry so the test does not
    # contend with any host-global single-instance flock from an active server process.
    machinery = _build_transport_machinery(session_registry=None, transport_registry=None)

    artifact_root = tmp_path / "runs"

    # Step 1: create run
    create_resp = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        debug_profile="qemu-gdbstub-default",
    )
    assert create_resp.ok is True, f"kernel.create_run failed: {create_resp.model_dump(mode='json')}"
    run_id = create_resp.data["run_id"]

    # Step 2: build (already-built artifacts from source dir are used if present)
    build_resp = kernel_build_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        build_profile="x86_64-default",
        force_rebuild=False,
    )
    assert build_resp.ok is True, f"kernel.build failed: {build_resp.model_dump(mode='json')}"

    # Step 3: boot — pass machinery.admission so the boot-READY snapshot is published into
    # the same AdmissionService that transaction.open() will read.
    boot_resp = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        force_reboot=True,
        admission=machinery.admission,
    )
    assert boot_resp.ok is True, f"target.boot failed: {boot_resp.model_dump(mode='json')}"

    # Step 4: debug.start_session via the MIGRATED transaction path.
    gdb_mi_engine = GdbMiEngine()
    gdb_mi_sessions = GdbMiSessionRegistry()
    debug_resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile="qemu-gdbstub-default",
        new_session=True,
        transaction=machinery.transaction,
        admission=machinery.admission,
        session_registry=machinery.session_registry,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
    )
    assert debug_resp.ok is True, f"debug.start_session (migrated) failed: {debug_resp.model_dump(mode='json')}"

    debug_session_id = debug_resp.data["debug_session_id"]
    assert debug_session_id, "debug.start_session must return a debug_session_id"

    # The durable registry must carry a HALTED record for this target (write-before-attach invariant).
    from kdive.seams.target import TargetKey

    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    record = machinery.session_registry.read_record(target_key)
    assert record is not None, "a durable HALTED record must exist in the session registry after debug.start_session"
    assert record.execution_state == ExecutionState.HALTED, (
        f"durable record must be HALTED before gdb attach runs, got {record.execution_state}"
    )

    # Step 5: read registers — the migrated path produces the same observable results as the
    # legacy path: ok=True with a non-empty 'registers' dict.
    reg_resp = debug_read_registers_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        registers=["rip", "rsp"],
        debug_session_id=debug_session_id,
        runtime=DebugRuntime(
            session_registry=machinery.session_registry,
            gdb_mi_engine=gdb_mi_engine,
            gdb_mi_sessions=gdb_mi_sessions,
        ),
    )
    assert reg_resp.ok is True, f"debug.read_registers failed: {reg_resp.model_dump(mode='json')}"
    assert reg_resp.data.get("registers"), (
        "debug.read_registers must return non-empty register data from the live guest"
    )
