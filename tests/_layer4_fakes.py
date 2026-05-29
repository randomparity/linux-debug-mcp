# tests/_layer4_fakes.py
"""Shared Layer-4 test harness (plan Task A0). One source of fakes for every load-bearing
open()/close()/gating/recovery test, so a contract change touches one file, not a dozen."""

from __future__ import annotations

import threading

from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore, TargetSnapshot
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.safety.secret_registry import SecretRegistry
from linux_debug_mcp.safety.secrets import SecretReferenceKind
from linux_debug_mcp.seams.guard import InProcessStopCapableGuard
from linux_debug_mcp.seams.secrets import EnvSecretsBackend, SecretsStore
from linux_debug_mcp.seams.target import BreakHint, ConsoleKind, PlatformMetadata, TargetKey, TargetState
from linux_debug_mcp.transport.base import (
    BackendAttachment,
    BreakMethod,
    BreakPlan,
    EndpointExposure,
    LineRole,
    OpenRequest,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportLocality,
    TransportRef,
)

KEY = TargetKey(provisioner="local-qemu", target_id="run-1")
PLATFORM = PlatformMetadata(
    console_kind=ConsoleKind.UART,
    console_count=1,
    dedicated_debug_line=False,
    ssh_reachable=True,
    break_hints=[BreakHint.GDBSTUB_NATIVE],
)
CHANNEL = TransportRef(provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))


class FakeQemuTransport(Transport):
    """Loopback-local qemu-gdbstub stand-in. `crash=True` raises in attach (rollback seam).
    `backend_pid` set ⇒ attach emits the `backend_process` partial BEFORE returning, so the
    write-ahead backend_pid path (Finding #1) is exercised."""

    def __init__(
        self, *, crash: bool = False, backend_pid: int | None = None, backend_start_time: str | None = None
    ) -> None:
        self._crash = crash
        self._backend_pid = backend_pid
        self._backend_start_time = backend_start_time
        self.closed: list[str] = []

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
        if self._backend_pid is not None:
            # emit pid+start_time as one partial (mirrors transport/proxy.py:184) so the
            # transaction can write it through into the OPENING record before we return.
            on_partial("backend_process", {"pid": self._backend_pid, "start_time": self._backend_start_time})
        if self._crash:
            raise RuntimeError("attach blew up")
        return BackendAttachment(
            console_endpoint=None,
            rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),
            backend_pid=self._backend_pid,
            backend_start_time=self._backend_start_time,
        )

    def close(self, session) -> None:
        self.closed.append(session.session_id)

    def health(self, session) -> str:
        return "ready"


class FakeBrokeredTransport(FakeQemuTransport):
    """brokered_required remote stand-in — its endpoint-returning open is refused pre-attach."""

    @property
    def capability(self) -> TransportCapability:
        return TransportCapability(
            provider_name="redfish-sol",
            locality=TransportLocality.REMOTE,
            provides_console=True,
            provides_rsp=True,
            supports_uart_break=False,
            endpoint_exposure=EndpointExposure.BROKERED_REQUIRED,
        )


class FakeBreakPolicy:
    def plan(self, *, channel, platform, disproved):
        return BreakPlan(method=BreakMethod.GDBSTUB_NATIVE, channel_id=channel.channel_id, rationale="rsp")


class FakeReapProxy:
    """Records start-time-fenced reaps so reconcile-after-death tests assert reap-by-identity.

    `kills_live_backend` controls the bool returned from `stop_by_identity` (Finding F1): True
    simulates a live orphan we just killed, False simulates a dead/unfenceable record where the
    reaper signaled nothing. Default False matches the cold-restart case where backends are dead."""

    def __init__(self, *, kills_live_backend: bool = False) -> None:
        self.reaped: list[tuple[int, str | None]] = []
        self._kills_live_backend = kills_live_backend

    def stop_by_identity(self, pid: int, start_time: str | None) -> bool:
        self.reaped.append((pid, start_time))
        return self._kills_live_backend


class FakeBlockingReapProxy:
    """stop_by_identity blocks until `unblock()` is called, so a transport-transaction test can
    drive the lifecycle dispatcher's `teardown_deadline` path and observe what runs while the
    `invalidate` worker is wedged on the SIGTERM/wait/SIGKILL sequence. Used to verify Fix B:
    when invalidate is wedged, force_drop must leave the durable record intact so
    `SessionRegistry.reconcile()` can reap the orphan on the next process start.

    `entered` fires as the FIRST action of `stop_by_identity`, so a test that needs to assert
    "the invalidate worker is genuinely wedged inside the proxy" can wait on `entered` rather
    than racing thread-startup vs. `outstanding_overdue()` snapshotting on heavily-loaded CI."""

    def __init__(self) -> None:
        self._block = threading.Event()
        self.entered = threading.Event()
        self.reaped: list[tuple[int, str | None]] = []

    def stop_by_identity(self, pid: int, start_time: str | None) -> bool:
        self.entered.set()
        self.reaped.append((pid, start_time))
        self._block.wait()
        return True

    def unblock(self) -> None:
        self._block.set()


class FakeSshRunner:
    """Blocks in run() until its cancel event fires, so the async-halt cancel bridge (Fix 3)
    is exercised without a real subprocess. Consumed by Task B2 — depends on the
    `SshCommandResult.cancelled` field that Task B1 adds."""

    def __init__(self) -> None:
        self.cancel_observed = threading.Event()
        self.started = threading.Event()

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
        from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult

        self.started.set()
        if cancel is not None:
            cancel.wait(timeout)
            if cancel.is_set():
                self.cancel_observed.set()
                return SshCommandResult(exit_status=-1, timed_out=False, cancelled=True)
        return SshCommandResult(exit_status=0, timed_out=False)


def seed_snapshot(
    store: SnapshotStore,
    *,
    key: TargetKey = KEY,
    generation: int = 1,
    transports=(CHANNEL,),
    platform: PlatformMetadata = PLATFORM,
    state: TargetState = TargetState.READY,
) -> None:
    """Publish an authoritative TargetSnapshot (mirrors the Task B0 producer, ADR 0007)."""
    store.put(key, TargetSnapshot(generation=generation, transports=tuple(transports), platform=platform, state=state))


def build_txn(
    transport: Transport,
    *,
    registry: SessionRegistry,
    guard=None,
    leases=None,
    generation: int = 1,
    state: TargetState = TargetState.READY,
):
    """Construct a TransportTransaction over a seeded snapshot. Returns (txn, admission)."""
    store = SnapshotStore()
    seed_snapshot(store, generation=generation, state=state)
    admission = AdmissionService(store)
    txn = TransportTransaction(
        admission=admission,
        registry=registry,
        guard=guard or InProcessStopCapableGuard(),
        leases=leases or ConsoleLeaseManager(),
        secrets=SecretsStore(
            definitions=[], backends={SecretReferenceKind.ENV: EnvSecretsBackend()}, registry=SecretRegistry()
        ),
        break_policy=FakeBreakPolicy(),
        transports={transport.capability.provider_name: transport},
    )
    return txn, admission


def make_request(provider: str = "qemu-gdbstub", *, generation: int = 1) -> OpenRequest:
    ref = (
        CHANNEL
        if provider == "qemu-gdbstub"
        else TransportRef(provider=provider, channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))
    )
    return OpenRequest(target_key=KEY, generation=generation, transport_ref=ref, platform=PLATFORM)
