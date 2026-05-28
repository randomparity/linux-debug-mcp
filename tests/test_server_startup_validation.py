"""Startup-validation behaviour for create_app (plan Task B6).

create_app constructs the Layer-4 transport machinery (durable SessionRegistry, AdmissionService,
the open()/close() transaction over the real transport capabilities) and, BEFORE any tool can
admit, acquires the host-global single-instance flock and runs crash reconciliation. It also
re-checks every registered transport capability so a misconfigured registry fails loud at startup
rather than presenting trusted metadata that would authorize an unsafe endpoint.

These tests drive that wiring through the injectable `session_registry=` / `transport_registry=`
seams (the same dependency-injection points the production main() uses to wire the real
host-global registry), never a mock of the machinery itself.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from linux_debug_mcp.coordination.registry import InstanceLockError, SessionRegistry
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.server import create_app
from linux_debug_mcp.transport.base import (
    EndpointExposure,
    ExecutionState,
    RecordState,
    TransportCapability,
    TransportLocality,
    TransportRegistry,
    TransportSession,
    new_session_id,
)

HALTED_TARGET = TargetKey(provisioner="local-qemu", target_id="run-crashed")


def _halted_record(key: TargetKey, *, generation: int) -> TransportSession:
    """A durable ownership record left HALTED by a crash-while-halted — the state reconcile must
    tombstone so a fresh attach stays gated `recovery_required` (ADR 0005, spec §4.7)."""
    return TransportSession(
        session_id=new_session_id(),
        target_key=key,
        generation=generation,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.READY,
        execution_state=ExecutionState.HALTED,
        created_at=datetime.now(UTC),
    )


def test_create_app_runs_reconcile_before_serving(tmp_path):
    # A prior incarnation crashed while a target was HALTED, leaving a durable record. Reconcile
    # MUST run during create_app (before any tool can admit) and tombstone that target so the next
    # attach is gated recovery_required.
    registry = SessionRegistry(directory=tmp_path)
    registry.write_record(_halted_record(HALTED_TARGET, generation=7))
    assert registry.read_tombstone(HALTED_TARGET) is None  # not yet reconciled

    create_app(session_registry=registry)

    tombstone = registry.read_tombstone(HALTED_TARGET)
    assert tombstone is not None
    assert tombstone.generation == 7
    # the orphan record was reaped/cleared by reconcile, leaving only the durable tombstone.
    assert registry.read_record(HALTED_TARGET) is None


def test_create_app_rejects_remote_loopback_local_capability(tmp_path):
    # The capability-validation belt re-checks every registered transport at startup. A REMOTE
    # transport that advertises loopback_local is a misconfigured registry — create_app must fail
    # loud, never serve trusted metadata that would authorize a raw TCP endpoint off-host (§8.4).
    #
    # TransportCapability's own model validator forbids constructing a REMOTE+loopback_local
    # capability, and TransportRegistry.register forbids registering loopback_local for a
    # non-allowlisted provider — so build the misconfigured registry by bypassing register() with a
    # capability the schema cannot mint in one step, mirroring a corrupt/forged registry state.
    bad_capability = TransportCapability.model_construct(
        provider_name="redfish-sol",
        provider_family="transport",
        locality=TransportLocality.REMOTE,
        architectures=(),
        provides_console=True,
        provides_rsp=True,
        supports_uart_break=False,
        endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
        operations=(),
    )
    transport_registry = TransportRegistry()
    transport_registry._capabilities[bad_capability.provider_name] = bad_capability

    with pytest.raises(ValueError, match="loopback_local"):
        create_app(
            session_registry=SessionRegistry(directory=tmp_path),
            transport_registry=transport_registry,
        )


def test_second_app_instance_fails_loud(tmp_path):
    # Two server instances contending on the same registry dir: the first acquires the host-global
    # single-instance flock, the second MUST fail loud (never admit alongside the first, ADR 0005
    # §10.2). The two SessionRegistry objects share `tmp_path` so they contend on one instance.lock.
    first_registry = SessionRegistry(directory=tmp_path)
    create_app(session_registry=first_registry)

    second_registry = SessionRegistry(directory=tmp_path)
    with pytest.raises(InstanceLockError):
        create_app(session_registry=second_registry)
