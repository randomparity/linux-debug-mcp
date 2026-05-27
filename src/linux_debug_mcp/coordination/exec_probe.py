from __future__ import annotations

from linux_debug_mcp.coordination.admission import AdmissionService, ExecutionProof
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import ExecutionState


def probe_execution_state(
    *, registry: SessionRegistry, admission: AdmissionService, target_key: TargetKey, generation: int
) -> ExecutionProof:
    """Layer-4 fresh liveness probe (§4.6). Reads the authoritative `execution_state` the
    stop-capable controller persisted into the durable record and stamps the current
    generation + execution epoch so the ssh-tier gate can fence a stale proof. Fail-closed:
    no record (or no executing fact) ⇒ UNKNOWN — never an optimistic EXECUTING."""
    record = registry.read_record(target_key)
    state = record.execution_state if record is not None else ExecutionState.UNKNOWN
    return ExecutionProof(
        generation=generation,
        epoch=admission.current_execution_epoch(target_key),
        state=state,
    )
