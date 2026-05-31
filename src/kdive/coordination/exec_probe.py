from __future__ import annotations

import threading

from kdive.coordination.admission import AdmissionService, ExecutionProof
from kdive.coordination.registry import SessionRegistry
from kdive.seams.target import TargetKey
from kdive.transport.core.base import ExecutionState, TcpEndpoint, TransportSession
from kdive.transport.core.bounded import BoundedIOTimeout, Deadline, connect_tcp
from kdive.transport.core.rsp_probe import RSP_MAX_ACCUMULATE_BYTES, rsp_frame


def probe_execution_state(
    *, registry: SessionRegistry, admission: AdmissionService, target_key: TargetKey, generation: int
) -> ExecutionProof:
    """Layer-4 cached-fact reader for the ssh-tier admit gate (§4.6). Reads the
    `execution_state` the stop-capable controller persisted into the durable record and stamps
    the current generation + execution epoch so the gate can fence a stale proof. Fail-closed:
    no record (or no executing fact) ⇒ UNKNOWN — never an optimistic EXECUTING.

    This is the ssh-tier admit-fact path against a READY/DEBUGGING target: the controller's
    last-known durable write is authoritative because legacy out-of-band halt bypasses are fenced.
    The post-break confirmation path uses `probe_rsp_halted` instead (a real bounded RSP exchange),
    because the inject_break handler has just written HALTED itself and reading that cached flag
    back would be circular."""
    record = registry.read_record(target_key)
    state = record.execution_state if record is not None else ExecutionState.UNKNOWN
    return ExecutionProof(
        generation=generation,
        epoch=admission.current_execution_epoch(target_key),
        state=state,
    )


# RSP stop replies start with `T` (stop reply with optional register state) or `S` (signal),
# per the GDB Remote Serial Protocol (`gdb/doc/gdb.texinfo`, "Stop Reply Packets"). Either one
# means the target is halted at a stop point, which is the post-break confirmation invariant. Any
# other reply (or no reply / a malformed frame / a connection failure) is False: fail closed.
def probe_rsp_halted(
    session: TransportSession,
    *,
    deadline_s: float = 1.0,
) -> bool:
    """Bounded liveness probe: perform one RSP `?` exchange against `session`'s `rsp_endpoint` and
    return True iff the peer answers with a stop reply (`T..` or `S..`)
    within `deadline_s`. False on any I/O error, timeout, malformed frame, or non-stop reply.

    This is the `transport.inject_break` post-break confirmation. The handler's earlier
    `_halt_debug_transport` writes HALTED to the durable record BEFORE the break runs (so the
    ssh-tier admit gate sees HALTED for the whole break window), and reading that cached flag
    back in the post-probe would be circular — `break_unconfirmed` could never fire on a kernel
    that silently kept running. A real RSP `?` against the gdbstub catches exactly that case:
    a still-EXECUTING kernel either does not answer or does not produce a stop reply.

    ADR 0001 records the split: the cached-flag read (`probe_execution_state`) remains the
    ssh-tier admit fact (the controller's authoritative write, fenced by F8 against legacy
    out-of-band halts); this real RSP probe is the post-break confirmation. Two probes, two
    purposes — no circular flag-back-into-flag chain."""
    endpoint = session.rsp_endpoint
    if not isinstance(endpoint, TcpEndpoint):
        return False  # no RSP channel to probe (a unix-socket or absent endpoint cannot answer)
    deadline = Deadline.after(deadline_s)
    cancel = threading.Event()
    try:
        sock = connect_tcp(endpoint.host, endpoint.port, deadline=deadline, cancel=cancel)
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
            stop_reply = _first_stop_reply(buffer)
            if stop_reply is not None:
                return True
            if len(buffer) > RSP_MAX_ACCUMULATE_BYTES:
                break
    except OSError:
        return False
    finally:
        sock.close()
    return False


def _first_stop_reply(buffer: bytes) -> bytes | None:
    """Return the payload of the first complete RSP frame whose payload starts with `T` or `S`
    (a stop reply), or None if no such frame is present yet. Leading `+`/`-` acks are tolerated.
    A frame whose checksum does not validate is rejected — a non-RSP listener that scribbles a
    `$T..#xx` lookalike cannot spoof a stop reply."""
    start = buffer.find(b"$")
    if start == -1:
        return None
    hash_idx = buffer.find(b"#", start)
    if hash_idx == -1 or hash_idx + 2 >= len(buffer):
        return None
    payload = buffer[start + 1 : hash_idx]
    checksum_hex = buffer[hash_idx + 1 : hash_idx + 3]
    try:
        expected = int(checksum_hex, 16)
    except ValueError:
        return None
    if (sum(payload) % 256) != expected:
        return None
    if not payload or payload[0:1] not in (b"T", b"S"):
        return None
    return payload
