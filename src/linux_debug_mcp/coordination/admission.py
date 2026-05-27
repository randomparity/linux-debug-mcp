from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.lifecycle import InvalidationResult, LifecycleDispatcher, LifecycleEvent
from linux_debug_mcp.seams.target import LeaseInfo, PlatformMetadata, TargetKey, TargetState
from linux_debug_mcp.transport.base import (
    DEFAULT_MIN_LEASE_TTL_SECONDS,
    ExecutionState,
    OpenRequest,
    TransportRef,
)

# States from which no live op may attach (the target is mid-transition or dead).
_NON_LIVE_STATES = frozenset(
    {
        TargetState.ACQUIRING,
        TargetState.PREPARING,
        TargetState.BOOTING,
        TargetState.RESETTING,
        TargetState.RELEASING,
        TargetState.CRASHED,
    }
)


class AdmissionOp(StrEnum):
    TRANSPORT_OPEN = "transport.open"  # stop-capable attach (requires READY)
    SSH_TIER = "ssh_tier"  # smoke tests / ssh debug reads (READY or DEBUGGING)


class AdmissionState(StrEnum):
    PENDING = "pending"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"
    COMPLETED = "completed"
    ABANDONED = "abandoned"  # force-dropped overdue handle whose owner could not roll it back


@dataclass(frozen=True)
class ExecutionProof:
    """A FRESH execution-state observation, produced ONLY by the Layer-4 bounded liveness probe
    (§4.6/§5.6). Layer 2 never manufactures it — so a positive ssh-tier admission against a
    DEBUGGING target always rests on a fresh probe, never a cached/stale flag (spec §4.6: "do not
    trust a possibly-stale EXECUTING"). Two freshness fences: `generation` is the snapshot
    generation the probe observed at (rejects a proof from a prior incarnation), and `epoch` is
    the per-target **execution epoch** the probe read at (`current_execution_epoch`). Because a
    bare halt/continue does NOT bump `generation`, `epoch` is what stops an `EXECUTING` proof
    taken before an `EXECUTING→HALTED` transition from being replayed afterwards: every transition
    bumps the epoch, so a stale proof no longer matches and admission re-probes instead of hanging
    on a frozen network stack. `state` is the probed `ExecutionState`. The probe (and its
    `probe_timeout`) is Layer 4; admission only consumes the value — no callback/IO under the lock."""

    generation: int
    epoch: int
    state: ExecutionState


class AdmissionError(RuntimeError):
    """Admission refusal. `category` is the agent-facing ErrorCategory; `code` is the precise
    machine-readable reason (spec §4.2/§8.1)."""

    def __init__(self, message: str, *, category: ErrorCategory, code: str) -> None:
        super().__init__(message)
        self.category = category
        self.code = code


@dataclass(frozen=True)
class TargetSnapshot:
    """Authoritative per-target facts admission re-binds against (spec §4.1). The local-qemu
    adapter (Layer 4) writes this when a run boots to READY; provisioning later owns it."""

    generation: int
    transports: tuple[TransportRef, ...]
    platform: PlatformMetadata
    state: TargetState
    lease: LeaseInfo | None = None


class AdmissionHandle:
    """Opaque scoped binding (spec §3.3). Cancellation is **private and monotonic** — only the
    AdmissionService signals it (and never clears it); callers get a read-only `cancelled`
    property and an interruptible `wait_cancelled(timeout)`, with no public Event to clear or
    reassign. Identity/authority fields (`channel`, `platform`) are read-only and bound from
    the authoritative snapshot at admit() time, so downstream code never re-reads caller copies."""

    __slots__ = (
        "_handle_id",
        "_target_key",
        "_generation",
        "_op",
        "_channel",
        "_platform",
        "_recovery",
        "_state",
        "_cancel",
        "_reaped",
    )

    def __init__(
        self,
        *,
        handle_id: str,
        target_key: TargetKey,
        generation: int,
        op: AdmissionOp,
        channel: TransportRef | None,
        platform: PlatformMetadata,
        recovery: bool,
    ) -> None:
        self._handle_id = handle_id
        self._target_key = target_key
        # The authoritative snapshot generation this handle was admitted against. Bound at
        # registration so targeted async operations (cancel_ssh_tier) can fence on it: a late
        # cancel from a prior incarnation must never touch a handle admitted after a reset/reopen.
        self._generation = generation
        self._op = op
        self._channel = channel
        self._platform = platform
        self._recovery = recovery
        self._state = AdmissionState.PENDING
        self._cancel = threading.Event()
        # Set by AdmissionService.confirm_reaped() once the Layer-4 reaper has reclaimed every
        # external resource this binding held (backend child, lease, guard). Private and
        # monotonic, like _cancel: only the service signals it, and abandon() requires it so a
        # cancelled binding can never be deregistered (unblocking reopen) before teardown is proven.
        self._reaped = threading.Event()

    @property
    def handle_id(self) -> str:
        return self._handle_id

    @property
    def target_key(self) -> TargetKey:
        return self._target_key

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def op(self) -> AdmissionOp:
        return self._op

    @property
    def channel(self) -> TransportRef | None:
        return self._channel

    @property
    def platform(self) -> PlatformMetadata:
        # PlatformMetadata is a mutable pydantic model; return a defensive deep copy each access
        # so a consumer cannot mutate the handle's bound authoritative facts (ssh_reachable,
        # console_kind, break_hints) between admission and break-plan selection.
        return self._platform.model_copy(deep=True)

    @property
    def recovery(self) -> bool:
        return self._recovery

    @property
    def state(self) -> AdmissionState:
        return self._state

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    @property
    def reaped(self) -> bool:
        return self._reaped.is_set()

    def wait_cancelled(self, timeout: float | None = None) -> bool:
        return self._cancel.wait(timeout)


def _isolate_snapshot(snapshot: TargetSnapshot) -> TargetSnapshot:
    """Return a copy whose mutable Layer-1 models (LeaseInfo/PlatformMetadata have
    validate_assignment, so they are mutable) are deep-copied, so neither a caller retaining
    the original nor a consumer of get() can mutate the published authoritative facts.
    `transports` are frozen, deeply-immutable TransportRefs, so the tuple is shared safely."""
    return TargetSnapshot(
        generation=snapshot.generation,
        transports=tuple(snapshot.transports),
        platform=snapshot.platform.model_copy(deep=True),
        state=snapshot.state,
        lease=snapshot.lease.model_copy(deep=True) if snapshot.lease is not None else None,
    )


class SnapshotStore:
    """In-memory TargetKey → TargetSnapshot map (spec §4.1). Thread-safe, and isolates the
    authoritative facts on both put() and get() so a retained reference cannot mutate
    `lease.expires_at` / `platform.ssh_reachable` after publication without a generation bump.
    `generation` is the **monotonic freshness fence**, so put() rejects any regression for a
    key: a stale/out-of-order publisher storing generation N after N+1 cannot make a pre-reset
    OpenRequest admissible again (it would defeat stale_handle before any lease/guard acquire)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshots: dict[TargetKey, TargetSnapshot] = {}

    def put(self, target_key: TargetKey, snapshot: TargetSnapshot) -> None:
        with self._lock:
            current = self._snapshots.get(target_key)
            if current is not None and snapshot.generation < current.generation:
                raise AdmissionError(
                    f"snapshot generation regression for target: {snapshot.generation} < {current.generation}",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                    code="snapshot_generation_regression",
                )
            self._snapshots[target_key] = _isolate_snapshot(snapshot)

    def get(self, target_key: TargetKey) -> TargetSnapshot | None:
        with self._lock:
            stored = self._snapshots.get(target_key)
            return _isolate_snapshot(stored) if stored is not None else None


class AdmissionService:
    """The short-critical-section admission gate (spec §4.2). One RLock per TargetKey guards
    freshness + snapshot re-binding + lease near-expiry + the static state gate, then
    registers a pending binding with a cancel fence. The open() transaction (Layer 4) drives
    promote/rollback. `invalidate_lifecycle` enforces the §4.5 ordering — close_admission (step 1)
    runs to completion before `dispatcher.emit` (step 2 teardown), so admission is provably closed
    before any subscriber can release a lease/guard."""

    def __init__(
        self,
        snapshot_store: SnapshotStore,
        *,
        default_min_lease_ttl: int = DEFAULT_MIN_LEASE_TTL_SECONDS,
    ) -> None:
        self._store = snapshot_store
        self._default_min_lease_ttl = default_min_lease_ttl
        self._table_lock = threading.Lock()
        self._key_locks: dict[TargetKey, threading.RLock] = {}
        self._bindings: dict[TargetKey, list[AdmissionHandle]] = defaultdict(list)
        self._closed_at: dict[TargetKey, int] = {}  # lifecycle closure: target_key -> gen closed at
        self._recovery_required: dict[TargetKey, int] = {}  # tombstone gate: target_key -> parked gen (§4.7)
        self._exec_epoch: dict[TargetKey, int] = {}  # §4.6 execution epoch: bumps on EVERY exec-state transition

    def _key_lock(self, target_key: TargetKey) -> threading.RLock:
        with self._table_lock:
            lock = self._key_locks.get(target_key)
            if lock is None:
                lock = threading.RLock()
                self._key_locks[target_key] = lock
            return lock

    def current_execution_epoch(self, target_key: TargetKey) -> int:
        """The per-target execution epoch Layer 4 stamps onto an `ExecutionProof` right after it
        probes `EXECUTING` (§4.6). admit_ssh_tier admits only if the proof's epoch still matches,
        so a transition between probe and admit invalidates the proof."""
        with self._key_lock(target_key):
            return self._exec_epoch.get(target_key, 0)

    def note_execution_transition(self, target_key: TargetKey, generation: int) -> int:
        """Layer 4 calls this on EVERY execution-state transition the stop-capable controller
        causes (`EXECUTING→HALTED`, `HALTED→EXECUTING`, `→UNKNOWN`). It bumps the execution epoch so
        any `ExecutionProof` stamped before the transition no longer matches — a stale `EXECUTING`
        can never be replayed across a halt. **Generation-fenced:** `generation` is the incarnation
        the transition was observed at; the bump fires only when it matches the authoritative
        snapshot generation, so a transition from a PRIOR incarnation (a stale/late controller)
        cannot poison the current epoch and spuriously reject a fresh current-generation EXECUTING
        proof (§5.6). Returns the (possibly unchanged) current epoch.

        **Caller precondition (Layer 4, [ADR 0002]):** the caller MUST be the current stop-capable
        controller acting under its **live `StopCapableGuard` token**. A debug session attaches and
        detaches WITHIN a generation (§3.1/§5.1 — detach does not bump generation), so the
        generation fence alone cannot distinguish a stale same-generation controller; the guard
        token is the contract's single authority for that (§5.6 rule 1, "a stale token is a
        no-op"). A detached session released its token, so its late event worker is non-authoritative
        and MUST NOT call this. Layer 2 does not duplicate the guard (ADR 0002, rejected option 1)."""
        with self._key_lock(target_key):
            snapshot = self._store.get(target_key)
            if snapshot is None or generation != snapshot.generation:
                return self._exec_epoch.get(target_key, 0)
            epoch = self._exec_epoch.get(target_key, 0) + 1
            self._exec_epoch[target_key] = epoch
            return epoch

    def publish_snapshot(self, target_key: TargetKey, snapshot: TargetSnapshot) -> None:
        """The authoritative-facts publication entry Layer 4 MUST use for a live target. It holds
        the SAME per-TargetKey lock as admit/reopen/close, so a generation bump can never
        interleave between an admit's snapshot read and its handle registration — admit sees one
        consistent snapshot for the whole critical section, and a publication either fully precedes
        or fully follows it. (`SnapshotStore.put` keeps its own monotonic-generation guard as
        defense in depth; calling it directly is only for single-threaded test seeding before
        admission is active.)"""
        with self._key_lock(target_key):
            self._store.put(target_key, snapshot)

    def admit(self, target_key: TargetKey, request: OpenRequest, *, now: datetime | None = None) -> AdmissionHandle:
        """transport.open admission: requires a `transport_ref`, the target must be READY."""
        with self._key_lock(target_key):
            snapshot, channel = self._validate_open(target_key, request, now or datetime.now(UTC), recovery=False)
            if snapshot.state is not TargetState.READY:
                raise AdmissionError(
                    "stop-capable open requires READY",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="target_not_ready",
                )
            return self._register(target_key, AdmissionOp.TRANSPORT_OPEN, channel, snapshot, recovery=False)

    def admit_recovery(
        self, target_key: TargetKey, request: OpenRequest, *, now: datetime | None = None
    ) -> AdmissionHandle:
        """The one admission entry permitted while a target is `recovery_required` (§4.7): it
        bypasses the recovery_required gate (NOT the lifecycle close gate), requires a
        generation-current tombstone (never a general bypass), and may attach to DEBUGGING."""
        with self._key_lock(target_key):
            snapshot, channel = self._validate_open(target_key, request, now or datetime.now(UTC), recovery=True)
            self._require_recovery_tombstone(target_key, snapshot)
            return self._register(target_key, AdmissionOp.TRANSPORT_OPEN, channel, snapshot, recovery=True)

    def admit_ssh_tier(
        self,
        target_key: TargetKey,
        generation: int,
        platform: PlatformMetadata,
        *,
        lease: LeaseInfo | None = None,
        min_lease_ttl: int | None = None,
        execution_proof: ExecutionProof | None = None,
        now: datetime | None = None,
    ) -> AdmissionHandle:
        """ssh-backed live-tier admission (smoke tests / ssh debug reads), registered in the SAME
        per-TargetKey service as transport.open so it shares the cancel fence, binding table, and
        lifecycle invalidation (contract §5.3). An ssh-only target may have `transports == ()`, so
        this carries **no transport_ref** and binds no channel. **READY** admits with no execution
        proof. **DEBUGGING** admits ONLY when the caller supplies a fresh, generation-current
        `ExecutionProof` reporting `EXECUTING` (§5.6) — the probe is Layer 4; Layer 2 fences it by
        generation and never trusts a cached flag. `HALTED` → `target_halted`; a missing, stale, or
        `UNKNOWN` proof → `execution_state_unknown` (fail-closed, never left to hang)."""
        now = now or datetime.now(UTC)
        with self._key_lock(target_key):
            snapshot = self._bind_snapshot(target_key, generation, recovery=False)
            self._check_platform_drift(snapshot, platform)
            self._check_lease_identity(snapshot, lease)
            self._check_lease_ttl(snapshot, lease, min_lease_ttl, now)
            self._reject_non_live(snapshot.state)
            if snapshot.state is not TargetState.READY:  # the only other live state is DEBUGGING
                self._require_executing_proof(target_key, snapshot, execution_proof)
            return self._register(target_key, AdmissionOp.SSH_TIER, None, snapshot, recovery=False)

    def _validate_open(
        self,
        target_key: TargetKey,
        request: OpenRequest,
        now: datetime,
        *,
        recovery: bool,
    ) -> tuple[TargetSnapshot, TransportRef]:
        """All authoritative checks for a transport_ref-carrying (open/recovery) request."""
        if request.target_key != target_key:
            raise AdmissionError(
                "request.target_key does not match the admission target",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="target_mismatch",
            )
        snapshot = self._bind_snapshot(target_key, request.generation, recovery=recovery)
        channel = self._rebind(request.transport_ref, snapshot)
        self._check_caps(request.required_caps, channel)
        self._check_platform_drift(snapshot, request.platform)
        self._check_lease_identity(snapshot, request.lease)
        self._check_lease_ttl(snapshot, request.lease, request.min_lease_ttl, now)
        self._reject_non_live(snapshot.state)
        return snapshot, channel

    def _require_recovery_tombstone(self, target_key: TargetKey, snapshot: TargetSnapshot) -> None:
        tombstone_generation = self._recovery_required.get(target_key)
        if tombstone_generation is None or tombstone_generation != snapshot.generation:
            raise AdmissionError(
                "recovery-mode attach requires a generation-current recovery_required tombstone",
                category=ErrorCategory.READINESS_FAILURE,
                code="not_recovery_required",
            )

    def _check_platform_drift(self, snapshot: TargetSnapshot, platform: PlatformMetadata) -> None:
        # platform is a cached request fact (contract §3.3): reject if it has drifted from the
        # authoritative snapshot, so a stale/foreign handle fails before any acquisition.
        if platform != snapshot.platform:
            raise AdmissionError(
                "request.platform does not match the authoritative snapshot (stale/foreign facts)",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="stale_platform",
            )

    def _bind_snapshot(self, target_key: TargetKey, generation: int, *, recovery: bool) -> TargetSnapshot:
        # Ordinary lifecycle closure (reset/release/crash teardown) blocks ALL new work —
        # including admit_recovery() — so no live op registers before leases/guards are
        # revoked. This is distinct from the recovery_required tombstone gate below.
        if target_key in self._closed_at:
            raise AdmissionError(
                "admission closed for target",
                category=ErrorCategory.READINESS_FAILURE,
                code="admission_closed",
            )
        snapshot = self._store.get(target_key)
        tombstone_generation = self._recovery_required.get(target_key)
        if not recovery and tombstone_generation is not None:  # noqa: SIM102 — keep the tombstone gate explicit
            # Generation-aware tombstone (§4.7): gate ordinary admit while the tombstone is
            # current OR ahead of the authoritative snapshot. At bare startup (no snapshot / no
            # authoritative generation) FAIL CLOSED. Only a tombstone strictly OLDER than the
            # current snapshot is stale (a reset advanced past the parked generation) and is
            # superseded — admission is allowed (Layer 4 clears it via the reset path). A
            # tombstone AHEAD of the snapshot (snapshot regressed below it, or it was parked at a
            # not-yet-published generation) must fail closed, never admit against the stale facts.
            if snapshot is None or tombstone_generation >= snapshot.generation:
                raise AdmissionError(
                    "target is recovery_required; only transport.open(recovery=true) may attach",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="recovery_required",
                )
        if snapshot is None:
            raise AdmissionError(
                "no authoritative snapshot for target",
                category=ErrorCategory.STALE_HANDLE,
                code="stale_handle",
            )
        if generation != snapshot.generation:
            raise AdmissionError(
                f"stale generation {generation} != {snapshot.generation}",
                category=ErrorCategory.STALE_HANDLE,
                code="stale_handle",
            )
        return snapshot

    def _check_caps(self, required_caps: Iterable[str], channel: TransportRef) -> None:
        if not set(required_caps) <= set(channel.caps):
            raise AdmissionError(
                "selected channel does not satisfy the tier's required_caps",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="insufficient_caps",
            )

    def _register(
        self,
        target_key: TargetKey,
        op: AdmissionOp,
        channel: TransportRef | None,
        snapshot: TargetSnapshot,
        recovery: bool,
    ) -> AdmissionHandle:
        handle = AdmissionHandle(
            handle_id=uuid.uuid4().hex,
            target_key=target_key,
            generation=snapshot.generation,  # bind the admitted generation for async fencing
            op=op,
            channel=channel,
            platform=snapshot.platform,  # authoritative facts bound from the snapshot copy
            recovery=recovery,
        )
        self._bindings[target_key].append(handle)
        return handle

    def _rebind(self, ref: TransportRef, snapshot: TargetSnapshot) -> TransportRef:
        for offered in snapshot.transports:
            if offered.provider == ref.provider and offered.channel_id == ref.channel_id:
                if (
                    offered.target_ref == ref.target_ref
                    and offered.line_role == ref.line_role
                    and offered.caps == ref.caps
                ):
                    return offered  # re-bind to the snapshot's object, never the caller copy
                raise AdmissionError(
                    "transport_ref does not match snapshot",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                    code="foreign_ref",
                )
        raise AdmissionError(
            "no such channel in snapshot",
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="foreign_ref",
        )

    def _check_lease_identity(self, snapshot: TargetSnapshot, lease: LeaseInfo | None) -> None:
        # Scarce-target lease fence (contract §3.1/§5.3): when the authoritative snapshot holds
        # a lease, the request MUST carry the matching lease_id — a prior holder (or a
        # hand-crafted request that omits the lease) cannot replay a handle. An unleased target
        # (e.g. local qemu, snapshot.lease is None) has no lease requirement.
        #
        # Identity is matched on lease_id ONLY, never expires_at: §5.3 step 1 makes the snapshot's
        # lease (lease_id + expires_at) authoritative and the request's lease "a cache ... never
        # the source of truth". expires_at freshness is enforced separately against the SNAPSHOT in
        # _check_lease_ttl. Comparing the request's cached expires_at for equality would wrongly
        # reject a valid current holder whose lease was renewed (snapshot expires_at advanced while
        # the request carries the older cached value) — the opposite of the contract's re-bind rule.
        if snapshot.lease is None:
            return
        if lease is None or lease.lease_id != snapshot.lease.lease_id:
            raise AdmissionError(
                "request lease is missing or does not match the authoritative snapshot lease",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="stale_lease",
            )

    def _check_lease_ttl(
        self,
        snapshot: TargetSnapshot,
        lease: LeaseInfo | None,
        min_lease_ttl: int | None,
        now: datetime,
    ) -> None:
        if snapshot.lease is None or snapshot.lease.expires_at is None:
            return  # no lease constraint (e.g. local qemu)
        min_ttl = min_lease_ttl if min_lease_ttl is not None else self._default_min_lease_ttl
        if snapshot.lease.expires_at <= now + timedelta(seconds=min_ttl):
            raise AdmissionError(
                "snapshot lease too close to expiry for min_lease_ttl",
                category=ErrorCategory.READINESS_FAILURE,
                code="lease_near_expiry",
            )

    def _reject_non_live(self, state: TargetState) -> None:
        if state in _NON_LIVE_STATES:
            raise AdmissionError(
                f"target not in a live state: {state}",
                category=ErrorCategory.READINESS_FAILURE,
                code="target_not_ready",
            )

    def _require_executing_proof(
        self,
        target_key: TargetKey,
        snapshot: TargetSnapshot,
        proof: ExecutionProof | None,
    ) -> None:
        # §4.6/§5.6: ssh-tier against a DEBUGGING target is admitted ONLY on a fresh, generation-
        # AND epoch-current EXECUTING proof from the Layer-4 probe. No proof (incl. probe_timeout)
        # or an UNKNOWN proof fails closed; a proof from a prior incarnation (generation) or from
        # before an execution-state transition (epoch) is stale and refused — re-probe rather than
        # admit against a possibly-HALTED kernel; a current HALTED proof is rejected immediately.
        if proof is None or proof.state is ExecutionState.UNKNOWN:
            raise AdmissionError(
                "ssh-tier op against a DEBUGGING target requires a fresh EXECUTING probe (Layer 4)",
                category=ErrorCategory.READINESS_FAILURE,
                code="execution_state_unknown",
            )
        if proof.generation != snapshot.generation:
            raise AdmissionError(
                f"stale execution proof: probed at generation {proof.generation} != {snapshot.generation}",
                category=ErrorCategory.STALE_HANDLE,
                code="stale_handle",
            )
        if proof.epoch != self._exec_epoch.get(target_key, 0):
            raise AdmissionError(
                "stale execution proof: an execution-state transition occurred since the probe; re-probe",
                category=ErrorCategory.READINESS_FAILURE,
                code="execution_state_unknown",
            )
        if proof.state is ExecutionState.HALTED:
            raise AdmissionError(
                "target halted in debugger; resume or detach first",
                category=ErrorCategory.READINESS_FAILURE,
                code="target_halted",
            )
        # proof.state is EXECUTING, generation-current, epoch-current -> admit.

    def cancel_ssh_tier(self, target_key: TargetKey, generation: int, halt_epoch: int) -> list[AdmissionHandle]:
        """§5.6 async-halt cancellation: when the kernel halts under the stop-capable controller,
        in-flight ssh-tier ops would hang on a dead network stack. Cancel the fence on every live
        SSH_TIER binding **of the given generation** (their owners then roll back) WITHOUT closing
        admission — the target is still DEBUGGING, not torn down, so once it resumes a fresh
        EXECUTING proof can admit ssh work again. transport.open (stop-capable) bindings are
        untouched. Returns the cancelled handles. **Does not bump the epoch** — recording the
        EXECUTING→HALTED transition is `note_execution_transition`'s job (the single epoch bumper);
        this primitive only acts on the binding table.

        Two fences:
        - **Generation:** a late HALTED from a PRIOR incarnation carries that incarnation's
          generation and is a complete no-op when it does not match the authoritative snapshot
          (it cannot touch work admitted after a reset/reopen).
        - **Halt epoch:** `halt_epoch` is the execution epoch the caller recorded the halt at (the
          value `note_execution_transition` returned for THIS `EXECUTING→HALTED`). The cancel is a
          no-op unless it still equals the current epoch — so a **delayed** cancel worker whose
          halt was already followed by a resume (which bumped the epoch) does NOT cancel ssh work
          legitimately admitted against that newer EXECUTING epoch (§5.6 rule 2: ssh-tier is
          permitted while EXECUTING). The cancel applies only to the specific halt it was raised for.

        **Caller precondition (Layer 4, [ADR 0002]):** the caller MUST be the current stop-capable
        controller acting under its **live `StopCapableGuard` token**. Because a debug session
        attaches/detaches WITHIN a generation (§3.1/§5.1), the generation fence cannot reject a
        stale SAME-controller-slot session (e.g. a detached session A's late `HALTED` worker); the
        guard token is the contract's single authority for that (§5.6 rule 1, "a stale token is a
        no-op", guard "never outlives the session"). Layer 2 does not model a parallel stop-session
        authority (ADR 0002); the halt-epoch fence above additionally bounds a *current* controller's
        own delayed cancel to the halt it was raised for."""
        with self._key_lock(target_key):
            snapshot = self._store.get(target_key)
            if snapshot is None or generation != snapshot.generation:
                return []  # stale/unknown generation: prior-incarnation event
            if halt_epoch != self._exec_epoch.get(target_key, 0):
                return []  # a later transition (resume/another halt) advanced the epoch: stale cancel
            cancelled = [
                h
                for h in self._bindings.get(target_key, ())
                if h.op is AdmissionOp.SSH_TIER and h.generation == generation
            ]
            for handle in cancelled:
                handle._cancel.set()  # monotonic private fence; only the service signals it
            return cancelled

    def promote(self, handle: AdmissionHandle) -> AdmissionHandle:
        """Promote a PENDING binding to a live session/op binding. Rejects a non-registered,
        non-PENDING (double-promote), or cancelled handle so a rolled-back/completed handle
        can never escape lifecycle cancellation."""
        with self._key_lock(handle.target_key):
            if handle not in self._bindings.get(handle.target_key, ()) or handle.state is not AdmissionState.PENDING:
                raise AdmissionError(
                    "handle is not a registered PENDING binding",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="handle_not_pending",
                )
            if handle.cancelled:
                raise AdmissionError(
                    "admission cancelled before promotion",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="admission_cancelled",
                )
            handle._state = AdmissionState.PROMOTED
            return handle

    def complete(self, handle: AdmissionHandle) -> None:
        """Normal **success** terminal disposal: a finished ssh-tier op or a cleanly-closed
        (already PROMOTED) session. A **cancelled handle may NOT be completed** — close_admission
        / cancel_ssh_tier set the cancel fence to tear the binding down, and completing it would
        deregister the binding (mirroring abandon/rollback) before the reaper has proven its
        backend/lease/guard were reclaimed, letting reopen() admit a new incarnation alongside
        still-live resources (§4.5/§5.4) or report success for an op invalid against a
        halted/torn-down kernel (§5.6). A cancelled handle must rollback, or abandon after
        confirm_reaped. This mirrors the cancel guard promote() already enforces. A **PENDING
        transport.open may NOT be completed** either — it must promote on success or rollback on
        failure; completing it straight from PENDING would deregister an in-flight open without
        rolling back its partial guard/lease/backend resources."""
        with self._key_lock(handle.target_key):
            if handle.cancelled:
                raise AdmissionError(
                    "a cancelled handle must roll back (or abandon after confirm_reaped), not complete",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="admission_cancelled",
                )
            if handle.state is AdmissionState.PENDING and handle.op is AdmissionOp.TRANSPORT_OPEN:
                raise AdmissionError(
                    "a pending transport.open must promote or roll back, not complete",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="invalid_terminal_transition",
                )
            self._dispose_locked(handle, AdmissionState.COMPLETED)

    def rollback(self, handle: AdmissionHandle) -> None:
        """Failure/cancel terminal disposal (open transaction rollback). A **PENDING** binding
        committed no resources (promote is the commit point, §5.3), so it disposes freely. But a
        **PROMOTED** binding on a **closed** target holds live backend/lease/guard that the §5.4
        teardown must reclaim, and deregistering it is what unblocks `reopen()`; so — exactly like
        `abandon()` — it requires the reaper's `confirm_reaped` proof first. Otherwise an owner that
        observed cancellation and rolled back before teardown completed would let `reopen()` admit
        generation N+1 alongside the still-live prior-generation resources (§5.3/§5.4 lifecycle
        fence). A promoted binding on a target that is NOT closed (an open that failed on its own,
        no reset in flight) rolls back freely — the owner releases what it just acquired and no
        reopen race exists."""
        with self._key_lock(handle.target_key):
            if handle.state is AdmissionState.PROMOTED and handle.target_key in self._closed_at and not handle.reaped:
                raise AdmissionError(
                    "a promoted session on a closed target must be reaped (confirm_reaped) before "
                    "rollback can deregister it; reopen stays blocked until teardown is proven",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="reaper_confirmation_required",
                )
            self._dispose_locked(handle, AdmissionState.ROLLED_BACK)

    def confirm_reaped(self, handle: AdmissionHandle) -> None:
        """The Layer-4 reaper calls this once it has reclaimed **every** external resource the
        binding held (force-killed the backend child, released the lease and guard) for a
        cancelled handle on a closed target. Private and monotonic, like the cancel fence: it is
        the proof-of-teardown that abandon() requires, so a still-live promoted session can never
        be deregistered (unblocking reopen) before its resources are gone."""
        with self._key_lock(handle.target_key):
            if handle.target_key not in self._closed_at or not handle.cancelled:
                raise AdmissionError(
                    "confirm_reaped requires a closed target and a cancelled handle",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="reap_not_permitted",
                )
            if handle not in self._bindings.get(handle.target_key, ()):
                raise AdmissionError(
                    "handle already disposed or not registered",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="handle_already_disposed",
                )
            handle._reaped.set()

    def abandon(self, handle: AdmissionHandle) -> None:
        """Explicit, audited terminal disposal of an **overdue, cancelled** handle whose owner
        could not roll it back (e.g. a wedged open worker), only on a **closed** target whose
        resources the Layer-4 reaper has already reclaimed (`confirm_reaped`) — never a way to
        drop a live promoted session out from under lifecycle cancellation, and never before
        teardown is proven. Deregisters it so reopen() can proceed. Late effects are token/gen
        fenced."""
        with self._key_lock(handle.target_key):
            if handle.target_key not in self._closed_at or not handle.cancelled:
                raise AdmissionError(
                    "abandon requires a closed target and a cancelled handle",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="abandon_not_permitted",
                )
            if not handle.reaped:
                raise AdmissionError(
                    "abandon requires the reaper to confirm the binding's resources were reclaimed",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="reaper_confirmation_required",
                )
            self._dispose_locked(handle, AdmissionState.ABANDONED)

    def _dispose_locked(self, handle: AdmissionHandle, terminal: AdmissionState) -> None:
        # caller holds the key lock
        bindings = self._bindings.get(handle.target_key)
        if (
            bindings is None
            or handle not in bindings
            or handle.state not in (AdmissionState.PENDING, AdmissionState.PROMOTED)
        ):
            raise AdmissionError(
                "handle already disposed or not registered",
                category=ErrorCategory.READINESS_FAILURE,
                code="handle_already_disposed",
            )
        handle._state = terminal
        bindings.remove(handle)

    def close_admission(self, target_key: TargetKey) -> list[AdmissionHandle]:
        """§4.5 step 1: reject new admit() for the key and set the cancel fence on every live
        binding. Records the generation being torn down so admission cannot be reopened until a
        strictly-newer incarnation appears. **Idempotent**: a duplicate close while already
        closed preserves the FIRST closed-at generation (a later close at N+1 must not push the
        reopen bar to N+2 and strand a recovered target). Returns the cancelled handles."""
        with self._key_lock(target_key):
            if target_key not in self._closed_at:
                snapshot = self._store.get(target_key)
                self._closed_at[target_key] = snapshot.generation if snapshot is not None else -1
            handles = list(self._bindings.get(target_key, ()))
            for handle in handles:
                handle._cancel.set()  # monotonic private fence; only the service signals it
            return handles

    def reopen(self, target_key: TargetKey) -> None:
        """Reopen admission for the key only after the §4.5 generation bump (step 5) has been
        published to the SnapshotStore. The decision is read from the **authoritative
        snapshot under the lock**, not a caller-supplied number: it rejects unless a snapshot
        exists AND its generation is strictly greater than the generation closed at. So an
        early reopen before the new snapshot is published — or a racing reopen during
        reset/release — leaves admission closed and a stale-generation OpenRequest still
        rejected (the replay the gate prevents)."""
        with self._key_lock(target_key):
            closed_generation = self._closed_at.get(target_key)
            if closed_generation is None:
                return  # not closed
            snapshot = self._store.get(target_key)
            if snapshot is None or snapshot.generation <= closed_generation:
                raise AdmissionError(
                    "admission stays closed: authoritative snapshot has not advanced past the closed generation",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="generation_not_advanced",
                )
            # A terminal handle is removed from _bindings by _dispose, so a non-empty list means
            # pending/promoted work from the prior generation is still unwinding. Refuse to
            # reopen until every old handle is rolled back / completed / abandoned, so new work
            # is never admitted alongside stale work that could still return or mutate.
            if self._bindings.get(target_key):
                raise AdmissionError(
                    "cannot reopen: prior-generation bindings still outstanding; roll back or abandon them first",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="bindings_outstanding",
                )
            del self._closed_at[target_key]

    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None:
        """Layer-4 reconciliation marks a parked-kernel TargetKey at the generation it was
        parked at (§4.7). Generation-fenced: it never **regresses** a current tombstone with an
        older generation (a stale mark for N can't overwrite a newer N+1 mark). While marked,
        ordinary admit() is rejected `recovery_required` (fail-closed at bare startup) until the
        snapshot advances past it or it is cleared; only admit_recovery() may attach meanwhile."""
        with self._key_lock(target_key):
            existing = self._recovery_required.get(target_key)
            if existing is not None and generation < existing:
                return
            self._recovery_required[target_key] = generation

    def clear_recovery_required(self, target_key: TargetKey, expected_generation: int) -> None:
        """Cleared by Layer-4's three clearance paths (probe→EXECUTING, reset advancing
        generation, or a completed recovery-mode attach). Generation-fenced: a stale clear for
        generation N is a no-op if a newer N+1 tombstone now stands, so a stale actor cannot
        free a still-parked newer incarnation."""
        with self._key_lock(target_key):
            if self._recovery_required.get(target_key) == expected_generation:
                del self._recovery_required[target_key]

    def invalidate_lifecycle(self, event: LifecycleEvent, dispatcher: LifecycleDispatcher) -> InvalidationResult:
        """§4.5 steps 1→2 in the **mandatory** order, enforced in one place so teardown can never
        run while admission is still open. Step 1: `close_admission(event.target_key)` — set the
        cancel fence on every live binding and reject new admit() for the key. This is a confirmed,
        synchronous, non-blocking primitive (lock-guarded flag flips only, no IO, no callbacks), so
        it always completes here before step 2 begins — there is no best-effort hook that could
        leave admission open. Step 2: `dispatcher.emit(event)` — the bounded teardown. Because the
        fence is provably set before any subscriber runs, no concurrent admit() can enter the
        owner-free window and seize a freed lease against the not-yet-bumped generation. The
        Layer-4 lifecycle transaction wraps this with §4.5 steps 3–5 (revoke lease/guard via the
        subscribers, bump generation)."""
        self.close_admission(event.target_key)  # step 1: mandatory, confirmed, before any teardown
        return dispatcher.emit(event)  # step 2: teardown only — admission already closed
