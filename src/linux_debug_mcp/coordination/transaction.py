from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import cast

from linux_debug_mcp.coordination.admission import AdmissionHandle, AdmissionService
from linux_debug_mcp.coordination.endpoint_safety import assert_loopback_endpoint, refuse_unsafe_exposure
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager, LeaseOwner
from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.coordination.selection import select_stop_capable_channel
from linux_debug_mcp.seams.break_policy import BreakPolicy
from linux_debug_mcp.seams.guard import GuardToken, StopCapableGuard
from linux_debug_mcp.seams.lifecycle import LifecycleDispatcher, LifecycleEvent
from linux_debug_mcp.seams.secrets import SecretsResolver
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import (
    ExecutionState,
    OpenRequest,
    RecordState,
    Transport,
    TransportSession,
    new_session_id,
)

_ATTACH_DEADLINE_SECONDS = 30.0


@dataclass(frozen=True)
class _OpenState:
    """The resources an in-flight open() has acquired so far, in acquisition order. open() rebuilds
    it with `replace()` as each step succeeds and hands it to `_rollback`, which unwinds in reverse.
    Frozen so a rollback can never accidentally mutate it mid-unwind."""

    guard_token: GuardToken | None = None
    lease_token: str | None = None
    session_id: str | None = None
    backend_pid: int | None = None
    backend_start: str | None = None
    # The promoted admission binding for the committed session. Carried on the frozen state so the
    # lifecycle subscriber's force_drop() can deregister it (confirm_reaped → abandon) out-of-band,
    # the same way close() deregisters it (complete) on the in-owner path.
    admission_handle: AdmissionHandle | None = None


class _SessionSubscriber:
    """The §4.5 lifecycle subscriber for one open session — a long-lived object held by the
    dispatcher (not an ephemeral callback), so it is a named module-level class. On invalidation it
    releases the guard/lease/backend/record the session holds, keyed off the frozen `_OpenState`, so
    a RESETTING/CRASHED/RELEASING transition completes even when no owner is around to close().

    Split along the lifecycle contract (`seams/lifecycle.py`):

    - `invalidate` performs the **bounded, possibly-blocking** teardown — namely
      `proxy.stop_by_identity` (SIGTERM → wait → SIGKILL ≤ TERM_GRACE + KILL_GRACE seconds). It is
      run on a supervised worker the dispatcher joins under the deadline, so a slow signal sequence
      doesn't block the dispatcher itself.
    - `force_drop` is invoked **only when invalidate exceeds the deadline** and **MUST be
      non-blocking**: in-memory token/lease/guard pops, `confirm_reaped → abandon` on the admission
      handle, and the durable record delete. No SIGTERM/wait. If `invalidate` already ran cleanly,
      `force_drop` is a no-op (everything it would pop is already gone). If `invalidate` wedged on
      the signal sequence, `force_drop` still drops the in-memory line; the orphan backend becomes
      `SessionRegistry.reconcile()`'s job on the next process start (per §4.5 / lifecycle.py:36-44).
    """

    def __init__(self, transaction: TransportTransaction, session: TransportSession, state: _OpenState) -> None:
        self._transaction = transaction
        self._session = session
        self._state = state
        # Gates the durable `delete_record` so an out-of-band force_drop CANNOT erase the
        # ownership record while the backend kill is still pending. Set by `invalidate` after
        # `proxy.stop_by_identity` resolves (cleanly or via suppressed exception); pre-set when
        # there is no backend to reap. While unset, `force_drop` drops the in-memory line but
        # leaves `owner-*.json` on disk so `SessionRegistry.reconcile()` reaps the orphan on the
        # next process start (the §4.5 backstop the dispatcher's bounded `teardown_deadline`
        # delegates to when invalidate wedges).
        self._killed = threading.Event()
        if state.backend_pid is None:
            self._killed.set()

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        # Bounded-blocking teardown: reap the backend by identity (SIGTERM/wait/SIGKILL) on the
        # supervised worker, then drop the in-memory and durable lines just like force_drop would.
        # `force_drop` is idempotent, so calling it here after the reap completes the teardown
        # without duplicating the unwind logic.
        transport = self._transaction._transports[self._session.provider]
        if self._state.backend_pid is not None:
            proxy = getattr(transport, "_proxy", None)
            if proxy is not None:
                # TODO: a Transport.reap_backend() hook would avoid the private-attribute reach
                # (out of scope here).
                with contextlib.suppress(Exception):
                    proxy.stop_by_identity(self._state.backend_pid, self._state.backend_start)
        # Confirm "the kill resolved" (returned cleanly, raised+suppressed, or was skipped because
        # no proxy is wired). Only set here — never in force_drop — so a force_drop dispatched
        # while this worker is still wedged on stop_by_identity will NOT see `_killed` and will
        # leave the durable record in place for reconcile(). If invalidate eventually unwedges,
        # its `self.force_drop(event)` tail below sees `_killed` and deletes the record.
        self._killed.set()
        self.force_drop(event)

    def force_drop(self, event: LifecycleEvent) -> None:
        # NON-BLOCKING out-of-band release: pop the in-memory token/lease/guard, deregister the
        # admission handle (confirm_reaped → abandon), and conditionally delete the durable
        # record. NO proxy.stop_by_identity — the blocking signal sequence belongs to `invalidate`
        # (which the dispatcher supervises with a deadline). Idempotent: a clean invalidate
        # already popped everything, so each step is a no-op the second time around.
        if self._state.lease_token is not None:
            self._transaction._leases.release(self._session.target_key, self._state.lease_token)
        if self._state.guard_token is not None:
            self._transaction._guard.release(self._session.target_key, self._state.guard_token)  # FENCED (ADR 0002)
        self._transaction._tokens.pop(self._session.session_id, None)
        # Deregister the cancelled promoted binding so reopen() is not blocked by `bindings_outstanding`.
        # invalidate_lifecycle ran close_admission (which set the cancel fence and recorded the target
        # as closed) before emit, so confirm_reaped → abandon is the §5.4 contract.
        if self._state.admission_handle is not None:
            with contextlib.suppress(Exception):
                self._transaction._admission.confirm_reaped(self._state.admission_handle)
                self._transaction._admission.abandon(self._state.admission_handle)
        self._transaction._handles.pop(self._session.session_id, None)
        # Only delete the durable ownership record once the backend kill has resolved. While the
        # dispatcher's bounded force_drop fires from a wedged invalidate (`_killed` still unset),
        # the record persists on disk so `SessionRegistry.reconcile()` on the next process start
        # finds the orphan PID and reaps it via `stop_by_identity(record.backend_pid, …)`. If the
        # wedge later resolves, invalidate sets `_killed` and re-calls force_drop, which then
        # deletes the record. delete_record is idempotent (unlink + missing_ok=True), so a
        # double-delete on the unwedge path is harmless. The `expected_session_id` fence prevents
        # a stale subscriber from erasing a fresh session's record that has overwritten the old
        # one at the same target_key path (e.g. a wedge-tail unblock running after a new session
        # has admitted — the wedged worker's force_drop tail would otherwise unconditionally
        # delete by target_key).
        if self._killed.is_set():
            self._transaction._registry.delete_record(
                self._session.target_key, expected_session_id=self._session.session_id
            )
        # Drop the dispatcher binding now that we've torn down everything this subscriber owned.
        # Stale subscribers left in the map would receive every future invalidate_lifecycle for
        # this target_key — and each of their force_drops would attempt a delete_record (now
        # session-id fenced). The fence makes the unsubscribe belt-and-suspenders, but removing
        # the entry also keeps `_subscribers` from accreting indefinitely as sessions cycle.
        if self._transaction._dispatcher is not None:
            self._transaction._dispatcher.unsubscribe(self._session.target_key, self._session.session_id)


class TransportTransaction:
    """The §4.3 open()/close() write-ahead transaction (ADR 0003/0005). Owns TransportSession
    end-to-end; rolls back in reverse at every step, leaking no guard/lease/record/backend."""

    def __init__(
        self,
        *,
        admission: AdmissionService,
        registry: SessionRegistry,
        guard: StopCapableGuard,
        leases: ConsoleLeaseManager,
        secrets: SecretsResolver,
        break_policy: BreakPolicy,
        transports: dict[str, Transport],
    ) -> None:
        self._admission = admission
        self._registry = registry
        self._guard = guard
        self._leases = leases
        self._secrets = secrets
        self._break_policy = break_policy
        self._transports = transports
        # Finding #4: the fenced GuardToken is held in-process (the frozen stop_guard_token: str
        # cannot carry the fence — ADR 0003); close()/lifecycle release by this token, not revoke().
        self._tokens: dict[str, GuardToken] = {}
        # The promoted AdmissionHandle for each live session, keyed by session_id. close() deregisters
        # it (complete); force_drop deregisters it (confirm_reaped → abandon). Without this the
        # promoted binding lingers and blocks the next reopen()/admit (`bindings_outstanding`).
        self._handles: dict[str, AdmissionHandle] = {}
        self._dispatcher: LifecycleDispatcher | None = None

    def bind_lifecycle(self, dispatcher: LifecycleDispatcher) -> None:
        """Bind the §4.5 lifecycle dispatcher every subsequently-opened session subscribes to, so a
        RESETTING/CRASHED/RELEASING invalidation tears the session down out-of-band (force_drop:
        FENCED guard/lease release + backend reap + record delete), independently of any in-flight
        owner. Optional — an unbound transaction simply skips subscription."""
        self._dispatcher = dispatcher

    def _subscribe_session(self, session: TransportSession, state: _OpenState) -> None:
        """Register the just-opened session with the bound lifecycle dispatcher. The subscriber's
        force_drop() is the §4.5 out-of-band release path: it releases the guard/lease/backend/record
        this session holds — admission is closed separately by the lifecycle transition."""
        if self._dispatcher is None:
            return
        self._dispatcher.subscribe(session.target_key, session.session_id, _SessionSubscriber(self, session, state))

    def open(
        self,
        request: OpenRequest,
        *,
        recovery: bool = False,
        crash_after: frozenset[str] = frozenset(),
    ) -> TransportSession:
        """Run the §4.3 write-ahead open transaction and return a READY ownership record.

        Admits the request, selects a break-capable channel, acquires the stop-capable guard and
        (if the provider owns a console) the console lease, resolves secrets, writes the durable
        OPENING record, attaches the backend, and commits a READY record under admission promote.

        Args:
            request: The settled-contract open request (target_key, generation, transport_ref,
                required_caps, platform, optional lease).
            recovery: When True, admit through the recovery gate (`admit_recovery`) and clear the
                recovery tombstone on commit — the one path permitted while a target is
                recovery_required.
            crash_after: Crash-point labels for the write-ahead test seam; raising at a labeled
                durable stage exercises rollback/reconciliation. Empty in production.

        Returns:
            The committed READY `TransportSession` (record_state == READY).

        Raises:
            Any error from admission, selection, the guard/lease, secret resolution, or attach. On
            ANY failure the transaction rolls back fully in reverse order — guard, lease, durable
            record, and backend are all released/deleted — leaking nothing, and the error
            propagates unchanged.
        """
        transport = self._transports[request.transport_ref.provider]
        capability = transport.capability
        # (1) pre-attach endpoint-safety refusal — trusted metadata, before any acquisition.
        refuse_unsafe_exposure(capability, op="transport.open")
        # (2) admission.
        admit = self._admission.admit_recovery if recovery else self._admission.admit
        handle = admit(request.target_key, request)
        state = _OpenState()
        try:
            # The open path always admits with an authoritative channel; admission rejects open
            # requests without one. Bind a narrowed local for the rest of the transaction.
            channel = handle.channel
            if channel is None:
                raise RuntimeError("open transaction requires an authoritative channel on the handle")
            # (3) break-plan selection (authoritative channel from the handle).
            selection = select_stop_capable_channel(
                target_key=request.target_key,
                transports=(channel,),
                required_caps=request.required_caps,
                platform=handle.platform,
                break_policy=self._break_policy,
            )
            _crash(crash_after, "selected")
            # (4) stop-capable guard (target-wide single holder).
            guard_token = self._guard.acquire(request.target_key)
            state = replace(state, guard_token=guard_token)
            _crash(crash_after, "guard")
            # (5) console lease (only providers that own a console).
            if capability.provides_console:
                state = replace(state, lease_token=self._leases.acquire(request.target_key, LeaseOwner.TRANSPORT))
            _crash(crash_after, "lease")
            # (6) secrets (never persisted/logged).
            resolved_secrets = self._secrets.resolve(list(channel.secret_refs))
            # (7) write-ahead OPENING record. The fenced token is held in-process keyed by
            # session_id (stop_guard_token persists only its secret as an audit marker — ADR 0003).
            session_id = new_session_id()
            self._tokens[session_id] = guard_token
            state = replace(state, session_id=session_id)
            record = TransportSession(
                session_id=session_id,
                target_key=request.target_key,
                generation=request.generation,
                provider=capability.provider_name,
                channel_id=channel.channel_id,
                record_state=RecordState.OPENING,
                console_lease_token=state.lease_token,
                stop_guard_token=guard_token.secret,
                attach_epoch=handle.admit_epoch,
                break_plan=selection.break_plan,
                execution_state=ExecutionState.EXECUTING,
                created_at=datetime.now(UTC),
            )
            self._registry.write_record(record)
            _crash(crash_after, "record_written")

            # (8) attach. The on_partial closure WRITES THROUGH backend_pid/start-time into the
            # durable OPENING record the instant "backend_process" is reported — before attach()
            # returns — so a death before READY is reapable (Finding #1). It also records the pid on
            # the unwind state so a crash before READY can reap the backend.
            backend_pid: int | None = None
            backend_start: str | None = None

            def on_partial(label: str, resource: object) -> None:
                nonlocal backend_pid, backend_start, state
                if label == "backend_process" and isinstance(resource, dict):
                    backend_process = cast(dict[str, object], resource)
                    pid_val = backend_process["pid"]
                    start_val = backend_process.get("start_time")
                    if not isinstance(pid_val, int) or (start_val is not None and not isinstance(start_val, str)):
                        return
                    backend_pid, backend_start = pid_val, start_val
                    state = replace(state, backend_pid=backend_pid, backend_start=backend_start)
                    self._registry.write_record(
                        record.model_copy(update=dict(backend_pid=backend_pid, backend_start_time=backend_start))
                    )

            attachment = transport.attach(
                request,
                # caller-driven attach cancellation is wired in A9; here the deadline is the only bound.
                cancel=threading.Event(),
                deadline=time.monotonic() + _ATTACH_DEADLINE_SECONDS,
                on_partial=on_partial,
                secrets=resolved_secrets,
            )
            if attachment.backend_pid is not None:
                # transports that report the pid on the returned attachment rather than via the
                # on_partial("backend_process") partial (redundant-but-harmless when both fire).
                backend_pid, backend_start = attachment.backend_pid, attachment.backend_start_time
                state = replace(state, backend_pid=backend_pid, backend_start=backend_start)
            # (9) assemble + loopback assert + READY record.
            for endpoint in (attachment.console_endpoint, attachment.rsp_endpoint):
                if endpoint is not None:
                    assert_loopback_endpoint(endpoint)
            session = record.model_copy(
                update=dict(
                    record_state=RecordState.READY,
                    console_endpoint=attachment.console_endpoint,
                    rsp_endpoint=attachment.rsp_endpoint,
                    backend_pid=backend_pid,
                    backend_start_time=backend_start,
                    artifacts=[attachment.console_artifact] if attachment.console_artifact else [],
                )
            )
            self._registry.write_record(session)
            _crash(crash_after, "ready")
            # (10) commit. A recovery attach clears the recovery gate through the DUAL-WRITE
            # helper (Finding #5) — durable tombstone + admission cache together, never one alone.
            #
            # Finding F3: hold the admission key lock across promote → register → subscribe so a
            # concurrent `invalidate_lifecycle` cannot cancel the freshly-promoted handle in the
            # gap between `promote()` (which only succeeds under the lock) and
            # `_subscribe_session()` (which registers the dispatcher subscriber that drives
            # force_drop). Without the extended critical section, a cancel between promote and
            # subscribe leaves the binding promoted-but-cancelled, with no subscriber to tear it
            # down — close() would later swallow the resulting `admission_cancelled` and the
            # backend/lease/guard would leak. The key lock is re-entrant (RLock), so `promote()`'s
            # own internal lock acquisition is a no-op.
            with self._admission.key_lock(request.target_key):
                self._admission.promote(handle)
                self._handles[session_id] = handle
                state = replace(state, admission_handle=handle)
                self._subscribe_session(session, state)
            if recovery:
                # Recovery-gate clearance runs OUTSIDE the admission key lock (Finding F4: a slow
                # filesystem must not stall the admission table) and **durable-first**: the
                # in-memory cache is cleared only AFTER the durable tombstone unlink succeeds.
                # Consequences:
                #   * A raise from `_clear_recovery_durable` (EIO on `_fsync_dir`, EACCES,
                #     ENOSPC, …) leaves the cache STILL MARKED and the tombstone STILL PRESENT —
                #     the gate is fail-closed end-to-end with no try/except-restore handshake.
                #   * Concurrent non-recovery `admit()` during the durable I/O sees the cache
                #     still set and is correctly rejected `recovery_required` (the prior
                #     ordering — clear cache inside the lock, then run durable I/O outside —
                #     opened a millisecond-to-seconds window scaling with filesystem latency
                #     where a non-recovery admit could slip past the gate while the durable I/O
                #     was still in flight).
                #   * If the process dies between the durable unlink and the cache clear,
                #     `reconcile()` on the next start finds no tombstone (it's already gone) so
                #     the cache stays clear — same outcome, just reached via cold restart.
                self._clear_recovery_durable(request.target_key, request.generation)
                self._clear_recovery_cache(request.target_key, request.generation)
            return session
        except BaseException:
            self._rollback(request.target_key, state, transport, handle)
            raise

    def _rollback(
        self,
        target_key: TargetKey,
        state: _OpenState,
        transport: Transport,
        handle: AdmissionHandle,
    ) -> None:
        # reverse order; each guarded so a partial rollback still completes.
        if state.backend_pid is not None:
            proxy = getattr(transport, "_proxy", None)
            if proxy is not None:
                # best-effort reap reaching the concrete transport's proxy; a reap failure must
                # never mask the original error.
                # TODO: a Transport.reap_backend() hook would avoid the private-attribute reach
                # (out of scope here — would touch the Transport ABC + Layer-3 impls).
                with contextlib.suppress(Exception):
                    proxy.stop_by_identity(state.backend_pid, state.backend_start)
        if state.session_id is not None:
            self._tokens.pop(state.session_id, None)
            self._handles.pop(state.session_id, None)  # keep _handles symmetric with _tokens
            # Session-id fenced: rollback only erases the record this in-flight open() wrote
            # (the OPENING/READY record carries `session_id == state.session_id` by construction).
            self._registry.delete_record(target_key, expected_session_id=state.session_id)
        if state.lease_token is not None:
            self._leases.release(target_key, state.lease_token)
        if state.guard_token is not None:
            self._guard.release(target_key, state.guard_token)  # FENCED by-token release (ADR 0002)
        # rollback is best-effort; an admission-rollback failure must never mask the original error.
        with contextlib.suppress(Exception):
            self._admission.rollback(handle)

    def close(self, session_id: str, *, force: bool = False) -> None:
        """Tear down an open session: write CLOSING, close the backend, release the lease and the
        stop-capable guard, then delete the durable record.

        Args:
            session_id: The session to close. Unknown ids are a no-op.
            force: When False (the default), a session closed while HALTED/UNKNOWN leaves a
                recovery tombstone (dual-write to admission) so the parked kernel stays gated. When
                True, that close-while-halted tombstone is skipped and the record is deleted
                cleanly — the caller asserts the target needs no recovery gating.
        """
        # load the durable record by scanning (close is keyed by session_id; the record is by
        # TargetKey, so resolve via list_records — small set).
        record = next((r for r in self._registry.list_records() if r.session_id == session_id), None)
        if record is None:
            return
        transport = self._transports[record.provider]
        closing = record.model_copy(update=dict(record_state=RecordState.CLOSING))
        self._registry.write_record(closing)
        transport.close(closing)
        if record.console_lease_token is not None:
            self._leases.release(record.target_key, record.console_lease_token)
        # FENCED by-token release (Finding #4): the in-memory GuardToken, never revoke().
        token = self._tokens.pop(session_id, None)
        if token is not None:
            self._guard.release(record.target_key, token)
        # Deregister the promoted admission binding for this cleanly-closed session. complete() is the
        # success-terminal disposal for an already-PROMOTED session (its guard for a cancelled/closed
        # handle does not apply to a clean close); without it the binding lingers PROMOTED and blocks
        # a later reopen() with `bindings_outstanding`. Guarded so a disposal hiccup can't mask the
        # teardown — a lifecycle invalidation's force_drop deregisters via confirm_reaped → abandon.
        handle = self._handles.pop(session_id, None)
        if handle is not None:
            with contextlib.suppress(Exception):
                self._admission.complete(handle)
        # close-while-halted marks recovery via the DUAL-WRITE helper (Finding #5): durable
        # tombstone + admission cache together, never one alone. Otherwise delete cleanly.
        if record.execution_state in (ExecutionState.HALTED, ExecutionState.UNKNOWN) and not force:
            self._mark_recovery(record.target_key, record.generation, reason="closed_while_halted")
        # Session-id fenced delete: protects against the close() running for a recycled session_id
        # racing a new session that may have just claimed the same target_key.
        self._registry.delete_record(record.target_key, expected_session_id=record.session_id)
        # Drop the lifecycle binding for this cleanly-closed session. Without this, the dispatcher
        # would keep delivering future invalidate_lifecycle events to the stale subscriber, and
        # every one of those force_drops would re-attempt a record delete (now session-id fenced,
        # so a no-op, but unnecessary work). Idempotent — unsubscribing an already-removed name
        # is a no-op.
        if self._dispatcher is not None:
            self._dispatcher.unsubscribe(record.target_key, session_id)

    def _mark_recovery(self, target_key: TargetKey, generation: int, *, reason: str) -> None:
        """Single source of truth is the durable tombstone; admission's `_recovery_required` is a
        write-through cache (Finding #5 / ADR 0005). Always write BOTH atomically."""
        self._registry.write_tombstone(RecoveryTombstone(target_key=target_key, generation=generation, reason=reason))
        self._admission.mark_recovery_required(target_key, generation)

    def _clear_recovery_cache(self, target_key: TargetKey, generation: int) -> None:
        """In-memory half of the dual-write clearance: drops the admission cache flag. Safe to
        call under the admission key lock — no file I/O. Always paired with
        `_clear_recovery_durable`; a crash between them is recovered by `reconcile()` re-asserting
        the persisted tombstone into the cache on next start."""
        self._admission.clear_recovery_required(target_key, generation)

    def _clear_recovery_durable(self, target_key: TargetKey, generation: int) -> None:
        """Durable half of the dual-write clearance: unlinks the on-disk tombstone (`unlink` +
        `_fsync_dir`). MUST be called outside the admission key lock so a slow filesystem doesn't
        stall the admission table (Finding F4)."""
        self._registry.clear_tombstone(target_key, expected_generation=generation)


def _crash(crash_after: frozenset[str], label: str) -> None:
    """Write-ahead crash-point seam (ADR 0005): tests pass `crash_after={label}` to simulate a
    process death immediately after a labeled durable stage, exercising rollback/reconciliation."""
    if label in crash_after:
        raise _SimulatedCrash(label)


class _SimulatedCrash(RuntimeError):
    pass
