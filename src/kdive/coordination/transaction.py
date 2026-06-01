from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import cast

from kdive.coordination.admission import AdmissionHandle, AdmissionService
from kdive.coordination.endpoint_safety import assert_loopback_endpoint, refuse_unsafe_exposure
from kdive.coordination.lease import ConsoleLeaseManager, LeaseOwner
from kdive.coordination.registry import RecoveryTombstone, SessionRegistry
from kdive.coordination.selection import Selection, select_stop_capable_channel
from kdive.domain import ErrorCategory
from kdive.seams.break_policy import BreakPolicy
from kdive.seams.guard import GuardToken, StopCapableGuard
from kdive.seams.lifecycle import LifecycleDispatcher, LifecycleEvent
from kdive.seams.secrets import SecretsResolver
from kdive.seams.target import TargetKey
from kdive.seams.transport_state import (
    ExecutionState,
    OpenRequest,
    RecordState,
    TransportSession,
    new_session_id,
)
from kdive.transport.core.base import BackendAttachment, Transport
from kdive.transport.core.bounded import Deadline
from kdive.transport.core.break_inject import BreakRequestMethod, InjectBreakError, inject_break

logger = logging.getLogger(__name__)

_ATTACH_DEADLINE_SECONDS = 30.0


def _best_effort_reap(transport: Transport, state: _OpenState) -> None:
    """Single backend-reap path for both teardown (`invalidate`) and open-failure unwind
    (`_rollback`) — TD-07. No-op when no supervised backend pid was recorded; otherwise delegate to
    the transport's `reap_backend()` hook with the failure suppressed, because a reap error must
    never mask the original teardown/rollback error (ADR 0002). Replaces the duplicated
    `getattr(transport, '_proxy', None)` private reach the two sites previously shared."""
    if state.backend_pid is None:
        return
    try:
        transport.reap_backend(state.backend_pid, state.backend_start)
    except Exception:  # noqa: BLE001 - best-effort; a reap failure must not mask the original error
        logger.warning(
            "transaction: best-effort reap_backend(pid=%s) failed during unwind",
            state.backend_pid,
            exc_info=True,
        )


def _write_backend_partial(
    registry: SessionRegistry, record: TransportSession, resource: object
) -> tuple[int, str | None] | None:
    """Handle a transport's ``on_partial("backend_process", ...)`` callback during attach() (TD-25).

    Validate the reported backend identity and, if well-formed, WRITE IT THROUGH into the durable
    OPENING record before attach() returns — so a backend death before READY is reapable by
    startup reconciliation. Returns the ``(pid, start_time)`` the caller mirrors onto the in-memory unwind
    state, or None for a malformed or non-backend partial.

    Atomicity & exception contract: ``registry.write_record`` is a single atomic os.replace, so the
    durable record never reflects a half-written backend identity — it lands whole or not at all.
    The durable write happens BEFORE the caller updates the in-memory unwind state, so a crash in the
    window between them leaves the durable record as the source of truth (``reconcile()`` reaps from
    it) while the in-memory state is merely one step behind (it only ever under-reports, never reaps
    a wrong pid). A malformed partial is ignored: this never raises, so a bad partial can never abort
    attach().
    """
    if not isinstance(resource, dict):
        return None
    backend_process = cast(dict[str, object], resource)
    pid_val = backend_process.get("pid")
    start_val = backend_process.get("start_time")
    if not isinstance(pid_val, int) or (start_val is not None and not isinstance(start_val, str)):
        return None
    registry.write_record(record.model_copy(update=dict(backend_pid=pid_val, backend_start_time=start_val)))
    return pid_val, start_val


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


@dataclass(frozen=True)
class _OpeningRecord:
    record: TransportSession
    state: _OpenState


@dataclass(frozen=True)
class _AttachedOpenBackend:
    attachment: BackendAttachment
    state: _OpenState
    backend_pid: int | None
    backend_start: str | None


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
        _best_effort_reap(transport, self._state)
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
            try:
                self._transaction._admission.confirm_reaped(self._state.admission_handle)
                self._transaction._admission.abandon(self._state.admission_handle)
            except Exception:  # noqa: BLE001 - out-of-band drop is best-effort; never raise
                # TD-42: log instead of silently swallowing. `_handles.pop` below still runs, so the
                # in-memory binding is dropped; a confirm_reaped/abandon failure here leaves the
                # admission-side binding for reconcile() to reap and must be visible, not hidden.
                logger.warning(
                    "transaction.force_drop: confirm_reaped/abandon failed for session %s",
                    self._session.session_id,
                    exc_info=True,
                )
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
        # The fenced GuardToken is held in-process; the persisted stop_guard_token string is
        # audit-only and cannot release the guard. close()/lifecycle release by this token.
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

    def _write_opening_record(
        self,
        *,
        request: OpenRequest,
        handle: AdmissionHandle,
        selection: Selection,
        provider_name: str,
        guard_token: GuardToken,
        lease_token: str | None,
        state: _OpenState,
    ) -> _OpeningRecord:
        # The fenced token is held in-process keyed by session_id; stop_guard_token persists only
        # its secret as an audit marker (ADR 0003).
        session_id = new_session_id()
        self._tokens[session_id] = guard_token
        state = replace(state, session_id=session_id)
        record = TransportSession(
            session_id=session_id,
            target_key=request.target_key,
            generation=request.generation,
            provider=provider_name,
            channel_id=selection.channel.channel_id,
            record_state=RecordState.OPENING,
            console_lease_token=lease_token,
            stop_guard_token=guard_token.secret,
            attach_epoch=handle.admit_epoch,
            break_plan=selection.break_plan,
            execution_state=ExecutionState.EXECUTING,
            created_at=datetime.now(UTC),
        )
        self._registry.write_record(record)
        return _OpeningRecord(record=record, state=state)

    def _attach_open_backend(
        self,
        *,
        request: OpenRequest,
        transport: Transport,
        record: TransportSession,
        state: _OpenState,
        resolved_secrets: dict[str, str],
        publish_state: Callable[[_OpenState], None],
    ) -> _AttachedOpenBackend:
        backend_pid: int | None = None
        backend_start: str | None = None

        def on_partial(label: str, resource: object) -> None:
            # Thin adapter: _write_backend_partial does the durable write-through (and documents
            # the atomicity contract); the closure only mirrors the result onto the in-memory
            # unwind state. The state update MUST stay here (synchronous with the partial) so an
            # attach-time crash unwinds with a reapable pid — it cannot move into the helper.
            nonlocal backend_pid, backend_start, state
            if label != "backend_process":
                return
            result = _write_backend_partial(self._registry, record, resource)
            if result is None:
                return
            backend_pid, backend_start = result
            state = replace(state, backend_pid=backend_pid, backend_start=backend_start)
            publish_state(state)

        attachment = transport.attach(
            request,
            # caller-driven attach cancellation is wired in A9; here the deadline is the only bound.
            cancel=threading.Event(),
            deadline=Deadline.after(_ATTACH_DEADLINE_SECONDS),
            on_partial=on_partial,
            secrets=resolved_secrets,
        )
        if attachment.backend_pid is not None:
            # transports that report the pid on the returned attachment rather than via the
            # on_partial("backend_process") partial (redundant-but-harmless when both fire).
            backend_pid, backend_start = attachment.backend_pid, attachment.backend_start_time
            state = replace(state, backend_pid=backend_pid, backend_start=backend_start)
            publish_state(state)
        return _AttachedOpenBackend(
            attachment=attachment,
            state=state,
            backend_pid=backend_pid,
            backend_start=backend_start,
        )

    def _commit_open_session(
        self,
        *,
        request: OpenRequest,
        handle: AdmissionHandle,
        session: TransportSession,
        state: _OpenState,
        recovery: bool,
        publish_state: Callable[[_OpenState], None],
    ) -> _OpenState:
        # Hold the admission key lock across promote → register → subscribe. Otherwise a concurrent
        # lifecycle invalidation can cancel the promoted handle before the subscriber exists to tear
        # down the backend/lease/guard. The key lock is re-entrant, so `promote()`'s own internal
        # lock acquisition is a no-op.
        with self._admission.key_lock(request.target_key):
            self._admission.promote(handle)
            self._handles[session.session_id] = handle
            state = replace(state, admission_handle=handle)
            publish_state(state)
            self._subscribe_session(session, state)
        if recovery:
            # Recovery-gate clearance runs outside the admission key lock so slow filesystem writes
            # do not stall the admission table. It is durable-first: the in-memory cache is cleared
            # only after the durable tombstone unlink succeeds.
            #
            # Consequences:
            #   * A raise from `_clear_recovery_durable` (EIO on `_fsync_dir`, EACCES, ENOSPC, …)
            #     leaves the cache STILL MARKED and the tombstone STILL PRESENT — the gate is
            #     fail-closed end-to-end with no try/except-restore handshake.
            #   * Concurrent non-recovery `admit()` during the durable I/O sees the cache still set
            #     and is correctly rejected `recovery_required`.
            #   * If the process dies between the durable unlink and the cache clear, `reconcile()`
            #     on the next start finds no tombstone (it's already gone) so the cache stays clear.
            self._clear_recovery_durable(request.target_key, request.generation)
            self._clear_recovery_cache(request.target_key, request.generation)
        return state

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

        def publish_state(updated: _OpenState) -> None:
            nonlocal state
            state = updated

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
            lease_token: str | None = None
            if capability.provides_console:
                lease_token = self._leases.acquire(request.target_key, LeaseOwner.TRANSPORT)
                state = replace(state, lease_token=lease_token)
            _crash(crash_after, "lease")
            # (6) secrets (never persisted/logged).
            resolved_secrets = self._secrets.resolve(list(channel.secret_refs))
            opening = self._write_opening_record(
                request=request,
                handle=handle,
                selection=selection,
                provider_name=capability.provider_name,
                guard_token=guard_token,
                lease_token=lease_token,
                state=state,
            )
            record = opening.record
            state = opening.state
            _crash(crash_after, "record_written")

            attached = self._attach_open_backend(
                request=request,
                transport=transport,
                record=record,
                state=state,
                resolved_secrets=resolved_secrets,
                publish_state=publish_state,
            )
            attachment = attached.attachment
            state = attached.state
            # (9) assemble + loopback assert + READY record.
            for endpoint in (attachment.console_endpoint, attachment.rsp_endpoint):
                if endpoint is not None:
                    assert_loopback_endpoint(endpoint)
            session = record.model_copy(
                update=dict(
                    record_state=RecordState.READY,
                    console_endpoint=attachment.console_endpoint,
                    rsp_endpoint=attachment.rsp_endpoint,
                    backend_pid=attached.backend_pid,
                    backend_start_time=attached.backend_start,
                    artifacts=[attachment.console_artifact] if attachment.console_artifact else [],
                )
            )
            self._registry.write_record(session)
            _crash(crash_after, "ready")
            state = self._commit_open_session(
                request=request,
                handle=handle,
                session=session,
                state=state,
                recovery=recovery,
                publish_state=publish_state,
            )
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
        def cleanup(description: str, step: Callable[[], object]) -> None:
            try:
                step()
            except Exception:  # noqa: BLE001 - rollback must not mask the primary open failure
                logger.warning("transaction.open rollback cleanup failed: %s", description, exc_info=True)

        # reverse order; each guarded so a partial rollback still completes.
        _best_effort_reap(transport, state)
        if state.session_id is not None:
            session_id = state.session_id
            self._tokens.pop(session_id, None)
            self._handles.pop(session_id, None)  # keep _handles symmetric with _tokens
            # Session-id fenced: rollback only erases the record this in-flight open() wrote
            # (the OPENING/READY record carries `session_id == state.session_id` by construction).
            cleanup(
                "delete opening record",
                lambda: self._registry.delete_record(target_key, expected_session_id=session_id),
            )
            dispatcher = self._dispatcher
            if dispatcher is not None:
                cleanup(
                    "unsubscribe lifecycle subscriber",
                    lambda: dispatcher.unsubscribe(target_key, session_id),
                )
        if state.lease_token is not None:
            lease_token = state.lease_token
            cleanup("release console lease", lambda: self._leases.release(target_key, lease_token))
        if state.guard_token is not None:
            guard_token = state.guard_token
            cleanup(
                "release stop guard",
                lambda: self._guard.release(target_key, guard_token),  # FENCED by-token release (ADR 0002)
            )
        # rollback is best-effort; an admission-rollback failure must never mask the original error.
        cleanup("rollback admission handle", lambda: self._admission.rollback(handle))

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
        close_error: Exception | None = None
        cleanup_errors: list[Exception] = []
        try:
            transport.close(closing)
        except Exception as exc:  # noqa: BLE001 - cleanup must still run, then the close error is reported.
            close_error = exc

        def cleanup(step) -> None:
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - run every cleanup step, aggregate below.
                cleanup_errors.append(exc)

        lease_token = record.console_lease_token
        if lease_token is not None:
            cleanup(lambda: self._leases.release(record.target_key, lease_token))
        # Fenced by-token release: use the in-memory GuardToken, never the audit-only token string.
        token = self._tokens.pop(session_id, None)
        if token is not None:
            cleanup(lambda: self._guard.release(record.target_key, token))
        # Deregister the promoted admission binding for this cleanly-closed session. complete() is the
        # success-terminal disposal for an already-PROMOTED session (its guard for a cancelled/closed
        # handle does not apply to a clean close); without it the binding lingers PROMOTED and blocks
        # a later reopen() with `bindings_outstanding`.
        handle = self._handles.pop(session_id, None)
        if handle is not None:
            cleanup(lambda: self._admission.complete(handle))
        # close-while-halted marks recovery through the dual-write helper: durable
        # tombstone + admission cache together, never one alone. Otherwise delete cleanly.
        if record.execution_state in (ExecutionState.HALTED, ExecutionState.UNKNOWN) and not force:
            cleanup(lambda: self._mark_recovery(record.target_key, record.generation, reason="closed_while_halted"))
        # Session-id fenced delete: protects against the close() running for a recycled session_id
        # racing a new session that may have just claimed the same target_key.
        cleanup(lambda: self._registry.delete_record(record.target_key, expected_session_id=record.session_id))
        # Drop the lifecycle binding for this cleanly-closed session. Without this, the dispatcher
        # would keep delivering future invalidate_lifecycle events to the stale subscriber, and
        # every one of those force_drops would re-attempt a record delete (now session-id fenced,
        # so a no-op, but unnecessary work). Idempotent — unsubscribing an already-removed name
        # is a no-op.
        dispatcher = self._dispatcher
        if dispatcher is not None:
            cleanup(lambda: dispatcher.unsubscribe(record.target_key, session_id))

        if close_error is not None:
            if cleanup_errors:
                raise ExceptionGroup("transport close failed after cleanup errors", [close_error, *cleanup_errors])
            raise close_error
        if cleanup_errors:
            raise ExceptionGroup("transport close cleanup failed", cleanup_errors)

    def force_release(self, session_id: str) -> None:
        """Last-resort remediation when close() failed and stranded a HALTED record (SessionGuard
        teardown, ADR 0013). MORE forceful than close, NOT a retry: skip the failure-prone
        transport.close and drop only the lines that keep the ssh-tier probe reading HALTED — a
        session-id-fenced delete_record, a FENCED by-token guard release (never revoke — ADR 0002),
        and a by-token console-lease release. Any still-live backend is reaped by
        SessionRegistry.reconcile() on next start. Idempotent; an unknown session_id is a no-op."""
        record = next((r for r in self._registry.list_records() if r.session_id == session_id), None)
        if record is None:
            self._tokens.pop(session_id, None)
            self._handles.pop(session_id, None)
            return
        if record.console_lease_token is not None:
            self._leases.release(record.target_key, record.console_lease_token)
        token = self._tokens.pop(session_id, None)
        if token is not None:
            self._guard.release(record.target_key, token)  # FENCED by-token (ADR 0002), never revoke()
        handle = self._handles.pop(session_id, None)
        if handle is not None:
            with contextlib.suppress(Exception):
                self._admission.confirm_reaped(handle)
                self._admission.abandon(handle)
        self._registry.delete_record(record.target_key, expected_session_id=record.session_id)
        if self._dispatcher is not None:
            self._dispatcher.unsubscribe(record.target_key, session_id)

    def inject_break_for_session(self, session_id: str, requested_method: BreakRequestMethod) -> None:
        """Execute the session's admitted break plan over the owning transport's live break handle
        (#82 / ADR 0024). Resolves the durable record by session_id, asks the transport for its
        live ``BreakResources``, and delegates to ``inject_break``. When no record/plan exists, or
        the transport exposes no break handle (a gdbstub-qemu transport, or the handle is gone),
        raises ``InjectBreakError(break_inject_unavailable)`` — never a silent no-op. The
        ``gdbstub_native`` guard lives in ``inject_break`` itself."""
        record = next((r for r in self._registry.list_records() if r.session_id == session_id), None)
        if record is None or record.break_plan is None:
            raise InjectBreakError(
                f"no admitted break plan for session {session_id}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"code": "break_inject_unavailable"},
            )
        transport = self._transports.get(record.provider)
        resources = transport.break_resources(record) if transport is not None else None
        if resources is None:
            raise InjectBreakError(
                f"transport {record.provider!r} exposes no break-injection handle for session {session_id}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"code": "break_inject_unavailable"},
            )
        inject_break(
            method=requested_method,
            break_plan=record.break_plan,
            proxy=resources.proxy,
            proxy_handle=resources.proxy_handle,
            ssh_runner=resources.ssh_runner,
            ssh_argv_prefix=resources.ssh_argv_prefix,
            work_dir=resources.work_dir,
        )

    def _mark_recovery(self, target_key: TargetKey, generation: int, *, reason: str) -> None:
        """Single source of truth is the durable tombstone; admission's `_recovery_required` is a
        write-through cache. Always write BOTH atomically."""
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
        stall the admission table."""
        self._registry.clear_tombstone(target_key, expected_generation=generation)


def _crash(crash_after: frozenset[str], label: str) -> None:
    """Write-ahead crash-point seam (ADR 0005): tests pass `crash_after={label}` to simulate a
    process death immediately after a labeled durable stage, exercising rollback/reconciliation."""
    if label in crash_after:
        raise _SimulatedCrash(label)


class _SimulatedCrash(RuntimeError):
    pass
