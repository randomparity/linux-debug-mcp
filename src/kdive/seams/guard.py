from __future__ import annotations

import contextlib
import logging
import threading
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

from kdive.seams.target import TargetKey
from kdive.seams.transport_state import ExecutionState, TransportSession

logger = logging.getLogger(__name__)


class GuardConflict(RuntimeError):
    """Raised when acquire() fails because the target already has a stop-capable holder
    (spec §4.4/§4.6: one stop-capable session per TargetKey, target-wide)."""


@dataclass(frozen=True)
class GuardToken:
    """Fenced single-holder token. `fence` is monotonic across the guard so a token from a
    revoked/superseded holder can never release or act on a later holder."""

    target_key: TargetKey
    fence: int
    secret: str


@runtime_checkable
class StopCapableGuard(Protocol):
    def acquire(self, target_key: TargetKey) -> GuardToken: ...

    def release(self, target_key: TargetKey, token: GuardToken) -> bool: ...

    def revoke(self, target_key: TargetKey) -> None: ...


class InProcessStopCapableGuard:
    """Minimal in-process impl of the #08-owned `StopCapableGuard` interface. One holder per
    TargetKey, target-wide — both `debug.gdb` (RSP) and `debug.kdb` (console) acquire it, so
    a single stop-capable session is enforced even with no console lease. #08 later swaps this
    impl behind the same Protocol and must pass these same tests (roadmap seam-ownership rule)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._holders: dict[TargetKey, GuardToken] = {}
        self._fence = 0

    def acquire(self, target_key: TargetKey) -> GuardToken:
        with self._lock:
            if target_key in self._holders:
                raise GuardConflict(f"stop-capable session already held for {target_key}")
            self._fence += 1
            token = GuardToken(target_key=target_key, fence=self._fence, secret=uuid.uuid4().hex)
            self._holders[target_key] = token
            return token

    def release(self, target_key: TargetKey, token: GuardToken) -> bool:
        """Idempotent, **TargetKey-fenced** by-token release (contract §5.6: `release(target_key,
        token)`). Returns True iff `token` is the current holder of `target_key`. A token whose
        `target_key` does not match the argument (a misrouted token from another target), or a
        stale/fenced token (post-revoke or post-release), is a no-op returning False — so cleanup
        keyed on the wrong target can never release another target's live stop-capable guard."""
        with self._lock:
            if token.target_key != target_key:
                return False
            current = self._holders.get(target_key)
            if current is None or current != token:
                return False
            del self._holders[target_key]
            return True

    def revoke(self, target_key: TargetKey) -> None:
        """Coarse, **tokenless** force-free of the current holder — the §5.6 contract primitive for
        an invalidator that does not hold the session's token. The §5.4 invalidation path in this
        codebase does NOT use it: `TransportTransaction` holds the `GuardToken` in-process and frees
        the guard by the fenced `release(target_key, token)` instead (ADR 0002 / ADR 0015),
        so `revoke` has no in-process caller today. It is retained as a Protocol primitive a swapped
        #08 impl (or a tokenless force-reap path) can use.

        Safe-use precondition: revoke clears the CURRENT holder unconditionally, so it can wrongly
        clear a NEWER holder that acquired after a §5.4 revoke -> re-acquire — the "stale clears
        newer" violation fenced release prevents. Call it ONLY when no live holder it would wrongly
        clear can exist: the post-restart reconcile path, where the instance.lock flock + reconcile-
        before-admit prove the prior holder dead (ADR 0002). Within one server lifetime, token-
        holding paths MUST use `release(target_key, token)`. The outstanding token is still fenced: a
        subsequent `release(old_token)` is a no-op, so a revoke can never be undone by a stale token."""
        with self._lock:
            self._holders.pop(target_key, None)


TeardownReason = Literal["ended", "attach_error"]


class PreconditionError(RuntimeError):
    """Raised by a Precondition.check to abort a session enter/verify. `name` identifies the
    failing precondition for the handler's READINESS_FAILURE response."""

    def __init__(self, message: str, *, name: str) -> None:
        super().__init__(message)
        self.name = name


@dataclass(frozen=True)
class SessionGuardContext:
    """Run-scoped facts a precondition/teardown step needs. No live handles, so it is built on
    each handler exit path from values already in scope (ADR 0013).

    Field authority by phase (a #69/#70 step MUST respect this):
    - `session_id` is None only at `enter` (pre-attach), before the transaction commits a session;
      every teardown/verify context carries it.
    - `generation` is authoritative on the post-attach `verify_attached` and attach-error/ended
      `teardown` contexts (the committed incarnation). At `enter` it is a 0 placeholder — the
      snapshot generation is not yet read — so a pre-attach precondition MUST NOT key on it.
    - `reason` is the teardown intent on teardown contexts; at `enter` it is set to "attach_error"
      as a forward-looking default (any abort there fails before acquisition) and is not a signal a
      pre-attach precondition should branch on."""

    target_key: TargetKey
    generation: int
    session_id: str | None
    reason: TeardownReason


@dataclass(frozen=True)
class TeardownReport:
    """Outcome of teardown(). `resume_ok` is the AC1 post-condition (no orphaned HALTED record)
    after close()+force_reap; resume_ok=False is a logged INFRASTRUCTURE_FAILURE, never raised."""

    step_errors: dict[str, str] = field(default_factory=dict)
    close_error: str | None = None
    resume_ok: bool = True
    resume_detail: str = ""


@runtime_checkable
class PreAttachPrecondition(Protocol):
    name: str

    def check(self, ctx: SessionGuardContext) -> None:
        """Runs before any resource is acquired. Raise PreconditionError to abort the enter."""
        ...


@runtime_checkable
class PostAttachPrecondition(Protocol):
    name: str

    def check(self, ctx: SessionGuardContext, session: TransportSession) -> None:
        """Runs after the attach commits a session (can read the running kernel over RSP).
        Raise PreconditionError to abort; the caller runs teardown(reason="attach_error")."""
        ...


@runtime_checkable
class TeardownStep(Protocol):
    name: str

    def teardown(self, ctx: SessionGuardContext) -> None:
        """Idempotent, non-fatal teardown action (e.g. watchdog-restore). MUST NOT raise to abort
        teardown; SessionGuard suppresses+aggregates exceptions."""
        ...


class SessionGuard:
    """Stateless lifecycle policy for interactive stop-capable debug sessions (spec
    docs/archive/superpowers/specs/2026-05-29-session-guard-design.md, ADR 0013). Composes the existing
    guard/lease/transaction primitives; holds no per-session state. #66 ships empty slots; #69
    adds a TeardownStep, #70 adds pre/post-attach Preconditions."""

    def __init__(
        self,
        *,
        pre_attach: Sequence[PreAttachPrecondition] = (),
        post_attach: Sequence[PostAttachPrecondition] = (),
        teardown_steps: Sequence[TeardownStep] = (),
    ) -> None:
        self._pre_attach = tuple(pre_attach)
        self._post_attach = tuple(post_attach)
        self._teardown_steps = tuple(teardown_steps)

    def enter(self, ctx: SessionGuardContext) -> None:
        """Run pre_attach preconditions in declared order. First failure raises PreconditionError
        and aborts; nothing is acquired (the caller attaches only after enter() returns)."""
        for precondition in self._pre_attach:
            precondition.check(ctx)

    def verify_attached(self, ctx: SessionGuardContext, session: TransportSession) -> None:
        """Run post_attach preconditions against the live session. First failure raises
        PreconditionError; the caller runs teardown(reason="attach_error")."""
        for precondition in self._post_attach:
            precondition.check(ctx, session)

    def teardown(
        self,
        ctx: SessionGuardContext,
        *,
        close: Callable[[], None],
        read_record: Callable[[], TransportSession | None],
        force_reap: Callable[[], None],
    ) -> TeardownReport:
        """The single idempotent teardown invariant (ADR 0013). Run teardown_steps in REVERSE
        order (suppress+aggregate), then close() (suppress+record), verify the resume
        post-condition via read_record, and if a live HALTED record remains invoke force_reap and
        re-verify. Never raises; resume_ok=False is a logged INFRASTRUCTURE_FAILURE."""
        step_errors: dict[str, str] = {}
        for step in reversed(self._teardown_steps):
            try:
                step.teardown(ctx)
            except Exception as exc:  # noqa: BLE001 - a step must never abort teardown
                step_errors[step.name] = repr(exc)
                logger.warning("session-guard: teardown step %s raised: %r", step.name, exc)

        close_error: str | None = None
        try:
            close()
        except Exception as exc:  # noqa: BLE001 - close failure is exactly what force_reap remediates
            close_error = repr(exc)
            logger.warning("session-guard: close raised during teardown: %r", exc)

        resume_ok, detail = self._resume_holds(read_record)
        if not resume_ok:
            with contextlib.suppress(Exception):
                force_reap()
            resume_ok, detail = self._resume_holds(read_record)
            if not resume_ok:
                logger.error(
                    "session-guard: resume invariant violated for %s after force_reap: %s",
                    ctx.target_key,
                    detail,
                )
        return TeardownReport(
            step_errors=step_errors, close_error=close_error, resume_ok=resume_ok, resume_detail=detail
        )

    @staticmethod
    def _resume_holds(read_record: Callable[[], TransportSession | None]) -> tuple[bool, str]:
        """The AC1 post-condition: the durable record is gone, or present but not HALTED."""
        record = read_record()
        if record is None:
            return True, ""
        if record.execution_state is ExecutionState.HALTED:
            return False, "durable record still reports HALTED with no owner"
        return True, ""
