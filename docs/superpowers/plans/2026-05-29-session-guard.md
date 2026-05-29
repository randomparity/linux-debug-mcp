# SessionGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `SessionGuard` seam that wraps interactive stop-capable `debug.*` sessions with ordered pre/post-attach preconditions and one idempotent teardown that guarantees the target is resumed (never left `HALTED` with no owner) and helpers are reaped, on clean end and on attach error.

**Architecture:** A thin, stateless composition layer over the existing `StopCapableGuard`/`ConsoleLease`/`TransportTransaction`/`AdmissionService` primitives. `SessionGuard` lives in `seams/guard.py` beside `StopCapableGuard`. It adds plug-in slots (`PreAttachPrecondition`, `PostAttachPrecondition`, `TeardownStep`) that #69/#70 fill, and a `teardown(close, read_record, force_reap)` routine that verifies the resume post-condition and remediates via a new `TransportTransaction.force_release`. The two debug handlers route their attach/teardown through it; the lifecycle dispatcher is untouched and conformance-tested.

**Tech Stack:** Python 3.11+, Pydantic v2 (`domain.py` models), `pytest`, `ruff`, `ty`. Handlers are tested directly with injected fakes (see `tests/_layer4_fakes.py`).

**Spec:** `docs/superpowers/specs/2026-05-29-session-guard-design.md` · **ADR:** `docs/adr/0013-session-guard-precondition-teardown-seam.md`

---

## File structure

- `src/linux_debug_mcp/seams/guard.py` — **modify**: add `PreconditionError`, `SessionGuardContext`, `TeardownReport`, `PreAttachPrecondition`, `PostAttachPrecondition`, `TeardownStep` Protocols, and the `SessionGuard` class. (Keeps `StopCapableGuard` where it is — same seam file.)
- `src/linux_debug_mcp/coordination/transaction.py` — **modify**: add `TransportTransaction.force_release(session_id)`.
- `src/linux_debug_mcp/server.py` — **modify**: route `debug_start_session_handler` and `debug_end_session_handler` through `SessionGuard`; construct + inject one `SessionGuard` in the transport-machinery builder; thread a `session_guard` kwarg.
- `tests/test_session_guard.py` — **create**: unit tests for the `SessionGuard` seam (enter ordering, post-attach rollback, teardown reasons, remediation, idempotency, step isolation).
- `tests/test_transport_transaction.py` — **modify**: add `force_release` tests (skips `transport.close`, fenced by-token release, no-clobber).
- `tests/test_session_guard_wiring.py` — **create**: handler-level tests (start/end routed through guard, resume-on-error, HALTED fast-reject conformance, timeout-path conformance).

---

## Task 1: SessionGuard seam — context, report, protocols

**Files:**
- Modify: `src/linux_debug_mcp/seams/guard.py`
- Test: `tests/test_session_guard.py` (create)

- [ ] **Step 1: Write the failing test for the context/report/protocol surface**

Create `tests/test_session_guard.py`:

```python
import pytest

from linux_debug_mcp.seams.guard import (
    PostAttachPrecondition,
    PreAttachPrecondition,
    PreconditionError,
    SessionGuard,
    SessionGuardContext,
    TeardownReport,
    TeardownStep,
)
from linux_debug_mcp.seams.target import TargetKey


def _ctx(reason: str = "ended", session_id: str | None = "sess-1") -> SessionGuardContext:
    return SessionGuardContext(
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=1,
        session_id=session_id,
        reason=reason,
    )


def test_context_is_frozen():
    ctx = _ctx()
    with pytest.raises((AttributeError, TypeError)):
        ctx.reason = "attach_error"  # type: ignore[misc]


def test_precondition_error_is_raisable():
    with pytest.raises(PreconditionError):
        raise PreconditionError("symbol mismatch", name="symbol-lock")


def test_empty_guard_protocols_importable():
    guard = SessionGuard()
    assert isinstance(guard, SessionGuard)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_session_guard.py -q`
Expected: FAIL — `ImportError: cannot import name 'SessionGuard' from linux_debug_mcp.seams.guard`.

- [ ] **Step 3: Add the surface to `seams/guard.py`**

Append to `src/linux_debug_mcp/seams/guard.py` (after the existing `InProcessStopCapableGuard`). Add the needed imports at the top of the file: `import contextlib`, `import logging`, `from collections.abc import Callable, Sequence`, `from dataclasses import dataclass, field`, `from typing import Literal`. Add `from linux_debug_mcp.transport.base import ExecutionState, TransportSession` (these are existing types).

```python
logger = logging.getLogger(__name__)

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
    each handler exit path from values already in scope. `session_id` is None only during enter
    before the transaction commits a session id."""

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
        """Idempotent, non-fatal teardown action (e.g. watchdog-restore). MUST NOT raise to
        abort teardown; SessionGuard suppresses+aggregates exceptions."""
        ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_session_guard.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/guard.py tests/test_session_guard.py
git commit -m "feat(session-guard): add precondition/teardown protocols + context"
```

---

## Task 2: SessionGuard.enter + verify_attached

**Files:**
- Modify: `src/linux_debug_mcp/seams/guard.py`
- Test: `tests/test_session_guard.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_session_guard.py`:

```python
class _RecordingPre:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self._calls = calls
        self._fail = fail

    def check(self, ctx: SessionGuardContext) -> None:
        self._calls.append(self.name)
        if self._fail:
            raise PreconditionError(f"{self.name} failed", name=self.name)


class _RecordingPost:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self._calls = calls
        self._fail = fail

    def check(self, ctx: SessionGuardContext, session) -> None:  # noqa: ANN001 - fake
        self._calls.append(self.name)
        if self._fail:
            raise PreconditionError(f"{self.name} failed", name=self.name)


def test_enter_runs_preconditions_in_order():
    calls: list[str] = []
    guard = SessionGuard(pre_attach=[_RecordingPre("a", calls), _RecordingPre("b", calls)])
    guard.enter(_ctx(reason="ended", session_id=None))
    assert calls == ["a", "b"]


def test_enter_first_failure_aborts_no_later_precondition():
    calls: list[str] = []
    guard = SessionGuard(pre_attach=[_RecordingPre("a", calls, fail=True), _RecordingPre("b", calls)])
    with pytest.raises(PreconditionError) as exc:
        guard.enter(_ctx(reason="ended", session_id=None))
    assert exc.value.name == "a"
    assert calls == ["a"]


def test_verify_attached_runs_post_preconditions_in_order():
    calls: list[str] = []
    guard = SessionGuard(post_attach=[_RecordingPost("p", calls), _RecordingPost("q", calls)])
    guard.verify_attached(_ctx(), session=object())
    assert calls == ["p", "q"]


def test_verify_attached_first_failure_raises():
    calls: list[str] = []
    guard = SessionGuard(post_attach=[_RecordingPost("p", calls, fail=True), _RecordingPost("q", calls)])
    with pytest.raises(PreconditionError) as exc:
        guard.verify_attached(_ctx(), session=object())
    assert exc.value.name == "p"
    assert calls == ["p"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_session_guard.py -q`
Expected: FAIL — `SessionGuard` has no `enter`/`verify_attached` (or `__init__` rejects kwargs).

- [ ] **Step 3: Implement the `SessionGuard` class**

Append to `src/linux_debug_mcp/seams/guard.py`:

```python
class SessionGuard:
    """Stateless lifecycle policy for interactive stop-capable debug sessions (spec
    docs/superpowers/specs/2026-05-29-session-guard-design.md, ADR 0013). Composes the existing
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_session_guard.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/guard.py tests/test_session_guard.py
git commit -m "feat(session-guard): add enter + verify_attached precondition phases"
```

---

## Task 3: SessionGuard.teardown — steps, close, resume verify, remediation

**Files:**
- Modify: `src/linux_debug_mcp/seams/guard.py`
- Test: `tests/test_session_guard.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_session_guard.py`:

```python
class _RecordingStep:
    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self.name = name
        self._calls = calls
        self._fail = fail

    def teardown(self, ctx: SessionGuardContext) -> None:
        self._calls.append(self.name)
        if self._fail:
            raise RuntimeError(f"{self.name} boom")


class _FakeHaltedRecord:
    """Stand-in whose execution_state mimics a still-HALTED TransportSession."""

    def __init__(self) -> None:
        self.execution_state = ExecutionState.HALTED


def _ended_teardown(guard: SessionGuard, *, record_after_close, calls=None):
    """Drive teardown for a clean end with injected fakes; returns the TeardownReport."""
    state = {"closed": False, "force_reaped": False}

    def close() -> None:
        state["closed"] = True

    def read_record():
        return record_after_close(state)

    def force_reap() -> None:
        state["force_reaped"] = True

    report = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    return report, state


def test_teardown_steps_run_in_reverse_then_close():
    calls: list[str] = []
    guard = SessionGuard(teardown_steps=[_RecordingStep("first", calls), _RecordingStep("second", calls)])
    report, state = _ended_teardown(guard, record_after_close=lambda s: None)
    assert calls == ["second", "first"]  # LIFO unwind
    assert state["closed"] is True
    assert report.resume_ok is True
    assert state["force_reaped"] is False


def test_teardown_step_failure_is_suppressed_and_aggregated():
    calls: list[str] = []
    guard = SessionGuard(teardown_steps=[_RecordingStep("ok", calls), _RecordingStep("bad", calls, fail=True)])
    report, state = _ended_teardown(guard, record_after_close=lambda s: None)
    assert calls == ["bad", "ok"]  # reverse; bad first, still proceeds to ok + close
    assert state["closed"] is True
    assert "bad" in report.step_errors
    assert report.resume_ok is True


def test_teardown_resume_ok_true_when_record_deleted():
    guard = SessionGuard()
    report, _ = _ended_teardown(guard, record_after_close=lambda s: None)
    assert report.resume_ok is True
    assert report.close_error is None


def test_teardown_close_raises_then_force_reap_clears():
    state = {"force_reaped": False}

    def close() -> None:
        raise RuntimeError("transport.close wedged")

    reads = [_FakeHaltedRecord(), None]  # HALTED after failed close, gone after force_reap

    def read_record():
        return reads.pop(0)

    def force_reap() -> None:
        state["force_reaped"] = True

    guard = SessionGuard()
    report = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    assert report.close_error is not None
    assert state["force_reaped"] is True
    assert report.resume_ok is True


def test_teardown_resume_false_when_force_reap_also_fails():
    def close() -> None:
        raise RuntimeError("wedged")

    def read_record():
        return _FakeHaltedRecord()  # still HALTED on every read

    def force_reap() -> None:
        return None  # did nothing

    guard = SessionGuard()
    report = guard.teardown(_ctx(reason="ended"), close=close, read_record=read_record, force_reap=force_reap)
    assert report.resume_ok is False
    assert report.resume_detail


def test_teardown_idempotent_second_call_is_noop_resume_ok():
    guard = SessionGuard()
    report, state = _ended_teardown(guard, record_after_close=lambda s: None)
    report2, state2 = _ended_teardown(guard, record_after_close=lambda s: None)
    assert report2.resume_ok is True
    assert state2["force_reaped"] is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_session_guard.py -q`
Expected: FAIL — `SessionGuard` has no `teardown`.

- [ ] **Step 3: Implement `teardown`**

Add to the `SessionGuard` class in `src/linux_debug_mcp/seams/guard.py`:

```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_session_guard.py -q`
Expected: PASS (all tests).

- [ ] **Step 5: Lint + type-check the new module, then commit**

Run: `uv run ruff check src/linux_debug_mcp/seams/guard.py tests/test_session_guard.py && uv run ruff format src/linux_debug_mcp/seams/guard.py tests/test_session_guard.py && uv run ty check src`
Expected: no errors.

```bash
git add src/linux_debug_mcp/seams/guard.py tests/test_session_guard.py
git commit -m "feat(session-guard): add idempotent teardown with resume verify + remediation"
```

---

## Task 4: TransportTransaction.force_release

**Files:**
- Modify: `src/linux_debug_mcp/coordination/transaction.py`
- Test: `tests/test_transport_transaction.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_transport_transaction.py` (it already imports the Layer-4 fakes; mirror the existing close-test setup in that file for `_open_session`/fixture names — reuse whatever helper opens a session there). Add:

```python
def test_force_release_skips_transport_close(layer4):
    # layer4: the existing fixture/harness that builds a TransportTransaction + FakeQemuTransport.
    session = layer4.open_session()  # reuse the helper the close() tests use
    transport = layer4.transport
    transport.closed.clear()
    layer4.transaction.force_release(session.session_id)
    assert transport.closed == []  # force_release must NOT call transport.close


def test_force_release_deletes_record_and_releases_guard(layer4):
    session = layer4.open_session()
    layer4.transaction.force_release(session.session_id)
    assert layer4.registry.read_record(session.target_key) is None
    # guard is free again: a fresh acquire succeeds (no GuardConflict)
    layer4.guard.acquire(session.target_key)


def test_force_release_does_not_clobber_newer_holder(layer4):
    session = layer4.open_session()
    # release the first session's guard cleanly, then a new holder acquires the SAME target_key
    layer4.guard.release(session.target_key, layer4.transaction._tokens[session.session_id])
    new_token = layer4.guard.acquire(session.target_key)
    layer4.transaction.force_release(session.session_id)  # stale session id
    # the NEW holder still owns the guard: releasing new_token succeeds (it was never revoked)
    assert layer4.guard.release(session.target_key, new_token) is True
```

> If `tests/test_transport_transaction.py` does not expose a `layer4` fixture/helper, write the three tests using the same construction the existing `close()` tests in that file use (build `TransportTransaction` from `tests/_layer4_fakes.py`, `open()` a session, then call `force_release`). Match the existing module's helper names rather than inventing new ones.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_transport_transaction.py -q -k force_release`
Expected: FAIL — `TransportTransaction` has no `force_release`.

- [ ] **Step 3: Implement `force_release`**

Add to `class TransportTransaction` in `src/linux_debug_mcp/coordination/transaction.py` (after `close`):

```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_transport_transaction.py -q -k force_release`
Expected: PASS.

- [ ] **Step 5: Lint + type-check, then commit**

Run: `uv run ruff check src/linux_debug_mcp/coordination/transaction.py tests/test_transport_transaction.py && uv run ruff format src/linux_debug_mcp/coordination/transaction.py tests/test_transport_transaction.py && uv run ty check src`
Expected: no errors.

```bash
git add src/linux_debug_mcp/coordination/transaction.py tests/test_transport_transaction.py
git commit -m "feat(transport): add force_release fenced out-of-band remediation"
```

---

## Task 5: Wire SessionGuard into the debug handlers

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`debug_start_session_handler` ~4002-4187, `debug_end_session_handler` ~4723-4776, the `_TransportMachinery` builder ~5837, and the `@app.tool` debug registrations + injection)
- Test: `tests/test_session_guard_wiring.py` (create)

> **Read first:** `src/linux_debug_mcp/server.py:4002-4187` and `:4723-4776` to see the exact current attach-error `transaction.close(..., force=False)` call and the clean-end `transaction.close(..., force=True)` call this task replaces. The attach-error close lives in the `except ProviderDebugError` block (~4132); the clean-end close is at ~4767.

- [ ] **Step 1: Write the failing wiring tests**

Create `tests/test_session_guard_wiring.py`. Model the run/manifest/provider setup on the existing `tests/test_debug_handlers.py` and `tests/test_server_debug_reads_while_halted.py` (reuse their fixtures/builders for a debug-booted run, a fake `QemuGdbstubProvider`, and the injected `transaction`/`admission`/`session_registry`). Add:

```python
def test_start_session_runs_enter_before_open(debug_run):
    # debug_run: helper producing (artifact_root, run_id) for a SUCCEEDED debug boot, mirroring
    # test_debug_handlers / test_server_debug_reads_while_halted setup.
    calls: list[str] = []

    class _Pre:
        name = "pre"

        def check(self, ctx) -> None:  # noqa: ANN001
            calls.append("pre")

    guard = SessionGuard(pre_attach=[_Pre()])
    resp = debug_start_session_handler(
        **debug_run.start_kwargs(session_guard=guard)
    )
    assert resp.ok is True
    assert calls == ["pre"]


def test_start_session_open_failure_does_not_call_guard_teardown(debug_run):
    # A transaction.open() that raises GuardConflict returns the early failure response
    # WITHOUT a guard.teardown call (open self-rolls-back; no sid).
    teardown_calls: list[str] = []

    class _Guard(SessionGuard):
        def teardown(self, ctx, **kw):  # noqa: ANN001, ANN003
            teardown_calls.append(ctx.reason)
            return super().teardown(ctx, **kw)

    resp = debug_start_session_handler(
        **debug_run.start_kwargs(session_guard=_Guard(), open_raises=GuardConflict("held"))
    )
    assert resp.ok is False
    assert teardown_calls == []  # open() failure is the existing early-return, not a guard teardown


def test_end_session_routes_through_guard_teardown(debug_run):
    debug_run.open_session()
    seen: list[str] = []

    class _Guard(SessionGuard):
        def teardown(self, ctx, **kw):  # noqa: ANN001, ANN003
            seen.append(ctx.reason)
            return super().teardown(ctx, **kw)

    resp = debug_end_session_handler(**debug_run.end_kwargs(session_guard=_Guard()))
    assert resp.ok is True
    assert seen == ["ended"]
```

> The exact `debug_run` helper API (`start_kwargs`, `end_kwargs`, `open_session`, `open_raises`) is yours to write in the test module — keep it a thin wrapper over the same fixtures the sibling debug-handler tests already use. The behavioral assertions above are the contract.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_session_guard_wiring.py -q`
Expected: FAIL — `debug_start_session_handler`/`debug_end_session_handler` reject the `session_guard` kwarg.

- [ ] **Step 3: Add the `session_guard` kwarg + enter/verify_attached to `debug_start_session_handler`**

In `src/linux_debug_mcp/server.py`, add `session_guard: SessionGuard | None = None` to `debug_start_session_handler`'s signature. Build the context and call `enter` before `transaction.open()`, and `verify_attached` after `provider.start_session` commits. Concretely, inside the `if transport_enabled:` block, immediately before `request = _debug_open_request(...)` (line ~4088), insert:

```python
                target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
                guard_ctx = SessionGuardContext(
                    target_key=target_key, generation=0, session_id=None, reason="attach_error"
                )
                if session_guard is not None:
                    try:
                        session_guard.enter(guard_ctx)
                    except PreconditionError as exc:
                        return ToolResponse.failure(
                            category=ErrorCategory.READINESS_FAILURE,
                            message=str(exc),
                            run_id=run_id,
                            details={"code": "precondition_failed", "precondition": exc.name},
                            suggested_next_actions=["artifacts.get_manifest"],
                        )
```

Then, after the successful `result = provider.start_session(...)` block and the `transport_session.session_id` is known (after line ~4154 where `details["transport_session_id"]` is set, still inside the `with store.debug_lock`), add a post-attach verify that tears down on failure:

```python
            if session_guard is not None and transport_session is not None:
                post_ctx = SessionGuardContext(
                    target_key=transport_session.target_key,
                    generation=transport_session.generation,
                    session_id=transport_session.session_id,
                    reason="attach_error",
                )
                try:
                    session_guard.verify_attached(post_ctx, transport_session)
                except PreconditionError as exc:
                    sid = transport_session.session_id
                    session_guard.teardown(
                        post_ctx,
                        close=lambda: transaction.close(sid, force=False),
                        read_record=lambda: session_registry.read_record(transport_session.target_key),
                        force_reap=lambda: transaction.force_release(sid),
                    )
                    return ToolResponse.failure(
                        category=ErrorCategory.READINESS_FAILURE,
                        message=str(exc),
                        run_id=run_id,
                        details={"code": "precondition_failed", "precondition": exc.name},
                        suggested_next_actions=["artifacts.get_manifest"],
                    )
```

Then replace the existing attach-error recovery in the `except ProviderDebugError` block (line ~4132) — change the bare `transaction.close(...)` call to route through the guard when one is wired:

```python
                if transport_session is not None and transaction is not None:
                    sid = transport_session.session_id
                    tkey = transport_session.target_key
                    if session_guard is not None and session_registry is not None:
                        session_guard.teardown(
                            SessionGuardContext(
                                target_key=tkey, generation=transport_session.generation,
                                session_id=sid, reason="attach_error",
                            ),
                            close=lambda: transaction.close(sid, force=False),
                            read_record=lambda: session_registry.read_record(tkey),
                            force_reap=lambda: transaction.force_release(sid),
                        )
                    else:
                        with contextlib.suppress(Exception):
                            transaction.close(sid, force=False)
```

- [ ] **Step 4: Add the `session_guard` kwarg + clean teardown to `debug_end_session_handler`**

Add `session_guard: SessionGuard | None = None` to `debug_end_session_handler`'s signature. Replace the clean-close at line ~4767 (`if response.ok and transaction is not None and transport_session_id is not None: transaction.close(transport_session_id, force=True)`) with:

```python
    if response.ok and transaction is not None and transport_session_id is not None:
        tkey = TargetKey(provisioner="local-qemu", target_id=run_id)
        if session_guard is not None and session_registry is not None:
            session_guard.teardown(
                SessionGuardContext(target_key=tkey, generation=0, session_id=transport_session_id, reason="ended"),
                close=lambda: transaction.close(transport_session_id, force=True),
                read_record=lambda: session_registry.read_record(tkey),
                force_reap=lambda: transaction.force_release(transport_session_id),
            )
        else:
            transaction.close(transport_session_id, force=True)
```

Add the imports at the top of `server.py` if not present: `from linux_debug_mcp.seams.guard import PreconditionError, SessionGuard, SessionGuardContext` (alongside the existing `InProcessStopCapableGuard` import).

- [ ] **Step 5: Construct + inject one `SessionGuard`**

In the transport-machinery builder (near line ~5837 where `TransportTransaction` is built), construct `session_guard = SessionGuard()` and store it on `_TransportMachinery` (add the field). Then at the two `@app.tool` debug registrations for `debug.start_session` and `debug.end_session`, pass `session_guard=machinery.session_guard` alongside the existing `transaction=`/`admission=`/`session_registry=` arguments. (Grep `debug_start_session_handler(` at ~5617 for the registration wrapper and the tool wrapper for `debug.end_session`.)

- [ ] **Step 6: Run the wiring tests + the existing debug-handler suite**

Run: `uv run python -m pytest tests/test_session_guard_wiring.py tests/test_debug_handlers.py tests/test_server_debug_reads_while_halted.py -q`
Expected: PASS (new wiring tests pass; no regression in existing debug-handler tests).

- [ ] **Step 7: Lint + type-check, then commit**

Run: `uv run ruff check src/linux_debug_mcp/server.py tests/test_session_guard_wiring.py && uv run ruff format src/linux_debug_mcp/server.py tests/test_session_guard_wiring.py && uv run ty check src`
Expected: no errors.

```bash
git add src/linux_debug_mcp/server.py tests/test_session_guard_wiring.py
git commit -m "feat(session-guard): route debug start/end through SessionGuard"
```

---

## Task 6: Conformance tests — resume-on-error, HALTED fast-reject, timeout path

**Files:**
- Test: `tests/test_session_guard_wiring.py`

- [ ] **Step 1: Write the conformance tests**

Append to `tests/test_session_guard_wiring.py`:

```python
def test_resume_on_error_reaps_and_tombstones(debug_run):
    # provider.start_session raises after _halt parked HALTED -> teardown(reason="attach_error").
    resp = debug_start_session_handler(
        **debug_run.start_kwargs(session_guard=SessionGuard(), start_session_raises=True)
    )
    assert resp.ok is False
    target_key = debug_run.target_key
    # backend reaped + record not left a live HALTED session (deleted), tombstone gates future admit
    assert debug_run.session_registry.read_record(target_key) is None
    assert debug_run.proxy_stop_called is True  # fake backend reap hook fired


def test_ssh_tier_rejected_while_halted_then_admitted_after_end(debug_run):
    debug_run.open_session(session_guard=SessionGuard())  # parks HALTED
    # ssh-tier run_tests admit is fast-rejected target_halted, not hung
    with pytest.raises(AdmissionError) as exc:
        debug_run.admit_run_tests_ssh_tier()
    assert exc.value.code == "target_halted"
    # clean end resumes; the same admit now succeeds
    debug_run.end_session(session_guard=SessionGuard())
    handle = debug_run.admit_run_tests_ssh_tier()
    assert handle is not None


def test_timeout_path_leaves_no_orphan_or_halted_record(debug_run):
    debug_run.open_session(session_guard=SessionGuard())
    # emit a resetting lifecycle event for the session's target (the existing dispatcher path)
    debug_run.emit_resetting()
    target_key = debug_run.target_key
    assert debug_run.session_registry.read_record(target_key) is None  # reaped by _SessionSubscriber
    assert debug_run.proxy_stop_called is True  # no orphaned helper
```

> Reuse the existing `_admit_run_tests_ssh_tier` (`server.py:508`) and the lifecycle-emit helpers from `tests/test_workflow_layer4_wiring.py` / `tests/test_server_run_tests_gating.py` for `admit_run_tests_ssh_tier`/`emit_resetting`. These tests assert AC1 (no orphan, never left HALTED) and AC2 (HALTED fast-reject) bound to the SessionGuard lifecycle.

- [ ] **Step 2: Run to verify they pass (logic already implemented in Tasks 4–5 + existing code)**

Run: `uv run python -m pytest tests/test_session_guard_wiring.py -q`
Expected: PASS. If `test_resume_on_error_reaps_and_tombstones` fails because the existing attach-error path already tombstones+deletes identically, confirm the assertions match the established `transaction.close(force=False)` behavior (delete record + `closed_while_halted` tombstone) rather than changing production code.

- [ ] **Step 3: Run the full guardrail suite**

Run: `uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q`
Expected: all green; the env-gated `gdb`/`virsh` integration tests skip.

- [ ] **Step 4: Commit**

```bash
git add tests/test_session_guard_wiring.py
git commit -m "test(session-guard): AC1 resume/no-orphan + AC2 HALTED fast-reject conformance"
```

---

## Task 7: Final guardrails + ADR/spec status flip

**Files:**
- Modify: `docs/superpowers/specs/2026-05-29-session-guard-design.md` (Status: proposed → accepted)

- [ ] **Step 1: Flip the spec status**

In `docs/superpowers/specs/2026-05-29-session-guard-design.md`, change `**Status:** proposed design` to `**Status:** accepted (implemented)`.

- [ ] **Step 2: Full guardrail run**

Run: `uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q && just check-docs`
Expected: all green.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-05-29-session-guard-design.md
git commit -m "docs(session-guard): mark spec accepted (implemented)"
```

---

## Notes for the implementer

- **No new `ErrorCategory` values.** Precondition failures map to the existing `READINESS_FAILURE`; an unresumable target is a logged `INFRASTRUCTURE_FAILURE` (logging only — `teardown` never raises).
- **Do not touch the lifecycle dispatcher or `_SessionSubscriber`.** The timeout/invalidation path is covered by their existing, tested reap; Task 6 only conformance-tests it. The one transaction change is the additive `force_release`.
- **`force_release` uses fenced by-token release, never `guard.revoke`** (ADR 0002 / ADR 0013 rejected-alt 8) — a `revoke` could clobber a concurrent reopen's newer holder.
- **Redaction unchanged.** The handlers' existing `Redactor` paths for summaries/details/artifacts stay as-is; `SessionGuard` returns no guest-derived text (the `TeardownReport` carries only step names and exception `repr`s — keep step `name`s non-sensitive).
- **Idempotency.** `teardown` and `force_release` must be safe to call twice (a re-attempted `debug.end_session`). The session-id-fenced `delete_record` and the stale-token-no-op guard release provide this.
