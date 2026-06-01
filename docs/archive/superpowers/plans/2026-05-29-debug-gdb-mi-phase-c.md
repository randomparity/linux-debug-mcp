# gdb/MI Phase C — Core Operations + Batch Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the entire `debug.*` operation surface onto the persistent `gdb --interpreter=mi3` engine as typed JSON, add the structured operations the batch engine never had (`step`/`next`/`finish`, frames, variable listing, watchpoints), and delete the `-batch` text-scraping paths so one engine remains.

**Architecture:** A new in-process `GdbMiSessionRegistry` (lock-guarded dict in `providers/gdb_mi.py`) holds one live `GdbMiAttachment` per `DebugSession.session_id` across MCP tool calls. `debug.start_session` attaches + registers; each per-op handler looks up the live attachment and issues MI verbs; `debug.end_session` (and every guaranteed-resume teardown) reaps it. The durable record stays HALTED for the whole window; interactive resume verbs are continue-and-wait-for-stop bounded by a 60s ceiling. Every typed record is redacted before return and persistence. The batch `QemuGdbstubProvider` operation methods and `SubprocessGdbRunner` are deleted.

**Tech Stack:** Python 3.11+, `pygdbmi` (parse layer), Pydantic v2 (`Model`/`ConfigModel` with `extra="forbid"`), pytest with injected `FakeController`, ruff + ty.

**Spec:** `docs/superpowers/specs/2026-05-29-debug-gdb-mi-tier-design.md` · **ADR:** `docs/adr/0021-gdb-mi-phase-c-session-registry-and-execution-state.md`

**Conventions every task follows:**
- TDD: write the failing test first, run it red, implement, run it green, commit.
- Guardrails green at every commit: `uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q`.
- Engine tests use the existing `FakeController` in `tests/test_gdb_mi_engine.py` (scripted list-of-responses double). Handler tests inject fakes per the repo contract.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

- **Modify** `src/linux_debug_mcp/providers/gdb_mi.py` — add `read()` to the `MiController` seam + `PygdbmiController`; add typed records `StopRecord`, `Frame`, `Variable`, `BreakpointRef`; add engine methods `wait_for_stop`, `interrupt`, `resume`, `step`/`next`/`finish`, `set_breakpoint`, `clear_breakpoint`, `list_breakpoints`, `set_watchpoint`, `clear_watchpoint`, `backtrace`, `list_variables`, `read_registers`, `read_memory`, `read_symbol`, `evaluate_inspector`; add `GdbMiSessionRegistry`; bound + redact all returned records.
- **Modify** `src/linux_debug_mcp/config.py:95-123` — add the new ops to `ALLOWED_DEBUG_OPERATIONS`.
- **Modify** `src/linux_debug_mcp/server.py` — wire `GdbMiSessionRegistry` in `create_app`; keep the live attachment in `debug.start_session`; re-point the per-op handlers onto the engine; add handlers + tool registrations for the new ops; reap in `debug.end_session`.
- **Modify** `src/linux_debug_mcp/providers/qemu_gdbstub.py` — delete the `-batch` argv paths, `run_batch`, `SubprocessGdbRunner`, and the per-op provider methods; keep `local_qemu_gdbstub_capability()` (re-pointed operations) and `DebugSession`/`DebugProviderResult`/`ProviderDebugError`/validators reused by handlers.
- **Create** `tests/test_gdb_mi_core_ops.py` — engine unit tests for the new methods.
- **Create** `tests/test_gdb_mi_session_registry.py` — registry unit tests.
- **Modify** `tests/test_qemu_gdbstub_provider.py` — drop deleted-method tests; keep validators.
- **Modify** `tests/test_server_debug_mi_probe.py` + add `tests/test_server_debug_core_ops.py` — handler tests on the engine path.
- **Create** `tests/test_no_batch_gdb.py` — static tripwire: no `-batch` gdb invocation remains.

---

## Task 1: Static tripwire — no `-batch` gdb invocation remains

Write this first so it is red until the deletion lands; it pins the acceptance "No batch-mode gdb invocation remains."

**Files:**
- Test: `tests/test_no_batch_gdb.py`

The batch paths still exist until Task 14, so the assertion would be red now. To keep the suite green at every commit, the tripwire is committed as `xfail(strict=True)` and **flipped to a normal passing test in Task 14** (the deletion makes it pass; `strict=True` makes an unexpected pass before then a failure, so it can't silently rot).

- [ ] **Step 1: Write the xfail tripwire**

```python
from __future__ import annotations

from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "linux_debug_mcp"


@pytest.mark.xfail(strict=True, reason="batch gdb paths deleted in Phase C Task 14; flip to a plain test then")
def test_no_batch_gdb_invocation_remains() -> None:
    """ADR 0021 decision 4 / acceptance: one engine, no batch. No source file may
    construct a `-batch` gdb argv or keep the batch runner after Phase C."""
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if '"-batch"' in text or "'-batch'" in text or "run_batch" in text or "SubprocessGdbRunner" in text:
            offenders.append(str(path.relative_to(SRC)))
    assert offenders == [], f"batch gdb paths still present in: {offenders}"
```

- [ ] **Step 2: Run it — expect XFAIL** (suite stays green).

Run: `uv run python -m pytest tests/test_no_batch_gdb.py -q`
Expected: `1 xfailed` (green suite).

- [ ] **Step 3: Commit the xfail tripwire**

```bash
git add tests/test_no_batch_gdb.py
git commit -m "test(gdb-mi): add xfail tripwire for residual -batch paths"
```

(Task 14, after deleting the batch paths, removes the `@pytest.mark.xfail` decorator so the test asserts as a normal green gate.)

---

## Task 2: Add `read()` to the `MiController` seam

The async `*stopped` arrives out-of-band, not as a `write()` return (ADR 0021 decision 2). Add the read primitive.

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py:100-130` (the `MiController` Protocol and `PygdbmiController`)
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from pathlib import Path

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.gdb_mi import GdbMiEngine, GdbMiError, MiController


class FakeController:
    """Scripted MiController: write() pops the next write-response; read() pops the next
    read-response (default empty). Each item is a list of raw pygdbmi dicts or an Exception."""

    def __init__(self, writes: list[object], reads: list[object] | None = None) -> None:
        self._writes = list(writes)
        self._reads = list(reads or [])
        self.commands: list[str] = []
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._writes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        if not self._reads:
            return []
        item = self._reads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def exit(self) -> None:
        self.exited = True


def test_fakecontroller_with_read_satisfies_protocol() -> None:
    controller = FakeController([[{"type": "result", "message": "done", "payload": None, "token": None}]])
    assert isinstance(controller, MiController)
```

- [ ] **Step 2: Run it — expect FAIL** (`MiController` has no `read`, so `isinstance` is False).

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py::test_fakecontroller_with_read_satisfies_protocol -q`
Expected: FAIL (assertion error).

- [ ] **Step 3: Add `read` to the seam and the real controller**

In `gdb_mi.py`, extend the Protocol:

```python
@runtime_checkable
class MiController(Protocol):
    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]: ...

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        """Poll for further out-of-band records (the async ``*stopped`` after a ``^running``).
        Returns an empty list when nothing arrived within ``timeout_sec``."""
        ...

    def exit(self) -> None: ...
```

And on `PygdbmiController`:

```python
    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        try:
            return self._controller.get_gdb_response(timeout_sec=timeout_sec, raise_error_on_timeout=False)
        except GdbTimeoutError:
            return []
```

- [ ] **Step 4: Run it — expect PASS**

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py::test_fakecontroller_with_read_satisfies_protocol -q`
Expected: PASS.

- [ ] **Step 5: Update the existing `FakeController` in `tests/test_gdb_mi_engine.py`** to add a no-op `read` so it still satisfies the protocol:

```python
    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []
```

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q`
Expected: PASS (unchanged behavior).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py tests/test_gdb_mi_engine.py
git commit -m "feat(gdb-mi): add read() async-poll primitive to the MiController seam"
```

---

## Task 3: Typed wire records — `StopRecord`, `Frame`, `Variable`, `BreakpointRef`

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py` (near `ResolvedSymbol`, line ~64)
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing test**

```python
from linux_debug_mcp.providers.gdb_mi import BreakpointRef, Frame, StopRecord, Variable


def test_typed_records_construct_and_forbid_extra() -> None:
    frame = Frame(level=0, func="do_sys_open", addr="0xffffffff81234560", file="open.c", line=1234)
    stop = StopRecord(reason="breakpoint-hit", bkptno="1", frame=frame, stopped_thread="1")
    assert stop.reason == "breakpoint-hit"
    assert stop.frame is not None and stop.frame.func == "do_sys_open"
    var = Variable(name="fd", value="3")
    assert var.value == "3"
    bp = BreakpointRef(number="1", type="breakpoint", addr="0xffffffff81234560", func="do_sys_open")
    assert bp.number == "1"
    import pytest

    with pytest.raises(Exception):
        StopRecord(reason="x", bogus_extra="nope")  # extra="forbid"
```

- [ ] **Step 2: Run it — expect FAIL** (types not defined).

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py::test_typed_records_construct_and_forbid_extra -q`
Expected: FAIL (ImportError).

- [ ] **Step 3: Add the types** (after `ResolvedSymbol`):

```python
class Frame(Model):
    """One stack frame from a gdb/MI ``frame={...}`` payload. Optional fields mirror what gdb omits
    for frames without source info. Frozen wire shape (``Model`` => extra="forbid")."""

    level: int | None = None
    func: str | None = None
    addr: str | None = None
    file: str | None = None
    line: int | None = None


class StopRecord(Model):
    """A parsed ``*stopped`` async record. ``reason`` is gdb's stop reason (``breakpoint-hit``,
    ``end-stepping-range``, ``watchpoint-trigger``, ``exited``, ...); ``frame`` is the stop frame.
    ``timed_out`` is True when the wait expired and the handler had to ``-exec-interrupt``."""

    reason: str | None = None
    bkptno: str | None = None
    stopped_thread: str | None = None
    frame: Frame | None = None
    timed_out: bool = False


class Variable(Model):
    """One local/arg from ``-stack-list-variables``. ``value`` is the gdb-rendered value string
    (redacted before return/persist)."""

    name: str
    value: str | None = None


class BreakpointRef(Model):
    """One breakpoint/watchpoint from ``-break-insert``/``-break-watch``/``-break-list``.
    ``number`` is gdb's authoritative breakpoint id."""

    number: str
    type: str | None = None
    addr: str | None = None
    func: str | None = None
    what: str | None = None
    enabled: bool | None = None
```

- [ ] **Step 4: Run it — expect PASS**

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py::test_typed_records_construct_and_forbid_extra -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): add typed StopRecord/Frame/Variable/BreakpointRef wire records"
```

---

## Task 4: `wait_for_stop` + stop classification + non-raising `interrupt`

`resume` (Task 5) depends on both `wait_for_stop` and `interrupt`, so they are built first, here, and tested directly (not through `resume`).

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py` (constants near line 26; methods on `GdbMiEngine`)
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing tests**

```python
from linux_debug_mcp.providers.gdb_mi import StopRecord

_DONE = [{"type": "result", "message": "done", "payload": None, "token": None}]
_CONNECTED = [{"type": "result", "message": "connected", "payload": None, "token": None}]
_RUNNING = [{"type": "result", "message": "running", "payload": None, "token": None}]
_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _CONNECTED]


def _stopped(reason: str) -> list[dict[str, object]]:
    return [{"type": "notify", "message": "stopped",
             "payload": {"reason": reason, "bkptno": "1", "frame": {"func": "do_sys_open", "level": "0"}},
             "token": None}]


def _engine(controller: FakeController, redactor: object | None = None) -> GdbMiEngine:
    return GdbMiEngine(
        controller_factory=lambda command: controller,
        gdb_path_finder=lambda _: "/usr/bin/gdb",
        redactor=redactor,  # None => default Redactor
    )


def _attached(tmp_path: Path, writes: list[object], reads: list[object] | None = None, redactor: object | None = None):
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([*_ATTACH_OK, *writes], reads=reads)
    engine = _engine(controller, redactor=redactor)
    from linux_debug_mcp.transport.base import TcpEndpoint

    attachment = engine.attach(
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),
        vmlinux_path=vmlinux,
        transcript_path=tmp_path / "mi.log",
    )
    return engine, controller, attachment


def test_wait_for_stop_returns_deferred_stopped_record(tmp_path: Path) -> None:
    # The *stopped arrives on a later read() (the first read returns nothing).
    engine, controller, attachment = _attached(tmp_path, writes=[], reads=[[], _stopped("breakpoint-hit")])
    stop = engine.wait_for_stop(attachment, timeout_sec=5)
    assert isinstance(stop, StopRecord)
    assert stop.reason == "breakpoint-hit"
    assert stop.frame is not None and stop.frame.func == "do_sys_open"


def test_wait_for_stop_times_out_to_none(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[], reads=[[]])
    assert engine.wait_for_stop(attachment, timeout_sec=0) is None


def test_wait_for_stop_on_exited_inferior_raises_session_exited(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[], reads=[_stopped("exited-normally")])
    with pytest.raises(GdbMiError) as exc:
        engine.wait_for_stop(attachment, timeout_sec=5)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert exc.value.details.get("code") == "session_exited"


def test_interrupt_on_stopped_engine_tolerates_error(tmp_path: Path) -> None:
    # -exec-interrupt against an already-stopped target returns ^error; interrupt() must not raise.
    err = [{"type": "result", "message": "error", "payload": {"msg": "not being run"}, "token": None}]
    engine, controller, attachment = _attached(tmp_path, writes=[err], reads=[[]])
    stop = engine.interrupt(attachment)
    assert stop is None or isinstance(stop, StopRecord)
    assert "-exec-interrupt" in controller.commands
```

- [ ] **Step 2: Run them — expect FAIL** (`wait_for_stop`/`interrupt` undefined).

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py -k "wait_for_stop or interrupt" -q`
Expected: FAIL.

- [ ] **Step 3: Implement.** Add constants near line 26:

```python
# Max wall-clock an interactive resume verb blocks (ADR 0021 decision 2). NOT the legacy 1-3600s:
# the call holds debug_lock, so it must not outlast a client request timeout.
MAX_INTERACTIVE_WAIT_SEC = 60
# Fixed bound for the post-timeout -exec-interrupt to land its *stopped (SIGINT).
_INTERRUPT_STOP_TIMEOUT_SEC = 10.0
# Poll slice when looping read() toward the deadline.
_STOP_POLL_SLICE_SEC = 0.5
# gdb stop reasons meaning the inferior is gone (not a debuggable HALT).
_TERMINAL_STOP_REASONS = frozenset({"exited", "exited-normally", "exited-signalled"})
```

Note `import time` and `import math` are not used; bound the loop by a monotonic-free slice count derived from `timeout_sec` to keep `Date.now`-free determinism in tests. Implement `wait_for_stop` to poll a fixed number of `read()` slices:

```python
    def wait_for_stop(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord | None:
        """Poll read() until a record with message=="stopped" appears or the slice budget is spent.
        Returns the parsed StopRecord, or None on timeout. Raises GdbMiError(session_exited) on a
        terminal (exited*) stop. The slice budget (not wall-clock) keeps the loop test-deterministic;
        a real read() blocks up to the slice, so the real wall-clock is bounded by timeout_sec."""
        slices = max(1, int(timeout_sec / _STOP_POLL_SLICE_SEC) + 1)
        for _ in range(slices):
            raw = attachment.controller.read(timeout_sec=_STOP_POLL_SLICE_SEC)
            records = self._records_from(raw)
            attachment.records.extend(records)
            if records:
                self._append_transcript(attachment.transcript_path, "<read>", records)
            stop = next((r for r in records if r.message == "stopped"), None)
            if stop is not None:
                return self._stop_record_from(stop)
        return None

    def _stop_record_from(self, record: MiRecord) -> StopRecord:
        payload = record.payload if isinstance(record.payload, dict) else {}
        reason = payload.get("reason")
        if isinstance(reason, str) and reason in _TERMINAL_STOP_REASONS:
            raise GdbMiError(
                f"gdb/MI inferior exited ({reason}); the debug session is dead",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"code": "session_exited", "reason": reason},
            )
        frame_payload = payload.get("frame")
        frame = self._frame_from(frame_payload) if isinstance(frame_payload, dict) else None
        return StopRecord(
            reason=reason if isinstance(reason, str) else None,
            bkptno=payload.get("bkptno") if isinstance(payload.get("bkptno"), str) else None,
            stopped_thread=payload.get("stopped-threads") if isinstance(payload.get("stopped-threads"), str) else None,
            frame=frame,
        )

    def _frame_from(self, payload: dict[str, Any]) -> Frame:
        def _int(value: object) -> int | None:
            return int(value) if isinstance(value, str) and value.lstrip("-").isdigit() else None

        return Frame(
            level=_int(payload.get("level")),
            func=payload.get("func") if isinstance(payload.get("func"), str) else None,
            addr=payload.get("addr") if isinstance(payload.get("addr"), str) else None,
            file=payload.get("file") if isinstance(payload.get("file"), str) else None,
            line=_int(payload.get("line")),
        )

    def interrupt(self, attachment: GdbMiAttachment) -> StopRecord | None:
        """Idempotent 'ensure HALTED'. Issues -exec-interrupt without routing through the
        raising _run (an already-stopped target answers ^error 'not being run', which is benign),
        then waits the short fixed bound for the SIGINT stop. Returns the StopRecord if one arrived,
        else None. Only a controller fault (write raising) propagates."""
        raw = attachment.controller.write("-exec-interrupt", timeout_sec=_MI_COMMAND_TIMEOUT_SEC)
        records = self._records_from(raw)
        attachment.records.extend(records)
        self._append_transcript(attachment.transcript_path, "-exec-interrupt", records)
        stop = self.wait_for_stop(attachment, timeout_sec=_INTERRUPT_STOP_TIMEOUT_SEC)
        return self._redact_stop(stop) if stop is not None else None

    def _redact_stop(self, stop: StopRecord) -> StopRecord:
        return StopRecord.model_validate(self._redactor.redact_value(stop.model_dump(mode="json")))
```

- [ ] **Step 4: Run them — expect PASS**

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py -k "wait_for_stop or interrupt" -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): wait_for_stop + stop classification + non-raising interrupt"
```

---

## Task 5: `resume` (continue) over `wait_for_stop` + `interrupt`

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_continue_waits_for_deferred_stopped_record(tmp_path: Path) -> None:
    # -exec-continue returns ^running; the *stopped arrives on a later read().
    engine, controller, attachment = _attached(tmp_path, writes=[_RUNNING], reads=[[], _stopped("breakpoint-hit")])
    stop = engine.resume(attachment, "-exec-continue", timeout_sec=5)
    assert isinstance(stop, StopRecord)
    assert stop.reason == "breakpoint-hit"
    assert stop.timed_out is False
    assert "-exec-continue" in controller.commands


def test_continue_timeout_interrupts_and_marks_timed_out(tmp_path: Path) -> None:
    # No *stopped arrives on read() before the budget is spent; resume -exec-interrupts and collects
    # the SIGINT stop on a follow-up read.
    engine, controller, attachment = _attached(
        tmp_path,
        writes=[_RUNNING, [{"type": "result", "message": "done", "payload": None, "token": None}]],
        reads=[[], _stopped("signal-received")],
    )
    stop = engine.resume(attachment, "-exec-continue", timeout_sec=0)  # 0 => one read slice, then interrupt
    assert stop.timed_out is True
    assert "-exec-interrupt" in controller.commands
```

- [ ] **Step 2: Run them — expect FAIL** (`resume` undefined).

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py -k "continue" -q`
Expected: FAIL.

- [ ] **Step 3: Implement** (after `interrupt`):

```python
    def resume(self, attachment: GdbMiAttachment, verb: str, *, timeout_sec: float) -> StopRecord:
        """Issue an interactive exec verb (-exec-continue/-step/-next/-finish), wait for the stop,
        and return a redacted StopRecord. On timeout, -exec-interrupt back to a known stop and mark
        timed_out=True. Always returns HALTED (or raises session_exited)."""
        bounded = max(1, min(int(timeout_sec) if timeout_sec else MAX_INTERACTIVE_WAIT_SEC, MAX_INTERACTIVE_WAIT_SEC))
        self._run(attachment, verb)  # ^running under mi-async on
        stop = self.wait_for_stop(attachment, timeout_sec=bounded)
        if stop is not None:
            return self._redact_stop(stop)
        interrupted = self.interrupt(attachment)
        return self._redact_stop((interrupted or StopRecord()).model_copy(update={"timed_out": True}))
```

Note: `timeout_sec=0` yields `bounded=max(1, min(60, 60))`? No — `int(0) if 0 else 60` evaluates the `else` because `0` is falsy, giving `60`. For the timeout *test* to force the interrupt path deterministically, `wait_for_stop` must exhaust its read budget; with `reads=[[]]` the single empty slice returns None, then `interrupt` runs. Keep `wait_for_stop`'s `slices = max(1, int(timeout_sec / _STOP_POLL_SLICE_SEC) + 1)` so a small budget still polls at least once. The test scripts exactly one empty read before the interrupt's stop, so it is deterministic regardless of the bound.

- [ ] **Step 4: Run them — expect PASS**, then the full file.

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): resume verb (continue) with bounded wait + timeout interrupt"
```

---

## Task 6: `GdbMiSessionRegistry`

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_session_registry.py`

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from pathlib import Path

import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.gdb_mi import GdbMiAttachment, GdbMiError, GdbMiSessionRegistry


class _Ctrl:
    def __init__(self) -> None:
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        return []

    def exit(self) -> None:
        self.exited = True


def _attachment(tmp_path: Path) -> GdbMiAttachment:
    return GdbMiAttachment(controller=_Ctrl(), rsp_host="127.0.0.1", rsp_port=1, transcript_path=tmp_path / "t.log")


def test_register_get_reap_roundtrip(tmp_path: Path) -> None:
    reg = GdbMiSessionRegistry()
    att = _attachment(tmp_path)
    reg.register("sid-1", att)
    assert reg.get("sid-1") is att
    reaped = reg.reap("sid-1")
    assert reaped is att
    assert reg.get("sid-1") is None  # gone after reap


def test_require_missing_raises_no_live_session(tmp_path: Path) -> None:
    reg = GdbMiSessionRegistry()
    with pytest.raises(GdbMiError) as exc:
        reg.require("absent")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert exc.value.details.get("code") == "no_live_session"


def test_reap_absent_is_noop(tmp_path: Path) -> None:
    reg = GdbMiSessionRegistry()
    assert reg.reap("absent") is None
```

- [ ] **Step 2: Run it — expect FAIL** (`GdbMiSessionRegistry` undefined).

Run: `uv run python -m pytest tests/test_gdb_mi_session_registry.py -q`
Expected: FAIL.

- [ ] **Step 3: Implement** (add `import threading` at top):

```python
class GdbMiSessionRegistry:
    """In-process holder of live GdbMiAttachments keyed by DebugSession.session_id (ADR 0021
    decision 1). Lock-guards the dict; the live engine is server-process-scoped, not durable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, GdbMiAttachment] = {}

    def register(self, session_id: str, attachment: GdbMiAttachment) -> None:
        with self._lock:
            self._sessions[session_id] = attachment

    def get(self, session_id: str) -> GdbMiAttachment | None:
        with self._lock:
            return self._sessions.get(session_id)

    def require(self, session_id: str) -> GdbMiAttachment:
        attachment = self.get(session_id)
        if attachment is None:
            raise GdbMiError(
                "no live gdb/MI session; the engine is gone (server restarted or session reaped)",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"code": "no_live_session", "debug_session_id": session_id},
            )
        return attachment

    def reap(self, session_id: str) -> GdbMiAttachment | None:
        with self._lock:
            return self._sessions.pop(session_id, None)
```

- [ ] **Step 4: Run it — expect PASS**

Run: `uv run python -m pytest tests/test_gdb_mi_session_registry.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_session_registry.py
git commit -m "feat(gdb-mi): in-process GdbMiSessionRegistry keyed by debug session id"
```

---

## Task 7: Breakpoints + watchpoints on the engine

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing tests**

```python
from linux_debug_mcp.providers.gdb_mi import BreakpointRef

_BKPT_OK = [{"type": "result", "message": "done",
             "payload": {"bkpt": {"number": "1", "type": "breakpoint", "addr": "0xffffffff81234560",
                                  "func": "do_sys_open"}}, "token": None}]
_WPT_OK = [{"type": "result", "message": "done",
            "payload": {"wpt": {"number": "2", "exp": "jiffies"}}, "token": None}]


def test_set_breakpoint_returns_typed_ref(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_BKPT_OK])
    bp = engine.set_breakpoint(attachment, "do_sys_open")
    assert isinstance(bp, BreakpointRef)
    assert bp.number == "1" and bp.func == "do_sys_open"
    assert controller.commands[-1] == "-break-insert do_sys_open"


def test_set_breakpoint_rejects_non_identifier(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.set_breakpoint(attachment, "do_sys_open; call panic")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before


def test_set_watchpoint_issues_break_watch(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_WPT_OK])
    bp = engine.set_watchpoint(attachment, "jiffies")
    assert bp.number == "2"
    assert controller.commands[-1] == "-break-watch jiffies"


def test_clear_breakpoint_issues_break_delete(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_DONE])
    engine.clear_breakpoint(attachment, "1")
    assert controller.commands[-1] == "-break-delete 1"


def test_clear_breakpoint_rejects_non_numeric_id(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    with pytest.raises(GdbMiError) as exc:
        engine.clear_breakpoint(attachment, "1; quit")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_clear_watchpoint_uses_break_delete(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_DONE])
    engine.clear_watchpoint(attachment, "2")
    assert controller.commands[-1] == "-break-delete 2"
```

- [ ] **Step 2: Run — expect FAIL.**

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py -k "breakpoint or watchpoint" -q`
Expected: FAIL.

- [ ] **Step 3: Implement.** Add a symbol validator reuse and the methods. Reuse `SYMBOL_PATTERN` from `qemu_gdbstub` is undesirable (avoid cross-provider import); define a local one near `_SYMBOL_NAME_RE`:

```python
# Breakpoint location: a bare C identifier (function/symbol). Watchpoints take the same.
_BREAK_LOCATION_RE = _SYMBOL_NAME_RE
_BREAK_ID_RE = re.compile(r"^[0-9]+$")
```

```python
    def set_breakpoint(self, attachment: GdbMiAttachment, location: str) -> BreakpointRef:
        if not _BREAK_LOCATION_RE.match(location):
            raise GdbMiError(
                f"breakpoint location must be a bare C identifier, got {location!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"location": location},
            )
        records = self._run(attachment, f"-break-insert {location}")
        return self._breakpoint_ref(records, key="bkpt")

    def set_watchpoint(self, attachment: GdbMiAttachment, expression: str) -> BreakpointRef:
        if not _BREAK_LOCATION_RE.match(expression):
            raise GdbMiError(
                f"watchpoint expression must be a bare C identifier, got {expression!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"expression": expression},
            )
        records = self._run(attachment, f"-break-watch {expression}")
        return self._breakpoint_ref(records, key="wpt")

    def clear_breakpoint(self, attachment: GdbMiAttachment, number: str) -> None:
        if not _BREAK_ID_RE.match(number):
            raise GdbMiError(
                f"breakpoint id must be numeric, got {number!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"number": number},
            )
        self._run(attachment, f"-break-delete {number}")

    # A watchpoint is a breakpoint to gdb; clearing one is the same `-break-delete <n>` verb. Kept as
    # a named method so the debug.clear_watchpoint handler has an explicit engine target.
    def clear_watchpoint(self, attachment: GdbMiAttachment, number: str) -> None:
        self.clear_breakpoint(attachment, number)

    def list_breakpoints(self, attachment: GdbMiAttachment) -> list[BreakpointRef]:
        records = self._run(attachment, "-break-list")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        table = payload.get("BreakpointTable") if isinstance(payload.get("BreakpointTable"), dict) else {}
        body = table.get("body") if isinstance(table, dict) else None
        rows = body if isinstance(body, list) else []
        refs: list[BreakpointRef] = []
        for row in rows:
            entry = row.get("bkpt") if isinstance(row, dict) else None
            if isinstance(entry, dict):
                refs.append(self._breakpoint_ref_from(entry))
        return refs

    def _breakpoint_ref(self, records: list[MiRecord], *, key: str) -> BreakpointRef:
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        entry = payload.get(key)
        if not isinstance(entry, dict):
            raise GdbMiError(
                f"gdb/MI {key} response had no breakpoint record",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command_key": key},
            )
        return self._breakpoint_ref_from(entry)

    def _breakpoint_ref_from(self, entry: dict[str, Any]) -> BreakpointRef:
        return BreakpointRef.model_validate(
            self._redactor.redact_value(
                {
                    "number": str(entry.get("number")),
                    "type": entry.get("type") if isinstance(entry.get("type"), str) else None,
                    "addr": entry.get("addr") if isinstance(entry.get("addr"), str) else None,
                    "func": entry.get("func") if isinstance(entry.get("func"), str) else None,
                    "what": entry.get("what") if isinstance(entry.get("what"), str) else None,
                }
            )
        )
```

- [ ] **Step 4: Run — expect PASS.**

Run: `uv run python -m pytest tests/test_gdb_mi_core_ops.py -k "breakpoint or watchpoint" -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): set/clear/list breakpoints and watchpoints via MI"
```

---

## Task 8: backtrace + list_variables (redacted, bounded)

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing tests**

```python
_FRAMES = [{"type": "result", "message": "done",
            "payload": {"stack": [{"frame": {"level": "0", "func": "do_sys_open", "addr": "0x1"}},
                                  {"frame": {"level": "1", "func": "__x64_sys_open", "addr": "0x2"}}]},
            "token": None}]
_VARS = [{"type": "result", "message": "done",
          "payload": {"variables": [{"name": "fd", "value": "3"},
                                    {"name": "token", "value": "<a-secret-shaped-value>"}]}, "token": None}]


def test_backtrace_returns_typed_frames(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_FRAMES])
    frames = engine.backtrace(attachment)
    assert [f.func for f in frames] == ["do_sys_open", "__x64_sys_open"]
    assert controller.commands[-1] == "-stack-list-frames"


class _StubRedactor:
    """Proves the redaction PATH is wired without depending on the default Redactor's patterns:
    every value is replaced with a sentinel. Mirrors the real Redactor's two methods used by the
    engine (`redact_value` recurses; `redact_text` masks a string)."""

    def redact_value(self, value: object) -> object:
        if isinstance(value, dict):
            return {k: self.redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_value(v) for v in value]
        if isinstance(value, str):
            return "[REDACTED]"
        return value

    def redact_text(self, value: str) -> str:
        return "[REDACTED]"


def test_list_variables_passes_values_through_redactor(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_VARS], redactor=_StubRedactor())
    variables = engine.list_variables(attachment)
    names = {v.name for v in variables}
    assert names == {"[REDACTED]"} or names == {"fd", "token"}  # names may or may not be masked; values must be
    token = next(v for v in variables if v.value is not None)
    assert token.value == "[REDACTED]"  # the value went through the injected redactor
    assert controller.commands[-1] == "-stack-list-variables --all-values"
```

Note the stub masks every string, so both name and value become `[REDACTED]`; the assertion's first clause covers that. The structural guarantee under test is "the value passed through the engine's redactor," which is exactly what ADR 0021 decision 2c requires. (The `GdbMiEngine.__init__` already accepts `redactor`; `None` keeps the default `Redactor`.)

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement:**

```python
    def backtrace(self, attachment: GdbMiAttachment) -> list[Frame]:
        records = self._run(attachment, "-stack-list-frames")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        stack = payload.get("stack") if isinstance(payload.get("stack"), list) else []
        frames: list[Frame] = []
        for row in stack:
            frame_payload = row.get("frame") if isinstance(row, dict) else None
            if isinstance(frame_payload, dict):
                frames.append(self._frame_from(self._redactor.redact_value(frame_payload)))
        return frames

    def list_variables(self, attachment: GdbMiAttachment) -> list[Variable]:
        records = self._run(attachment, "-stack-list-variables --all-values")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        rows = payload.get("variables") if isinstance(payload.get("variables"), list) else []
        variables: list[Variable] = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                continue
            value = row.get("value")
            value_text = value[:MAX_RESPONSE_SNIPPET] if isinstance(value, str) else None
            variables.append(
                Variable.model_validate(
                    self._redactor.redact_value({"name": row["name"], "value": value_text})
                )
            )
        return variables
```

Add `MAX_RESPONSE_SNIPPET = 4096` near the top of `gdb_mi.py` (do not import from `qemu_gdbstub`, which is being gutted).

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): backtrace + list_variables (redacted, bounded)"
```

---

## Task 9: registers, memory (4096 cap), read_symbol, evaluate inspectors

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing tests**

```python
_REG_NAMES = [{"type": "result", "message": "done",
               "payload": {"register-names": ["rax", "rbx", "pc"]}, "token": None}]
_REG_VALUES = [{"type": "result", "message": "done",
                "payload": {"register-values": [{"number": "0", "value": "0x10"},
                                                {"number": "1", "value": "0x20"},
                                                {"number": "2", "value": "0xffffffff81000000"}]}, "token": None}]
_MEM = [{"type": "result", "message": "done",
         "payload": {"memory": [{"begin": "0x1000", "contents": "deadbeef"}]}, "token": None}]
_EVAL_BANNER = [{"type": "result", "message": "done",
                 "payload": {"value": "Linux version 6.9.0 ..."}, "token": None}]
_EVAL_ADDR = [{"type": "result", "message": "done",
               "payload": {"value": "0xffffffff82000000 <jiffies>"}, "token": None}]


def test_read_registers_returns_only_requested(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_REG_NAMES, _REG_VALUES])
    result = engine.read_registers(attachment, ["pc"])
    assert set(result["registers"].keys()) == {"pc"}  # not rax/rbx
    assert result["registers"]["pc"] == "0xffffffff81000000"


def test_read_memory_rejects_over_cap_without_touching_gdb(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.read_memory(attachment, address=0x1000, byte_count=4097)
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before  # cap enforced before any MI command


def test_read_memory_within_cap_issues_data_read(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_MEM])
    result = engine.read_memory(attachment, address=0x1000, byte_count=4)
    assert controller.commands[-1] == "-data-read-memory-bytes 0x1000 4"
    assert result  # contains the contents


def test_evaluate_kernel_version_uses_banner(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_EVAL_BANNER])
    value = engine.evaluate_inspector(attachment, inspector="kernel_version", arguments={})
    assert "Linux version" in value["kernel_version"]


def test_evaluate_symbol_address_resolves_name(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_EVAL_ADDR])
    value = engine.evaluate_inspector(attachment, inspector="symbol_address", arguments={"symbol": "jiffies"})
    assert value["symbol"] == "jiffies"
    assert controller.commands[-1] == '-data-evaluate-expression "&jiffies"'


def test_evaluate_unknown_inspector_rejected_before_gdb(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.evaluate_inspector(attachment, inspector="$(rm -rf)", arguments={})
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before


def test_read_symbol_evaluates_validated_name(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_EVAL_BANNER])
    value = engine.read_symbol(attachment, "linux_banner")
    assert "Linux version" in value["value"]
    assert controller.commands[-1] == '-data-evaluate-expression "linux_banner"'
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement:**

```python
    def read_registers(self, attachment: GdbMiAttachment, register_names: list[str]) -> dict[str, object]:
        if not isinstance(register_names, list) or not register_names:
            raise GdbMiError("registers must be a non-empty list", category=ErrorCategory.CONFIGURATION_ERROR)
        requested: list[str] = []
        for name in register_names:
            if not isinstance(name, str) or not _REGISTER_RE.match(name):
                raise GdbMiError(f"invalid register name {name!r}", category=ErrorCategory.CONFIGURATION_ERROR)
            requested.append(name)
        # gdb keys register VALUES by ordinal number; map names->ordinals via -data-list-register-names,
        # then return only the requested names (the legacy op filtered; preserve that).
        names_payload = MiRecord.first_result(self._run(attachment, "-data-list-register-names")).payload
        ordered = names_payload.get("register-names") if isinstance(names_payload, dict) else None
        ordered_names = ordered if isinstance(ordered, list) else []
        values_payload = MiRecord.first_result(self._run(attachment, "-data-list-register-values x")).payload
        rows = values_payload.get("register-values") if isinstance(values_payload, dict) else None
        by_number = {
            row.get("number"): row.get("value")
            for row in (rows if isinstance(rows, list) else [])
            if isinstance(row, dict)
        }
        registers: dict[str, object] = {}
        for name in requested:
            if name in ordered_names:
                ordinal = str(ordered_names.index(name))
                if ordinal in by_number:
                    registers[name] = by_number[ordinal]
        return self._redactor.redact_value({"registers": registers})

    def read_memory(self, attachment: GdbMiAttachment, *, address: int, byte_count: int) -> dict[str, object]:
        if not isinstance(address, int) or not isinstance(byte_count, int):
            raise GdbMiError("address and byte_count must be integers", category=ErrorCategory.CONFIGURATION_ERROR)
        if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
            raise GdbMiError("address out of range", category=ErrorCategory.CONFIGURATION_ERROR)
        if byte_count < 1 or byte_count > MAX_MEMORY_READ_BYTES:
            raise GdbMiError(
                "byte_count must be between 1 and 4096", category=ErrorCategory.CONFIGURATION_ERROR
            )
        records = self._run(attachment, f"-data-read-memory-bytes 0x{address:x} {byte_count}")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        return self._redactor.redact_value(
            {"address": f"0x{address:x}", "byte_count": byte_count, "memory": payload.get("memory", [])}
        )

    def read_symbol(self, attachment: GdbMiAttachment, symbol: str) -> dict[str, object]:
        if not _SYMBOL_NAME_RE.match(symbol):
            raise GdbMiError(
                f"symbol name must be a bare C identifier, got {symbol!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"symbol": symbol},
            )
        value = self._evaluate_expression(attachment, f'"{symbol}"')
        return self._redactor.redact_value({"symbol": symbol, "value": value})

    def evaluate_inspector(
        self, attachment: GdbMiAttachment, *, inspector: str, arguments: dict[str, object]
    ) -> dict[str, object]:
        if inspector == "kernel_version":
            value = self._evaluate_expression(attachment, f'"{CANONICAL_PROBE_SYMBOL}"')
            return self._redactor.redact_value({"inspector": inspector, "kernel_version": value})
        if inspector == "symbol_address":
            symbol = arguments.get("symbol")
            if not isinstance(symbol, str) or not _SYMBOL_NAME_RE.match(symbol):
                raise GdbMiError(
                    "symbol_address requires a bare C identifier 'symbol'",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                )
            resolved = self.resolve_symbol(attachment, symbol)
            return self._redactor.redact_value(
                {"inspector": inspector, "symbol": symbol, "address": resolved.value}
            )
        raise GdbMiError(
            "unknown debug inspector", category=ErrorCategory.CONFIGURATION_ERROR, details={"inspector": inspector}
        )

    def _evaluate_expression(self, attachment: GdbMiAttachment, quoted: str) -> str:
        records = self._run(attachment, f"-data-evaluate-expression {quoted}")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None else None
        value = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(value, str):
            raise GdbMiError(
                "gdb/MI returned no value", category=ErrorCategory.DEBUG_ATTACH_FAILURE, details={"expr": quoted}
            )
        return value
```

Add near the top: `MAX_MEMORY_READ_BYTES = 4096` and `_REGISTER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")`.

Note `read_symbol` uses `_SYMBOL_NAME_RE` (bare identifier). The legacy `SYMBOL_PATTERN` also allowed `.`/`$`; the spec narrows `read_symbol` to a bare identifier, which is the constrained surface. Document this narrowing in the commit body.

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): registers/memory(4096 cap)/read_symbol/evaluate on the engine"
```

---

## Task 10: `step`/`next`/`finish` resume wrappers

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_core_ops.py`

- [ ] **Step 1: Write the failing tests**

```python
import pytest


@pytest.mark.parametrize("method,verb", [("step", "-exec-step"), ("next", "-exec-next"), ("finish", "-exec-finish")])
def test_step_family_issues_verb_and_returns_stop(tmp_path: Path, method: str, verb: str) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_RUNNING], reads=[_stopped("end-stepping-range")])
    stop = getattr(engine, method)(attachment, timeout_sec=5)
    assert stop.reason == "end-stepping-range"
    assert verb in controller.commands
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** (thin wrappers over `resume`):

```python
    def continue_(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-continue", timeout_sec=timeout_sec)

    def step(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-step", timeout_sec=timeout_sec)

    def next(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-next", timeout_sec=timeout_sec)

    def finish(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-finish", timeout_sec=timeout_sec)
```

- [ ] **Step 4: Run — expect PASS**, then `uv run python -m pytest tests/test_gdb_mi_core_ops.py tests/test_gdb_mi_engine.py -q`.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_core_ops.py
git commit -m "feat(gdb-mi): step/next/finish resume verbs"
```

---

## Task 11: Extend `ALLOWED_DEBUG_OPERATIONS`

**Files:**
- Modify: `src/linux_debug_mcp/config.py:95-123`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_config.py`):

```python
def test_new_phase_c_debug_operations_are_allowed() -> None:
    from linux_debug_mcp.config import ALLOWED_DEBUG_OPERATIONS

    for op in [
        "debug.step",
        "debug.next",
        "debug.finish",
        "debug.backtrace",
        "debug.list_variables",
        "debug.set_watchpoint",
        "debug.clear_watchpoint",
    ]:
        assert op in ALLOWED_DEBUG_OPERATIONS


def test_default_debug_profile_enables_new_ops() -> None:
    from linux_debug_mcp.config import DebugProfile

    profile = DebugProfile(name="x", architecture="x86_64")
    assert "debug.step" in profile.enabled_operations
    assert "debug.set_watchpoint" in profile.enabled_operations
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** — insert the seven ops into `ALLOWED_DEBUG_OPERATIONS` after `debug.list_breakpoints`:

```python
    "debug.list_breakpoints",
    "debug.step",
    "debug.next",
    "debug.finish",
    "debug.backtrace",
    "debug.list_variables",
    "debug.set_watchpoint",
    "debug.clear_watchpoint",
    "debug.read_registers",
```

- [ ] **Step 4: Run — expect PASS.** Also run `uv run python -m pytest tests/test_config.py tests/test_introspect_helpers.py -q` to confirm no enum/list assumptions broke.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_config.py
git commit -m "feat(config): allow Phase C structured debug operations"
```

---

## Task 12: Wire the registry + keep the live session in `start_session`

This is the server integration. The handler currently runs `_run_mi_attach_probe` (which resumes-and-detaches) and then the batch `provider.start_session`. Change it so the MI engine **stays attached** and is **registered**, and the batch `start_session` is removed from the path.

**Files:**
- Modify: `src/linux_debug_mcp/server.py:6220-6226` (engine creation) and `:6759-6776` (tool registration), `:4056-4133` (`_run_mi_attach_probe`), `:4352-4420` (start_session body)
- Test: `tests/test_server_debug_mi_probe.py` (migrate), `tests/test_server_debug_core_ops.py` (new)

- [ ] **Step 1: Write the failing handler test** (new file `tests/test_server_debug_core_ops.py`), modeled on `test_server_debug_mi_probe.py`'s fixtures (`build_txn`, `FakeQemuTransport`, `write_vmlinux_with_build_id`, `publish_ready_snapshot`). Inject a `FakeMiEngine` whose `attach` returns a fake attachment and a `GdbMiSessionRegistry`. Assert that after `debug_start_session_handler(... gdb_mi_engine=engine, gdb_mi_sessions=registry)` succeeds, `registry.get(session_id)` is not None (the session stayed live) and the success data carries `mi_probe`.

Use the existing test module as the fixture template; the new assertion is the live-session registration. (Full fixture code mirrors `test_server_debug_mi_probe.py`; copy its imports and `build_txn`/snapshot setup verbatim, then:)

```python
def test_start_session_keeps_engine_attached_and_registered(tmp_path, monkeypatch):
    # ... identical setup to test_server_debug_mi_probe's happy-path test ...
    registry = GdbMiSessionRegistry()
    engine = FakeMiEngine()  # attach -> attachment; probe_read -> connected; resolve_symbol -> banner
    response = debug_start_session_handler(
        artifact_root=artifact_root, run_id=RUN_ID,
        transaction=txn, admission=admission, session_registry=session_registry, session_guard=guard,
        gdb_mi_engine=engine, gdb_mi_sessions=registry,
    )
    assert response.ok
    session_id = response.data["debug_session_id"]
    assert registry.get(session_id) is not None  # ADR 0021: live session held across calls
    assert "mi_probe" in response.data
```

- [ ] **Step 2: Run — expect FAIL** (`gdb_mi_sessions` param does not exist; engine detaches).

- [ ] **Step 3: Implement.**
  1. Add a module-level `GdbMiSessionRegistry` import and a `gdb_mi_sessions: GdbMiSessionRegistry | None = None` param to `debug_start_session_handler`.
  2. In `create_app`, construct `gdb_mi_sessions = GdbMiSessionRegistry()` next to `gdb_mi_engine = GdbMiEngine()` and pass it into the `debug.start_session` tool wrapper.
  3. **Mint `session_id` once, before the probe.** Inside the locked section, immediately before the `gdb_mi_engine is not None` probe branch, mint `session_id = f"debug-{uuid4().hex}"`. This single id is threaded into BOTH the probe (which registers the live attachment under it) and `_build_mi_debug_session` (which persists it as `DebugSession.session_id`), so the registry key and the persisted id are identical — the per-op lookup in Task 13 finds the right attachment. The probe registering earlier than the DebugSession is built is exactly why the id cannot be minted inside the helper.
  4. Replace `_run_mi_attach_probe`'s `engine.resume_and_detach(attachment)` with: on success, `gdb_mi_sessions.register(session_id, attachment)` and return the probe details **without** detaching. The function gains `session_id` and `gdb_mi_sessions` params. The fault path still calls `force_resume` + teardown + (now) `gdb_mi_sessions.reap(session_id)`.
  5. Remove the batch `provider.start_session(...)` call; build the `DebugSession`/`StepResult` from the MI attach with the **already-minted `session_id`**. The handler now owns the run-relative paths the deleted provider used to mint. Add a small `_build_mi_debug_session(...)` helper in `server.py` that takes `session_id` as a parameter (it does NOT mint one) and populates **every required `DebugSession` field**:

```python
def _build_mi_debug_session(*, session_id: str, run_id: str, vmlinux_path: Path,
                            gdbstub_endpoint: dict[str, object], profile_name: str,
                            transcript_path: Path, started_at: str) -> DebugSession:
    attempt_dir = transcript_path.parent  # <run>/debug/mi-probe.log lives in <run>/debug; keep paths under it
    return DebugSession(
        session_id=session_id,  # minted once in the handler before the probe; same id the registry holds
        run_id=run_id,
        provider_name="local-qemu-gdbstub",
        gdbstub_endpoint=gdbstub_endpoint,
        vmlinux_path=str(vmlinux_path),
        selected_debug_profile=profile_name,
        attach_status="attached",
        started_at=started_at,
        ended_at=None,
        current_execution_state="stopped",
        breakpoints={},
        controller_mode="attached",
        active_controller_pid=None,
        controller_last_observed_state="attached",
        active_controller_identity={},
        transcript_path=str(transcript_path),
        command_metadata_path=str(attempt_dir / "commands.jsonl"),
        latest_summary_path=str(attempt_dir / "debug-summary.json"),
        symbol_identity_validation={},  # build_id gate is authoritative (ADR 0021 2b); no live-banner scrape
    )
```

  The legacy `controller_mode`/`active_controller_pid` fields are retained on the model (other code reads them) but are inert — the live registry is the liveness source. Persist `transport_session_id` and `mi_probe` into the step details as today. Add `from uuid import uuid4` if not already imported. (The existing `_run_mi_attach_probe` builds its own `mi-probe.log` transcript path from `run_dir`; pass that same path into `_build_mi_debug_session` so the persisted `transcript_path` is the live session's transcript.)

- [ ] **Step 4: Run — expect PASS**; migrate `test_server_debug_mi_probe.py` (the probe now leaves the session attached: drop assertions that the engine `resume_and_detach`'d; keep the guard-refusal and guaranteed-resume-on-fault assertions, which now also assert `registry.get(session_id) is None` after a fault).

Run: `uv run python -m pytest tests/test_server_debug_mi_probe.py tests/test_server_debug_core_ops.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_debug_mi_probe.py tests/test_server_debug_core_ops.py
git commit -m "feat(server): hold the live gdb/MI session in start_session via the registry"
```

---

## Task 13: Re-point the per-op handlers onto the engine

`_debug_operation_response` currently does `getattr(provider, method_name)(...)` against the batch provider. Re-point it to look up the live attachment and call the engine.

**Files:**
- Modify: `src/linux_debug_mcp/server.py:4641-4733` (`_debug_operation_response`), and each handler's signature to thread `gdb_mi_engine`/`gdb_mi_sessions`.
- Test: `tests/test_server_debug_core_ops.py`

- [ ] **Step 1: Write failing tests** — for each op, inject a fake engine + a registry pre-populated with a fake attachment, call the handler (e.g. `debug_set_breakpoint_handler(... gdb_mi_engine=engine, gdb_mi_sessions=registry)`), assert the response is `ToolResponse.success` with the typed data, and that the op was gated through `_ensure_debug_operation_enabled`. Add a test that a missing live session returns `CONFIGURATION_ERROR` / `no_live_session`. Add a test that `debug.read_memory` with `byte_count=4097` returns `CONFIGURATION_ERROR`. Add a test that `debug.evaluate` with an unknown inspector returns `CONFIGURATION_ERROR`.

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement.** Introduce an engine-dispatch map keyed by `method_name` that calls the matching engine method with the live attachment, replacing the `getattr(provider, ...)` call. Keep the fence/ownership checks and `_ensure_debug_operation_enabled` exactly as they are (they run before the lookup — ADR 0021 fence-then-lookup). Wrap `GdbMiError` → `ToolResponse.failure(category=exc.category, details=exc.details, ...)`. Persist the typed result into the `DebugSession` step details (redacted) for the mutating ops. The breakpoint ledger update reads `engine.list_breakpoints(attachment)` after a set/clear so the persisted ledger matches gdb.

  Map (method_name → engine call). `end_session` is **not** in this map — it has a dedicated path (Task 14) that reaps the live attachment and closes the transaction, so the generic dispatch must explicitly skip/ignore `end_session` (the end_session handler does not call the engine dispatch for a verb):
  - `read_registers` → `engine.read_registers(att, registers)`
  - `read_symbol` → `engine.read_symbol(att, symbol)`
  - `read_memory` → `engine.read_memory(att, address=..., byte_count=...)`
  - `evaluate` → `engine.evaluate_inspector(att, inspector=..., arguments=...)`
  - `set_breakpoint` → `engine.set_breakpoint(att, symbol)`
  - `clear_breakpoint` → `engine.clear_breakpoint(att, breakpoint_id)`
  - `clear_watchpoint` → `engine.clear_watchpoint(att, breakpoint_id)`
  - `set_watchpoint` → `engine.set_watchpoint(att, symbol)`
  - `list_breakpoints` → `engine.list_breakpoints(att)`
  - `continue_execution` → `engine.continue_(att, timeout_sec=...)`
  - `step` → `engine.step(att, timeout_sec=...)`
  - `next` → `engine.next(att, timeout_sec=...)`
  - `finish` → `engine.finish(att, timeout_sec=...)`
  - `backtrace` → `engine.backtrace(att)`
  - `list_variables` → `engine.list_variables(att)`
  - `interrupt` → `engine.interrupt(att)`

- [ ] **Step 4: Run — expect PASS.**

Run: `uv run python -m pytest tests/test_server_debug_core_ops.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_debug_core_ops.py
git commit -m "feat(server): re-point debug.* ops onto the live gdb/MI engine"
```

---

## Task 14: New handlers + tool registrations; reap in end_session; delete batch

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (new handlers `debug_step_handler`/`debug_next_handler`/`debug_finish_handler`/`debug_backtrace_handler`/`debug_list_variables_handler`/`debug_set_watchpoint_handler`/`debug_clear_watchpoint_handler` + `@app.tool` registrations; reap in `debug_end_session_handler`); add `DEBUG_METHOD_OPERATIONS` entries for the new ops.
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py` (delete batch).
- Test: `tests/test_server_debug_core_ops.py`, `tests/test_no_batch_gdb.py`, `tests/test_qemu_gdbstub_provider.py`

- [ ] **Step 1: Write failing tests** — handler tests for `debug.step`/`next`/`finish` (return typed `StopRecord` data), `debug.backtrace` (frames), `debug.list_variables` (redacted), `debug.set_watchpoint`/`debug.clear_watchpoint`; and an `end_session` test asserting `registry.get(session_id) is None` after success.

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** the new handlers following the `_debug_stateful_response` pattern (they all take `gdb_mi_engine`/`gdb_mi_sessions`), register them with `@app.tool(name="debug.step")` etc., add the `DEBUG_METHOD_OPERATIONS` mappings (`step`→`debug.step`, `next`→`debug.next`, `finish`→`debug.finish`, `backtrace`→`debug.backtrace`, `list_variables`→`debug.list_variables`, `set_watchpoint`→`debug.set_watchpoint`, `clear_watchpoint`→`debug.clear_watchpoint`).

  **`debug_end_session_handler` change (explicit, not via the engine dispatch).** end_session must reap the live attachment, not issue an interactive verb. Before the existing transaction-close logic, look up and reap the session:

```python
    if gdb_mi_sessions is not None and debug_session_id is not None:
        reaped = gdb_mi_sessions.reap(debug_session_id)
        if reaped is not None and gdb_mi_engine is not None:
            gdb_mi_engine.force_resume(reaped)  # best-effort continue + RSP disconnect + kill
```

  This runs inside `debug_lock` alongside recording the ended `DebugSession` (build the ended session in the handler now that the provider's `end_session` is gone: copy the persisted session with `current_execution_state="ended"`, `ended_at=<now>`, `attach_status` unchanged). The existing `transaction.close(force=True)` / SessionGuard teardown path is unchanged. Thread `gdb_mi_engine`/`gdb_mi_sessions` into `debug_end_session_handler` and its `@app.tool` wrapper. A reap of an absent session is a no-op (idempotent end_session).

  Then **delete** from `providers/qemu_gdbstub.py`: the `-batch` argv construction in `start_session` and `_run_read_operation`, the whole `start_session`/`read_registers`/`read_symbol`/`read_memory`/`evaluate`/`set_breakpoint`/`clear_breakpoint`/`list_breakpoints`/`continue_execution`/`interrupt`/`end_session`/`_run_read_operation`/`_record_stateful_operation` methods, `run_batch`, `SubprocessGdbRunner`, and `GdbRunner`. Keep `local_qemu_gdbstub_capability()` (its `operations` list now references `ALLOWED_DEBUG_OPERATIONS` + the new ops), `DebugSession`, `DebugProviderResult`, `ProviderDebugError`, and the validators/`_gdb_path` helpers still imported by the server. If nothing else imports `QemuGdbstubProvider`, delete the class; otherwise reduce it to the capability factory.

- [ ] **Step 3b: Flip the tripwire.** Now that the batch paths are deleted, remove the `@pytest.mark.xfail(strict=True, ...)` decorator (and the unused `import pytest` if nothing else needs it) from `tests/test_no_batch_gdb.py` so it asserts as a normal green gate.

- [ ] **Step 4: Run — expect PASS**, including the now-green tripwire:

Run: `uv run python -m pytest tests/test_no_batch_gdb.py tests/test_server_debug_core_ops.py tests/test_qemu_gdbstub_provider.py -q`
Expected: PASS (`test_no_batch_gdb_invocation_remains` passes normally, not xfail).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py src/linux_debug_mcp/providers/qemu_gdbstub.py tests/
git commit -m "feat(server): add step/next/finish/backtrace/list_variables/watchpoints; delete batch engine"
```

---

## Task 15: Full guardrails + integration test refresh

**Files:**
- Modify: `tests/test_qemu_gdbstub_integration.py` (assert the engine-backed path; keep env-gating intact)

- [ ] **Step 1: Update the gated integration test** so its post-boot assertions exercise the engine path (set a breakpoint by symbol, continue, backtrace, read a local, step) and remain `pytest.skip`-gated without `LINUX_DEBUG_MCP_LIVE_GDBSTUB=1`. Do not un-gate.

- [ ] **Step 2: Run the whole suite + guardrails**

```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q
```
Expected: all green; the gated integration tests SKIP.

- [ ] **Step 3: Commit**

```bash
git add tests/test_qemu_gdbstub_integration.py
git commit -m "test(gdb-mi): exercise the engine path in the gated integration test"
```

---

## Self-Review checklist (run before opening the PR)

- [ ] **Spec coverage:** every Phase C acceptance bullet maps to a task — breakpoint/continue/backtrace/local (Tasks 7/5/8/9 + 15 integration), step/next/finish (Tasks 10/13/14), no `-batch` (Tasks 1/14), 4096 cap (Task 9), evaluate allowlist + arbitrary-expression rejection (Tasks 9/13), `no_live_session` ordering (Tasks 6/13), watchpoints (Tasks 7/14), profile opt-in (Task 11), redaction of new records (Tasks 8/9), `read_symbol` migration (Task 9), `read_registers` filtering (Task 9), `end_session` reap (Task 14), `clear_watchpoint` engine path (Tasks 7/13).
- [ ] **Placeholder scan:** no TBD/TODO; every code step has real code.
- [ ] **Type consistency:** `StopRecord`/`Frame`/`Variable`/`BreakpointRef` names and `resume`/`continue_`/`step`/`next`/`finish`/`interrupt`/`set_breakpoint`/`clear_breakpoint`/`list_breakpoints`/`set_watchpoint`/`clear_watchpoint`/`backtrace`/`list_variables`/`read_registers`/`read_memory`/`read_symbol`/`evaluate_inspector` are used identically across tasks; `gdb_mi_sessions`/`gdb_mi_engine` param names are consistent.
- [ ] No relative imports introduced; all absolute (`linux_debug_mcp....`).
