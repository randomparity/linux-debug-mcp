# debug.gdb Phase A — gdb/MI engine foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a persistent `gdb --interpreter=mi3` engine (parsed by `pygdbmi`) that attaches to a target over the gdb Remote Serial Protocol via `TransportSession.rsp_endpoint`, reads one MI record as typed JSON, and detaches cleanly — with a guaranteed-resume invariant that never leaves the kernel `HALTED` on error — plus a gdb-MI capability prerequisite probe.

**Architecture:** A new `providers/gdb_mi.py` holds the engine (`GdbMiEngine`), an injectable `MiController` seam (real impl wraps `pygdbmi.GdbController`; fakes used in unit tests), and typed `MiRecord` records. The engine is wired into the **transport-enabled** branch of `debug_start_session_handler` as an additive attach-probe that runs against `TransportSession.rsp_endpoint` *before* the legacy batch `provider.start_session`. The probe is gated on a new injected `gdb_mi_engine` argument — `None` (every existing test) preserves current behavior exactly; `create_app()` wires a real engine; the new Phase-A tests inject fakes. On any probe fault the engine performs a best-effort `-exec-continue` + detach/kill (RSP disconnect resumes QEMU), and the handler tears the transaction down — un-halting the durable record when resume is confirmed so a fresh ssh-tier op succeeds. The batch read-ops paths and the batch `start_session` remain the session-of-record until Phase C (per ADR 0019, "replace, don't deprecate": the batch paths are deleted in Phase C, not Phase A).

**Tech Stack:** Python 3.11+, `pygdbmi==0.11.0.0` (new pinned runtime dep), Pydantic v2 (`Model`/`ConfigModel`, `extra="forbid"`), pytest with injected fakes, ruff + ty.

---

## Context the implementer must know

- **QEMU's gdbstub accepts a single TCP connection.** The Phase-A engine therefore **attaches → reads one record → detaches** rather than holding the connection across calls; that keeps the legacy batch read-ops (which each connect transiently) working until Phase C migrates them. This is the documented coexistence window (ADR 0019 Consequences).
- **Handlers are the unit of testing** — call `debug_start_session_handler(...)` directly with injected `transaction=`, `admission=`, `session_registry=`, and the new `gdb_mi_engine=`. Do not go through MCP.
- **`ToolResponse.success/failure`** with the most specific `ErrorCategory`; populate `suggested_next_actions` with literal tool names (`"artifacts.get_manifest"`, `"debug.read_registers"`, …).
- **Redaction:** any gdb/MI transcript text or record payload that is returned **or persisted** goes through `Redactor()` (`redact_text`, `redact_value`). Raw transcripts stay on disk under `<run>/debug/`; only redacted snippets go into responses.
- **`Model`** (domain.py) and **`ConfigModel`** (config.py) both set `extra="forbid"` and `validate_assignment=True`. New wire models inherit `Model`.
- **Existing seam APIs** (verified):
  - `StopCapableGuard.acquire(target_key) -> GuardToken` raises `GuardConflict` (a bare `RuntimeError` subclass, **no `code` attribute**) on a second acquire. The handler already maps `GuardConflict` → `ErrorCategory.TRANSPORT_CONFLICT` with `details={"code": getattr(exc, "code", "stop_capable_conflict")}`. **Note:** the issue text says `stop_session_conflict`; the implemented code value is `stop_capable_conflict`. Do **not** invent a new code — assert the implemented value and flag the wording mismatch in the PR body.
  - `TransportSession.rsp_endpoint: Endpoint | None` is a `TcpEndpoint` (loopback-pinned `host`, `port`) on the qemu-gdbstub path.
  - `transaction.open(request, recovery=...) -> TransportSession`; `transaction.close(session_id, force=bool)`; `transaction.force_release(session_id)`.
  - `_halt_debug_transport(session=, admission=, session_registry=)` writes the durable record `HALTED` + bumps the execution epoch + cancels in-flight ssh-tier.
  - `PrerequisiteRunner` protocol: `which(cmd) -> str|None`, `run(argv, timeout) -> (returncode, stdout, stderr)`. `check_prerequisites(*, artifact_root, source_path, enable_libvirt_check, runner=None)` returns `list[PrerequisiteCheck]`.
- **pygdbmi facts** (verified against 0.11.0.0):
  - `GdbController(command: list[str] | None = None, time_to_check_for_additional_output_sec: float = 0.2)`.
  - `.write(mi_cmd, timeout_sec=1, raise_error_on_timeout=True, read_response=True) -> list[dict]`; raises `pygdbmi.constants.GdbTimeoutError` on timeout.
  - `.exit() -> None` terminates the subprocess.
  - `pygdbmi.gdbmiparser.parse_response(line: str) -> dict` with keys `type` (`result`/`notify`/`exec`/`console`/`log`/`output`/`target`), `message` (str|None), `payload` (dict|list|str|None), `token` (int|None). The `stream` key may or may not be present depending on the record — treat it as optional.

---

## File Structure

- **Create** `src/linux_debug_mcp/providers/gdb_mi.py` — typed `MiRecord`, `GdbMiError`, the `MiController` protocol + `PygdbmiController` real impl, and `GdbMiEngine` (attach / probe_read / resume_and_detach / force_resume).
- **Modify** `pyproject.toml` — add `pygdbmi==0.11.0.0` to `[project] dependencies`.
- **Modify** `src/linux_debug_mcp/prereqs/checks.py` — add `_gdb_mi_capability_check(runner)` (min gdb 9.1 + mi3 `^done` probe) to `check_prerequisites`.
- **Modify** `src/linux_debug_mcp/server.py` — `_resume_debug_transport` helper; new `gdb_mi_engine` arg on `debug_start_session_handler`; the additive MI attach-probe in the transport-enabled branch; wire a real `GdbMiEngine` in `create_app()`'s debug.start_session tool.
- **Create** `tests/test_gdb_mi_engine.py` — engine unit tests (attach/probe/detach, guaranteed-resume, RSP-timeout, tool-exception) via a fake `MiController`.
- **Create** `tests/test_gdb_mi_record.py` — `MiRecord` parsing/typing unit tests.
- **Create** `tests/test_prereqs_gdb_mi.py` — capability-probe unit tests via fake `PrerequisiteRunner`.
- **Create** `tests/test_server_debug_mi_probe.py` — handler-level tests: happy-path probe, guard-conflict on qemu-gdbstub (no lease), and the three fault-injection cases with ssh-tier behavior, using `_layer4_fakes` + a fake engine.
- **Create** `tests/test_gdb_mi_integration.py` — gated end-to-end against real gdb + QEMU gdbstub (skipped when the live env is absent).

---

## Task 1: Add the pinned `pygdbmi` runtime dependency

**Files:**
- Modify: `pyproject.toml:11-14`

- [ ] **Step 1: Add the dependency**

Edit the `dependencies` list so it reads:

```toml
dependencies = [
  "mcp>=1.9,<2",
  "pydantic>=2.7,<3",
  "pygdbmi==0.11.0.0",
]
```

- [ ] **Step 2: Sync the environment**

Run: `uv pip install -e '.[test]'`
Expected: installs `pygdbmi==0.11.0.0` with no resolution error.

- [ ] **Step 3: Supply-chain audit**

Run: `uv pip install pip-audit >/dev/null 2>&1; uv run pip-audit 2>&1 | tail -20`
Expected: no known vulnerability attributed to `pygdbmi`. If pip-audit reports an advisory for `pygdbmi`, stop and surface it (do not proceed). Record the audit result in the PR body.

- [ ] **Step 4: Verify the import resolves**

Run: `uv run python -c "from pygdbmi.gdbcontroller import GdbController; from pygdbmi.gdbmiparser import parse_response; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml
git commit -m "build: add pinned pygdbmi runtime dependency"
```

---

## Task 2: Typed `MiRecord` + parse layer

**Files:**
- Create: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_record.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_gdb_mi_record.py
from __future__ import annotations

import pytest

from linux_debug_mcp.providers.gdb_mi import MiRecord, parse_mi_records


def test_parse_result_done_record() -> None:
    [record] = parse_mi_records('^done,features=["frozen-varobjs"]')
    assert isinstance(record, MiRecord)
    assert record.type == "result"
    assert record.message == "done"
    assert record.payload == {"features": ["frozen-varobjs"]}
    assert record.token is None


def test_parse_running_and_stopped() -> None:
    records = parse_mi_records('^running\n*stopped,reason="breakpoint-hit",thread-id="1"')
    assert [r.message for r in records] == ["running", "stopped"]
    assert records[1].type == "notify"
    assert records[1].payload == {"reason": "breakpoint-hit", "thread-id": "1"}


def test_parse_console_stream_record() -> None:
    [record] = parse_mi_records('~"hello\\n"')
    assert record.type == "console"
    assert record.payload == "hello\n"


def test_parse_ignores_blank_lines_and_gdb_prompt() -> None:
    # the literal MI terminator "(gdb)" and blank lines are not records
    records = parse_mi_records("\n(gdb)\n^done\n")
    assert [r.message for r in records] == ["done"]


def test_first_result_record_helper() -> None:
    records = parse_mi_records('~"noise\\n"\n^done,value="0x1"')
    result = MiRecord.first_result(records)
    assert result is not None and result.message == "done" and result.payload == {"value": "0x1"}
    assert MiRecord.first_result(parse_mi_records('~"only console\\n"')) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_gdb_mi_record.py -q`
Expected: FAIL with `ModuleNotFoundError` / `ImportError` (module not yet created).

- [ ] **Step 3: Write minimal implementation**

Create `src/linux_debug_mcp/providers/gdb_mi.py` with the record layer:

```python
from __future__ import annotations

from typing import Any

from pygdbmi.gdbmiparser import parse_response

from linux_debug_mcp.domain import Model

# The literal MI prompt terminator gdb emits between command results; not a record.
_MI_PROMPT = "(gdb)"
# Keys pygdbmi may emit on a parsed record; whitelist so an unexpected extra key is dropped
# rather than tripping the extra="forbid" model boundary.
_KNOWN_KEYS = ("type", "message", "payload", "token", "stream")


class MiRecord(Model):
    """One parsed gdb/MI record (gdb manual "GDB/MI Output Syntax"). `type` is the MI record
    class (`result`/`notify`/`exec`/`console`/`log`/`output`/`target`); `message` is the result
    class (`done`/`running`/`connected`/`error`/`exit`) or async class; `payload` is the parsed
    value tree. Frozen wire shape (`Model` ⇒ extra="forbid")."""

    type: str
    message: str | None = None
    payload: dict[str, Any] | list[Any] | str | None = None
    token: int | None = None
    stream: str | None = None

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> MiRecord:
        return cls(**{key: raw[key] for key in _KNOWN_KEYS if key in raw})

    @staticmethod
    def first_result(records: list[MiRecord]) -> MiRecord | None:
        """The first `result`-class record (`^done`/`^running`/`^error`/…), or None."""
        return next((record for record in records if record.type == "result"), None)


def parse_mi_records(text: str) -> list[MiRecord]:
    """Parse newline-delimited MI output into typed records, skipping blank lines and the
    literal `(gdb)` prompt terminator. Used both for the controller's returned dicts (already
    parsed) and for raw transcript text in tests."""
    records: list[MiRecord] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped == _MI_PROMPT:
            continue
        records.append(MiRecord.from_raw(parse_response(stripped)))
    return records
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_gdb_mi_record.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_record.py
git commit -m "feat(gdb-mi): add typed MiRecord and MI parse layer"
```

---

## Task 3: `MiController` seam + `GdbMiError` + real `PygdbmiController`

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_engine.py` (the controller-level slice)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_gdb_mi_engine.py
from __future__ import annotations

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.gdb_mi import GdbMiError, MiController


class FakeController:
    """Injectable MiController: each write() pops the next scripted response (a list of raw
    pygdbmi dicts) or raises the scripted exception. Records every command for assertions."""

    def __init__(self, scripted: list[object]) -> None:
        self._scripted = list(scripted)
        self.commands: list[str] = []
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._scripted.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def exit(self) -> None:
        self.exited = True


def test_facecontroller_satisfies_protocol() -> None:
    controller = FakeController([[{"type": "result", "message": "done", "payload": None, "token": None}]])
    assert isinstance(controller, MiController)


def test_gdb_mi_error_carries_category() -> None:
    err = GdbMiError("boom", category=ErrorCategory.DEBUG_ATTACH_FAILURE, details={"k": "v"})
    assert err.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert err.details == {"k": "v"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q`
Expected: FAIL with `ImportError` (`GdbMiError`, `MiController` not defined).

- [ ] **Step 3: Write minimal implementation**

Append to `src/linux_debug_mcp/providers/gdb_mi.py`:

```python
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, runtime_checkable

from pygdbmi.constants import GdbTimeoutError

from linux_debug_mcp.domain import ErrorCategory

# Minimum gdb release that documents the mi3 interpreter (GDB manual "GDB/MI" chapter).
MIN_GDB_VERSION = (9, 1)
# Per-command MI write timeout. The attach `-target-select remote` and the probe read are the only
# Phase-A commands; 10s comfortably bounds a healthy localhost RSP connect without hanging the tool.
_MI_COMMAND_TIMEOUT_SEC = 10.0


class GdbMiError(Exception):
    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.details = details or {}


@runtime_checkable
class MiController(Protocol):
    """The injectable subprocess seam. The real impl drives a `gdb --interpreter=mi3` child via
    pygdbmi; tests inject a scripted fake. `write` returns the raw pygdbmi record dicts for the
    command; `exit` terminates the child."""

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]: ...

    def exit(self) -> None: ...


class PygdbmiController:
    """Real `MiController`: a managed `gdb --interpreter=mi3` subprocess via `pygdbmi`."""

    def __init__(self, command: list[str]) -> None:
        from pygdbmi.gdbcontroller import GdbController

        self._controller = GdbController(command=command)

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        try:
            return self._controller.write(command, timeout_sec=timeout_sec, raise_error_on_timeout=True)
        except GdbTimeoutError as exc:
            raise GdbMiError(
                f"gdb/MI command timed out after {timeout_sec}s: {command}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command, "timeout_seconds": timeout_sec},
            ) from exc

    def exit(self) -> None:
        self._controller.exit()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_engine.py
git commit -m "feat(gdb-mi): add MiController seam, GdbMiError, pygdbmi controller"
```

---

## Task 4: `GdbMiEngine` — attach / probe_read / resume_and_detach / force_resume

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_engine.py`

The engine never raises out of the resume paths (guaranteed-resume invariant). `attach`/`probe_read` may raise `GdbMiError`; the handler catches it and calls `force_resume`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_gdb_mi_engine.py`:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.providers.gdb_mi import GdbMiEngine, MiRecord
from linux_debug_mcp.transport.base import TcpEndpoint

_DONE: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
_CONNECTED: list[dict[str, object]] = [{"type": "result", "message": "connected", "payload": None, "token": None}]
_RUNNING: list[dict[str, object]] = [{"type": "result", "message": "running", "payload": None, "token": None}]
_BANNER: list[dict[str, object]] = [
    {"type": "result", "message": "done", "payload": {"value": "Linux version 6.9.0-test"}, "token": None}
]


def _engine(controller: FakeController, tmp_path: Path) -> tuple[GdbMiEngine, object]:
    engine = GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")
    return engine, engine


def _endpoint() -> TcpEndpoint:
    return TcpEndpoint(host="127.0.0.1", port=5551)


def test_attach_loads_symbols_and_selects_remote(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([_DONE, _DONE, _DONE, _CONNECTED])  # set confirm/pagination, file, target-select
    engine = GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")
    attachment = engine.attach(
        rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "debug" / "mi.log"
    )
    assert any(cmd.startswith("-file-exec-and-symbols") for cmd in controller.commands)
    assert any(cmd == "-target-select remote 127.0.0.1:5551" for cmd in controller.commands)
    assert MiRecord.first_result(attachment.records).message == "connected"
    assert (tmp_path / "debug" / "mi.log").is_file()  # transcript persisted


def test_attach_rejects_non_loopback_endpoint(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([])
    engine = GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")
    with pytest.raises(GdbMiError) as exc:
        engine.attach(
            rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),  # patched below to non-loopback via monkeypatch
            vmlinux_path=vmlinux,
            transcript_path=tmp_path / "mi.log",
        ) if False else engine._validate_rsp_host("10.0.0.5")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_attach_missing_gdb_raises_missing_dependency(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    engine = GdbMiEngine(controller_factory=lambda command: FakeController([]), gdb_path_finder=lambda _: None)
    with pytest.raises(GdbMiError) as exc:
        engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    assert exc.value.category == ErrorCategory.MISSING_DEPENDENCY


def test_probe_read_returns_one_typed_record(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([_DONE, _DONE, _DONE, _CONNECTED, _BANNER])
    engine = GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    record = engine.probe_read(attachment)
    assert isinstance(record, MiRecord)
    assert record.message == "done"
    assert record.payload == {"value": "Linux version 6.9.0-test"}


def test_resume_and_detach_continues_then_exits(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([_DONE, _DONE, _DONE, _CONNECTED, _RUNNING, _DONE])
    engine = GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    confirmed = engine.resume_and_detach(attachment)
    assert confirmed is True
    assert controller.exited is True
    assert "-exec-continue" in controller.commands
    assert any(cmd.startswith("-target-detach") for cmd in controller.commands)


def test_force_resume_swallows_errors_and_kills(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    # continue raises, detach raises — force_resume must still exit() and report resume confirmed
    # because killing the controller disconnects RSP, which resumes QEMU.
    controller = FakeController(
        [_DONE, _DONE, _DONE, _CONNECTED, RuntimeError("continue failed"), RuntimeError("detach failed")]
    )
    engine = GdbMiEngine(controller_factory=lambda command: controller, gdb_path_finder=lambda _: "/usr/bin/gdb")
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    confirmed = engine.force_resume(attachment)
    assert confirmed is True
    assert controller.exited is True
```

> Note: `test_attach_rejects_non_loopback_endpoint` exercises the private `_validate_rsp_host` guard directly because `TcpEndpoint` already pins loopback at its own schema boundary, so a non-loopback value cannot be constructed to pass in. Keep the engine's own guard anyway (defense in depth) and test it directly.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q`
Expected: FAIL (`GdbMiEngine` not defined).

- [ ] **Step 3: Write the engine implementation**

Append to `src/linux_debug_mcp/providers/gdb_mi.py`:

```python
import contextlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from linux_debug_mcp.safety.redaction import Redactor
from linux_debug_mcp.transport.base import Endpoint, TcpEndpoint


@dataclass
class GdbMiAttachment:
    """A live attach: the controller plus the typed records produced by the connect sequence."""

    controller: MiController
    rsp_host: str
    rsp_port: int
    records: list[MiRecord] = field(default_factory=list)


class GdbMiEngine:
    """Persistent `gdb --interpreter=mi3` engine. Phase A: attach over RSP, read one MI record as
    typed JSON, detach cleanly — and never leave the target HALTED on error (force_resume)."""

    def __init__(
        self,
        *,
        controller_factory: Callable[[list[str]], MiController] | None = None,
        gdb_path_finder: Callable[[str], str | None] = shutil.which,
        redactor: Redactor | None = None,
    ) -> None:
        self._controller_factory = controller_factory or (lambda command: PygdbmiController(command))
        self._gdb_path_finder = gdb_path_finder
        self._redactor = redactor or Redactor()

    def attach(self, *, rsp_endpoint: Endpoint | None, vmlinux_path: Path, transcript_path: Path) -> GdbMiAttachment:
        host, port = self._validate_endpoint(rsp_endpoint)
        gdb_path = self._gdb_path_finder("gdb")
        if gdb_path is None:
            raise GdbMiError(
                "missing required gdb tool", category=ErrorCategory.MISSING_DEPENDENCY, details={"missing_tools": ["gdb"]}
            )
        resolved_vmlinux = vmlinux_path.expanduser().resolve()
        if not resolved_vmlinux.is_file():
            raise GdbMiError(
                "vmlinux symbol file does not exist",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"vmlinux_path": str(vmlinux_path)},
            )
        controller = self._controller_factory([gdb_path, "--nx", "--quiet", "--interpreter=mi3"])
        attachment = GdbMiAttachment(controller=controller, rsp_host=host, rsp_port=port)
        try:
            self._run(attachment, "-gdb-set confirm off", transcript_path)
            self._run(attachment, "-gdb-set pagination off", transcript_path)
            self._run(attachment, f"-file-exec-and-symbols {self._mi_path(resolved_vmlinux)}", transcript_path)
            self._run(attachment, f"-target-select remote {host}:{port}", transcript_path)
        except GdbMiError:
            with contextlib.suppress(Exception):
                controller.exit()
            raise
        return attachment

    def probe_read(self, attachment: GdbMiAttachment, *, command: str = '-data-evaluate-expression "linux_banner"') -> MiRecord:
        """Read one MI record as typed JSON (Phase-A foundation read). Returns the result record."""
        # transcript is reused from attach(); resolve it from the controller-independent path on the
        # attachment is not stored, so callers pass the same transcript_path they used for attach.
        records = self._records_from(attachment.controller.write(command, timeout_sec=_MI_COMMAND_TIMEOUT_SEC))
        result = MiRecord.first_result(records)
        if result is None:
            raise GdbMiError(
                "gdb/MI probe read returned no result record",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command},
            )
        if result.message == "error":
            raise GdbMiError(
                "gdb/MI probe read returned an error record",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command, "payload": self._redactor.redact_value(result.payload)},
            )
        return result

    def resume_and_detach(self, attachment: GdbMiAttachment) -> bool:
        """Clean teardown: continue the target, detach, exit the engine. Returns whether resume is
        confirmed (RSP disconnect via exit() resumes QEMU even if MI commands fail)."""
        return self._resume(attachment)

    def force_resume(self, attachment: GdbMiAttachment) -> bool:
        """Fault teardown: identical best-effort resume; never raises. The guaranteed-resume path."""
        return self._resume(attachment)

    def _resume(self, attachment: GdbMiAttachment) -> bool:
        with contextlib.suppress(Exception):
            attachment.controller.write("-exec-continue", timeout_sec=_MI_COMMAND_TIMEOUT_SEC)
        with contextlib.suppress(Exception):
            attachment.controller.write("-target-detach", timeout_sec=_MI_COMMAND_TIMEOUT_SEC)
        # exit() kills gdb → RSP TCP disconnect → QEMU resumes the guest. This is the backstop that
        # makes resume guaranteed even when continue/detach failed (e.g. a crashed engine).
        with contextlib.suppress(Exception):
            attachment.controller.exit()
        return True

    def _run(self, attachment: GdbMiAttachment, command: str, transcript_path: Path) -> None:
        records = self._records_from(attachment.controller.write(command, timeout_sec=_MI_COMMAND_TIMEOUT_SEC))
        attachment.records.extend(records)
        self._append_transcript(transcript_path, command, records)
        result = MiRecord.first_result(records)
        if result is not None and result.message == "error":
            raise GdbMiError(
                f"gdb/MI command failed: {command}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command, "payload": self._redactor.redact_value(result.payload)},
            )

    def _records_from(self, raw: list[dict[str, object]]) -> list[MiRecord]:
        return [MiRecord.from_raw(item) for item in raw]

    def _validate_endpoint(self, rsp_endpoint: Endpoint | None) -> tuple[str, int]:
        if not isinstance(rsp_endpoint, TcpEndpoint):
            raise GdbMiError(
                "transport session has no TCP RSP endpoint to attach over",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"rsp_endpoint": None if rsp_endpoint is None else rsp_endpoint.kind},
            )
        self._validate_rsp_host(rsp_endpoint.host)
        return rsp_endpoint.host, rsp_endpoint.port

    def _validate_rsp_host(self, host: str) -> None:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise GdbMiError(
                f"gdb/MI RSP host must be a loopback IP literal, got {host!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )

    def _mi_path(self, path: Path) -> str:
        text = str(path)
        if any(char in text for char in "\t\r\n"):
            raise GdbMiError("vmlinux path must not contain control whitespace", category=ErrorCategory.CONFIGURATION_ERROR)
        return text.replace("\\", "\\\\").replace(" ", "\\ ")

    def _append_transcript(self, transcript_path: Path, command: str, records: list[MiRecord]) -> None:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "observed_at": datetime.now(UTC).isoformat(),
            "command": command,
            "records": [record.model_dump(mode="json") for record in records],
        }
        with transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(self._redactor.redact_value(entry), default=str))
            handle.write("\n")
```

> The probe_read transcript: keep it simple — `probe_read` does not append to the transcript in Phase A (the attach sequence already wrote the connect records). If a reviewer wants the probe recorded, add a `transcript_path` parameter to `probe_read` mirroring `attach`. Do **not** leave a TODO; either omit or implement. (This plan omits it — the probe record is returned to the handler, which persists it via the debug step details.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q`
Expected: PASS (all engine tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_engine.py
git commit -m "feat(gdb-mi): add GdbMiEngine attach/probe/guaranteed-resume"
```

---

## Task 5: gdb-MI capability prerequisite probe

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/checks.py:37-55` (add the check to `check_prerequisites`) and append `_gdb_mi_capability_check`
- Test: `tests/test_prereqs_gdb_mi.py`

The probe runs **two** `runner.run` calls: `gdb --version` (parse `(major, minor)`) and the mi3 round-trip `gdb -nx -q --interpreter=mi3 -ex "-list-features" -ex "-gdb-exit"` (assert a `^done` result record in stdout). Pass requires both: version ≥ 9.1 **and** a valid mi3 `^done`. `gdb` absent → FAILED naming the requirement.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_prereqs_gdb_mi.py
from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.prereqs.checks import check_prerequisites

_VERSION_ARGV = ["gdb", "--version"]
_MI_ARGV = ["gdb", "-nx", "-q", "--interpreter=mi3", "-ex", "-list-features", "-ex", "-gdb-exit"]


class FakeRunner:
    def __init__(self, *, present: bool, version_out: str, mi_out: str, mi_code: int = 0) -> None:
        self._present = present
        self._version_out = version_out
        self._mi_out = mi_out
        self._mi_code = mi_code

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if self._present else None

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        if command == _VERSION_ARGV:
            return (0, self._version_out, "")
        if command == _MI_ARGV:
            return (self._mi_code, self._mi_out, "")
        return (0, "", "")


def _check(runner, tmp_path: Path):
    checks = check_prerequisites(
        artifact_root=tmp_path / "runs", source_path=None, enable_libvirt_check=False, runner=runner
    )
    return {check.check_id: check for check in checks}["tool.gdb_mi"]


def test_gdb_mi_probe_passes_on_modern_gdb(tmp_path: Path) -> None:
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 12.1\n", mi_out='^done,features=[]\n(gdb)\n')
    check = _check(runner, tmp_path)
    assert check.status == "passed"
    assert "12.1" in check.message


def test_gdb_mi_probe_fails_on_old_gdb_naming_versions(tmp_path: Path) -> None:
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 8.3.1\n", mi_out='^done\n(gdb)\n')
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "8.3" in check.message and "9.1" in check.message  # names detected + required


def test_gdb_mi_probe_fails_when_no_done_record(tmp_path: Path) -> None:
    # gdb accepts the mi3 name but yields no usable ^done record
    runner = FakeRunner(present=True, version_out="GNU gdb (GDB) 12.1\n", mi_out="garbage\n", mi_code=1)
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "mi3" in check.message.lower()


def test_gdb_mi_probe_fails_when_gdb_absent(tmp_path: Path) -> None:
    runner = FakeRunner(present=False, version_out="", mi_out="")
    check = _check(runner, tmp_path)
    assert check.status == "failed"
    assert "9.1" in check.message
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_prereqs_gdb_mi.py -q`
Expected: FAIL (`tool.gdb_mi` check absent → KeyError).

- [ ] **Step 3: Write the implementation**

In `src/linux_debug_mcp/prereqs/checks.py`, add to the imports at the top:

```python
import re
```

Append `_gdb_mi_capability_check` and register it. First add the call inside `check_prerequisites` right after the `_tool_check` loop (after line 49's `_agent_proxy_check` call is fine; place it before `_compiler_check`):

```python
    checks.append(_gdb_mi_capability_check(runner))
```

Then add the function and helpers at module scope:

```python
_GDB_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)(?:\.\d+)?\b")
_MI_MIN_VERSION = (9, 1)


def _parse_gdb_version(text: str) -> tuple[int, int] | None:
    match = _GDB_VERSION_RE.search(text)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def _gdb_mi_capability_check(runner: PrerequisiteRunner) -> PrerequisiteCheck:
    """Verify gdb supports the mi3 machine interface the debug.gdb tier requires: gdb must be
    present, at least 9.1 (the GDB manual's documented mi3 introduction), and must answer one mi3
    command with a well-formed `^done` record — not merely accept the `mi3` interpreter name."""
    required = f"{_MI_MIN_VERSION[0]}.{_MI_MIN_VERSION[1]}"
    if runner.which("gdb") is None:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=f"gdb was not found; the debug.gdb tier requires gdb >= {required} with mi3 support",
            suggested_fix=f"Install gdb >= {required} with your distribution package manager.",
        )
    try:
        _code, version_out, _err = runner.run(["gdb", "--version"], 10)
        mi_code, mi_out, _mi_err = runner.run(
            ["gdb", "-nx", "-q", "--interpreter=mi3", "-ex", "-list-features", "-ex", "-gdb-exit"], 10
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=f"could not probe gdb mi3 capability: {exc}",
            suggested_fix=f"Confirm gdb >= {required} is installed and runnable.",
        )
    version = _parse_gdb_version(version_out)
    if version is None or version < _MI_MIN_VERSION:
        detected = f"{version[0]}.{version[1]}" if version is not None else "unknown"
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=f"gdb {detected} is too old for the mi3 interface; the debug.gdb tier requires gdb >= {required}",
            suggested_fix=f"Upgrade gdb to >= {required}.",
        )
    if mi_code != 0 or "^done" not in mi_out:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=(
                f"gdb {version[0]}.{version[1]} did not return a valid mi3 ^done record; the debug.gdb "
                f"tier requires a working mi3 interpreter (gdb >= {required})"
            ),
            suggested_fix=f"Confirm gdb >= {required} was built with mi3 support.",
        )
    return PrerequisiteCheck(
        check_id="tool.gdb_mi",
        status=PrerequisiteStatus.PASSED,
        message=f"gdb {version[0]}.{version[1]} supports the mi3 machine interface",
        details={"version": f"{version[0]}.{version[1]}"},
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_prereqs_gdb_mi.py tests/test_prereqs.py -q`
Expected: PASS (new tests + the existing prereqs suite unaffected; the existing suite's `FakeRunner.run` returns `(0, "", "")` for unmatched argv, so `tool.gdb_mi` resolves without error).

> **Cross-check:** open `tests/test_prereqs.py` and confirm its `FakeRunner.run` tolerates the two new `gdb` argv (it returns a default tuple for unknown commands). If it raises on unknown argv, widen its `run` to return `(0, "", "")` for unmatched commands in the same commit, noting the change.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/prereqs/checks.py tests/test_prereqs_gdb_mi.py
git commit -m "feat(prereqs): add gdb mi3 capability probe with 9.1 minimum"
```

---

## Task 6: Wire the engine into the transport-enabled `debug.start_session` path

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — add `_resume_debug_transport`; add `gdb_mi_engine` parameter to `debug_start_session_handler`; insert the additive MI attach-probe in the `transport_enabled` branch after `_halt_debug_transport`; wire a real `GdbMiEngine` in the `create_app()` debug.start_session tool registration.
- Test: covered by Task 7.

**Design:** The probe is additive and gated on `gdb_mi_engine is not None`. It runs **after** `_halt_debug_transport` (durable HALTED) and **before** `provider.start_session` (the legacy batch session-of-record). On probe success it records the typed MI record into the debug step details (`mi_probe`) and the kernel is left for the batch path to re-attach. On probe failure it tears the transaction down via the existing `session_guard.teardown` / `transaction.close` machinery, **after** un-halting the durable record when resume is confirmed.

- [ ] **Step 1: Add `_resume_debug_transport` near `_halt_debug_transport`**

Insert after `_halt_debug_transport` (around server.py:4011):

```python
def _resume_debug_transport(
    *,
    session: TransportSession,
    admission: AdmissionService,
    session_registry: SessionRegistry,
) -> None:
    """Inverse of _halt_debug_transport for the guaranteed-resume path: once the MI engine confirms
    the kernel is EXECUTING again (best-effort continue + RSP disconnect), persist HALTED->EXECUTING
    and bump the execution epoch so a fresh ssh-tier proof at the new epoch is accepted. Writing the
    durable record EXECUTING also makes transaction.close() leave NO closed_while_halted recovery
    tombstone, so a subsequent ssh-tier operation succeeds with the target back in EXECUTING (§5.6)."""
    session_registry.write_record(session.model_copy(update={"execution_state": ExecutionState.EXECUTING}))
    admission.note_execution_transition(session.target_key, session.generation)
```

- [ ] **Step 2: Add the `gdb_mi_engine` parameter**

Add to `debug_start_session_handler`'s signature (after `build_id_reader=...`):

```python
    gdb_mi_engine: GdbMiEngine | None = None,
```

Add the import near the other provider imports at the top of server.py:

```python
from linux_debug_mcp.providers.gdb_mi import GdbMiEngine, GdbMiError
```

- [ ] **Step 3: Insert the MI attach-probe after `_halt_debug_transport`**

In the `transport_enabled` branch, immediately after the `_halt_debug_transport(...)` call (server.py:4227), add:

```python
                if gdb_mi_engine is not None:
                    probe_failure = _run_mi_attach_probe(
                        engine=gdb_mi_engine,
                        transport_session=transport_session,
                        vmlinux_path=Path(vmlinux.path),
                        run_dir=store.run_dir(run_id),
                        run_id=run_id,
                        transaction=transaction,
                        admission=admission,
                        session_registry=session_registry,
                        session_guard=session_guard,
                        redactor=redactor,
                    )
                    if probe_failure is not None:
                        return probe_failure
```

- [ ] **Step 4: Add the `_run_mi_attach_probe` helper**

Add near `debug_start_session_handler` (it encapsulates the probe + guaranteed-resume teardown so the handler body stays under the complexity limit):

```python
def _run_mi_attach_probe(
    *,
    engine: GdbMiEngine,
    transport_session: TransportSession,
    vmlinux_path: Path,
    run_dir: Path,
    run_id: str,
    transaction: TransportTransaction,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    session_guard: SessionGuard | None,
    redactor: Redactor,
) -> ToolResponse | None:
    """Phase-A gdb/MI foundation probe: attach over the guard-protected TransportSession.rsp_endpoint,
    read one MI record as typed JSON, detach cleanly. Returns None on success (the legacy batch
    start_session then runs as the session-of-record), or a failure ToolResponse after a
    guaranteed-resume teardown that never leaves the kernel HALTED. The probe and the batch attach
    are sequential (QEMU's gdbstub takes one connection at a time); Phase C collapses them by moving
    the session-of-record onto the engine."""
    transcript_path = run_dir / "debug" / "mi-probe.log"
    try:
        attachment = engine.attach(
            rsp_endpoint=transport_session.rsp_endpoint, vmlinux_path=vmlinux_path, transcript_path=transcript_path
        )
        record = engine.probe_read(attachment)
        engine.resume_and_detach(attachment)
        return None
    except GdbMiError as exc:
        resume_confirmed = False
        with contextlib.suppress(Exception):
            resume_confirmed = engine.force_resume(attachment)  # type: ignore[possibly-undefined]
        if resume_confirmed:
            _resume_debug_transport(
                session=transport_session, admission=admission, session_registry=session_registry
            )
        _teardown_debug_transport(
            transport_session=transport_session,
            transaction=transaction,
            session_registry=session_registry,
            session_guard=session_guard,
        )
        details = redactor.redact_value({**exc.details, "transport_session_id": transport_session.session_id})
        return ToolResponse.failure(
            category=exc.category,
            message=redactor.redact_text(str(exc)),
            run_id=run_id,
            details=details,
            suggested_next_actions=["host.check_prerequisites", "artifacts.get_manifest"],
        )
```

> `attachment` may be undefined if `engine.attach` raised before binding it. Guard with the `contextlib.suppress` + `# type: ignore[possibly-undefined]` as shown, or restructure to bind `attachment = None` before the `try` and `if attachment is not None: resume_confirmed = engine.force_resume(attachment)`. Prefer the explicit `attachment = None` form — it is clearer and needs no ignore. Use:
>
> ```python
>     attachment = None
>     try:
>         attachment = engine.attach(...)
>         engine.probe_read(attachment)
>         engine.resume_and_detach(attachment)
>         return None
>     except GdbMiError as exc:
>         resume_confirmed = engine.force_resume(attachment) if attachment is not None else True
>         ...
> ```
>
> When `attach` fails before connecting (bad endpoint / missing gdb / missing vmlinux), no RSP connection was made, so the target was never halted by the engine — treat resume as confirmed (`True`) so the durable record is un-halted and no tombstone is left.

- [ ] **Step 5: Extract `_teardown_debug_transport`**

The existing `ProviderDebugError` handler block (server.py:4248-4265) already contains the teardown (session_guard.teardown / transaction.close). Extract it verbatim into a shared helper so both the existing batch path and the new probe path use one implementation:

```python
def _teardown_debug_transport(
    *,
    transport_session: TransportSession,
    transaction: TransportTransaction,
    session_registry: SessionRegistry | None,
    session_guard: SessionGuard | None,
) -> None:
    """Tear down an open transport session after a failed attach: SessionGuard-supervised close when
    the guard is wired, else a guarded transaction.close(force=False). Shared by the legacy batch
    attach-failure path and the Phase-A MI probe-failure path."""
    sid = transport_session.session_id
    tkey = transport_session.target_key
    if session_guard is not None and session_registry is not None:
        session_guard.teardown(
            SessionGuardContext(
                target_key=tkey, generation=transport_session.generation, session_id=sid, reason="attach_error"
            ),
            close=lambda: transaction.close(sid, force=False),
            read_record=lambda: session_registry.read_record(tkey),
            force_reap=lambda: transaction.force_release(sid),
        )
    else:
        with contextlib.suppress(Exception):
            transaction.close(sid, force=False)
```

Then replace the inline teardown in the `ProviderDebugError` block (server.py:4248-4265) with a call to `_teardown_debug_transport(...)`, keeping the surrounding `exc_details`/`StepResult` recording unchanged.

- [ ] **Step 6: Wire a real engine in `create_app()`**

Find the `debug.start_session` tool registration in `create_app()` (the wrapper that calls `debug_start_session_handler(...)` with `transaction=`, `admission=`, etc. — around server.py:6628-6637) and add `gdb_mi_engine=GdbMiEngine()` to that call. Construct one module/closure-level `GdbMiEngine()` in `_build_transport_machinery` or the create_app body and pass it through, mirroring how `transaction`/`admission` are threaded.

- [ ] **Step 7: Run the full existing suite to prove no regression**

Run: `uv run python -m pytest tests/test_server_debug_session_migration.py tests/test_debug_handlers.py tests/test_server_debug_reads_while_halted.py -q`
Expected: PASS — all existing transport-path tests pass `gdb_mi_engine=None` (default) so the probe is skipped and behavior is identical.

- [ ] **Step 8: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src
git add src/linux_debug_mcp/server.py
git commit -m "feat(debug): run gdb/MI attach-probe over TransportSession rsp_endpoint"
```

---

## Task 7: Handler-level probe, guard-conflict, and fault-injection tests

**Files:**
- Create: `tests/test_server_debug_mi_probe.py`

Reuse `_layer4_fakes.FakeQemuTransport` / `build_txn` and the `_create_debug_ready_run` / `_profiles` patterns from `test_server_debug_session_migration.py` (copy the small helpers in; there is no shared conftest for them). Inject a fake engine.

- [ ] **Step 1: Write the fake engine + happy-path test**

```python
# tests/test_server_debug_mi_probe.py
from __future__ import annotations

from pathlib import Path

from _layer4_fakes import FakeQemuTransport, build_txn
from conftest import FakeTestProvider, kernel_provenance_details, rootfs, write_vmlinux_with_build_id

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile, RootfsProfile
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.gdb_mi import GdbMiError, MiRecord
from linux_debug_mcp.seams.target import (
    BreakHint, ConsoleKind, PlatformMetadata, TargetKey, publish_ready_snapshot,
)
from linux_debug_mcp.server import debug_start_session_handler, target_run_tests_handler
from linux_debug_mcp.transport.base import ExecutionState, LineRole, TransportRef

# (copy RUN_ID/KEY/GDBSTUB_ENDPOINT/RSP_CHANNEL/PLATFORM_WITH_SSH/_build_transaction/
#  _create_debug_ready_run/_profiles/FakeDebugProvider from test_server_debug_session_migration.py)


class FakeEngine:
    """A GdbMiEngine-shaped fake. `fail_on` selects which step raises GdbMiError."""

    def __init__(self, *, fail_on: str | None = None, resume_confirmed: bool = True) -> None:
        self.fail_on = fail_on
        self._resume_confirmed = resume_confirmed
        self.attached = False
        self.resumed = False
        self.forced = False

    def attach(self, *, rsp_endpoint, vmlinux_path, transcript_path):
        if self.fail_on == "attach":
            raise GdbMiError("attach blew up", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        self.attached = True
        return object()  # opaque attachment handle

    def probe_read(self, attachment, **_):
        if self.fail_on == "probe":
            raise GdbMiError("rsp timeout", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        return MiRecord(type="result", message="done", payload={"value": "Linux version 6.9.0-test"})

    def resume_and_detach(self, attachment) -> bool:
        self.resumed = True
        return True

    def force_resume(self, attachment) -> bool:
        self.forced = True
        return self._resume_confirmed


def test_probe_success_records_session_and_leaves_record_halted(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine()
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeDebugProvider(), debug_profiles=_profiles(),
        transaction=txn, admission=admission, session_registry=registry, gdb_mi_engine=engine,
    )
    assert resp.ok is True
    assert engine.attached and engine.resumed
    record = registry.read_record(KEY)
    assert record is not None and record.execution_state == ExecutionState.HALTED  # batch path owns the kernel
```

- [ ] **Step 2: Write the guard-conflict (no-lease qemu-gdbstub) test**

```python
def test_second_stop_capable_attach_refused_on_qemu_gdbstub(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)
    common = dict(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeDebugProvider(), debug_profiles=_profiles(),
        transaction=txn, admission=admission, session_registry=registry, gdb_mi_engine=FakeEngine(),
    )
    first = debug_start_session_handler(**common)
    assert first.ok is True
    second = debug_start_session_handler(new_session=True, **common)
    assert second.ok is False
    assert second.error.category == ErrorCategory.TRANSPORT_CONFLICT
    assert second.error.details["code"] == "stop_capable_conflict"  # NB: issue text says stop_session_conflict
```

- [ ] **Step 3: Write the three fault-injection tests**

```python
import pytest


@pytest.mark.parametrize("fail_on", ["attach", "probe"])
def test_probe_fault_resumes_and_frees_guard(tmp_path: Path, fail_on: str) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine(fail_on=fail_on, resume_confirmed=True)
    resp = debug_start_session_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeDebugProvider(), debug_profiles=_profiles(),
        transaction=txn, admission=admission, session_registry=registry, gdb_mi_engine=engine,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    # guaranteed resume + teardown: guard released (record deleted), target back to EXECUTING, no tombstone.
    assert registry.read_record(KEY) is None
    assert registry.read_tombstone(KEY) is None
    if fail_on != "attach":
        assert engine.forced is True


def test_ssh_tier_rejected_during_halt_then_succeeds_after_resume(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path)
    txn, admission = _build_transaction(registry=registry)

    # During the fault window the durable record is HALTED -> a concurrently-issued ssh-tier op is
    # fast-rejected. Simulate "during" by asserting target_run_tests rejects while a HALTED record is
    # present (a successful probe leaves the batch session HALTED).
    ok = debug_start_session_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeDebugProvider(), debug_profiles=_profiles(),
        transaction=txn, admission=admission, session_registry=registry, gdb_mi_engine=FakeEngine(),
    )
    assert ok.ok is True
    rootfs_profile: RootfsProfile = rootfs(tmp_path)
    during = target_run_tests_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile}, admission=admission, session_registry=registry,
    )
    assert during.ok is False and during.error.details["code"] == "target_halted"

    # A probe FAULT with confirmed resume un-halts the target; a fresh ssh-tier op then succeeds.
    txn2, admission2 = _build_transaction(registry=_make_registry(tmp_path / "r2"))
    reg2 = _make_registry(tmp_path / "r2b")
    txn3, admission3 = _build_transaction(registry=reg2)
    faulted = debug_start_session_handler(
        artifact_root=artifact_root, run_id=RUN_ID, new_session=True, provider=FakeDebugProvider(),
        debug_profiles=_profiles(), transaction=txn3, admission=admission3, session_registry=reg2,
        gdb_mi_engine=FakeEngine(fail_on="probe", resume_confirmed=True),
    )
    assert faulted.ok is False
    after = target_run_tests_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs_profile}, admission=admission3, session_registry=reg2,
    )
    assert after.ok is True
```

> The "during vs after" test is fiddly because `run-1`'s snapshot is seeded per transaction. Keep it focused: the load-bearing assertions are (a) `target_halted` while a HALTED record exists, and (b) `ok` after a confirmed-resume fault leaves the record un-halted with no tombstone. If wiring two registries proves awkward, split into two tests — one for each side — rather than forcing one scenario. Do not leave a flaky test.

- [ ] **Step 4: Run the tests**

Run: `uv run python -m pytest tests/test_server_debug_mi_probe.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_server_debug_mi_probe.py
git commit -m "test(debug): cover gdb/MI probe, guard conflict, fault-injection resume"
```

---

## Task 8: Gated end-to-end integration test (real gdb + QEMU gdbstub)

**Files:**
- Create: `tests/test_gdb_mi_integration.py`

Mirror the gating helpers in `tests/test_transport_open_close_integration.py` (`_live_gdbstub_active`, `_gdbstub_skip_reason`, the `_GDBSTUB_REQUIRED_ENV` list). The test drives the real engine against the rsp_endpoint produced by `transaction.open()` from `_build_transport_machinery`.

- [ ] **Step 1: Write the gated test**

```python
# tests/test_gdb_mi_integration.py
from __future__ import annotations

import os
from pathlib import Path

import pytest

_GDBSTUB_REQUIRED_ENV = [
    "LINUX_DEBUG_MCP_LIVE_GDBSTUB", "LINUX_DEBUG_MCP_SOURCE", "LINUX_DEBUG_MCP_ROOTFS",
    "LINUX_DEBUG_MCP_DOMAIN", "LINUX_DEBUG_MCP_LIBVIRT_URI", "LINUX_DEBUG_MCP_READINESS_MARKER",
]


def _live() -> bool:
    return os.environ.get("LINUX_DEBUG_MCP_LIVE_GDBSTUB") == "1" and all(os.environ.get(n) for n in _GDBSTUB_REQUIRED_ENV)


@pytest.mark.skipif(not _live(), reason="live gdbstub integration test; set LINUX_DEBUG_MCP_LIVE_GDBSTUB=1 + companions")
def test_engine_attaches_reads_one_record_and_detaches(tmp_path: Path) -> None:
    """Drive the real GdbMiEngine against the rsp_endpoint a real transaction.open() returns: attach
    over RSP, read one MI record as typed JSON, detach cleanly; assert resume confirmed."""
    from linux_debug_mcp.providers.gdb_mi import GdbMiEngine, MiRecord
    # Build through to a READY transport session exactly as test_transport_open_close_integration
    # does (build->boot->_build_transport_machinery->transaction.open via debug.start_session), then
    # read transport_session.rsp_endpoint from the durable record and drive the engine on it.
    # ... (follow the build/boot/machinery sequence from test_transport_open_close_integration.py) ...
    # engine = GdbMiEngine()
    # attachment = engine.attach(rsp_endpoint=record.rsp_endpoint, vmlinux_path=vmlinux, transcript_path=...)
    # mi_record = engine.probe_read(attachment)
    # assert isinstance(mi_record, MiRecord) and mi_record.message in {"done", "connected"}
    # assert engine.resume_and_detach(attachment) is True
    pytest.skip("fill in the build/boot/open sequence from the sibling integration module when running live")
```

> Write the full build→boot→open sequence by copying the relevant steps from `test_transport_open_close_integration.py::test_qemu_gdbstub_flow_unchanged` (it already obtains a live READY transport session). The final assertions are the three above. **Do not** un-gate it — it must skip cleanly with no live env, like the sibling module.

- [ ] **Step 2: Verify it skips cleanly**

Run: `uv run python -m pytest tests/test_gdb_mi_integration.py -q`
Expected: SKIPPED (1 skipped), never a failure, in local/CI without the live env.

- [ ] **Step 3: Commit**

```bash
git add tests/test_gdb_mi_integration.py
git commit -m "test(gdb-mi): add gated live-gdbstub attach/read/detach integration test"
```

---

## Task 9: Flip the spec status and update the ADR index note

**Files:**
- Modify: `docs/superpowers/specs/2026-05-29-debug-gdb-mi-tier-design.md:3` (status `proposed` → `Phase A implemented`)

- [ ] **Step 1: Update the status line**

Change the spec header status from `proposed (2026-05-29)` to `Phase A implemented (2026-05-29); B/C/D proposed`.

- [ ] **Step 2: Run the doc guard**

Run: `just check-docs`
Expected: PASS (no "sprint" terms introduced).

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-05-29-debug-gdb-mi-tier-design.md
git commit -m "docs: mark debug.gdb Phase A implemented in the tier spec"
```

---

## Final verification (before opening the PR)

- [ ] `uv run ruff check && uv run ruff format --check`
- [ ] `uv run ty check src` (hard-gating; zero errors)
- [ ] `uv run python -m pytest -q` (full suite green; the live-gdbstub and agent-proxy integration tests SKIP, which is expected)
- [ ] `just check-docs`
- [ ] Confirm the four issue acceptance criteria + the four added criteria each map to a passing (or correctly-skipped) test, and note the `stop_session_conflict`→`stop_capable_conflict` wording mismatch in the PR body.

---

## Self-review notes

- **Spec coverage:** engine (Tasks 2-4) ↔ AC#1/#3/#6; dependency (Task 1) ↔ AC#5; prereq probe (Task 5) ↔ AC#4/#7; guard conflict (Task 7) ↔ AC#2; fault-injection ssh-tier (Task 7) ↔ added AC#3; gated integration (Task 8) ↔ AC#1/#6 live; rsp_endpoint re-point (Task 6) ↔ added AC#1.
- **Type consistency:** `MiRecord`, `GdbMiError`, `GdbMiEngine` (`attach`/`probe_read`/`resume_and_detach`/`force_resume`), `MiController.write/exit`, `_resume_debug_transport`, `_teardown_debug_transport`, `_run_mi_attach_probe` names are used consistently across tasks.
- **Out of Phase A (do not implement):** symbol provenance over RSP (Phase B), the MI-typed debug operations + deleting batch paths (Phase C), module symbols / serial-KGDB / RSP-stall robustness (Phase D).
