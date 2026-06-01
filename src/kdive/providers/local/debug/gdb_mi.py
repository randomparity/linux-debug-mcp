from __future__ import annotations

import contextlib
import ipaddress
import json
import math
import re
import shutil
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pygdbmi.constants import GdbTimeoutError
from pygdbmi.gdbmiparser import parse_response

from kdive.domain import ErrorCategory, Model
from kdive.providers.debug import MAX_INTERACTIVE_WAIT_SEC, MAX_MEMORY_READ_BYTES, GdbMiError
from kdive.safety.redaction import Redactor
from kdive.seams.transport_state import Endpoint, TcpEndpoint

# Minimum gdb release that documents the mi3 interpreter (GDB manual "GDB/MI" chapter).
MIN_GDB_VERSION = (9, 1)
# Per-command MI write timeout. 10s bounds a healthy localhost RSP connect/read. The resume path
# uses ASYNC continue (mi-async on), so `-exec-continue` returns `^running` immediately rather than
# blocking until a stop that a free-running kernel never produces.
_MI_COMMAND_TIMEOUT_SEC = 10.0

# gdb's RSP read timeout (`set remotetimeout`). Generous-but-finite (ADR 0023 decision 1): every RSP
# packet gdb waits on is bounded and gdb owns the wait, so a slow/silent serial stub yields a clean
# gdb-reported disconnect rather than an opaque hang under the MI write timeout.
RSP_REMOTE_TIMEOUT_SEC = 30
# Bounded retry for the RSP connect (`-target-select remote`). The connect is idempotent until
# `^connected` (no target state mutates), so retrying ANY connect error a fixed small number of times
# is sound without classifying gdb's error text (ADR 0023 decision 2).
_CONNECT_RETRY_COUNT = 3
_CONNECT_RETRY_BACKOFF_SEC = 0.5

# The literal MI prompt terminator gdb emits between command results; not a record.
_MI_PROMPT = "(gdb)"
# Keys pygdbmi may emit on a parsed record; whitelist so an unexpected extra key is dropped
# rather than tripping the extra="forbid" model boundary.
_KNOWN_KEYS = ("type", "message", "payload", "token", "stream")

# A bare C identifier. The name-shape gate (ADR 0020 decision 2) keeps resolve_symbol's
# `-data-evaluate-expression "&<name>"` an address-of-a-name, never an arbitrary expression.
_SYMBOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# The fixed canonical symbol the Phase-B attach probe resolves: present in every kernel image
# (the /proc/version string), so it needs no kernel-config gating (ADR 0020 decision 3).
CANONICAL_PROBE_SYMBOL = "linux_banner"

# Fixed bound for the post-timeout -exec-interrupt to land its *stopped (SIGINT).
_INTERRUPT_STOP_TIMEOUT_SEC = 10.0
# Poll slice when looping read() toward the deadline.
_STOP_POLL_SLICE_SEC = 0.5
# gdb stop reasons meaning the inferior is gone (not a debuggable HALT).
_TERMINAL_STOP_REASONS = frozenset({"exited", "exited-normally", "exited-signalled"})
# Snippet bound for variable values so a deep frame cannot bloat the response.
MAX_RESPONSE_SNIPPET = 4096
# A register name (passed to -data-list-register-names lookup).
_REGISTER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# A breakpoint/watchpoint location: a bare C identifier (function/symbol/expression).
_BREAK_LOCATION_RE = _SYMBOL_NAME_RE
# A gdb breakpoint id is a bare integer.
_BREAK_ID_RE = re.compile(r"^[0-9]+$")
# A runtime section base address: a 0x-prefixed hex literal (ADR 0022). Re-validated in the engine
# (defence in depth) before it is interpolated into the add-symbol-file console command.
_HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]+$")
# An ELF section name as it appears under /sys/module/<name>/sections/ (e.g. .text, .data, .bss).
_SECTION_NAME_RE = re.compile(r"^\.[A-Za-z0-9_.]+$")
# The mandatory section: add-symbol-file's positional load address.
_MODULE_TEXT_SECTION = ".text"


class MiRecord(Model):
    """One parsed gdb/MI record (gdb manual "GDB/MI Output Syntax"). ``type`` is the MI record
    class (``result``/``notify``/``exec``/``console``/``log``/``output``/``target``); ``message`` is
    the result class (``done``/``running``/``connected``/``error``/``exit``) or async class;
    ``payload`` is the parsed value tree. Frozen wire shape (``Model`` => extra="forbid")."""

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
        """The first ``result``-class record (``^done``/``^running``/``^error``/...), or None."""
        return next((record for record in records if record.type == "result"), None)


class ResolvedSymbol(Model):
    """One name->address resolution via gdb/MI ``-data-evaluate-expression "&<name>"``. ``value`` is
    the gdb-rendered link-time address string (e.g. ``"0x... <linux_banner>"``) stored verbatim --
    proof the symbol resolves in the loaded symbol table, NOT the relocated runtime address
    (ADR 0020). Frozen wire shape (``Model`` => extra="forbid")."""

    name: str
    value: str


class LoadedModule(Model):
    """One module whose symbols were loaded at runtime addresses via ``add-symbol-file`` (ADR 0022).
    ``sections`` maps the loaded ELF section names to their relocated base addresses (``.text`` is
    mandatory; the value is the redacted address string). Frozen wire shape (``Model`` =>
    extra="forbid")."""

    name: str
    sections: dict[str, str]


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


def parse_mi_records(text: str) -> list[MiRecord]:
    """Parse newline-delimited MI output into typed records, skipping blank lines and the literal
    ``(gdb)`` prompt terminator. Used both for the controller's returned dicts (already parsed) and
    for raw transcript text in tests."""
    records: list[MiRecord] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped == _MI_PROMPT:
            continue
        records.append(MiRecord.from_raw(parse_response(stripped)))
    return records


def _timeout_error(command: str, timeout_sec: float) -> GdbMiError:
    """The error an MI write timeout raises (ADR 0023 decision 3). Tagged `transport_stall` /
    INFRASTRUCTURE_FAILURE: a timeout reached through the per-op path (post-`^connected` by
    construction) means the RSP link stalled. `attach()` re-tags its own connect-phase timeouts as
    DEBUG_ATTACH_FAILURE, so this `transport_stall` tag only ever surfaces on an established session."""
    return GdbMiError(
        f"gdb/MI command timed out after {timeout_sec}s: {command}",
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        details={"code": "transport_stall", "command": command, "timeout_seconds": timeout_sec},
    )


@runtime_checkable
class MiController(Protocol):
    """The injectable subprocess seam. The real impl drives a ``gdb --interpreter=mi3`` child via
    pygdbmi; tests inject a scripted fake. ``write`` returns the raw pygdbmi record dicts for the
    command; ``read`` polls for further out-of-band records (the async ``*stopped`` that arrives
    after a ``^running``); ``exit`` terminates the child."""

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]: ...

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        """Poll for further out-of-band records. Returns an empty list when nothing arrived within
        ``timeout_sec`` (the async stop has not been emitted yet)."""
        ...

    def exit(self) -> None: ...


class PygdbmiController:
    """Real ``MiController``: a managed ``gdb --interpreter=mi3`` subprocess via ``pygdbmi``."""

    def __init__(self, command: list[str]) -> None:
        from pygdbmi.gdbcontroller import GdbController

        self._controller = GdbController(command=command)

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        try:
            return self._controller.write(command, timeout_sec=timeout_sec, raise_error_on_timeout=True)
        except GdbTimeoutError as exc:
            raise _timeout_error(command, timeout_sec) from exc

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        try:
            return self._controller.get_gdb_response(timeout_sec=timeout_sec, raise_error_on_timeout=False)
        except GdbTimeoutError:
            return []

    def exit(self) -> None:
        self._controller.exit()


@dataclass
class GdbMiAttachment:
    """A live attach: the controller, its transcript path, and the typed records produced so far."""

    controller: MiController
    rsp_host: str
    rsp_port: int
    transcript_path: Path
    records: list[MiRecord] = field(default_factory=list)


class _ExecutionControl:
    def __init__(self, engine: GdbMiEngine) -> None:
        self._engine = engine

    def wait_for_stop(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord | None:
        slices = max(1, int(timeout_sec / _STOP_POLL_SLICE_SEC) + 1)
        for _ in range(slices):
            records = self._engine._records_from(attachment.controller.read(timeout_sec=_STOP_POLL_SLICE_SEC))
            attachment.records.extend(records)
            if records:
                self._engine._append_transcript(attachment.transcript_path, "<read>", records)
            stop = next((record for record in records if record.message == "stopped"), None)
            if stop is not None:
                return self._engine._stop_record_from(stop)
        return None

    def interrupt(self, attachment: GdbMiAttachment) -> StopRecord | None:
        raw = attachment.controller.write("-exec-interrupt", timeout_sec=_MI_COMMAND_TIMEOUT_SEC)
        records = self._engine._records_from(raw)
        attachment.records.extend(records)
        self._engine._append_transcript(attachment.transcript_path, "-exec-interrupt", records)
        stop = self.wait_for_stop(attachment, timeout_sec=_INTERRUPT_STOP_TIMEOUT_SEC)
        return self._redact_stop(stop) if stop is not None else None

    def resume(self, attachment: GdbMiAttachment, verb: str, *, timeout_sec: float) -> StopRecord:
        # Round fractional requests up: a sub-second request should still wait at least its full
        # span (and the floor of 1s below), never truncate toward zero (5.7 -> 6, not 5).
        requested = math.ceil(timeout_sec) if timeout_sec else MAX_INTERACTIVE_WAIT_SEC
        bounded = max(1, min(requested, MAX_INTERACTIVE_WAIT_SEC))
        self._engine._run(attachment, verb)  # ^running under mi-async on
        stop = self.wait_for_stop(attachment, timeout_sec=bounded)
        if stop is not None:
            return self._redact_stop(stop)
        # The wait timed out. Fall back to -exec-interrupt: a reachable kernel CANNOT ignore a
        # delivered SIGINT, so if the interrupt write is accepted but no *stopped arrives, the link is
        # dead (silence-path stall, ADR 0023 decision 3) — distinct from a benign no-breakpoint timeout
        # where the SIGINT stop DOES arrive. A write-path stall on the interrupt itself raises
        # transport_stall straight from interrupt().
        interrupted = self.interrupt(attachment)
        if interrupted is None:
            raise GdbMiError(
                "gdb/MI RSP went silent: interrupt issued but no *stopped arrived; the link stalled",
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={"code": "transport_stall", "verb": verb},
            )
        return self._redact_stop(interrupted.model_copy(update={"timed_out": True}))

    def _redact_stop(self, stop: StopRecord) -> StopRecord:
        return StopRecord.model_validate(self._engine._redactor.redact_value(stop.model_dump(mode="json")))


class GdbMiEngine:
    """Persistent ``gdb --interpreter=mi3`` engine. Phase A: attach over RSP, read one MI record as
    typed JSON, detach cleanly -- and never leave the target HALTED on error (force_resume)."""

    def __init__(
        self,
        *,
        controller_factory: Callable[[list[str]], MiController] | None = None,
        gdb_path_finder: Callable[[str], str | None] = shutil.which,
        redactor: Redactor | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._controller_factory = controller_factory or (lambda command: PygdbmiController(command))
        self._gdb_path_finder = gdb_path_finder
        self._redactor = redactor or Redactor()
        # Injectable backoff sleep (ADR 0023 decision 2) so the connect retry is wall-clock-free in tests.
        self._sleep = sleep
        self._execution = _ExecutionControl(self)

    def attach(self, *, rsp_endpoint: Endpoint | None, vmlinux_path: Path, transcript_path: Path) -> GdbMiAttachment:
        host, port = self._validate_endpoint(rsp_endpoint)
        gdb_path = self._gdb_path_finder("gdb")
        if gdb_path is None:
            raise GdbMiError(
                "missing required gdb tool",
                category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": ["gdb"]},
            )
        resolved_vmlinux = vmlinux_path.expanduser().resolve()
        if not resolved_vmlinux.is_file():
            raise GdbMiError(
                "vmlinux symbol file does not exist",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"vmlinux_path": str(vmlinux_path)},
            )
        controller = self._controller_factory([gdb_path, "--nx", "--quiet", "--interpreter=mi3"])
        attachment = GdbMiAttachment(
            controller=controller, rsp_host=host, rsp_port=port, transcript_path=transcript_path
        )
        try:
            self._run(attachment, "-gdb-set confirm off")
            self._run(attachment, "-gdb-set pagination off")
            # mi-async makes the resume-path `-exec-continue` return `^running` immediately instead
            # of blocking until a stop a free-running kernel never emits (guaranteed-resume must not
            # hang).
            self._run(attachment, "-gdb-set mi-async on")
            self._run(attachment, f"-file-exec-and-symbols {self._mi_path(resolved_vmlinux)}")
            # `remotetimeout` is set BEFORE the connect so the RSP wait is finite from the first packet.
            self._run(attachment, f"-gdb-set remotetimeout {RSP_REMOTE_TIMEOUT_SEC}")
            self._connect_with_retry(attachment, host, port)
        except GdbMiError as exc:
            with contextlib.suppress(Exception):
                controller.exit()
            # Every attach-phase fault (including a connect-phase timeout) is an attach failure, never a
            # mid-session `transport_stall`: the session never reached `^connected`.
            raise self._as_attach_failure(exc) from exc
        return attachment

    def _connect_with_retry(self, attachment: GdbMiAttachment, host: str, port: int) -> None:
        """Issue `-target-select remote` with a bounded retry/backoff (ADR 0023 decision 2). The
        connect is idempotent until `^connected`, so any connect error is retried up to
        `_CONNECT_RETRY_COUNT` times; the last failure propagates. A connect-phase write timeout
        surfaces as a `transport_stall` GdbMiError; attach re-tags it `DEBUG_ATTACH_FAILURE` so a
        never-attached session is reported as an attach failure, not a mid-session stall (ADR 0023
        "established session is structural")."""
        command = f"-target-select remote {host}:{port}"
        last_exc: GdbMiError | None = None
        for attempt in range(_CONNECT_RETRY_COUNT):
            try:
                self._run(attachment, command)
                return
            except GdbMiError as exc:
                last_exc = self._as_attach_failure(exc)
                if attempt + 1 < _CONNECT_RETRY_COUNT:
                    self._sleep(_CONNECT_RETRY_BACKOFF_SEC)
        raise (
            last_exc
            if last_exc is not None
            else GdbMiError("gdb/MI RSP connect failed", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        )

    def _as_attach_failure(self, exc: GdbMiError) -> GdbMiError:
        """Re-tag a connect-phase fault as DEBUG_ATTACH_FAILURE. A connect-phase write timeout would
        otherwise carry `transport_stall` (the per-op tag), but a session that never reached
        `^connected` is an attach failure, not a mid-session link stall."""
        if exc.category is ErrorCategory.DEBUG_ATTACH_FAILURE and exc.details.get("code") != "transport_stall":
            return exc
        details = {key: value for key, value in exc.details.items() if key != "code"}
        return GdbMiError(str(exc), category=ErrorCategory.DEBUG_ATTACH_FAILURE, details=details)

    def probe_read(self, attachment: GdbMiAttachment) -> MiRecord:
        """Return the one MI record that PROVES the RSP attach reached the target: the ``^connected``
        result ``-target-select remote`` produced during ``attach()``. This is the canonical Phase-A
        "one MI record returned as typed JSON" -- it is unambiguous attach evidence, needs no symbol
        resolution (Phase B) and no extra target round-trip (a separate query like
        ``-list-thread-groups`` can return ``^done`` even without a live remote, so it is NOT used as
        the proof)."""
        connected = next((r for r in attachment.records if r.type == "result" and r.message == "connected"), None)
        if connected is None:
            raise GdbMiError(
                "gdb/MI attach produced no ^connected record; RSP attach did not complete",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"rsp_endpoint": f"{attachment.rsp_host}:{attachment.rsp_port}"},
            )
        return connected

    def resolve_symbol(self, attachment: GdbMiAttachment, symbol_name: str) -> ResolvedSymbol:
        """Resolve *symbol_name* to its address via ``-data-evaluate-expression "&<name>"`` and return
        the typed result (ADR 0020). *symbol_name* must be a bare C identifier; anything else is a
        CONFIGURATION_ERROR raised before gdb is touched. An MI ``^error`` (symbol absent / not loaded)
        or a ``^done`` with no ``value`` is a DEBUG_ATTACH_FAILURE -- symbols were supposed to be
        loaded, so an unresolvable canonical symbol is an attach-level failure, not a soft miss."""
        if not _SYMBOL_NAME_RE.match(symbol_name):
            raise GdbMiError(
                f"symbol name must be a bare C identifier, got {symbol_name!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"symbol": symbol_name},
            )
        records = self._run(attachment, f'-data-evaluate-expression "&{symbol_name}"')
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None else None
        value = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(value, str):
            raise GdbMiError(
                f"gdb/MI returned no value resolving symbol {symbol_name!r}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"symbol": symbol_name},
            )
        return ResolvedSymbol(name=symbol_name, value=value)

    # --- Phase D: module symbol loading ---------------------------------------------------------

    def load_module_symbols(
        self, attachment: GdbMiAttachment, *, name: str, ko_path: Path, sections: dict[str, str]
    ) -> LoadedModule:
        """Load a loadable module's symbols at their runtime addresses (ADR 0022) via
        ``-interpreter-exec console "add-symbol-file <ko> <text> -s <sec> <addr> ..."``. ``.text`` is
        the mandatory positional load address; the other sections follow as ``-s`` arguments in a
        deterministic order. Every address is re-validated as a 0x-hex literal and the ``.ko`` path is
        rejected if it carries whitespace or quotes, so the console string is non-injectable. An MI
        ``^error`` (bad address / unreadable object) is a DEBUG_ATTACH_FAILURE."""
        if _MODULE_TEXT_SECTION not in sections:
            raise GdbMiError(
                "module symbol load requires a .text section address",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"module": name},
            )
        for section, address in sections.items():
            if not _SECTION_NAME_RE.match(section) or not _HEX_ADDRESS_RE.match(address):
                raise GdbMiError(
                    f"module section/address must be a valid ELF section + 0x-hex address, got {section}={address!r}",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                    details={"module": name, "section": section},
                )
        text_address = sections[_MODULE_TEXT_SECTION]
        extra = "".join(
            f" -s {section} {sections[section]}" for section in sorted(sections) if section != _MODULE_TEXT_SECTION
        )
        command = f'-interpreter-exec console "add-symbol-file {self._console_ko(ko_path)} {text_address}{extra}"'
        self._run(attachment, command)
        return LoadedModule.model_validate(self._redactor.redact_value({"name": name, "sections": sections}))

    def _console_ko(self, ko_path: Path) -> str:
        """The module object path for the add-symbol-file console command. Rejected (not escaped) if
        it carries whitespace or a double-quote: a kernel build-tree path has neither, and refusing
        keeps the console string trivially non-injectable (gdb's console splits on whitespace)."""
        text = str(ko_path)
        if any(char in text for char in ' \t\r\n"'):
            raise GdbMiError(
                "module object path must not contain whitespace or quotes",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"ko_path": text},
            )
        return text

    # --- Phase C: interactive execution control -------------------------------------------------

    def wait_for_stop(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord | None:
        """Poll read() until a record with message=="stopped" appears or the slice budget is spent.
        Returns the parsed StopRecord, or None on timeout. Raises GdbMiError(session_exited) on a
        terminal (exited*) stop. The slice budget keeps the loop test-deterministic; a real read()
        blocks up to one slice, so the real wall-clock is bounded by timeout_sec."""
        return self._execution.wait_for_stop(attachment, timeout_sec=timeout_sec)

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
        thread = payload.get("stopped-threads")
        return StopRecord(
            reason=reason if isinstance(reason, str) else None,
            bkptno=payload.get("bkptno") if isinstance(payload.get("bkptno"), str) else None,
            stopped_thread=thread if isinstance(thread, str) else None,
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
        """Idempotent 'ensure HALTED'. Issues -exec-interrupt without routing through the raising
        _run (an already-stopped target answers ^error 'not being run', which is benign), then waits
        the short fixed bound for the SIGINT stop. Returns the StopRecord if one arrived, else None.
        Only a controller fault (write raising) propagates."""
        return self._execution.interrupt(attachment)

    def resume(self, attachment: GdbMiAttachment, verb: str, *, timeout_sec: float) -> StopRecord:
        """Issue an interactive exec verb (-exec-continue/-step/-next/-finish), wait for the stop, and
        return a redacted StopRecord. On timeout, -exec-interrupt back to a known stop and mark
        timed_out=True. Always returns HALTED (or raises session_exited)."""
        return self._execution.resume(attachment, verb, timeout_sec=timeout_sec)

    def continue_(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-continue", timeout_sec=timeout_sec)

    def step(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-step", timeout_sec=timeout_sec)

    def next(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-next", timeout_sec=timeout_sec)

    def finish(self, attachment: GdbMiAttachment, *, timeout_sec: float) -> StopRecord:
        return self.resume(attachment, "-exec-finish", timeout_sec=timeout_sec)

    # --- Phase C: breakpoints / watchpoints -----------------------------------------------------

    def set_breakpoint(self, attachment: GdbMiAttachment, location: str) -> BreakpointRef:
        if not _BREAK_LOCATION_RE.match(location):
            raise GdbMiError(
                f"breakpoint location must be a bare C identifier, got {location!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"location": location},
            )
        # Hardware breakpoint (-h): a software breakpoint's 0xCC write does not survive a frozen
        # boot's reset-vector insertion (the byte lands outside the not-yet-relocated kernel text) and
        # can fail on read-only kernel .text (CONFIG_STRICT_KERNEL_RWX). See ADR 0036.
        return self._breakpoint_ref(self._run(attachment, f"-break-insert -h {location}"), key="bkpt")

    def set_watchpoint(self, attachment: GdbMiAttachment, expression: str) -> BreakpointRef:
        if not _BREAK_LOCATION_RE.match(expression):
            raise GdbMiError(
                f"watchpoint expression must be a bare C identifier, got {expression!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"expression": expression},
            )
        return self._breakpoint_ref(self._run(attachment, f"-break-watch {expression}"), key="wpt")

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

    # --- Phase C: stack inspection --------------------------------------------------------------

    def backtrace(self, attachment: GdbMiAttachment) -> list[Frame]:
        records = self._run(attachment, "-stack-list-frames")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        stack_value = payload.get("stack")
        stack = stack_value if isinstance(stack_value, list) else []
        frames: list[Frame] = []
        for row in stack:
            if not isinstance(row, dict):
                continue
            # pygdbmi flattens `stack=[frame={...},frame={...}]` to the frame dicts directly, so the
            # row IS the frame; tolerate a `{"frame": {...}}` wrapper too in case a variant preserves it.
            wrapped = row.get("frame")
            frame_payload = wrapped if isinstance(wrapped, dict) else row
            redacted = self._redactor.redact_value(frame_payload)
            if isinstance(redacted, dict):
                frames.append(self._frame_from(redacted))
        return frames

    def list_variables(self, attachment: GdbMiAttachment) -> list[Variable]:
        records = self._run(attachment, "-stack-list-variables --all-values")
        result = MiRecord.first_result(records)
        payload = result.payload if result is not None and isinstance(result.payload, dict) else {}
        rows_value = payload.get("variables")
        rows = rows_value if isinstance(rows_value, list) else []
        variables: list[Variable] = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                continue
            value = row.get("value")
            value_text = value[:MAX_RESPONSE_SNIPPET] if isinstance(value, str) else None
            redacted = self._redactor.redact_value({"name": row["name"], "value": value_text})
            variables.append(Variable.model_validate(redacted))
        return variables

    # --- Phase C: register / memory / symbol / evaluate -----------------------------------------

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
        names_result = MiRecord.first_result(self._run(attachment, "-data-list-register-names"))
        names_payload = names_result.payload if names_result is not None else None
        ordered = names_payload.get("register-names") if isinstance(names_payload, dict) else None
        ordered_names = ordered if isinstance(ordered, list) else []
        values_result = MiRecord.first_result(self._run(attachment, "-data-list-register-values x"))
        values_payload = values_result.payload if values_result is not None else None
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
            raise GdbMiError("byte_count must be between 1 and 4096", category=ErrorCategory.CONFIGURATION_ERROR)
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
            return self._redactor.redact_value({"inspector": inspector, "symbol": symbol, "address": resolved.value})
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

    def resume_and_detach(self, attachment: GdbMiAttachment) -> bool:
        """Clean teardown: async continue, ``-target-disconnect``, exit the engine. Returns whether
        resume is confirmed (the exit() kill disconnects RSP, which resumes QEMU even if the MI
        commands failed)."""
        return self._resume(attachment)

    def force_resume(self, attachment: GdbMiAttachment) -> bool:
        """Fault teardown: identical best-effort resume; never raises. The guaranteed-resume path."""
        return self._resume(attachment)

    def _resume(self, attachment: GdbMiAttachment) -> bool:
        # Best-effort async continue: with mi-async on (set at attach) this returns `^running`
        # immediately and does NOT block waiting for a stop a free-running kernel never emits.
        with contextlib.suppress(Exception):
            attachment.controller.write("-exec-continue", timeout_sec=_MI_COMMAND_TIMEOUT_SEC)
        # `-target-disconnect` is the documented MI verb to leave a plain `target remote` running
        # and disconnect (`-target-detach` is the extended-remote/local-process verb and can error
        # against a plain remote stub).
        with contextlib.suppress(Exception):
            attachment.controller.write("-target-disconnect", timeout_sec=_MI_COMMAND_TIMEOUT_SEC)
        # exit() kills gdb -> RSP TCP disconnect -> QEMU resumes the guest. This is the guaranteed
        # backstop that resumes the target even when continue/disconnect failed (e.g. a crashed
        # engine), which is why _resume can honestly return True.
        with contextlib.suppress(Exception):
            attachment.controller.exit()
        return True

    def _run(self, attachment: GdbMiAttachment, command: str) -> list[MiRecord]:
        records = self._records_from(attachment.controller.write(command, timeout_sec=_MI_COMMAND_TIMEOUT_SEC))
        attachment.records.extend(records)
        self._append_transcript(attachment.transcript_path, command, records)
        result = MiRecord.first_result(records)
        if result is not None and result.message == "error":
            raise GdbMiError(
                f"gdb/MI command failed: {command}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command, "payload": self._redactor.redact_value(result.payload)},
            )
        return records

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
            raise GdbMiError(
                "vmlinux path must not contain control whitespace",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return text.replace("\\", "\\\\").replace(" ", "\\ ")

    def _append_transcript(self, transcript_path: Path, command: str, records: list[MiRecord]) -> None:
        """Append one redacted JSON-lines record per MI command to the session transcript.

        Lifecycle (TD-20): the transcript is a per-session file under ``<run>/debug/`` referenced by
        an ``ArtifactRef``; it grows by one line per MI command for the life of one debug session
        (bounded by the session, not the server) and is retained as a run artifact, cleaned up with
        the run directory. It is intentionally not rotated — a single interactive session's command
        count is small, and a rotated/truncated transcript would lose the forensic record the
        artifact exists to preserve. Revisit with size-based rotation only if a real session is
        observed to produce a pathologically large transcript.
        """
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "observed_at": datetime.now(UTC).isoformat(),
            "command": command,
            "records": [record.model_dump(mode="json") for record in records],
        }
        with transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(self._redactor.redact_value(entry), default=str))
            handle.write("\n")


class GdbMiSessionRegistry:
    """In-process holder of live GdbMiAttachments keyed by DebugSession.session_id (ADR 0021
    decision 1). Lock-guards the dict; the live engine is server-process-scoped, not durable, so a
    server restart strands the attachment and the next mutating debug.* op gets ``no_live_session``."""

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
