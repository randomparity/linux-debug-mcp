from __future__ import annotations

import contextlib
import ipaddress
import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pygdbmi.constants import GdbTimeoutError
from pygdbmi.gdbmiparser import parse_response

from linux_debug_mcp.domain import ErrorCategory, Model
from linux_debug_mcp.safety.redaction import Redactor
from linux_debug_mcp.transport.base import Endpoint, TcpEndpoint

# Minimum gdb release that documents the mi3 interpreter (GDB manual "GDB/MI" chapter).
MIN_GDB_VERSION = (9, 1)
# Per-command MI write timeout. 10s bounds a healthy localhost RSP connect/read. The resume path
# uses ASYNC continue (mi-async on), so `-exec-continue` returns `^running` immediately rather than
# blocking until a stop that a free-running kernel never produces.
_MI_COMMAND_TIMEOUT_SEC = 10.0

# The literal MI prompt terminator gdb emits between command results; not a record.
_MI_PROMPT = "(gdb)"
# Keys pygdbmi may emit on a parsed record; whitelist so an unexpected extra key is dropped
# rather than tripping the extra="forbid" model boundary.
_KNOWN_KEYS = ("type", "message", "payload", "token", "stream")


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
    """The injectable subprocess seam. The real impl drives a ``gdb --interpreter=mi3`` child via
    pygdbmi; tests inject a scripted fake. ``write`` returns the raw pygdbmi record dicts for the
    command; ``exit`` terminates the child."""

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]: ...

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
            raise GdbMiError(
                f"gdb/MI command timed out after {timeout_sec}s: {command}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command, "timeout_seconds": timeout_sec},
            ) from exc

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


class GdbMiEngine:
    """Persistent ``gdb --interpreter=mi3`` engine. Phase A: attach over RSP, read one MI record as
    typed JSON, detach cleanly -- and never leave the target HALTED on error (force_resume)."""

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
            self._run(attachment, f"-target-select remote {host}:{port}")
        except GdbMiError:
            with contextlib.suppress(Exception):
                controller.exit()
            raise
        return attachment

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

    def _run(self, attachment: GdbMiAttachment, command: str) -> None:
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
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "observed_at": datetime.now(UTC).isoformat(),
            "command": command,
            "records": [record.model_dump(mode="json") for record in records],
        }
        with transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(self._redactor.redact_value(entry), default=str))
            handle.write("\n")
