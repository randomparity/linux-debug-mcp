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
