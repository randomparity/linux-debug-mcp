"""dmesg helper: printk ring buffer. text is redacted host-side (spec §5)."""

from __future__ import annotations

from kdive.domain import Model
from kdive.introspect.helpers.base import HelperSpec


class Args(Model):
    max_entries: int = 1000


class Entry(Model):
    ts_usec: int
    level: int
    text: str


class Output(Model):
    entries: list[Entry]
    truncated: bool


SCRIPT = r"""
from drgn.helpers.linux.printk import get_printk_records

max_entries = int(args["max_entries"])
records = list(get_printk_records(prog))
truncated = len(records) > max_entries
rows = []
for rec in (records[-max_entries:] if truncated else records):
    rows.append({
        "ts_usec": int(rec.timestamp) // 1000,
        "level": int(rec.level),
        "text": rec.text.decode("utf-8", "replace") if isinstance(rec.text, (bytes, bytearray)) else str(rec.text),
    })
emit({"entries": rows, "truncated": truncated})
"""

SPEC = HelperSpec(name="dmesg", version=1, script=SCRIPT, args_model=Args, output_model=Output)
