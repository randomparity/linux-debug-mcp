"""Host-side core for debug.postmortem.list_dumps + .fetch (#95 / ADR 0029).

Pure, SSH-free enumeration parsing and fetch planning so the dump-listing and
file->ref mapping are unit-testable. The on-target script (``DUMP_LIST_SCRIPT_TEMPLATE``)
emits one JSON facts object; the host turns it into ``DumpEntry`` objects and a
``FetchSpec`` plan. The target emits facts; the host decides (the trust boundary
mirrors ``prereqs/kdump_probe.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from string import Template
from typing import Any

from kdive.domain import DumpEntry

DEFAULT_DUMP_DIR = "/var/crash"
VMCORE_NAME = "vmcore"
# Co-located files staged alongside the core, mapped to their result-ref key.
SYMBOL_REF_KEYS = {
    "vmcore-dmesg.txt": "vmcore_dmesg_ref",
    "vmlinux": "vmlinux_ref",
    "vmcoreinfo": "vmcoreinfo_ref",
}
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True)
class FetchSpec:
    """One file to scp: remote source, local name, the result-ref key, expected size."""

    remote_path: str
    local_name: str
    ref_key: str
    expected_size: int


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


def derive_dump_id(remote_dir: str) -> str:
    """Deterministic staging id: ``<slug(basename)>-<sha256(remote_dir)[:8]>``.

    The slug maps non-``[A-Za-z0-9._-]`` to ``_``; the hash suffix disambiguates two
    distinct remote dirs whose basenames slug identically (ADR 0029 decision 5).
    """
    slug = _SLUG_RE.sub("_", _basename(remote_dir)) or "dump"
    digest = sha256(remote_dir.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{digest}"


def _capture_time(mtime: Any) -> str | None:
    if isinstance(mtime, (int, float)) and not isinstance(mtime, bool):
        return datetime.fromtimestamp(mtime, UTC).isoformat()
    return None


def parse_dump_listing(probe: dict[str, Any]) -> list[DumpEntry]:
    """Turn the enumeration JSON into ``DumpEntry`` objects, newest first.

    An empty / missing dump dir yields ``[]`` (AC#1). Sort by ``capture_time`` desc
    (null last), tie-broken by ``path`` asc, for a stable agent-facing order.
    """
    entries: list[DumpEntry] = []
    for record in probe.get("dumps") or []:
        file_sizes = record.get("file_sizes") or {}
        entries.append(
            DumpEntry(
                path=record["dir"],
                kernel=record.get("kernel"),
                capture_time=_capture_time(record.get("mtime")),
                size_bytes=int(record.get("size") or 0),
                incomplete=bool(record.get("incomplete")),
                available_files=list(record.get("present") or []),
                file_sizes={str(k): int(v) for k, v in file_sizes.items()},
            )
        )
    entries.sort(key=_sort_key)
    return entries


def _sort_key(entry: DumpEntry) -> tuple[bool, str, str]:
    """(null-time-last, inverted-time-for-desc, path-asc).

    ``capture_time is None`` sorts last; non-null times are lexically inverted so an
    ascending sort yields newest-first; ``path`` breaks ties ascending.
    """
    if entry.capture_time is None:
        return (True, "", entry.path)
    return (False, _invert(entry.capture_time), entry.path)


def _invert(iso: str) -> str:
    """Lexically invert an ISO timestamp so ascending sort yields newest-first."""
    return "".join(chr(0x10FFFF - ord(c)) for c in iso)


def plan_fetch(entry: DumpEntry, *, vmcore_name: str = VMCORE_NAME) -> list[FetchSpec]:
    """Ordered scp plan: always the core file, then co-located symbol files present.

    Each spec carries the expected size from ``entry.file_sizes`` so every staged file
    gets the size-match truncation guard (ADR 0029 decision 4 / review finding 3).
    """
    specs = [
        FetchSpec(
            remote_path=f"{entry.path}/{vmcore_name}",
            local_name=VMCORE_NAME,
            ref_key="vmcore_ref",
            expected_size=int(entry.file_sizes.get(vmcore_name, entry.size_bytes)),
        )
    ]
    for name, ref_key in SYMBOL_REF_KEYS.items():
        if name in entry.available_files:
            specs.append(
                FetchSpec(
                    remote_path=f"{entry.path}/{name}",
                    local_name=name,
                    ref_key=ref_key,
                    expected_size=int(entry.file_sizes.get(name, 0)),
                )
            )
    return specs


DUMP_LIST_SCRIPT_TEMPLATE = Template(
    r"""import json, os, sys

DUMP_DIR = $dump_dir
CORES = ("vmcore", "vmcore.flat", "vmcore-incomplete")
SYMBOLS = ("vmcore-dmesg.txt", "vmlinux", "vmcoreinfo")


def _kernel(d):
    try:
        with open(os.path.join(d, "vmcore-dmesg.txt")) as fh:
            line = fh.readline().strip()
            return line or None
    except Exception:
        return None


def _record(d):
    core = None
    for name in CORES:
        if os.path.isfile(os.path.join(d, name)):
            core = name
            break
    if core is None:
        return None
    incomplete = core != "vmcore"
    file_sizes = {}
    try:
        st = os.stat(os.path.join(d, core))
        file_sizes[core] = st.st_size
        mtime = st.st_mtime
    except Exception:
        return None
    present = []
    for name in SYMBOLS:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            present.append(name)
            try:
                file_sizes[name] = os.stat(p).st_size
            except Exception:
                pass
    return {
        "dir": d,
        "vmcore_name": core,
        "size": file_sizes.get(core, 0),
        "mtime": mtime,
        "kernel": _kernel(d),
        "incomplete": incomplete,
        "present": present,
        "file_sizes": file_sizes,
    }


dumps = []
exists = os.path.isdir(DUMP_DIR)
if exists:
    try:
        names = sorted(os.listdir(DUMP_DIR))
    except Exception:
        names = []
    for name in names:
        sub = os.path.join(DUMP_DIR, name)
        if not os.path.isdir(sub):
            continue
        try:
            rec = _record(sub)
        except Exception:
            rec = None
        if rec is not None:
            dumps.append(rec)

sys.stdout.write(json.dumps({"dump_dir": DUMP_DIR, "exists": exists, "dumps": dumps}))
"""
)


def render_dump_list_script(*, dump_dir: str) -> str:
    """Render the on-target enumeration script with the dump dir as a python literal."""
    return DUMP_LIST_SCRIPT_TEMPLATE.substitute(dump_dir=repr(dump_dir))
