# `debug.postmortem.list_dumps` + `.fetch` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two live-target SSH tools — `debug.postmortem.list_dumps` (enumerate captured vmcores) and `debug.postmortem.fetch` (scp a dump + co-located symbols into the run dir with integrity, bounding, and idempotency) — feeding the offline analyzers (#92 crash, #55 from_vmcore).

**Architecture:** Both ops reuse the #84/#94 probe path (`_resolve_probe_context`, `_target_python_remote_argv`, `build_ssh_argv`, capped SSH round-trip, `_reject_if_target_halted`). New: a pure `postmortem/dumps.py` (enumeration script + `parse_dump_listing`/`derive_dump_id`/`plan_fetch`), `build_scp_argv`, two handlers, a `local-vmcore-retrieval` capability, and a `postmortem_fetch_lock`. See [spec](../specs/2026-05-30-debug-postmortem-list-dumps-fetch-design.md) and [ADR 0029](../../adr/0029-postmortem-list-dumps-fetch.md).

**Tech Stack:** Python 3.11+, Pydantic v2 (`Model` with `extra="forbid"`), pytest, FastMCP, ruff, ty.

**Guardrails (run after each implementation step):** `uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q`.

---

## File structure

- Create `src/linux_debug_mcp/postmortem/dumps.py` — enumeration script + pure host functions (`parse_dump_listing`, `derive_dump_id`, `plan_fetch`, `FetchSpec`).
- Create `src/linux_debug_mcp/providers/local_vmcore_retrieval.py` — the `local-vmcore-retrieval` capability factory.
- Modify `src/linux_debug_mcp/domain.py` — `DebugPostmortemListDumpsRequest`, `DebugPostmortemFetchRequest`, `DumpEntry`, `FetchedFile`.
- Modify `src/linux_debug_mcp/config.py` — add the two ops to `ALLOWED_DEBUG_OPERATIONS`; add `DEFAULT_FETCH_MAX_BYTES`, `FETCH_DISK_HEADROOM_BYTES`, `FETCH_TIMEOUT_BAND`.
- Modify `src/linux_debug_mcp/artifacts/store.py` — `postmortem_fetch_lock`.
- Modify `src/linux_debug_mcp/providers/plugins.py` — register the new capability.
- Modify `src/linux_debug_mcp/server.py` — generalize `_resolve_probe_context` (timeout band) and `_reject_if_target_halted` (action phrase), add `build_scp_argv`, `debug_postmortem_list_dumps_handler`, `debug_postmortem_fetch_handler`, and tool registrations.
- Create tests: `tests/test_postmortem_dumps.py`, `tests/test_postmortem_list_dumps.py`, `tests/test_postmortem_fetch.py`, `tests/test_vmcore_retrieval_capability.py`, `tests/test_postmortem_fetch_integration.py`.
- Modify `docs/debug-postmortem.md` — retrieval section.

---

## Task 1: Domain models

**Files:**
- Modify: `src/linux_debug_mcp/domain.py` (after `DebugPostmortemTriageRequest`, ~line 242)
- Test: `tests/test_postmortem_dumps.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_postmortem_dumps.py`:

```python
from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import (
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DumpEntry,
    FetchedFile,
)


def test_list_request_defaults() -> None:
    req = DebugPostmortemListDumpsRequest(run_id="r1", target_ref="local-qemu")
    assert req.timeout_seconds == 20
    assert req.dump_dir is None


def test_fetch_request_defaults() -> None:
    req = DebugPostmortemFetchRequest(run_id="r1", target_ref="local-qemu", dump_ref="/var/crash/d1")
    assert req.timeout_seconds == 300
    assert req.force is False
    assert req.max_bytes is None


def test_models_forbid_extra() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemListDumpsRequest(run_id="r1", target_ref="x", bogus=1)
    with pytest.raises(ValidationError):
        DumpEntry(path="/d", kernel=None, capture_time=None, size_bytes=1, incomplete=False, bogus=1)


def test_dump_entry_and_fetched_file_shape() -> None:
    e = DumpEntry(
        path="/var/crash/d1",
        kernel="6.8.0",
        capture_time="2026-05-30T00:00:00+00:00",
        size_bytes=1024,
        incomplete=False,
        available_files=["vmcore-dmesg.txt"],
        file_sizes={"vmcore": 1024, "vmcore-dmesg.txt": 32},
    )
    assert e.available_files == ["vmcore-dmesg.txt"]
    f = FetchedFile(name="vmcore", ref="debug/postmortem/dumps/d1/vmcore", sha256="ab", size_bytes=1024)
    assert f.name == "vmcore"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_dumps.py -q`
Expected: FAIL with `ImportError` (models not defined).

- [ ] **Step 3: Add the models**

In `domain.py`, after `DebugPostmortemTriageRequest` (before `_TriageSectionBase`), add:

```python
class DebugPostmortemListDumpsRequest(Model):
    """Request payload for ``debug.postmortem.list_dumps``. #95 / ADR 0029.

    Live-target SSH enumeration of captured vmcores. ``timeout_seconds`` is
    handler-bounded to ``[5, 60]`` (default 20); ``dump_dir`` overrides the
    ``/var/crash`` default and must be an absolute path (handler-validated).
    """

    run_id: str
    target_ref: str
    dump_dir: str | None = None
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemFetchRequest(Model):
    """Request payload for ``debug.postmortem.fetch``. #95 / ADR 0029.

    Stages a dump enumerated by ``list_dumps`` into the run dir. ``dump_ref`` is a
    ``path`` from ``list_dumps`` re-validated against a fresh enumeration.
    ``timeout_seconds`` is handler-bounded to ``[5, 3600]`` (default 300) and bounds
    each scp subprocess. ``max_bytes`` overrides the default size ceiling; ``force``
    re-transfers and overrides the incomplete-dump refusal.
    """

    run_id: str
    target_ref: str
    dump_ref: str
    force: bool = False
    dump_dir: str | None = None
    max_bytes: int | None = None
    timeout_seconds: int = 300
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DumpEntry(Model):
    """One captured vmcore enumerated by ``debug.postmortem.list_dumps``. #95.

    ``path`` is the remote dump directory (the ``dump_ref`` fetch accepts).
    ``file_sizes`` maps each present file name to its remote ``st_size`` and drives
    the per-file truncation guard in fetch.
    """

    path: str
    kernel: str | None
    capture_time: str | None
    size_bytes: int
    incomplete: bool = False
    available_files: list[str] = Field(default_factory=list)
    file_sizes: dict[str, int] = Field(default_factory=dict)


class FetchedFile(Model):
    """One file staged into the run dir by ``debug.postmortem.fetch``. #95."""

    name: str
    ref: str
    sha256: str
    size_bytes: int
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_postmortem_dumps.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_dumps.py -q
git add src/linux_debug_mcp/domain.py tests/test_postmortem_dumps.py
git commit -m "feat(domain): list_dumps/fetch request + DumpEntry/FetchedFile models"
```

---

## Task 2: config — operations + bounds constants

**Files:**
- Modify: `src/linux_debug_mcp/config.py:139` (after `debug.postmortem.check_prereqs`) and `src/linux_debug_mcp/config.py:151` (after `MAX_POSTMORTEM_CRASH_CALLS_PER_RUN`)
- Test: `tests/test_postmortem_dumps.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_postmortem_dumps.py`:

```python
def test_ops_and_bounds_registered() -> None:
    from linux_debug_mcp.config import (
        ALLOWED_DEBUG_OPERATIONS,
        DEFAULT_FETCH_MAX_BYTES,
        FETCH_DISK_HEADROOM_BYTES,
        FETCH_TIMEOUT_BAND,
    )

    assert "debug.postmortem.list_dumps" in ALLOWED_DEBUG_OPERATIONS
    assert "debug.postmortem.fetch" in ALLOWED_DEBUG_OPERATIONS
    assert DEFAULT_FETCH_MAX_BYTES > 0
    assert FETCH_DISK_HEADROOM_BYTES > 0
    assert FETCH_TIMEOUT_BAND == (5, 3600)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_dumps.py::test_ops_and_bounds_registered -q`
Expected: FAIL (`ImportError` / `AssertionError`).

- [ ] **Step 3: Add the ops and constants**

In `config.py`, inside `ALLOWED_DEBUG_OPERATIONS`, immediately after the `"debug.postmortem.check_prereqs"` line, add:

```python
    # Live-target vmcore retrieval (#95 / ADR 0029). ssh-tier diagnostics gated only
    # by the §5.6 HALTED fast-reject, not by DebugProfile.enabled_operations. Listed
    # for enumerability.
    "debug.postmortem.list_dumps",
    "debug.postmortem.fetch",
```

After the `MAX_POSTMORTEM_CRASH_CALLS_PER_RUN = 1000` line, add:

```python
# debug.postmortem.fetch bounds (#95 / ADR 0029 decision 7).
# Default transfer ceiling: a dump whose total fetch size exceeds this is refused
# (dump_too_large) before any byte moves, unless the request overrides max_bytes.
DEFAULT_FETCH_MAX_BYTES = 32 * 1024 * 1024 * 1024  # 32 GiB
# Free space the host must retain beyond the fetch total, else insufficient_disk.
FETCH_DISK_HEADROOM_BYTES = 1 * 1024 * 1024 * 1024  # 1 GiB
# fetch timeout band; bulk scp cannot fit the probe's [5, 60].
FETCH_TIMEOUT_BAND = (5, 3600)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_postmortem_dumps.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_dumps.py -q
git add src/linux_debug_mcp/config.py tests/test_postmortem_dumps.py
git commit -m "feat(config): enumerate list_dumps/fetch ops + fetch bounds constants"
```

---

## Task 3: `postmortem/dumps.py` — enumeration script + pure host functions

**Files:**
- Create: `src/linux_debug_mcp/postmortem/dumps.py`
- Test: `tests/test_postmortem_dumps.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_postmortem_dumps.py`:

```python
def test_parse_dump_listing_empty() -> None:
    from linux_debug_mcp.postmortem.dumps import parse_dump_listing

    assert parse_dump_listing({"dump_dir": "/var/crash", "exists": False, "dumps": []}) == []


def test_parse_dump_listing_one() -> None:
    from linux_debug_mcp.postmortem.dumps import parse_dump_listing

    probe = {
        "dump_dir": "/var/crash",
        "exists": True,
        "dumps": [
            {
                "dir": "/var/crash/d1",
                "vmcore_name": "vmcore",
                "size": 2048,
                "mtime": 1717027200.0,
                "kernel": "Linux version 6.8.0",
                "incomplete": False,
                "present": ["vmcore-dmesg.txt", "vmlinux"],
                "file_sizes": {"vmcore": 2048, "vmcore-dmesg.txt": 16, "vmlinux": 99},
            }
        ],
    }
    entries = parse_dump_listing(probe)
    assert len(entries) == 1
    e = entries[0]
    assert e.path == "/var/crash/d1"
    assert e.kernel == "Linux version 6.8.0"
    assert e.size_bytes == 2048
    assert e.capture_time is not None and e.capture_time.startswith("2026-")
    assert e.available_files == ["vmcore-dmesg.txt", "vmlinux"]
    assert e.file_sizes["vmcore"] == 2048


def test_parse_dump_listing_sort_and_missing_mtime() -> None:
    from linux_debug_mcp.postmortem.dumps import parse_dump_listing

    probe = {
        "dump_dir": "/var/crash",
        "exists": True,
        "dumps": [
            {"dir": "/var/crash/a", "vmcore_name": "vmcore", "size": 1, "mtime": 1.0,
             "kernel": None, "incomplete": False, "present": [], "file_sizes": {"vmcore": 1}},
            {"dir": "/var/crash/b", "vmcore_name": "vmcore", "size": 1, "mtime": 100.0,
             "kernel": None, "incomplete": False, "present": [], "file_sizes": {"vmcore": 1}},
            {"dir": "/var/crash/c", "vmcore_name": "vmcore", "size": 1, "mtime": None,
             "kernel": None, "incomplete": True, "present": [], "file_sizes": {"vmcore": 1}},
        ],
    }
    entries = parse_dump_listing(probe)
    # newest capture_time first; null capture_time sorts last; tie-break by path
    assert [e.path for e in entries] == ["/var/crash/b", "/var/crash/a", "/var/crash/c"]
    assert entries[-1].capture_time is None
    assert entries[-1].incomplete is True


def test_derive_dump_id_stable_and_slugged() -> None:
    from linux_debug_mcp.postmortem.dumps import derive_dump_id

    a = derive_dump_id("/var/crash/127.0.0.1-2026-05-30-12:00:00")
    b = derive_dump_id("/var/crash/127.0.0.1-2026-05-30-12:00:00")
    assert a == b
    assert ":" not in a and "/" not in a
    assert a != derive_dump_id("/var/crash/other-2026-05-30-12:00:00")


def test_derive_dump_id_disambiguates_collision() -> None:
    from linux_debug_mcp.postmortem.dumps import derive_dump_id

    # basenames slug identically but full paths differ -> different ids
    assert derive_dump_id("/var/crash/a:b") != derive_dump_id("/other/a:b")


def test_plan_fetch_maps_files_to_refs() -> None:
    from linux_debug_mcp.domain import DumpEntry
    from linux_debug_mcp.postmortem.dumps import plan_fetch

    entry = DumpEntry(
        path="/var/crash/d1", kernel=None, capture_time=None, size_bytes=2048, incomplete=False,
        available_files=["vmcore-dmesg.txt", "vmlinux"],
        file_sizes={"vmcore": 2048, "vmcore-dmesg.txt": 16, "vmlinux": 99},
    )
    specs = plan_fetch(entry, vmcore_name="vmcore")
    by_name = {s.local_name: s for s in specs}
    assert by_name["vmcore"].ref_key == "vmcore_ref"
    assert by_name["vmcore"].expected_size == 2048
    assert by_name["vmcore"].remote_path == "/var/crash/d1/vmcore"
    assert by_name["vmlinux"].ref_key == "vmlinux_ref"
    assert by_name["vmcore-dmesg.txt"].ref_key == "vmcore_dmesg_ref"
    # vmcoreinfo absent -> not planned
    assert "vmcoreinfo" not in by_name


def test_render_dump_list_script_substitutes_dir() -> None:
    from linux_debug_mcp.postmortem.dumps import render_dump_list_script

    script = render_dump_list_script(dump_dir="/var/crash")
    assert "/var/crash" in script
    assert "json.dumps" in script
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_dumps.py -q`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Create the module**

Create `src/linux_debug_mcp/postmortem/dumps.py`:

```python
"""Host-side core for debug.postmortem.list_dumps + .fetch (#95 / ADR 0029).

Pure, SSH-free enumeration parsing and fetch planning so the dump-listing and
file→ref mapping are unit-testable. The on-target script (``DUMP_LIST_SCRIPT_TEMPLATE``)
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

from linux_debug_mcp.domain import DumpEntry

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
    if isinstance(mtime, (int, float)):
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
    entries.sort(key=lambda e: (e.capture_time is None, _sort_key(e)))
    return entries


def _sort_key(entry: DumpEntry) -> tuple[str, str]:
    # capture_time desc → invert the ISO string for the secondary asc sort by negating
    # via a sentinel: ISO strings sort lexically, so use the negated ordinal trick by
    # mapping to a descending key. Simpler: sort ascending on (inverted-time, path).
    inverted = "" if entry.capture_time is None else _invert(entry.capture_time)
    return (inverted, entry.path)


def _invert(iso: str) -> str:
    # Lexically invert an ISO timestamp so ascending sort yields newest-first.
    return "".join(chr(0x10FFFF - ord(c)) if ord(c) < 0x10FFFF else c for c in iso)


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
        file_sizes[core] = os.stat(os.path.join(d, core)).st_size
    except Exception:
        return None
    try:
        mtime = os.stat(os.path.join(d, core)).st_mtime
    except Exception:
        mtime = None
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
```

Create `src/linux_debug_mcp/postmortem/__init__.py` only if missing (it already exists — verify with `ls`).

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_postmortem_dumps.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_dumps.py -q
git add src/linux_debug_mcp/postmortem/dumps.py tests/test_postmortem_dumps.py
git commit -m "feat(postmortem): pure dump enumeration parsing + fetch planning"
```

---

## Task 4: `local-vmcore-retrieval` capability

**Files:**
- Create: `src/linux_debug_mcp/providers/local_vmcore_retrieval.py`
- Modify: `src/linux_debug_mcp/providers/plugins.py:11` (import) and `:62` (factory list)
- Test: `tests/test_vmcore_retrieval_capability.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_vmcore_retrieval_capability.py`:

```python
from __future__ import annotations

from linux_debug_mcp.providers.local_vmcore_retrieval import local_vmcore_retrieval_capability
from linux_debug_mcp.providers.plugins import built_in_provider_plugin_specs


def test_capability_shape() -> None:
    cap = local_vmcore_retrieval_capability()
    assert cap.provider_name == "local-vmcore-retrieval"
    assert "debug.postmortem.list_dumps" in cap.operations
    assert "debug.postmortem.fetch" in cap.operations
    assert "ssh" in cap.required_host_tools
    assert "scp" in cap.required_host_tools
    assert cap.transports == ["ssh"]


def test_capability_registered_in_plugins() -> None:
    names = {
        cap().provider_name
        for spec in built_in_provider_plugin_specs()
        for cap in spec.provider_capability_factories
    }
    assert "local-vmcore-retrieval" in names
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_vmcore_retrieval_capability.py -q`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Create the capability + register it**

Create `src/linux_debug_mcp/providers/local_vmcore_retrieval.py`:

```python
"""local-vmcore-retrieval capability. #95 / ADR 0029 decision 10.

ssh-tier vmcore retrieval (list_dumps + fetch). fetch needs scp in addition to ssh,
so this is a dedicated capability rather than riding local-drgn-introspect (which
would over-declare scp for the pure introspect ops).
"""

from __future__ import annotations

from linux_debug_mcp.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)


def local_vmcore_retrieval_capability() -> ProviderCapability:
    semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=False,
    )
    return ProviderCapability(
        provider_name="local-vmcore-retrieval",
        provider_version="0.1.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=["debug.postmortem.list_dumps", "debug.postmortem.fetch"],
        required_host_tools=["ssh", "scp"],
        destructive_permissions=[],
        access_methods=["ssh", "filesystem"],
        semantics=semantics,
    )
```

In `plugins.py`, add the import after the `local_crash_postmortem` import (line 10):

```python
from linux_debug_mcp.providers.local_vmcore_retrieval import local_vmcore_retrieval_capability
```

And add `local_vmcore_retrieval_capability,` to the `provider_capability_factories` list, after `local_crash_postmortem_capability,` (line 62).

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_vmcore_retrieval_capability.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_vmcore_retrieval_capability.py -q
git add src/linux_debug_mcp/providers/local_vmcore_retrieval.py src/linux_debug_mcp/providers/plugins.py tests/test_vmcore_retrieval_capability.py
git commit -m "feat(providers): local-vmcore-retrieval capability (ssh+scp)"
```

---

## Task 5: `postmortem_fetch_lock` on ArtifactStore

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py` (after `collect_lock`, ~line 199)
- Test: `tests/test_postmortem_fetch.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_postmortem_fetch.py` with:

```python
from __future__ import annotations

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import RunRequest


def _store_with_run(tmp_path):
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1", source_path="/src", build_profile="x86_64-default",
            target_profile="local-qemu", rootfs_profile="minimal",
        )
    )
    return store


def test_postmortem_fetch_lock_is_reentrant_safe(tmp_path) -> None:
    store = _store_with_run(tmp_path)
    with store.postmortem_fetch_lock("r1"):
        pass  # acquires and releases without error
    with store.postmortem_fetch_lock("r1"):
        pass
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_fetch.py::test_postmortem_fetch_lock_is_reentrant_safe -q`
Expected: FAIL (`AttributeError: postmortem_fetch_lock`).

- [ ] **Step 3: Add the lock**

In `store.py`, after the `collect_lock` context manager, add:

```python
    @contextmanager
    def postmortem_fetch_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".postmortem-fetch.lock",
            locked_message="postmortem fetch is locked",
            failure_prefix="failed to lock postmortem fetch",
        ):
            yield
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_postmortem_fetch.py::test_postmortem_fetch_lock_is_reentrant_safe -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_fetch.py -q
git add src/linux_debug_mcp/artifacts/store.py tests/test_postmortem_fetch.py
git commit -m "feat(store): per-run postmortem_fetch_lock"
```

---

## Task 6: generalize `_resolve_probe_context` timeout band + `_reject_if_target_halted` action phrase

**Files:**
- Modify: `src/linux_debug_mcp/server.py:2184` (`_resolve_probe_context` signature + timeout check at ~2226) and `:594` (`_reject_if_target_halted`)
- Test: `tests/test_postmortem_list_dumps.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_postmortem_list_dumps.py` with the shared fakes (mirroring `tests/test_postmortem_check_prereqs.py`) and one band test:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import (
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
)
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import (
    debug_postmortem_fetch_handler,
    debug_postmortem_list_dumps_handler,
)

SECRET_KEY_REF = "s3cr3t-key"  # pragma: allowlist secret


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {
        "name": "minimal", "source": "/img.qcow2", "access_method": "ssh",
        "ssh_host": "127.0.0.1", "ssh_user": "root", "ssh_key_ref": SECRET_KEY_REF,
    }
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted_run(tmp_path) -> str:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(run_id="r1", source_path="/src", build_profile="x86_64-default",
                   target_profile="local-qemu", rootfs_profile="minimal")
    )
    store.record_step_result(manifest.run_id,
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="ok", artifacts=[]))
    return manifest.run_id


def test_list_dumps_rejects_out_of_band_timeout(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu", timeout_seconds=120),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_timeout"


def test_fetch_allows_large_timeout(tmp_path) -> None:
    # 600s is out-of-band for list ([5,60]) but in-band for fetch ([5,3600]); the
    # timeout check must not reject it (it will fail later on dump_not_found instead).
    run_id = _booted_run(tmp_path)

    @dataclass
    class _R:
        calls: list = field(default_factory=list)
        def which(self, c): return f"/usr/bin/{c}"
        def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text('{"dump_dir": "/var/crash", "exists": true, "dumps": []}', encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return SshCommandResult(exit_status=0, stdout="")

    resp = debug_postmortem_fetch_handler(
        DebugPostmortemFetchRequest(run_id=run_id, target_ref="local-qemu",
                                    dump_ref="/var/crash/none", timeout_seconds=600),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_R(),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_not_found"
```

(These reference handlers built in Tasks 7–8; the band generalization is exercised by the timeout assertions.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_list_dumps.py -q`
Expected: FAIL (`ImportError` — handlers not yet defined).

- [ ] **Step 3: Generalize the two helpers**

In `server.py`, change `_resolve_probe_context`'s signature to accept a band and use it. Replace the signature:

```python
def _resolve_probe_context(
    request: _SupportsProbeRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile],
    timeout_band: tuple[int, int] = (5, 60),
) -> tuple[_ProbeContext | None, ToolResponse | None]:
```

Replace the hard-coded timeout check (currently `if not (5 <= request.timeout_seconds <= 60):`) with:

```python
    lo, hi = timeout_band
    if not (lo <= request.timeout_seconds <= hi):
        return None, _configuration_failure(
            run_id=run_id,
            message=f"timeout_seconds must be in [{lo}, {hi}]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"},
        )
```

Generalize `_reject_if_target_halted` to take an action phrase. Change its signature and the message:

```python
def _reject_if_target_halted(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
    action: str = "probing kdump prerequisites",
) -> ToolResponse | None:
```

and in the HALTED branch replace the message string with:

```python
            message=f"target halted in debugger; resume or detach before {action}",
```

(The default keeps the existing kdump-prereq caller's message identical.)

- [ ] **Step 4: Run to verify it still fails on ImportError only**

Run: `uv run python -m pytest tests/test_postmortem_check_prereqs.py -q`
Expected: PASS (existing kdump tests unaffected by the default-arg generalization).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_check_prereqs.py -q
git add src/linux_debug_mcp/server.py
git commit -m "refactor(server): parametrize probe timeout band + halt-reject action"
```

---

## Task 7: `build_scp_argv` + `debug_postmortem_list_dumps_handler`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add `build_scp_argv` near `_target_python_remote_argv`; add the handler after `_assemble_kdump_response`, ~line 2688)
- Test: `tests/test_postmortem_list_dumps.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_postmortem_list_dumps.py`:

```python
def _list_runner(stdout: str, exit_status: int = 0):
    @dataclass
    class _R:
        calls: list = field(default_factory=list)
        def which(self, c): return f"/usr/bin/{c}"
        def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
            self.calls.append({"argv": argv, "stdin": stdin})
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return SshCommandResult(exit_status=exit_status, stdout="")
    return _R()


def test_list_dumps_empty_is_success(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu"),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(),
        ssh_runner=_list_runner('{"dump_dir": "/var/crash", "exists": false, "dumps": []}'),
    )
    assert resp.ok is True
    assert resp.data["dumps"] == []


def test_list_dumps_one_entry(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    stdout = (
        '{"dump_dir": "/var/crash", "exists": true, "dumps": ['
        '{"dir": "/var/crash/d1", "vmcore_name": "vmcore", "size": 2048, "mtime": 1717027200.0,'
        ' "kernel": "Linux version 6.8.0", "incomplete": false,'
        ' "present": ["vmcore-dmesg.txt"], "file_sizes": {"vmcore": 2048, "vmcore-dmesg.txt": 16}}]}'
    )
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu"),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_list_runner(stdout),
    )
    assert resp.ok is True
    assert resp.data["dumps"][0]["path"] == "/var/crash/d1"
    assert resp.data["dumps"][0]["kernel"] == "Linux version 6.8.0"
    assert "debug.postmortem.fetch" in resp.suggested_next_actions


def test_list_dumps_bad_dump_dir(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu", dump_dir="relative/path"),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=_list_runner("{}"),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_dump_dir"


def test_list_dumps_no_python(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu"),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(),
        ssh_runner=_list_runner("", exit_status=127),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "probe_no_python"


def test_build_scp_argv_quotes_remote_path() -> None:
    from linux_debug_mcp.config import RootfsProfile
    from linux_debug_mcp.server import build_scp_argv
    from pathlib import Path

    argv = build_scp_argv(
        rootfs_profile=RootfsProfile(name="m", source="/i", access_method="ssh",
                                     ssh_host="h", ssh_user="root"),
        known_hosts_path=Path("/tmp/kh"),
        remote_path="/var/crash/127.0.0.1-2026-05-30-12:00:00/vmcore",
        local_dest=Path("/tmp/dest/vmcore"),
        command_timeout=300,
    )
    assert argv[0] == "scp"
    assert "-T" in argv
    # the source arg is user@host:<quoted-path>; the local dest is the last arg
    src = [a for a in argv if a.startswith("root@h:")][0]
    assert "127.0.0.1-2026-05-30-12:00:00" in src
    assert argv[-1] == "/tmp/dest/vmcore"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_list_dumps.py -q`
Expected: FAIL (`ImportError` for the handlers / `build_scp_argv`).

- [ ] **Step 3: Add `build_scp_argv`**

In `server.py`, after `_target_python_remote_argv` (~line 332), add. Note `build_ssh_argv`, `shlex`, and `Path` are already imported at module scope (verify with `grep -n "^import shlex\|build_ssh_argv\|from pathlib" src/linux_debug_mcp/server.py`); if `shlex` is not imported, add `import shlex` to the imports.

```python
def build_scp_argv(
    *,
    rootfs_profile: RootfsProfile,
    known_hosts_path: Path,
    remote_path: str,
    local_dest: Path,
    command_timeout: int,
) -> list[str]:
    """Canonical ``scp`` argv mirroring ``build_ssh_argv``'s option shape (#95).

    scp's ``host:remote_path`` is expanded by a remote shell, so the remote path is
    ``shlex.quote``d after the ``user@host:`` prefix and ``-T`` disables the
    remote-side filename check (ADR 0029 decision 3).
    """
    configured_timeout = rootfs_profile.ssh_options.get("ConnectTimeout")
    if configured_timeout is not None and int(configured_timeout) > command_timeout:
        raise ValueError("ConnectTimeout cannot exceed command timeout")
    connect_timeout = configured_timeout or str(min(command_timeout, 10))
    strict = rootfs_profile.ssh_options.get("StrictHostKeyChecking", "accept-new")
    argv = [
        "scp",
        "-T",
        "-o", "BatchMode=yes",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", f"StrictHostKeyChecking={strict}",
    ]
    for key in sorted(rootfs_profile.ssh_options):
        if key in {"ConnectTimeout", "StrictHostKeyChecking"}:
            continue
        argv.extend(["-o", f"{key}={rootfs_profile.ssh_options[key]}"])
    argv.extend(["-P", str(rootfs_profile.ssh_port)])
    if rootfs_profile.ssh_key_ref:
        argv.extend(["-i", rootfs_profile.ssh_key_ref])
    source = f"{rootfs_profile.ssh_user}@{rootfs_profile.ssh_host}:{shlex.quote(remote_path)}"
    argv.extend([source, str(local_dest)])
    return argv
```

- [ ] **Step 4: Add a shared enumeration helper + the list handler**

After `_assemble_kdump_response` (~line 2688), add a helper that runs the enumeration probe and returns `(probe_dict, failure_response)`, plus the list handler:

```python
def _run_dump_enumeration(
    ctx: "_ProbeContext",
    *,
    runner: SshRunner,
    dump_dir: str,
    timeout_seconds: int,
    category: tuple[str, ...],
) -> tuple[dict[str, Any] | None, ToolResponse | None]:
    """Run DUMP_LIST_SCRIPT over SSH; return (parsed_probe, None) or (None, failure)."""
    run_id = ctx.run_id
    probe_id = uuid.uuid4().hex
    agent_dir, sensitive_dir = _prepare_probe_dirs(ctx.store, run_id, probe_id, category=category)
    use_sudo = ctx.rootfs.ssh_user != "root"
    remote_argv = _target_python_remote_argv(timeout_seconds=timeout_seconds, use_sudo=use_sudo)
    script = render_dump_list_script(dump_dir=dump_dir)
    try:
        ssh_argv = build_ssh_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            command=remote_argv,
            command_timeout=timeout_seconds + 10,
        )
    except ValueError as exc:
        return None, _configuration_failure(
            run_id=run_id, message=_redact_and_truncate(ctx.redactor, str(exc), cap=256),
            details={"code": "invalid_ssh_options"},
        )
    stdout_path = sensitive_dir / "stdout.raw"
    stderr_path = sensitive_dir / "stderr.raw"
    try:
        ssh_result = runner.run(
            ssh_argv, timeout=timeout_seconds + 10, stdout_path=stdout_path,
            stderr_path=stderr_path, stdin=script, max_stdout_bytes=PROBE_STDOUT_CAP,
        )
    except Exception as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=_redact_and_truncate(ctx.redactor, f"ssh probe raised: {exc}", cap=256),
            details={"code": "ssh_failure"},
        )
    for _path in (stdout_path, stderr_path):
        with contextlib.suppress(FileNotFoundError):
            _path.chmod(0o600)
    parsed, failure = _parse_enumeration_result(ctx, ssh_result=ssh_result, stdout_path=stdout_path)
    if failure is not None:
        return None, failure
    # Persist a redacted copy of the listing for forensics.
    (agent_dir / "probe.json").write_text(json.dumps(ctx.redactor.redact_value(parsed)), encoding="utf-8")
    return parsed, None


def _parse_enumeration_result(
    ctx: "_ProbeContext", *, ssh_result: SshCommandResult, stdout_path: Path,
) -> tuple[dict[str, Any] | None, ToolResponse | None]:
    run_id = ctx.run_id
    if ssh_result.oversized_output:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"enumeration stdout exceeded {PROBE_STDOUT_CAP} bytes",
            details={"code": "oversized_output"})
    raw = _read_capped(stdout_path, PROBE_STDOUT_CAP)
    if raw is None:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"enumeration stdout exceeded {PROBE_STDOUT_CAP} bytes",
            details={"code": "oversized_output"})
    if ssh_result.cancelled or ssh_result.timed_out or ssh_result.stdin_failed:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message="enumeration ssh round trip failed", details={"code": "ssh_failure"})
    if ssh_result.exit_status == 255:
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message="enumeration ssh transport failed before the target ran",
            details={"code": "ssh_connect_failure", "stderr": snippet})
    if ssh_result.exit_status == 127:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message="python3 is not available on the target; cannot enumerate dumps",
            details={"code": "probe_no_python"})
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        snippet = _redact_and_truncate(ctx.redactor, ssh_result.stderr_snippet or "", cap=256)
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"enumeration did not return parseable JSON (exit {ssh_result.exit_status})",
            details={"code": "probe_unparseable", "stderr": snippet})
    return parsed, None


def _validated_dump_dir(request: Any, run_id: str) -> tuple[str | None, ToolResponse | None]:
    dump_dir = request.dump_dir or DEFAULT_DUMP_DIR
    if not dump_dir.startswith("/"):
        return None, _configuration_failure(
            run_id=run_id, message=f"dump_dir must be an absolute path; got {dump_dir!r}",
            details={"code": "invalid_dump_dir"})
    return dump_dir, None


def debug_postmortem_list_dumps_handler(
    request: DebugPostmortemListDumpsRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """#95 / ADR 0029: enumerate captured vmcores over SSH."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = _resolve_probe_context(request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles)
    if failure is not None:
        return failure
    assert _ctx is not None
    ctx = _ctx
    dump_dir, dd_failure = _validated_dump_dir(request, ctx.run_id)
    if dd_failure is not None:
        return dd_failure
    assert dump_dir is not None
    try:
        halted = _reject_if_target_halted(
            run_id=ctx.run_id, admission=admission, session_registry=session_registry,
            action="enumerating dumps")
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=ctx.run_id, message=str(exc),
                                    details={"code": exc.code})
    if halted is not None:
        return halted
    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    parsed, failure = _run_dump_enumeration(
        ctx, runner=runner, dump_dir=dump_dir, timeout_seconds=request.timeout_seconds,
        category=("debug", "postmortem", "list_dumps"))
    if failure is not None:
        return failure
    assert parsed is not None
    entries = parse_dump_listing(parsed)
    return ToolResponse.success(
        summary=f"found {len(entries)} captured dump(s) under {dump_dir}",
        run_id=ctx.run_id,
        data={
            "dump_dir": dump_dir,
            "dumps": ctx.redactor.redact_value([e.model_dump(mode="json") for e in entries]),
        },
        suggested_next_actions=["debug.postmortem.fetch"],
    )
```

Add the imports at the top of `server.py` (near the other postmortem imports, ~line 88):

```python
from linux_debug_mcp.postmortem.dumps import (
    DEFAULT_DUMP_DIR,
    FetchSpec,
    derive_dump_id,
    parse_dump_listing,
    plan_fetch,
    render_dump_list_script,
)
from linux_debug_mcp.domain import (
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DumpEntry,
    FetchedFile,
)
```

(Add the new names to the existing `from linux_debug_mcp.domain import (...)` block rather than a second import if one already exists — check with `grep -n "from linux_debug_mcp.domain import" src/linux_debug_mcp/server.py`.)

- [ ] **Step 5: Run to verify list tests pass**

Run: `uv run python -m pytest tests/test_postmortem_list_dumps.py -q`
Expected: PASS for `test_list_dumps_*` and `test_build_scp_argv_quotes_remote_path` (the `test_fetch_*` tests still fail — handler in Task 8).

- [ ] **Step 6: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_list_dumps.py -k "list_dumps or scp" -q
git add src/linux_debug_mcp/server.py tests/test_postmortem_list_dumps.py
git commit -m "feat(server): build_scp_argv + debug.postmortem.list_dumps handler"
```

---

## Task 8: `debug_postmortem_fetch_handler`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (after the list handler)
- Test: `tests/test_postmortem_fetch.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_postmortem_fetch.py` (add the imports + fakes at the top of the file):

```python
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import (
    DebugPostmortemFetchRequest,
    StepResult,
    StepStatus,
)
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import debug_postmortem_fetch_handler

SECRET_KEY_REF = "s3cr3t-key"  # pragma: allowlist secret
_LISTING = (
    '{"dump_dir": "/var/crash", "exists": true, "dumps": ['
    '{"dir": "/var/crash/d1", "vmcore_name": "vmcore", "size": 16, "mtime": 1717027200.0,'
    ' "kernel": "Linux version 6.8.0", "incomplete": false,'
    ' "present": ["vmcore-dmesg.txt"], "file_sizes": {"vmcore": 16, "vmcore-dmesg.txt": 4}}]}'
)


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {"name": "minimal", "source": "/i", "access_method": "ssh",
            "ssh_host": "127.0.0.1", "ssh_user": "root", "ssh_key_ref": SECRET_KEY_REF}
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted(tmp_path) -> str:
    store = _store_with_run(tmp_path)
    store.record_step_result("r1",
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="ok", artifacts=[]))
    return "r1"


@dataclass
class _FetchRunner:
    """Emits the listing for the ssh enumeration; writes sized files for scp."""
    listing: str = _LISTING
    sizes: dict[str, int] = field(default_factory=lambda: {"vmcore": 16, "vmcore-dmesg.txt": 4})
    calls: list = field(default_factory=list)

    def which(self, c): return f"/usr/bin/{c}"

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
        self.calls.append({"argv": argv})
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.write_text("", encoding="utf-8")
        if argv[0] == "scp":
            dest = Path(argv[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            name = dest.name
            dest.write_bytes(b"x" * self.sizes.get(name, 0))
            stdout_path.write_text("", encoding="utf-8")
            return SshCommandResult(exit_status=0, stdout="")
        stdout_path.write_text(self.listing, encoding="utf-8")
        return SshCommandResult(exit_status=0, stdout="")


def _fetch(tmp_path, runner, **over):
    base = {"run_id": "r1", "target_ref": "local-qemu", "dump_ref": "/var/crash/d1"}
    base.update(over)
    return debug_postmortem_fetch_handler(
        DebugPostmortemFetchRequest(**base),
        artifact_root=tmp_path, rootfs_profiles=_rootfs(), ssh_runner=runner)


def test_fetch_success_stages_refs(tmp_path) -> None:
    run_id = _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner())
    assert resp.ok is True, resp.error
    assert resp.data["vmcore_ref"].endswith("/vmcore")
    assert resp.data["vmcore_dmesg_ref"].endswith("/vmcore-dmesg.txt")
    assert resp.data["vmlinux_ref"] is None
    files = {f["name"]: f for f in resp.data["files"]}
    assert files["vmcore"]["size_bytes"] == 16
    assert len(files["vmcore"]["sha256"]) == 64
    # staged file actually exists under the run dir
    vmcore = Path(tmp_path) / run_id / resp.data["vmcore_ref"]
    assert vmcore.is_file()


def test_fetch_dump_not_found(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(), dump_ref="/var/crash/missing")
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_not_found"


def test_fetch_truncated_transfer_detected(tmp_path) -> None:
    _booted(tmp_path)
    # scp writes a short vmcore (8 != expected 16)
    resp = _fetch(tmp_path, _FetchRunner(sizes={"vmcore": 8, "vmcore-dmesg.txt": 4}))
    assert resp.ok is False
    assert resp.error.details["code"] == "incomplete_transfer"


def test_fetch_truncated_symbol_detected(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(sizes={"vmcore": 16, "vmcore-dmesg.txt": 1}))
    assert resp.ok is False
    assert resp.error.details["code"] == "incomplete_transfer"


def test_fetch_dump_too_large(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(), max_bytes=4)
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_too_large"


def test_fetch_incomplete_refused(tmp_path) -> None:
    _booted(tmp_path)
    listing = _LISTING.replace('"vmcore_name": "vmcore"', '"vmcore_name": "vmcore-incomplete"').replace(
        '"incomplete": false', '"incomplete": true')
    resp = _fetch(tmp_path, _FetchRunner(listing=listing))
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_incomplete"


def test_fetch_incomplete_allowed_with_force(tmp_path) -> None:
    _booted(tmp_path)
    listing = _LISTING.replace('"vmcore_name": "vmcore"', '"vmcore_name": "vmcore-incomplete"').replace(
        '"incomplete": false', '"incomplete": true')
    runner = _FetchRunner(listing=listing, sizes={"vmcore": 16, "vmcore-dmesg.txt": 4})
    resp = _fetch(tmp_path, runner, force=True)
    assert resp.ok is True, resp.error


def test_fetch_idempotent_then_force(tmp_path) -> None:
    _booted(tmp_path)
    r1 = _fetch(tmp_path, _FetchRunner())
    assert r1.ok is True and r1.data["already_fetched"] is False
    r2 = _fetch(tmp_path, _FetchRunner())
    assert r2.ok is True and r2.data["already_fetched"] is True
    r3 = _fetch(tmp_path, _FetchRunner(), force=True)
    assert r3.ok is True and r3.data["already_fetched"] is False


def test_fetch_redacts_ssh_key(tmp_path) -> None:
    _booted(tmp_path)
    # ssh_key_ref appears in scp argv (-i <key>); the persisted fetch.json must not leak it
    resp = _fetch(tmp_path, _FetchRunner())
    assert resp.ok is True
    blob = str(resp.data)
    assert SECRET_KEY_REF not in blob
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_fetch.py -q`
Expected: FAIL (`ImportError` for `debug_postmortem_fetch_handler`).

- [ ] **Step 3: Implement the fetch handler**

In `server.py`, after `debug_postmortem_list_dumps_handler`, add:

```python
def _match_dump(parsed: dict[str, Any], dump_ref: str) -> DumpEntry | None:
    for entry in parse_dump_listing(parsed):
        if entry.path == dump_ref:
            return entry
    return None


def _stage_one_file(
    *, runner: SshRunner, ctx: "_ProbeContext", spec: FetchSpec, dest_dir: Path,
    sensitive_dir: Path, timeout_seconds: int,
) -> tuple[FetchedFile | None, ToolResponse | None]:
    run_id = ctx.run_id
    local_dest = dest_dir / spec.local_name
    try:
        scp_argv = build_scp_argv(
            rootfs_profile=ctx.rootfs,
            known_hosts_path=ctx.store.run_dir(run_id) / "sensitive" / "known_hosts",
            remote_path=spec.remote_path, local_dest=local_dest, command_timeout=timeout_seconds)
    except ValueError as exc:
        return None, _configuration_failure(
            run_id=run_id, message=_redact_and_truncate(ctx.redactor, str(exc), cap=256),
            details={"code": "invalid_ssh_options"})
    stdout_path = sensitive_dir / f"{spec.local_name}.scp.out"
    stderr_path = sensitive_dir / f"{spec.local_name}.scp.err"
    try:
        result = runner.run(scp_argv, timeout=timeout_seconds, stdout_path=stdout_path,
                            stderr_path=stderr_path, max_stdout_bytes=None)
    except Exception as exc:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=_redact_and_truncate(ctx.redactor, f"scp raised: {exc}", cap=256),
            details={"code": "ssh_failure"})
    if result.exit_status != 0 or result.timed_out or result.cancelled:
        snippet = _redact_and_truncate(ctx.redactor, result.stderr_snippet or "", cap=256)
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"scp of {spec.local_name} failed", details={"code": "incomplete_transfer", "stderr": snippet})
    local_size = local_dest.stat().st_size if local_dest.is_file() else -1
    if local_size != spec.expected_size:
        return None, ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"{spec.local_name} truncated: got {local_size} bytes, expected {spec.expected_size}",
            details={"code": "incomplete_transfer"})
    digest = _sha256_file(local_dest)
    ref = str(local_dest.relative_to(ctx.store.run_dir(run_id)))
    return FetchedFile(name=spec.local_name, ref=ref, sha256=digest, size_bytes=local_size), None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def debug_postmortem_fetch_handler(
    request: DebugPostmortemFetchRequest,
    *,
    artifact_root: Path,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    """#95 / ADR 0029: scp a captured dump (+ symbols) into the run dir."""
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    _ctx, failure = _resolve_probe_context(
        request, artifact_root=artifact_root, rootfs_profiles=rootfs_profiles,
        timeout_band=FETCH_TIMEOUT_BAND)
    if failure is not None:
        return failure
    assert _ctx is not None
    ctx = _ctx
    run_id = ctx.run_id
    dump_dir, dd_failure = _validated_dump_dir(request, run_id)
    if dd_failure is not None:
        return dd_failure
    assert dump_dir is not None
    try:
        halted = _reject_if_target_halted(
            run_id=run_id, admission=admission, session_registry=session_registry,
            action="fetching a dump")
    except AdmissionError as exc:
        return ToolResponse.failure(category=exc.category, run_id=run_id, message=str(exc),
                                    details={"code": exc.code})
    if halted is not None:
        return halted
    runner: SshRunner = ssh_runner or SubprocessSshRunner()
    parsed, failure = _run_dump_enumeration(
        ctx, runner=runner, dump_dir=dump_dir, timeout_seconds=min(request.timeout_seconds, 60),
        category=("debug", "postmortem", "fetch", "enumerate"))
    if failure is not None:
        return failure
    assert parsed is not None
    entry = _match_dump(parsed, request.dump_ref)
    if entry is None:
        return _configuration_failure(
            run_id=run_id, message=f"dump_ref not found in current listing: {request.dump_ref!r}",
            details={"code": "dump_not_found"})
    if entry.incomplete and not request.force:
        return ToolResponse.failure(
            category=ErrorCategory.READINESS_FAILURE, run_id=run_id,
            message="dump is incomplete (in-progress or vmcore.flat); pass force to fetch anyway",
            details={"code": "dump_incomplete"},
            suggested_next_actions=["debug.postmortem.list_dumps"])
    total = sum(entry.file_sizes.values()) or entry.size_bytes
    ceiling = request.max_bytes if request.max_bytes is not None else DEFAULT_FETCH_MAX_BYTES
    if total > ceiling:
        return _configuration_failure(
            run_id=run_id, message=f"dump total {total} bytes exceeds ceiling {ceiling}",
            details={"code": "dump_too_large"})
    dump_id = derive_dump_id(entry.path)
    dest_dir = ctx.store.run_dir(run_id) / "debug" / "postmortem" / "dumps" / dump_id
    free = shutil.disk_usage(ctx.store.run_dir(run_id)).free
    if free < total + FETCH_DISK_HEADROOM_BYTES:
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"insufficient host disk: {free} free, need {total} + headroom",
            details={"code": "insufficient_disk"})
    return _fetch_under_lock(
        ctx, runner=runner, request=request, entry=entry, dump_id=dump_id, dest_dir=dest_dir)


def _fetch_under_lock(
    ctx: "_ProbeContext", *, runner: SshRunner, request: DebugPostmortemFetchRequest,
    entry: DumpEntry, dump_id: str, dest_dir: Path,
) -> ToolResponse:
    run_id = ctx.run_id
    step_name = f"postmortem.fetch:{dump_id}"
    with ctx.store.postmortem_fetch_lock(run_id):
        manifest = ctx.store.load_manifest(run_id)
        prior = manifest.step_results.get(step_name)
        if prior is not None and prior.status == StepStatus.SUCCEEDED and not request.force:
            return _fetch_success_response(run_id, dict(prior.details), already_fetched=True)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True, mode=0o700)
        sensitive_dir = ctx.store.run_dir(run_id) / "sensitive" / "debug" / "postmortem" / "fetch" / dump_id
        sensitive_dir.mkdir(parents=True, exist_ok=True)
        sensitive_dir.chmod(0o700)
        fetched: list[FetchedFile] = []
        ref_map: dict[str, str | None] = {
            "vmcore_ref": None, "vmlinux_ref": None, "vmcoreinfo_ref": None, "vmcore_dmesg_ref": None,
            "modules_ref": None,
        }
        for spec in plan_fetch(entry, vmcore_name=entry.file_sizes and _core_name(entry) or "vmcore"):
            staged, failure = _stage_one_file(
                runner=runner, ctx=ctx, spec=spec, dest_dir=dest_dir, sensitive_dir=sensitive_dir,
                timeout_seconds=request.timeout_seconds)
            if failure is not None:
                shutil.rmtree(dest_dir, ignore_errors=True)
                return failure
            assert staged is not None
            fetched.append(staged)
            ref_map[spec.ref_key] = staged.ref
        details = {
            "dump_id": dump_id, "total_bytes": sum(f.size_bytes for f in fetched),
            "files": ctx.redactor.redact_value([f.model_dump(mode="json") for f in fetched]),
            **ref_map,
        }
        (dest_dir / "fetch.json").write_text(json.dumps(details), encoding="utf-8")
        step = StepResult(step_name=step_name, status=StepStatus.SUCCEEDED,
                          summary=f"fetched dump {dump_id} ({len(fetched)} files)",
                          artifacts=[ArtifactRef(path=str(dest_dir / "fetch.json"), kind="application/json")],
                          details=details)
        _record_terminal_build_result(ctx.store, run_id, step, )  # reuses the retry-with-backoff helper
    return _fetch_success_response(run_id, details, already_fetched=False)


def _core_name(entry: DumpEntry) -> str:
    for name in ("vmcore", "vmcore.flat", "vmcore-incomplete"):
        if name in entry.file_sizes:
            return name
    return "vmcore"


def _fetch_success_response(run_id: str, details: dict[str, Any], *, already_fetched: bool) -> ToolResponse:
    data = {**details, "already_fetched": already_fetched}
    return ToolResponse.success(
        summary=f"dump {details['dump_id']} staged ({details['total_bytes']} bytes)",
        run_id=run_id, data=data,
        suggested_next_actions=["debug.postmortem.crash", "debug.postmortem.triage",
                                "debug.introspect.from_vmcore"])
```

Add `import hashlib` and `import shutil` to `server.py`'s imports if not already present (check with `grep -n "^import hashlib\|^import shutil" src/linux_debug_mcp/server.py`). `_record_terminal_build_result` does not take a positional after `result`; call it `_record_terminal_build_result(ctx.store, run_id, step)` (remove the trailing comma artifact). `prior.status == StepStatus.SUCCEEDED` — confirm `StepResult.status` is the field name (it is, per domain.py).

Note on `plan_fetch` core name: pass `vmcore_name=_core_name(entry)` so an incomplete (`vmcore-incomplete`) dump fetched under `force` scps the actual core file present. Simplify the call to:

```python
        for spec in plan_fetch(entry, vmcore_name=_core_name(entry)):
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_postmortem_fetch.py tests/test_postmortem_list_dumps.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_fetch.py tests/test_postmortem_list_dumps.py -q
git add src/linux_debug_mcp/server.py tests/test_postmortem_fetch.py
git commit -m "feat(server): debug.postmortem.fetch handler (scp staging, integrity, idempotency)"
```

---

## Task 9: register the two MCP tools

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (in `create_app`, after the `debug.postmortem.check_prereqs` registration, ~line 8639)
- Test: `tests/test_postmortem_list_dumps.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_postmortem_list_dumps.py`:

```python
def test_tools_registered() -> None:
    from linux_debug_mcp.server import create_app

    app = create_app()
    names = {t.name for t in app._tool_manager.list_tools()}
    assert "debug.postmortem.list_dumps" in names
    assert "debug.postmortem.fetch" in names
```

(If `_tool_manager.list_tools()` is not the access pattern used elsewhere, mirror the existing tool-registration test — check `grep -rn "list_tools\|_tool_manager\|get_tools" tests/ | head`.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_postmortem_list_dumps.py::test_tools_registered -q`
Expected: FAIL.

- [ ] **Step 3: Register the tools**

In `create_app`, after the `debug_postmortem_check_prereqs` tool function, add:

```python
    @app.tool(name="debug.postmortem.list_dumps")
    def debug_postmortem_list_dumps(
        run_id: str,
        target_ref: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        dump_dir: str | None = None,
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugPostmortemListDumpsRequest(
            run_id=run_id, target_ref=target_ref, dump_dir=dump_dir,
            timeout_seconds=timeout_seconds, debug_profile=debug_profile,
            target_profile=target_profile, rootfs_profile=rootfs_profile)
        return debug_postmortem_list_dumps_handler(
            request, artifact_root=Path(artifact_root),
            admission=admission_service, session_registry=durable_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.fetch")
    def debug_postmortem_fetch(
        run_id: str,
        target_ref: str,
        dump_ref: str,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        force: bool = False,
        dump_dir: str | None = None,
        max_bytes: int | None = None,
        timeout_seconds: int = 300,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugPostmortemFetchRequest(
            run_id=run_id, target_ref=target_ref, dump_ref=dump_ref, force=force,
            dump_dir=dump_dir, max_bytes=max_bytes, timeout_seconds=timeout_seconds,
            debug_profile=debug_profile, target_profile=target_profile, rootfs_profile=rootfs_profile)
        return debug_postmortem_fetch_handler(
            request, artifact_root=Path(artifact_root),
            admission=admission_service, session_registry=durable_registry,
        ).model_dump(mode="json")
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_postmortem_list_dumps.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q
git add src/linux_debug_mcp/server.py tests/test_postmortem_list_dumps.py
git commit -m "feat(server): register list_dumps + fetch MCP tools"
```

---

## Task 10: env-gated live-target integration test

**Files:**
- Create: `tests/test_postmortem_fetch_integration.py`
- Test: itself (skipped without the guest env var)

- [ ] **Step 1: Write the gated test**

Create `tests/test_postmortem_fetch_integration.py`, mirroring `tests/test_kdump_prereqs_integration.py`'s gating:

```python
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("LDM_LIVE_DUMP_TARGET"),
    reason="set LDM_LIVE_DUMP_TARGET=run_id:target_ref:artifact_root to run the live SSH/scp fetch test",
)


def test_live_list_then_fetch() -> None:
    from pathlib import Path

    from linux_debug_mcp.domain import DebugPostmortemFetchRequest, DebugPostmortemListDumpsRequest
    from linux_debug_mcp.server import (
        debug_postmortem_fetch_handler,
        debug_postmortem_list_dumps_handler,
    )

    run_id, target_ref, artifact_root = os.environ["LDM_LIVE_DUMP_TARGET"].split(":", 2)
    listed = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref=target_ref),
        artifact_root=Path(artifact_root))
    assert listed.ok is True
    if not listed.data["dumps"]:
        pytest.skip("no captured dumps on the live target")
    dump_ref = listed.data["dumps"][0]["path"]
    fetched = debug_postmortem_fetch_handler(
        DebugPostmortemFetchRequest(run_id=run_id, target_ref=target_ref, dump_ref=dump_ref),
        artifact_root=Path(artifact_root))
    assert fetched.ok is True
    assert fetched.data["vmcore_ref"].endswith("/vmcore")
    assert len(fetched.data["files"][0]["sha256"]) == 64
```

- [ ] **Step 2: Verify it skips without the env var**

Run: `uv run python -m pytest tests/test_postmortem_fetch_integration.py -q`
Expected: 1 skipped.

- [ ] **Step 3: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_postmortem_fetch_integration.py -q
git add tests/test_postmortem_fetch_integration.py
git commit -m "test(postmortem): env-gated live SSH/scp fetch integration test"
```

---

## Task 11: docs — retrieval section

**Files:**
- Modify: `docs/debug-postmortem.md` (append a new top-level section)

- [ ] **Step 1: Append the retrieval section**

Add to `docs/debug-postmortem.md`:

```markdown
# `debug.postmortem.list_dumps` + `.fetch` — vmcore retrieval

`list_dumps` enumerates captured vmcores under the configured dump dir (default
`/var/crash`, the `vmcore` + `vmcore-dmesg.txt` layout) over SSH and returns one entry
per dump (`path`, `kernel`, `capture_time`, `size_bytes`, `incomplete`,
`available_files`). An empty dump dir returns an empty list, not an error.

`fetch` copies the selected dump (`dump_ref` = a `path` from `list_dumps`) plus any
co-located `vmcore-dmesg.txt` / `vmlinux` / `vmcoreinfo` into
`<run>/debug/postmortem/dumps/<dump_id>/`, returning run-relative refs
(`vmcore_ref`, `vmlinux_ref`, …) that `debug.postmortem.crash` and
`debug.introspect.from_vmcore` accept directly. Each file reports `sha256` + size.

## Integrity, bounding, idempotency

- **Truncation:** every staged file's local size must equal the size the enumeration
  reported; a mismatch (or non-zero scp exit) is `incomplete_transfer`, the partial
  staging dir is removed, and no success is recorded.
- **Bounding:** the total fetch size (known from the listing) must be within the
  effective ceiling (`max_bytes`, else `DEFAULT_FETCH_MAX_BYTES`) and the host must
  retain free space beyond it (`insufficient_disk`); both are checked before any byte
  moves.
- **Idempotency:** a second `fetch` of an already-staged dump returns the existing refs
  (`already_fetched=true`) without re-transferring; `force=true` re-transfers and
  replaces.
- **Incomplete dumps:** an in-progress (`vmcore-incomplete`) or flattened
  (`vmcore.flat`) dump is refused (`dump_incomplete`) unless `force`.

## Host-side vs target-side analysis

This phase pulls the vmcore to the host for offline analysis (#92 crash, #55
from_vmcore). For a dump too large to transfer economically, target-side analysis
(running `crash`/drgn on the target) avoids the move — that is the documented large-dump
alternative and is deferred to a future issue. Use the sizes `list_dumps` reports to
decide before committing to a fetch.

## ppc64le / fadump

The enumeration is layout-based (any dump-dir subdir holding a `vmcore`), so it is not
x86_64-specific by construction, but x86_64 `/var/crash` kdump is the only tested path.
POWER fadump may use a different dump path/capture layout; that is documented, not
silently claimed.
```

- [ ] **Step 2: Run the docs guard + commit**

```bash
just check-docs
git add docs/debug-postmortem.md
git commit -m "docs(postmortem): list_dumps/fetch retrieval section"
```

---

## Task 12: full guardrail sweep

- [ ] **Step 1: Run the full suite + all guardrails**

Run:
```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q && just check-docs
```
Expected: all green; integration tests skipped.

- [ ] **Step 2: Commit any formatting fixups** (only if `ruff format` changed files)

```bash
git add -A && git commit -m "style: ruff format fixups"
```

---

## Self-review notes

- **Spec coverage:** list (Task 7) + fetch (Task 8) + empty-list (Task 7) + refs (Task 8) + sha256/size + truncation (Task 8) + idempotency/force (Task 8) + redaction/HALTED (Tasks 7–8, HALTED via the reused `_reject_if_target_halted` default-arg path) + env-gated test (Task 10) + capability/config (Tasks 2, 4) + docs (Task 11) + bounding (`dump_too_large`/`insufficient_disk`/`dump_incomplete`, Task 8) + scp quoting (Task 7).
- **Type consistency:** `FetchSpec` fields (`remote_path`/`local_name`/`ref_key`/`expected_size`) are used identically in `plan_fetch` (Task 3) and `_stage_one_file` (Task 8); `ref_map` keys match `SYMBOL_REF_KEYS` values + `vmcore_ref` + `modules_ref`; `DumpEntry`/`FetchedFile` field names match across Tasks 1, 3, 7, 8.
- **HALTED handler test:** add a HALTED-injection test to `tests/test_postmortem_fetch.py` mirroring `tests/test_postmortem_check_prereqs.py::test_halted_target_is_fast_rejected` using a `_FakeAdmission`/`_FakeRegistry(ExecutionState.HALTED)` passed via `admission=`/`session_registry=`; assert `target_halted`. (Covered by reusing the existing helper; the test makes the reuse explicit.)
```
