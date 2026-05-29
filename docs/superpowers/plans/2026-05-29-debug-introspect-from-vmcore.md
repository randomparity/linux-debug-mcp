# `debug.introspect.from_vmcore` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add offline vmcore drgn introspection (`debug.introspect.from_vmcore` + `debug.introspect.from_vmcore_helper`) that runs the same drgn-script class as the live runner against a captured vmcore on the agent host, with no admission gate and a fail-loud vmcore↔vmlinux build-id check.

**Architecture:** A host ELF build-id reader supplies the authoritative expected build_id; the live wrapper template is split into a shared body + a swappable drgn-open prologue so the vmcore wrapper reuses the emit/caps/output framing verbatim; the post-runner result handling is extracted into a shared `_finalize_introspect_call` consumed by both the live and the new vmcore orchestrator; drgn runs locally via the existing `SubprocessSshRunner` fed a local argv. No admission, no SSH, no sudo — vmcore analysis is always concurrent-safe (interface-contracts §5.6 rule 3).

**Tech Stack:** Python 3.11+, Pydantic v2 (`domain.Model`, `extra="forbid"`), `string.Template` wrappers, drgn (host, env-gated in tests), pytest, ruff, ty.

**Spec:** `docs/superpowers/specs/2026-05-29-debug-introspect-from-vmcore-design.md`
**ADR:** `docs/adr/0010-introspect-from-vmcore-execution-model.md`

**Implementer notes carried from spec review (apply as you go):**
- The byte-identical-template test (Task 2) must capture its golden from the **pre-refactor** template text, before any split — otherwise it is circular.
- `_record_introspect_failure` must apply the same "omit `ssh_user` when `None`" rule the success finalizer uses (Task 5), so the failure path is symmetric on the vmcore side.
- The modules enumeration (Task 3) prefers `.ko.debug`, and a stripped/debuginfo-less `.ko` in the batch must not poison the whole `load_debug_info` call — load best-effort and warn, never fail.

---

## File structure

- Create `src/linux_debug_mcp/symbols/build_id.py` — `read_elf_build_id`, `BuildIdReadError` (pure ELF note parse).
- Modify `src/linux_debug_mcp/symbols/__init__.py` — export the two new names.
- Modify `src/linux_debug_mcp/providers/local_drgn_introspect.py` — split `WRAPPER_TEMPLATE` into `_WRAPPER_PROLOGUE_LIVE` + `_WRAPPER_BODY`; add `_WRAPPER_PROLOGUE_VMCORE`, `VMCORE_WRAPPER_TEMPLATE`, `render_vmcore_wrapper`, `render_vmcore_wrapper_skeleton`; extend `local_drgn_introspect_capability()`.
- Modify `src/linux_debug_mcp/domain.py` — `DebugIntrospectFromVmcoreRequest`, `DebugIntrospectFromVmcoreHelperRequest`.
- Modify `src/linux_debug_mcp/config.py` — add two ops to `ALLOWED_DEBUG_OPERATIONS`.
- Modify `src/linux_debug_mcp/server.py` — extract `_finalize_introspect_call`; add `_execute_vmcore_introspect_call`, `debug_introspect_from_vmcore_handler`, `debug_introspect_from_vmcore_helper_handler`; register two MCP tools.
- Create `tests/test_symbols_build_id.py`, `tests/test_vmcore_wrapper.py`, `tests/test_debug_introspect_from_vmcore.py`.
- Create `tests/golden/live_wrapper_template.txt` (one-time capture in Task 2).
- Modify `tests/test_drgn_introspect_integration.py` — add env-gated `test_from_vmcore_matches_live` (Task 10).

---

## Task 1: Host ELF build-id reader (`symbols/build_id.py`)

**Files:**
- Create: `src/linux_debug_mcp/symbols/build_id.py`
- Modify: `src/linux_debug_mcp/symbols/__init__.py`
- Test: `tests/test_symbols_build_id.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_symbols_build_id.py`. The helper `_elf` builds a minimal ELF with a `.note.gnu.build-id` note in a PT_NOTE segment, parametrised by class (32/64) and endianness.

```python
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from linux_debug_mcp.symbols import BuildIdReadError, read_elf_build_id

BUILD_ID = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")


def _note(endian: str) -> bytes:
    # NT_GNU_BUILD_ID = 3, name "GNU\0" (4 bytes), desc = BUILD_ID.
    name = b"GNU\x00"
    desc = BUILD_ID
    hdr = struct.pack(f"{endian}III", len(b"GNU\x00") - 0 if False else 4, len(desc), 3)
    # namesz counts "GNU\0" incl NUL = 4; both name and desc 4-byte aligned.
    body = name + desc  # 4 + 20 = 24, already aligned
    return hdr + body


def _elf(*, bits: int, endian: str) -> bytes:
    e = "<" if endian == "little" else ">"
    ei_class = 1 if bits == 32 else 2
    ei_data = 1 if endian == "little" else 2
    ident = bytes([0x7F]) + b"ELF" + bytes([ei_class, ei_data, 1]) + bytes(7)
    note = _note(e)
    if bits == 64:
        ehsize, phentsize = 64, 56
        e_phoff = ehsize
        note_off = ehsize + phentsize
        eh = struct.pack(
            f"{e}HHIQQQIHHHHHH", 2, 0x3E, 1, 0, e_phoff, 0, 0, ehsize, phentsize, 1, 0, 0, 0
        )
        ph = struct.pack(f"{e}IIQQQQQQ", 4, 0, note_off, 0, 0, len(note), len(note), 0)
    else:
        ehsize, phentsize = 52, 32
        e_phoff = ehsize
        note_off = ehsize + phentsize
        eh = struct.pack(
            f"{e}HHIIIIIHHHHHH", 2, 0x3E, 1, 0, e_phoff, 0, 0, ehsize, phentsize, 1, 0, 0, 0
        )
        ph = struct.pack(f"{e}IIIIIIII", 4, note_off, 0, 0, len(note), len(note), 0, 0)
    return ident + eh + ph + note


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_reads_build_id(tmp_path: Path, bits: int, endian: str) -> None:
    p = tmp_path / "vmlinux"
    p.write_bytes(_elf(bits=bits, endian=endian))
    assert read_elf_build_id(p) == BUILD_ID.hex()


def test_non_elf_raises(tmp_path: Path) -> None:
    p = tmp_path / "x"
    p.write_bytes(b"not an elf file at all")
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_truncated_raises(tmp_path: Path) -> None:
    p = tmp_path / "x"
    p.write_bytes(_elf(bits=64, endian="little")[:30])
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_note_absent_raises(tmp_path: Path) -> None:
    # A valid ELF header + program header pointing at a non-build-id note type.
    e = "<"
    ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1]) + bytes(7)
    name = b"GNU\x00"
    desc = b"\x00\x00\x00\x00"
    note = struct.pack(f"{e}III", 4, len(desc), 1) + name + desc  # type 1 != 3
    ehsize, phentsize = 64, 56
    note_off = ehsize + phentsize
    eh = struct.pack(f"{e}HHIQQQIHHHHHH", 2, 0x3E, 1, 0, ehsize, 0, 0, ehsize, phentsize, 1, 0, 0, 0)
    ph = struct.pack(f"{e}IIQQQQQQ", 4, 0, note_off, 0, 0, len(note), len(note), 0)
    p = tmp_path / "x"
    p.write_bytes(ident + eh + ph + note)
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(tmp_path / "nope")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_symbols_build_id.py -q`
Expected: FAIL — `ImportError: cannot import name 'read_elf_build_id'`.

- [ ] **Step 3: Implement `read_elf_build_id`**

Create `src/linux_debug_mcp/symbols/build_id.py`:

```python
"""Host-side ELF GNU build-id extraction. ADR 0010 / spec §5.

Pure-Python parse of the fixed ELF header → program-header table → PT_NOTE
segments, reading the NT_GNU_BUILD_ID note. No drgn/pyelftools dependency.
"""

from __future__ import annotations

import struct
from pathlib import Path

NT_GNU_BUILD_ID = 3
PT_NOTE = 4


class BuildIdReadError(Exception):
    """The file is not an ELF, is truncated, or carries no GNU build-id note.

    Callers map this to a caller-facing CONFIGURATION_ERROR
    (`vmlinux_build_id_unreadable`) — the caller supplied the wrong file.
    """


def _u(data: bytes, off: int, fmt: str, endian: str) -> tuple[int, ...]:
    size = struct.calcsize(endian + fmt)
    if off + size > len(data):
        raise BuildIdReadError(f"ELF truncated at offset {off}")
    return struct.unpack_from(endian + fmt, data, off)


def _scan_notes(blob: bytes, endian: str) -> str | None:
    off = 0
    while off + 12 <= len(blob):
        namesz, descsz, ntype = _u(blob, off, "III", endian)
        off += 12
        name_end = off + namesz
        desc_start = name_end + (-name_end % 4)
        desc_end = desc_start + descsz
        if desc_end > len(blob):
            return None
        if ntype == NT_GNU_BUILD_ID and blob[off:name_end].rstrip(b"\x00") == b"GNU":
            return blob[desc_start:desc_end].hex()
        off = desc_end + (-desc_end % 4)
    return None


def read_elf_build_id(path: Path) -> str:
    """Return the lower-case hex NT_GNU_BUILD_ID note from an ELF file.

    Raises :class:`BuildIdReadError` on a non-ELF (incl. compressed
    vmlinux.xz / vmlinuz), truncated, or note-absent file.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BuildIdReadError(f"cannot read {path}: {exc}") from exc
    if data[:4] != b"\x7fELF":
        raise BuildIdReadError("not an ELF file (bad magic)")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise BuildIdReadError("unsupported ELF class/endianness")
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    if is64:
        (e_phoff,) = _u(data, 32, "Q", endian)
        e_phentsize, e_phnum = _u(data, 54, "HH", endian)
    else:
        (e_phoff,) = _u(data, 28, "I", endian)
        e_phentsize, e_phnum = _u(data, 42, "HH", endian)
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        (p_type,) = _u(data, ph, "I", endian)
        if p_type != PT_NOTE:
            continue
        if is64:
            (p_offset,) = _u(data, ph + 8, "Q", endian)
            (p_filesz,) = _u(data, ph + 32, "Q", endian)
        else:
            (p_offset,) = _u(data, ph + 4, "I", endian)
            (p_filesz,) = _u(data, ph + 16, "I", endian)
        if p_offset + p_filesz > len(data):
            raise BuildIdReadError("PT_NOTE segment out of bounds")
        found = _scan_notes(data[p_offset : p_offset + p_filesz], endian)
        if found is not None:
            return found
    raise BuildIdReadError("no NT_GNU_BUILD_ID note found")
```

- [ ] **Step 4: Export from the package**

Modify `src/linux_debug_mcp/symbols/__init__.py` — add the import and `__all__` entries:

```python
from linux_debug_mcp.symbols.build_id import BuildIdReadError, read_elf_build_id
```
Add `"BuildIdReadError"` and `"read_elf_build_id"` to `__all__`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_symbols_build_id.py -q`
Expected: PASS (6 cases).

- [ ] **Step 6: Lint, type-check, commit**

```bash
uv run ruff check src/linux_debug_mcp/symbols tests/test_symbols_build_id.py
uv run ruff format src/linux_debug_mcp/symbols tests/test_symbols_build_id.py
uv run ty check src
git add src/linux_debug_mcp/symbols tests/test_symbols_build_id.py
git commit -m "feat(symbols): host ELF build-id reader for offline vmcore provenance (#55)"
```

---

## Task 2: Split the live wrapper into prologue + body (no behaviour change)

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py:77-248`
- Create: `tests/golden/live_wrapper_template.txt`
- Test: `tests/test_vmcore_wrapper.py` (golden assertion)

- [ ] **Step 1: Capture the golden template BEFORE refactoring**

Run (captures the current, pre-refactor template text verbatim):

```bash
mkdir -p tests/golden
uv run python -c "from linux_debug_mcp.providers.local_drgn_introspect import WRAPPER_TEMPLATE; import pathlib; pathlib.Path('tests/golden/live_wrapper_template.txt').write_text(WRAPPER_TEMPLATE.template, encoding='utf-8')"
```

- [ ] **Step 2: Write the golden regression test**

Create `tests/test_vmcore_wrapper.py` with the regression guard:

```python
from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.providers.local_drgn_introspect import WRAPPER_TEMPLATE

GOLDEN = Path(__file__).parent / "golden" / "live_wrapper_template.txt"


def test_live_wrapper_template_byte_identical_after_split() -> None:
    # ADR 0010: the prologue/body split must not change the live wrapper text.
    assert WRAPPER_TEMPLATE.template == GOLDEN.read_text(encoding="utf-8")
```

- [ ] **Step 3: Run the test — it passes now (sanity before the refactor)**

Run: `uv run python -m pytest tests/test_vmcore_wrapper.py -q`
Expected: PASS (golden == current template, trivially).

- [ ] **Step 4: Perform the mechanical split**

In `local_drgn_introspect.py`, replace the single `WRAPPER_TEMPLATE = Template(r"""...""")` assignment (lines ~77-248) with two raw-string fragments and a composition. `_WRAPPER_PROLOGUE_LIVE` is the text from `import sys as _li_sys` through the provenance-mismatch `_li_sys.exit(4)` block and the blank line that precedes `_li_emit_buffer = []` (current lines 1-145 of the template body). `_WRAPPER_BODY` is from `_li_emit_buffer = []` through the final `_li_sys.exit(6)` (current lines 146-end). Cut the existing text at exactly that boundary — do not retype it.

```python
_WRAPPER_PROLOGUE_LIVE = r"""import sys as _li_sys
...                                   # (verbatim through the §4.2 provenance-mismatch exit 4 block)
"""

_WRAPPER_BODY = r"""_li_emit_buffer = []
...                                   # (verbatim through the trailing finally: _li_sys.exit(6))
"""

WRAPPER_TEMPLATE = Template(_WRAPPER_PROLOGUE_LIVE + _WRAPPER_BODY)
```

- [ ] **Step 5: Run the golden test + the full existing wrapper/run suites**

Run: `uv run python -m pytest tests/test_vmcore_wrapper.py tests/test_introspect_wrapper.py tests/test_debug_introspect_run.py tests/test_introspect_helpers.py -q`
Expected: PASS — byte-identical template, and every live test unchanged.

- [ ] **Step 6: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git add src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_vmcore_wrapper.py tests/golden/live_wrapper_template.txt
git commit -m "refactor(introspect): split live wrapper into shared body + prologue (#55)"
```

---

## Task 3: Vmcore wrapper render

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py`
- Test: `tests/test_vmcore_wrapper.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_vmcore_wrapper.py`:

```python
import base64
import json

import pytest

from linux_debug_mcp.providers.local_drgn_introspect import (
    VMCORE_WRAPPER_TEMPLATE,
    WrapperRenderError,
    render_vmcore_wrapper,
    render_vmcore_wrapper_skeleton,
)

EXPECTED_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
CALL_ID = "0" * 32


def test_vmcore_wrapper_shares_body_with_live() -> None:
    # The shared body literal must appear verbatim in both templates.
    from linux_debug_mcp.providers.local_drgn_introspect import _WRAPPER_BODY
    assert _WRAPPER_BODY in VMCORE_WRAPPER_TEMPLATE.template
    assert _WRAPPER_BODY in WRAPPER_TEMPLATE.template


def test_render_vmcore_substitutes_all_placeholders() -> None:
    out = render_vmcore_wrapper(
        user_script="emit({'ok': True})",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        vmcore_path="/runs/r1/inputs/vmcore",
        vmlinux_path="/runs/r1/build/vmlinux",
        modules_path=None,
    )
    assert "$" not in out.replace("$li", "")  # no unsubstituted ${...}
    assert base64.b64encode(b"/runs/r1/inputs/vmcore").decode() in out
    assert base64.b64encode(b"/runs/r1/build/vmlinux").decode() in out
    assert base64.b64encode(b"").decode() in out  # modules absent -> b64("")
    assert EXPECTED_BUILD_ID in out


def test_render_vmcore_encodes_injection_path_safely() -> None:
    evil = "/runs/r1/x\".__import__('os').system('id')#"
    out = render_vmcore_wrapper(
        user_script="pass",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        vmcore_path=evil,
        vmlinux_path="/runs/r1/build/vmlinux",
        modules_path=None,
    )
    # The raw path never appears as a literal; only its base64 does.
    assert evil not in out
    assert base64.b64encode(evil.encode()).decode() in out


def test_render_vmcore_rejects_bad_build_id() -> None:
    with pytest.raises(WrapperRenderError):
        render_vmcore_wrapper(
            user_script="pass",
            expected_build_id="NOTHEX",
            call_id=CALL_ID,
            vmcore_path="/c",
            vmlinux_path="/v",
            modules_path=None,
        )


def test_render_vmcore_rejects_bad_call_id() -> None:
    with pytest.raises(WrapperRenderError):
        render_vmcore_wrapper(
            user_script="pass",
            expected_build_id=EXPECTED_BUILD_ID,
            call_id="xyz",
            vmcore_path="/c",
            vmlinux_path="/v",
            modules_path=None,
        )


def test_render_vmcore_skeleton_has_no_plaintext_script() -> None:
    out = render_vmcore_wrapper_skeleton(
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        user_script_sha256_hex="a" * 64,
        vmcore_path="/c",
        vmlinux_path="/v",
        modules_path=None,
    )
    assert "sha256:" + "a" * 64 in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_vmcore_wrapper.py -q`
Expected: FAIL — `ImportError: cannot import name 'render_vmcore_wrapper'`.

- [ ] **Step 3: Implement the vmcore prologue + render functions**

In `local_drgn_introspect.py`, add the vmcore prologue and template after the live one. The prologue mirrors `_WRAPPER_PROLOGUE_LIVE` but (a) decodes the three base64 path placeholders, (b) uses `set_core_dump`, (c) handles `build_id is None` → `provenance_unverifiable`, (d) loads vmlinux then best-effort modules. Keep `_li_result` keys identical to the live prologue so `_WRAPPER_BODY` is reused unchanged.

```python
_WRAPPER_PROLOGUE_VMCORE = Template(r"""import sys as _li_sys
import json as _li_json
import io as _li_io
import traceback as _li_traceback
import contextlib as _li_contextlib
import base64 as _li_b64
import os as _li_os

_li_caps = ${CAPS_JSON}

def _li_truncate(s, cap):
    return (s[:cap], True) if len(s) > cap else (s, False)

_li_result = {"call_id": "${CALL_ID}", "build_id": None, "outcome": None,
              "emits": [], "user_stdout": "", "prelude_ms": 0, "warnings": [],
              "truncated": {"emits": False, "user_stdout": False,
                            "traceback": False, "total_json": False,
                            "per_emit_size": False, "error_message": False}}

_li_vmcore = _li_b64.b64decode("${VMCORE_PATH_B64}").decode("utf-8")
_li_vmlinux = _li_b64.b64decode("${VMLINUX_PATH_B64}").decode("utf-8")
_li_modules = _li_b64.b64decode("${MODULES_PATH_B64}").decode("utf-8") or None

import time as _li_time
_li_t_prelude_start = _li_time.monotonic()

try:
    import drgn  # noqa: E402
    _li_pre_helpers = set(globals().keys()) | {"_li_pre_helpers", "_li_drgn_helper_names"}
    from drgn.helpers.linux import *  # noqa: F401,F403,E402
    _li_drgn_helper_names = set(globals().keys()) - _li_pre_helpers
    prog = drgn.Program()
    prog.set_core_dump(_li_vmcore)
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_open_failure", "error_type": etype, "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

_li_result["prelude_ms"] = int((_li_time.monotonic() - _li_t_prelude_start) * 1000)

try:
    _li_bid = prog.main_module().build_id
    _li_result["build_id"] = _li_bid.hex() if _li_bid else None
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_version_skew", "error_type": etype, "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

if _li_result["build_id"] is None:
    _li_result["outcome"] = {"status": "provenance_unverifiable",
                             "detail": "vmcore carries no embedded build-id"}
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(4)

if _li_result["build_id"] != "${EXPECTED_BUILD_ID}":
    _li_result["outcome"] = {"status": "provenance_mismatch",
                             "expected": "${EXPECTED_BUILD_ID}",
                             "actual": _li_result["build_id"]}
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(4)

try:
    prog.load_debug_info([_li_vmlinux])
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_open_failure", "error_type": etype, "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

if _li_modules:
    _li_ko = []
    for _li_r, _, _li_fs in _li_os.walk(_li_modules):
        for _li_f in _li_fs:
            if _li_f.endswith(".ko.debug"):
                _li_ko.append(_li_os.path.join(_li_r, _li_f))
    if not _li_ko:
        for _li_r, _, _li_fs in _li_os.walk(_li_modules):
            for _li_f in _li_fs:
                if _li_f.endswith(".ko"):
                    _li_ko.append(_li_os.path.join(_li_r, _li_f))
    if not _li_ko:
        _li_result["warnings"].append({"code": "modules_debuginfo_empty"})
    else:
        _li_loaded = 0
        for _li_p in _li_ko:
            try:
                prog.load_debug_info([_li_p])
                _li_loaded += 1
            except Exception:
                pass
        _li_result["warnings"].append(
            {"code": "modules_debuginfo_loaded" if _li_loaded else "modules_debuginfo_load_failed",
             "count": _li_loaded, "found": len(_li_ko)})

""").template

VMCORE_WRAPPER_TEMPLATE = Template(_WRAPPER_PROLOGUE_VMCORE + _WRAPPER_BODY)
```

> Note: modules are loaded one file at a time so a single debuginfo-less `.ko`
> cannot poison the batch (implementer note 3). `_li_result["warnings"]` is added
> by the vmcore prologue; the live `_WRAPPER_BODY` does not touch it, so reuse is safe.

Add the two render functions (mirroring `render_wrapper` / `render_wrapper_skeleton`):

```python
_VMCORE_PATH_FORBIDDEN = ("\x00",)


def _encode_path(value: str | None, *, field: str) -> str:
    text = value or ""
    if any(c in text for c in _VMCORE_PATH_FORBIDDEN):
        raise WrapperRenderError(f"{field} contains a forbidden byte")
    try:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    except UnicodeEncodeError as exc:  # non-UTF-8 surrogate path
        raise WrapperRenderError(f"{field} is not valid UTF-8: {exc}") from exc


def render_vmcore_wrapper(
    *,
    user_script: str,
    expected_build_id: str,
    call_id: str,
    vmcore_path: str,
    vmlinux_path: str,
    modules_path: str | None,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
) -> str:
    """Render the offline vmcore wrapper (spec §4.2). Paths are base64-encoded
    into pure-ASCII literals (ADR 0010 decision 8); only the build-id and
    call-id are regex-validated before substitution.
    """
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc
    return VMCORE_WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=base64.b64encode(user_script.encode("utf-8")).decode("ascii"),
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=base64.b64encode(args_json.encode("utf-8")).decode("ascii"),
        CAPS_JSON=json.dumps(merged_caps),
        VMCORE_PATH_B64=_encode_path(vmcore_path, field="vmcore_path"),
        VMLINUX_PATH_B64=_encode_path(vmlinux_path, field="vmlinux_path"),
        MODULES_PATH_B64=_encode_path(modules_path, field="modules_path"),
    )


def render_vmcore_wrapper_skeleton(
    *,
    expected_build_id: str,
    call_id: str,
    user_script_sha256_hex: str,
    vmcore_path: str,
    vmlinux_path: str,
    modules_path: str | None,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
) -> str:
    """Agent-visible companion: the user-script body is a sha256 pointer."""
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc
    placeholder = (
        f"# <user script: sha256:{user_script_sha256_hex}; "
        f"full source under sensitive/debug/introspect/{call_id}/wrapper.py>"
    )
    return VMCORE_WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=base64.b64encode(placeholder.encode("utf-8")).decode("ascii"),
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=base64.b64encode(args_json.encode("utf-8")).decode("ascii"),
        CAPS_JSON=json.dumps(merged_caps),
        VMCORE_PATH_B64=_encode_path(vmcore_path, field="vmcore_path"),
        VMLINUX_PATH_B64=_encode_path(vmlinux_path, field="vmlinux_path"),
        MODULES_PATH_B64=_encode_path(modules_path, field="modules_path"),
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_vmcore_wrapper.py -q`
Expected: PASS (all vmcore render tests + the golden regression).

- [ ] **Step 5: Exec-the-wrapper behaviour test against a stub drgn**

Append a test that `exec`s the rendered vmcore wrapper in-process against a stub `drgn` (reuse the `_install_stub_drgn` pattern from `tests/test_introspect_wrapper.py`) and asserts: a matching build_id runs the user script and emits; a mismatching build_id yields `outcome.status == "provenance_mismatch"` with exit 4; a `None` build_id yields `provenance_unverifiable` exit 4. Model the stub on the existing live wrapper test's stub (a `SimpleNamespace` `prog` with `set_core_dump`, `main_module().build_id`, `load_debug_info`).

Run: `uv run python -m pytest tests/test_vmcore_wrapper.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git add src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_vmcore_wrapper.py
git commit -m "feat(introspect): vmcore wrapper render with base64 paths + build-id fail-loud (#55)"
```

---

## Task 4: Request models

**Files:**
- Modify: `src/linux_debug_mcp/domain.py:117` (after `DebugIntrospectHelperRequest`)
- Test: covered by Task 6/7 handler tests; add a focused model test here.

- [ ] **Step 1: Write the failing test**

Create `tests/test_debug_introspect_from_vmcore.py` with the model edge tests:

```python
from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import (
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
)


def test_request_defaults() -> None:
    r = DebugIntrospectFromVmcoreRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", script="pass"
    )
    assert r.modules_ref is None
    assert r.timeout_seconds == 30
    assert r.allow_write is False
    assert r.args == {}


def test_request_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugIntrospectFromVmcoreRequest(
            run_id="r1", vmcore_ref="c", vmlinux_ref="v", script="pass", target_ref="nope"
        )


def test_helper_request_shape() -> None:
    r = DebugIntrospectFromVmcoreHelperRequest(
        run_id="r1", vmcore_ref="c", vmlinux_ref="v", name="sysinfo"
    )
    assert r.args == {}
    assert r.timeout_seconds == 30
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Add the models**

Insert in `domain.py` after `DebugIntrospectHelperRequest`:

```python
class DebugIntrospectFromVmcoreRequest(Model):
    """Request payload for ``debug.introspect.from_vmcore``. Spec §3.1.

    No ``target_ref``/``*_profile``: the offline path names no live target.
    ``vmcore_ref``/``vmlinux_ref``/``modules_ref`` are run-relative and confined
    to the run dir. The ``[5, 300]`` timeout band and script invariants are
    enforced by the handler (not Pydantic) so they surface as the spec's codes.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    script: str
    timeout_seconds: int = 30
    allow_write: bool = False
    args: dict[str, Any] = Field(default_factory=dict)


class DebugIntrospectFromVmcoreHelperRequest(Model):
    """Request payload for ``debug.introspect.from_vmcore_helper``. Spec §3.1."""

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -q`
Expected: PASS (3 cases).

- [ ] **Step 5: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git add src/linux_debug_mcp/domain.py tests/test_debug_introspect_from_vmcore.py
git commit -m "feat(domain): from_vmcore request models (#55)"
```

---

## Task 5: Extract `_finalize_introspect_call` from the live core (no behaviour change)

**Files:**
- Modify: `src/linux_debug_mcp/server.py:2955-3284` (the post-runner tail of `_execute_introspect_call`), `server.py:367-439` (`_record_introspect_failure`)
- Test: existing `tests/test_debug_introspect_run.py` + `tests/test_introspect_helpers.py` are the regression gate.

- [ ] **Step 1: Confirm the live suite is green (baseline)**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py tests/test_introspect_helpers.py -q`
Expected: PASS. Record the count.

- [ ] **Step 2: Introduce `_finalize_introspect_call` and make `ssh_user` omittable**

Define a new module-level function `_finalize_introspect_call` in `server.py` that takes the post-runner state and returns the `ToolResponse`. Move the body of `_execute_introspect_call` from the `raw_stdout = _read_capped(...)` line through the final happy-path `ToolResponse.success(...)` into it. Parametrise the five differing values via keyword args:

```python
def _finalize_introspect_call(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    ssh_result: SshCommandResult,
    stdout_path: Path,
    stderr_path: Path,
    agent_dir: Path,
    sensitive_call_dir: Path,
    redactor: Redactor,
    expected_build_id: str,
    request_timeout_seconds: int,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
    operation_name: str,
    drgn_open_message: str,
    exec_principal: str | None,
    post_validator: IntrospectPostValidator | None,
) -> ToolResponse:
    ...
```

**Exact rename checklist for the moved tail (do ALL — each is a guaranteed
`NameError` otherwise, because `request`, `build_id`, and `resolved_rootfs` are not
parameters of the finalizer):**
- every `request.timeout_seconds` → `request_timeout_seconds` (sites: the
  `PRELUDE_WARNING_FRACTION_PCT * request.timeout_seconds` diagnostic; the success
  `data`; `step_details["timeout_seconds"]`; the `_fail(...)` →
  `_record_introspect_failure(request_timeout_seconds=...)`);
- the `verify_build_id(expected=build_id, observed=...)` call →
  `expected=expected_build_id`;
- every `resolved_rootfs.ssh_user` → `exec_principal` (in the `_fail` closure's
  `ssh_user=` kwarg and the success `step_details`);
- the hard-coded `"drgn could not attach to the live target"` → `drgn_open_message`;
- in both the success step `details` and the `_fail`/`_record_introspect_failure`
  call, pass `ssh_user=exec_principal`.

The `_fail` inner closure moves with the tail and now closes over the finalizer's
parameters (`store`, `run_id`, `call_id`, `agent_dir`, `sensitive_call_dir`,
`redactor`, `raw_stderr`, `ssh_exit`, `request_timeout_seconds`, `duration_ms`,
`exec_principal`). `_read_capped`, `_head_tail`, `_record_introspect_failure`,
`_record_terminal_introspect_result`, and `PRELUDE_WARNING_FRACTION_PCT` are
module-level — no change. The `raw_stdout`/`raw_stderr`/`parsed`/`ssh_exit`
computations at the top of the moved block stay verbatim (they read `ssh_result`
and the path params).

Then update `_record_introspect_failure` (server.py:423-431) to **omit** the key when `None`:

```python
    details: dict[str, Any] = {
        "call_id": call_id,
        "timeout_seconds": request_timeout_seconds,
        "duration_ms": duration_ms,
        "wrapper_exit_code": ssh_exit,
        "outcome_status": outcome_status_for_forensics,
        "code": code,
    }
    if ssh_user is not None:
        details["ssh_user"] = ssh_user
```

And in the success step `details` inside `_finalize_introspect_call`, build `ssh_user` conditionally the same way (only add the key when `exec_principal is not None`). The live caller always passes a non-None user, so the live recorded shape is unchanged.

- [ ] **Step 3: Re-point `_execute_introspect_call` at the finalizer**

Replace the moved tail in `_execute_introspect_call` (after `admission.complete(handle)` succeeds and the raw files are chmod'd) with a single call:

```python
        finished_at = now()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        return _finalize_introspect_call(
            store=store,
            run_id=run_id,
            call_id=call_id,
            ssh_result=ssh_result,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            agent_dir=agent_dir,
            sensitive_call_dir=sensitive_call_dir,
            redactor=redactor,
            expected_build_id=build_id,
            request_timeout_seconds=request.timeout_seconds,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            operation_name=operation_name,
            drgn_open_message="drgn could not attach to the live target",
            exec_principal=resolved_rootfs.ssh_user,
            post_validator=post_validator,
        )
```

Keep the surrounding `try/except` admission-rollback envelope intact — the finalizer runs inside it (it can raise; the envelope still rolls back). The `admission.complete` AdmissionError branch (server.py:2920-2953) stays in `_execute_introspect_call` unchanged.

- [ ] **Step 4: Run the live regression suite**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py tests/test_introspect_helpers.py tests/test_debug_introspect_check_prereqs.py -q`
Expected: PASS — same count as Step 1. If any test asserts `details["ssh_user"]`, it still passes (live always sets it).

- [ ] **Step 5: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git commit -am "refactor(introspect): extract shared _finalize_introspect_call (#55)"
```

---

## Task 6: `debug.introspect.from_vmcore` handler

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (add `_execute_vmcore_introspect_call`, `debug_introspect_from_vmcore_handler`)
- Test: `tests/test_debug_introspect_from_vmcore.py`

- [ ] **Step 1: Write the failing happy-path + edge tests**

Append to `tests/test_debug_introspect_from_vmcore.py`. Reuse the run-dir builder and `FakeSshRunner` pattern from `tests/test_debug_introspect_run.py` (copy the minimal `FakeSshRunner` + a `_make_run` that also writes `inputs/vmcore` and `build/vmlinux` files).

```python
import json
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import debug_introspect_from_vmcore_handler

VALID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def _run(tmp_path: Path) -> ArtifactStore:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(RunRequest(run_id="r1", source_path="/s", build_profile="x86_64-default",
                                target_profile="local-qemu", rootfs_profile="minimal"))
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    (rd / "inputs" / "vmcore").write_bytes(b"core")
    (rd / "build" / "vmlinux").write_bytes(b"elf")
    return store


def _wrapper_json(build_id=VALID, status="ok", emits=None):
    return {"call_id": "0" * 32, "build_id": build_id, "outcome": {"status": status},
            "emits": emits or [{"k": 1}], "user_stdout": "", "prelude_ms": 1,
            "truncated": {"emits": False, "user_stdout": False, "traceback": False,
                          "total_json": False, "per_emit_size": False, "error_message": False}}


def _req(tmp_path, **kw):
    from linux_debug_mcp.domain import DebugIntrospectFromVmcoreRequest
    base = dict(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", script="emit({'k':1})")
    base.update(kw)
    return DebugIntrospectFromVmcoreRequest(**base)


def test_happy_path_succeeds(tmp_path):
    store = _run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(_wrapper_json()), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=runner,
        build_id_reader=lambda p: VALID)
    assert resp.status == StepStatus.SUCCEEDED
    assert resp.data["emits"] == [{"k": 1}]
    manifest = store.load_manifest("r1")
    step = next(s for n, s in manifest.step_results.items() if n.startswith("introspect:"))
    assert step.status == StepStatus.SUCCEEDED
    assert "ssh_user" not in step.details            # implementer note 2

def test_no_admission_no_boot_still_works(tmp_path):
    # AC#3: lifecycle independence — no admission service injected at all.
    store = _run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(_wrapper_json()), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID)
    assert resp.status == StepStatus.SUCCEEDED

def test_host_verify_catches_build_id_mismatch(tmp_path):
    # Wrapper reports ok but build_id disagrees with read_elf_build_id (AC#2).
    _run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(_wrapper_json(build_id="f"*40)), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID)
    assert resp.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.details["code"] == "provenance_mismatch"

def test_wrapper_self_abort_provenance_unverifiable(tmp_path):
    _run(tmp_path)
    body = _wrapper_json(build_id=None, status="provenance_unverifiable")
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=4, stdout=json.dumps(body), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID)
    assert resp.category == ErrorCategory.CONFIGURATION_ERROR

def test_missing_run(tmp_path):
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=FakeSshRunner(), build_id_reader=lambda p: VALID)
    assert resp.category == ErrorCategory.CONFIGURATION_ERROR

def test_missing_vmcore(tmp_path):
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path, vmcore_ref="inputs/nope"), artifact_root=tmp_path,
        runner=FakeSshRunner(), build_id_reader=lambda p: VALID)
    assert resp.details["code"] == "vmcore_not_found"

def test_escaping_vmcore_ref(tmp_path):
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path, vmcore_ref="../../etc/passwd"), artifact_root=tmp_path,
        runner=FakeSshRunner(), build_id_reader=lambda p: VALID)
    assert resp.category == ErrorCategory.CONFIGURATION_ERROR

def test_unreadable_vmlinux_is_config_error(tmp_path):
    from linux_debug_mcp.symbols import BuildIdReadError
    _run(tmp_path)
    def _boom(p):
        raise BuildIdReadError("not elf")
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=FakeSshRunner(), build_id_reader=_boom)
    assert resp.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.details["code"] == "vmlinux_build_id_unreadable"

def test_allow_write_rejected(tmp_path):
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path, allow_write=True), artifact_root=tmp_path,
        runner=FakeSshRunner(), build_id_reader=lambda p: VALID)
    assert resp.details["code"] == "allow_write_not_supported"

def test_bad_timeout(tmp_path):
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path, timeout_seconds=1), artifact_root=tmp_path,
        runner=FakeSshRunner(), build_id_reader=lambda p: VALID)
    assert resp.details["code"] == "invalid_timeout"

def test_timeout_exit_124(tmp_path):
    _run(tmp_path)
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=124, stdout="", stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID)
    assert resp.category == ErrorCategory.INFRASTRUCTURE_FAILURE

def test_redaction_masks_secret(tmp_path):
    _run(tmp_path)
    body = _wrapper_json(emits=[{"k": 1}])
    body["user_stdout"] = "token=ssh-rsa AAAAB3secretkey"
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    resp = debug_introspect_from_vmcore_handler(
        _req(tmp_path), artifact_root=tmp_path, runner=runner, build_id_reader=lambda p: VALID)
    assert "AAAAB3secretkey" not in json.dumps(resp.data)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -q`
Expected: FAIL — `ImportError: cannot import name 'debug_introspect_from_vmcore_handler'`.

- [ ] **Step 3: Implement `_execute_vmcore_introspect_call` + handler**

Add to `server.py`. The orchestrator follows spec §6 and ends by calling `_finalize_introspect_call`. Reuse `resolve_symbols`, `confine_run_relative`, `render_vmcore_wrapper`, `render_vmcore_wrapper_skeleton`, `read_elf_build_id` (via the injected `build_id_reader`), and the existing dir-mode preflight + budget + sensitive-dir code (copy the relevant blocks from `_execute_introspect_call`, dropping the admission/sudo/SSH-argv parts).

```python
def _execute_vmcore_introspect_call(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
    operation_name: str = "debug.introspect.from_vmcore",
    caps: dict[str, int] | None = None,
    post_validator: IntrospectPostValidator | None = None,
) -> ToolResponse:
    run_id = request.run_id
    now = clock or _utcnow
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if request.allow_write:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message="allow_write=true is not yet supported (#56)", details={"code": "allow_write_not_supported"})
    if not (5 <= request.timeout_seconds <= 300):
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}",
            details={"code": "invalid_timeout"})
    script_bytes = request.script.encode("utf-8")
    if not script_bytes or len(script_bytes) > SCRIPT_BYTE_CAP:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message="script must be non-empty and <= cap", details={"code": "invalid_script"})

    if _count_introspect_calls(manifest) >= MAX_INTROSPECT_CALLS_PER_RUN:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message="introspect call budget exhausted", details={"code": "manifest_call_budget_exhausted"})

    sensitive_dir = store.run_dir(run_id) / "sensitive"
    try:
        mode = sensitive_dir.stat().st_mode & 0o777
    except FileNotFoundError:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=f"{sensitive_dir} is missing; re-run kernel.create_run", details={"code": "sensitive_dir_missing"})
    if mode & 0o077:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=f"{sensitive_dir} mode is {oct(mode)}; expected 0o700",
            details={"code": "sensitive_dir_too_permissive", "actual_mode": oct(mode)})

    run_dir = store.run_dir(run_id)
    redactor = Redactor(secret_values=[])
    provenance_shell = KernelProvenance(build_id="", release="", vmlinux_ref=request.vmlinux_ref,
                                        modules_ref=request.modules_ref, cmdline="", config_ref=None)
    try:
        resolved = resolve_symbols(provenance_shell, run_dir=run_dir)
    except SymbolResolutionError as exc:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=str(exc), details={"code": "symbol_resolution_failed", "resolver_code": exc.code})
    try:
        vmcore_path = confine_run_relative(request.vmcore_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=str(exc), details={"code": "vmcore_not_found"})
    if not vmcore_path.is_file():
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=f"vmcore not found at {request.vmcore_ref!r}", details={"code": "vmcore_not_found"})

    try:
        expected_build_id = build_id_reader(resolved.vmlinux_path)
    except BuildIdReadError as exc:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message=str(exc), details={"code": "vmlinux_build_id_unreadable"})
    if not BUILD_ID_RE.match(expected_build_id):
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=run_id,
            message="vmlinux build_id is malformed", details={"code": "vmlinux_build_id_unreadable"})

    call_id = uuid.uuid4().hex
    agent_dir = run_dir / "debug" / "introspect" / call_id
    sensitive_call_dir = run_dir / "sensitive" / "debug" / "introspect" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.chmod(0o700)
    sensitive_call_dir.parent.chmod(0o700)
    sensitive_call_dir.parent.parent.chmod(0o700)

    args_json = json.dumps(request.args or {})
    modules_arg = str(resolved.modules_path) if resolved.modules_path is not None else None
    try:
        wrapper = render_vmcore_wrapper(user_script=request.script, expected_build_id=expected_build_id,
            call_id=call_id, vmcore_path=str(vmcore_path), vmlinux_path=str(resolved.vmlinux_path),
            modules_path=modules_arg, args_json=args_json, caps=caps)
        skeleton = render_vmcore_wrapper_skeleton(expected_build_id=expected_build_id, call_id=call_id,
            user_script_sha256_hex=user_script_sha256(request.script), vmcore_path=str(vmcore_path),
            vmlinux_path=str(resolved.vmlinux_path), modules_path=modules_arg, args_json=args_json, caps=caps)
    except WrapperRenderError as exc:
        shutil.rmtree(agent_dir, ignore_errors=True)
        shutil.rmtree(sensitive_call_dir, ignore_errors=True)
        failed = StepResult(step_name=f"introspect:{call_id}", status=StepStatus.FAILED,
            summary=f"wrapper render error: {exc}", artifacts=[],
            details={"call_id": call_id, "code": "wrapper_render_error", "duration_ms": 0})
        _record_terminal_introspect_result(store, run_id, failed)
        return ToolResponse.failure(category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id,
            message=f"wrapper render error: {exc}", details={"code": "wrapper_render_error", "call_id": call_id},
            suggested_next_actions=["artifacts.get_manifest"])

    wrapper_path = sensitive_call_dir / "wrapper.py"
    wrapper_fd = os.open(wrapper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(wrapper_fd, "w", encoding="utf-8") as fh:
        fh.write(wrapper)
    (agent_dir / "wrapper.skeleton.py").write_text(skeleton, encoding="utf-8")
    request_dump = request.model_dump(mode="json")
    request_dump["script"] = f"sha256:{user_script_sha256(request.script)}"
    (agent_dir / "request.json").write_text(json.dumps(redactor.redact_value(request_dump)), encoding="utf-8")

    stdout_path = sensitive_call_dir / "stdout.raw"
    stderr_path = sensitive_call_dir / "stderr.raw"
    active_runner: SshRunner = runner or SubprocessSshRunner()
    argv = ["timeout", "--kill-after=2s", f"{request.timeout_seconds}s", "python3", "-"]
    started_at = now()
    started_monotonic = time.monotonic()
    ssh_result = active_runner.run(argv, timeout=request.timeout_seconds + 10,
        stdout_path=stdout_path, stderr_path=stderr_path, cancel=threading.Event(),
        stdin=wrapper, max_stdout_bytes=RUN_STDOUT_CAP)
    for raw in (stdout_path, stderr_path):
        with contextlib.suppress(FileNotFoundError):
            raw.chmod(0o600)
    finished_at = now()
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)

    return _finalize_introspect_call(store=store, run_id=run_id, call_id=call_id, ssh_result=ssh_result,
        stdout_path=stdout_path, stderr_path=stderr_path, agent_dir=agent_dir,
        sensitive_call_dir=sensitive_call_dir, redactor=redactor, expected_build_id=expected_build_id,
        request_timeout_seconds=request.timeout_seconds, started_at=started_at, finished_at=finished_at,
        duration_ms=duration_ms, operation_name=operation_name,
        drgn_open_message="drgn could not open the vmcore", exec_principal=None, post_validator=post_validator)


def debug_introspect_from_vmcore_handler(
    request: DebugIntrospectFromVmcoreRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §6 / ADR 0010. Offline vmcore drgn introspection; no admission gate."""
    return _execute_vmcore_introspect_call(request, artifact_root=artifact_root, runner=runner,
        build_id_reader=build_id_reader, clock=clock, operation_name="debug.introspect.from_vmcore",
        caps=None, post_validator=None)
```

Add the imports at the top of `server.py`: `read_elf_build_id`, `BuildIdReadError` from `linux_debug_mcp.symbols`; `confine_run_relative`, `PathSafetyError` from `linux_debug_mcp.safety.paths`; `KernelProvenance` (already imported via seams); `render_vmcore_wrapper`, `render_vmcore_wrapper_skeleton` from the provider; `SubprocessSshRunner` (already imported). Verify each is present; add only the missing ones.

- [ ] **Step 4: Run the handler tests**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -q`
Expected: PASS (all cases incl. the no-admission lifecycle test and the no-`ssh_user` assertion).

- [ ] **Step 5: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git commit -am "feat(introspect): debug.introspect.from_vmcore handler (#55)"
```

---

## Task 7: `debug.introspect.from_vmcore_helper` handler

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_debug_introspect_from_vmcore.py`

- [ ] **Step 1: Write the failing tests**

Append:

```python
def test_helper_unknown_name(tmp_path):
    from linux_debug_mcp.domain import DebugIntrospectFromVmcoreHelperRequest
    from linux_debug_mcp.server import debug_introspect_from_vmcore_helper_handler
    _run(tmp_path)
    req = DebugIntrospectFromVmcoreHelperRequest(run_id="r1", vmcore_ref="inputs/vmcore",
        vmlinux_ref="build/vmlinux", name="nope")
    resp = debug_introspect_from_vmcore_helper_handler(req, artifact_root=tmp_path,
        runner=FakeSshRunner(), build_id_reader=lambda p: VALID)
    assert resp.details["code"] == "unknown_helper"

def test_helper_happy_path(tmp_path):
    # Use one concrete helper (sysinfo) with a hand-written valid emit that
    # satisfies its output_model exactly — no generic schema synthesis.
    from linux_debug_mcp.domain import DebugIntrospectFromVmcoreHelperRequest
    from linux_debug_mcp.server import debug_introspect_from_vmcore_helper_handler
    _run(tmp_path)
    sysinfo_emit = {
        "release": "6.1.0", "version": "#1 SMP", "machine": "x86_64",
        "nodename": "vm", "boot_cmdline": "ro quiet", "cpus_online": 4,
        "mem_total_pages": 1048576,
    }
    body = {"call_id": "0"*32, "build_id": VALID, "outcome": {"status": "ok"},
            "emits": [sysinfo_emit], "user_stdout": "", "prelude_ms": 1,
            "truncated": {"emits": False, "user_stdout": False, "traceback": False,
                          "total_json": False, "per_emit_size": False, "error_message": False}}
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    req = DebugIntrospectFromVmcoreHelperRequest(run_id="r1", vmcore_ref="inputs/vmcore",
        vmlinux_ref="build/vmlinux", name="sysinfo")
    resp = debug_introspect_from_vmcore_helper_handler(req, artifact_root=tmp_path,
        runner=runner, build_id_reader=lambda p: VALID)
    assert resp.status == StepStatus.SUCCEEDED
    assert resp.data["helper"] == "sysinfo"
    assert resp.data["result"]["cpus_online"] == 4
```

> The `sysinfo` emit above matches `introspect_helpers/sysinfo.py:Output` field-for-field
> (`release, version, machine, nodename, boot_cmdline, cpus_online, mem_total_pages`).
> If `sysinfo` is not in `HELPER_REGISTRY` at implementation time, pick any registered
> helper and paste its `output_model`'s exact fields the same way — do not synthesize
> a generic valid instance.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -k helper -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Implement the helper handler**

```python
def debug_introspect_from_vmcore_helper_handler(
    request: DebugIntrospectFromVmcoreHelperRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §3.1. Run a curated HELPER_REGISTRY helper against a vmcore."""
    spec = HELPER_REGISTRY.get(request.name)
    if spec is None:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=request.run_id,
            message=f"unknown helper {request.name!r}; valid: {sorted(HELPER_REGISTRY)}",
            details={"code": "unknown_helper", "valid": sorted(HELPER_REGISTRY)},
            suggested_next_actions=["debug.introspect.from_vmcore_helper"])
    try:
        validated_args = spec.args_model.model_validate(request.args)
    except ValidationError as exc:
        return ToolResponse.failure(category=ErrorCategory.CONFIGURATION_ERROR, run_id=request.run_id,
            message=_redact_and_truncate(Redactor(), str(exc), cap=512),
            details={"code": "helper_args_invalid"},
            suggested_next_actions=["debug.introspect.from_vmcore_helper"])
    run_request = DebugIntrospectFromVmcoreRequest(
        run_id=request.run_id, vmcore_ref=request.vmcore_ref, vmlinux_ref=request.vmlinux_ref,
        modules_ref=request.modules_ref, script=spec.script, timeout_seconds=request.timeout_seconds,
        allow_write=False, args=validated_args.model_dump(mode="json"))
    return _execute_vmcore_introspect_call(run_request, artifact_root=artifact_root, runner=runner,
        build_id_reader=build_id_reader, clock=clock,
        operation_name="debug.introspect.from_vmcore_helper", caps=HELPER_CAP_PROFILE,
        post_validator=_make_helper_post_validator(spec))
```

- [ ] **Step 4: Run the helper tests**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -k helper -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git commit -am "feat(introspect): debug.introspect.from_vmcore_helper handler (#55)"
```

---

## Task 8: Allowlist + capability operations

**Files:**
- Modify: `src/linux_debug_mcp/config.py:95-114`
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py:362-383`
- Test: `tests/test_introspect_helpers.py` (capability) or a new check in `tests/test_debug_introspect_from_vmcore.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_debug_introspect_from_vmcore.py`:

```python
def test_operations_in_allowlist():
    from linux_debug_mcp.config import ALLOWED_DEBUG_OPERATIONS
    assert "debug.introspect.from_vmcore" in ALLOWED_DEBUG_OPERATIONS
    assert "debug.introspect.from_vmcore_helper" in ALLOWED_DEBUG_OPERATIONS

def test_capability_advertises_vmcore_ops_concurrent_safe():
    from linux_debug_mcp.providers.local_drgn_introspect import local_drgn_introspect_capability
    cap = local_drgn_introspect_capability()
    assert "debug.introspect.from_vmcore" in cap.operations
    assert "debug.introspect.from_vmcore_helper" in cap.operations
    by_op = {c.operation: c for c in cap.operation_capabilities}
    assert by_op["debug.introspect.from_vmcore"].semantics.concurrent_safe is True
    assert by_op["debug.introspect.run"].semantics.concurrent_safe is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -k "allowlist or capability" -q`
Expected: FAIL.

- [ ] **Step 3: Update config + capability**

In `config.py`, add to `ALLOWED_DEBUG_OPERATIONS`:
```python
    "debug.introspect.from_vmcore",
    "debug.introspect.from_vmcore_helper",
```

In `local_drgn_introspect_capability()`, append the two ops to `operations` and provide explicit `operation_capabilities` so the vmcore ops carry `concurrent_safe=True`. Build the list from the existing default semantics for the live ops and a concurrent-safe override for the two vmcore ops:

```python
    live_semantics = OperationSemantics(idempotent=False, retryable=True, destructive=False,
                                        cancelable=True, concurrent_safe=False)
    vmcore_semantics = OperationSemantics(idempotent=False, retryable=True, destructive=False,
                                          cancelable=True, concurrent_safe=True)
    operations = ["debug.introspect.run", "debug.introspect.check_prerequisites",
                  "debug.introspect.helper", "debug.introspect.from_vmcore",
                  "debug.introspect.from_vmcore_helper"]
    return ProviderCapability(
        provider_name="local-drgn-introspect",
        provider_version="0.2.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=operations,
        required_host_tools=["ssh"],
        destructive_permissions=[],
        access_methods=["ssh"],
        semantics=live_semantics,
        operation_capabilities=[
            ProviderOperationCapability(operation=op, semantics=(vmcore_semantics if op.endswith("from_vmcore") or op.endswith("from_vmcore_helper") else live_semantics))
            for op in operations
        ],
    )
```

Import `ProviderOperationCapability` in the provider module if not already present.

- [ ] **Step 4: Run the tests + the providers.list test**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -k "allowlist or capability" tests/test_introspect_helpers.py -q`
Expected: PASS. If a `providers.list` snapshot test exists and now fails on the new ops, update its expectation.

- [ ] **Step 5: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git commit -am "feat(introspect): advertise from_vmcore ops (allowlist + concurrent-safe capability) (#55)"
```

---

## Task 9: Wire the MCP tools

**Files:**
- Modify: `src/linux_debug_mcp/server.py:5851` (after the `debug.introspect.check_prerequisites` tool, inside `create_app`)
- Test: a smoke check that the tools are registered.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_debug_introspect_from_vmcore.py`:

```python
def test_tools_registered():
    # Mirror the existing convention (tests/test_server.py:40 uses
    # create_app()._tool_manager._tools — a dict keyed by tool name).
    from linux_debug_mcp.server import create_app
    names = set(create_app()._tool_manager._tools)
    assert "debug.introspect.from_vmcore" in names
    assert "debug.introspect.from_vmcore_helper" in names
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -k registered -q`
Expected: FAIL.

- [ ] **Step 3: Register the tools**

In `create_app`, after the `debug.introspect.check_prerequisites` registration:

```python
    @app.tool(name="debug.introspect.from_vmcore")
    def debug_introspect_from_vmcore(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        script: str,
        modules_ref: str | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 30,
        allow_write: bool = False,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = DebugIntrospectFromVmcoreRequest(
            run_id=run_id, vmcore_ref=vmcore_ref, vmlinux_ref=vmlinux_ref, script=script,
            modules_ref=modules_ref, timeout_seconds=timeout_seconds, allow_write=allow_write,
            args=args or {})
        return debug_introspect_from_vmcore_handler(
            request, artifact_root=Path(artifact_root)).model_dump(mode="json")

    @app.tool(name="debug.introspect.from_vmcore_helper")
    def debug_introspect_from_vmcore_helper(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        name: str,
        modules_ref: str | None = None,
        args: dict[str, Any] | None = None,
        artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        request = DebugIntrospectFromVmcoreHelperRequest(
            run_id=run_id, vmcore_ref=vmcore_ref, vmlinux_ref=vmlinux_ref, name=name,
            modules_ref=modules_ref, args=args or {}, timeout_seconds=timeout_seconds)
        return debug_introspect_from_vmcore_helper_handler(
            request, artifact_root=Path(artifact_root)).model_dump(mode="json")
```

- [ ] **Step 4: Run the test + a stdio smoke**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -k registered -q`
Then: `timeout 2 uv run linux-debug-mcp || test $? -eq 124`
Expected: PASS; server starts and is killed by timeout (exit 124).

- [ ] **Step 5: Commit**

```bash
uv run ruff check src tests && uv run ruff format src tests && uv run ty check src
git commit -am "feat(introspect): register from_vmcore MCP tools (#55)"
```

---

## Task 10: Env-gated integration test (AC#1 real-equivalence)

**Files:**
- Modify: `tests/test_drgn_introspect_integration.py`

- [ ] **Step 1: Add the gated equivalence test**

Append, mirroring the existing gate style in that file. Gate on `LDM_VMCORE` (path to a captured core), `LDM_VMLINUX`, and a host `import drgn`:

```python
import os
import pytest

drgn = pytest.importorskip("drgn")
VMCORE = os.environ.get("LDM_VMCORE")
VMLINUX = os.environ.get("LDM_VMLINUX")

@pytest.mark.skipif(not (VMCORE and VMLINUX), reason="LDM_VMCORE/LDM_VMLINUX not set")
def test_from_vmcore_runs_script_against_real_core(tmp_path):
    # Stage the core+vmlinux into a run dir, run a fixed emit script, assert
    # the emitted JSON is well-formed and the build_id verifies.
    ...
```

Document in the test docstring that the full live-vs-offline equivalence (`test_from_vmcore_matches_live`) additionally requires a live booted target (the libvirt gate) and asserts equal `emits` for the same script.

- [ ] **Step 2: Verify it skips cleanly in CI conditions**

Run: `uv run python -m pytest tests/test_drgn_introspect_integration.py -q`
Expected: SKIPPED (no `LDM_VMCORE` in dev/CI), no errors.

- [ ] **Step 3: Commit**

```bash
git add tests/test_drgn_introspect_integration.py
git commit -m "test(introspect): env-gated from_vmcore integration test (#55)"
```

---

## Task 11: Full-suite guardrail sweep

- [ ] **Step 1: Run the complete suite + guardrails**

```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q && just check-docs
```
Expected: all green, zero warnings.

- [ ] **Step 2: If `ty` or `ruff` flag anything, fix and re-run before proceeding.**

---

## Self-review checklist (run before handing off)

- **Spec coverage:** §3.1 requests → Task 4; §4 wrapper split + vmcore prologue → Tasks 2-3; §5 build-id reader → Task 1; §6 orchestrator → Task 6; §7 finalizer → Task 5; §8 taxonomy → Task 6 edge tests; §9 concurrency (no gate) → Task 6 lifecycle test; §10 allowlist/capability → Task 8; §12 tests → Tasks 1-10; §13 AC mapping: AC#1 → Task 10, AC#2 → Task 6, AC#3 → Task 6 (`test_no_admission_no_boot_still_works`), AC#4 → Task 6 (`test_redaction_masks_secret`).
- **Implementer notes:** golden-before-refactor (Task 2 Step 1); `ssh_user` omit-when-None on both success and failure paths (Task 5 Step 2, asserted in Task 6 Step 1); modules per-file best-effort load (Task 3 Step 3).
- **Type consistency:** `read_elf_build_id`/`BuildIdReadError` (Task 1) used in Tasks 6/7; `render_vmcore_wrapper(*, vmcore_path, vmlinux_path, modules_path, ...)` signature identical across Tasks 3, 6, 7; `_finalize_introspect_call(...)` kwargs identical across Tasks 5 and 6.
