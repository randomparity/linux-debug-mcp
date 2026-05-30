# `debug.postmortem.crash` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `debug.postmortem.crash` MCP tool that runs a validated batch of `crash` commands against a captured vmcore + matching vmlinux on the agent host and returns parsed JSON keyed by command plus a preserved redacted transcript.

**Architecture:** Mirror the #55 offline vmcore path (`_execute_vmcore_introspect_call`): run-scoped, run-relative refs, no admission gate, host-authoritative build-id fail-loud, redaction, per-call manifest step. New pieces: a pure-Python VMCOREINFO build-id reader in `symbols/`, a `postmortem/` package (command sanitisation + batch script build + per-command output-file collection + parsers), a `local-crash-postmortem` capability, a `crash` prereq check, and the `server.py` orchestrator/handler/tool. Per-command framing uses server-controlled `> cmd-NNNN.out` output redirection, bounded by `prlimit --fsize`.

**Tech Stack:** Python 3.11+, pydantic v2, FastMCP, pytest, ruff, ty. Spec: `docs/superpowers/specs/2026-05-30-debug-postmortem-crash-design.md`; ADR `docs/adr/0026-postmortem-crash-batch-runner.md`.

---

## File structure

| File | Responsibility |
|---|---|
| `src/linux_debug_mcp/symbols/vmcore_build_id.py` (create) | `read_vmcore_build_id` + `VmcoreBuildIdError`/`VmcoreFormatUnsupported`/`VmcoreBuildIdAbsent` |
| `src/linux_debug_mcp/symbols/__init__.py` (modify) | export the new reader + exceptions |
| `src/linux_debug_mcp/postmortem/__init__.py` (create) | package marker + re-exports |
| `src/linux_debug_mcp/postmortem/crash_commands.py` (create) | command sanitise+allowlist (`validate_crash_command`), `validate_modules_path` |
| `src/linux_debug_mcp/postmortem/crash_batch.py` (create) | `build_command_script`, `collect_command_outputs` |
| `src/linux_debug_mcp/postmortem/crash_parsers.py` (create) | typed parsers + `parse_command` dispatch |
| `src/linux_debug_mcp/config.py` (modify) | `ALLOWED_DEBUG_OPERATIONS` += op; caps + `CRASH_COMMAND_ALLOWLIST` |
| `src/linux_debug_mcp/domain.py` (modify) | `DebugPostmortemCrashRequest` |
| `src/linux_debug_mcp/providers/local_crash_postmortem.py` (create) | `local_crash_postmortem_capability` |
| `src/linux_debug_mcp/providers/plugins.py` (modify) | register the capability |
| `src/linux_debug_mcp/prereqs/checks.py` (modify) | `crash` tool check |
| `src/linux_debug_mcp/server.py` (modify) | `_execute_postmortem_crash_call`, `_finalize_crash_call`, handler, tool registration |
| `docs/debug-postmortem.md` (create) | usage, parsed fields, build_id contract |
| `tests/test_vmcore_build_id.py` (create) | reader unit tests |
| `tests/test_crash_commands.py` (create) | validation unit tests |
| `tests/test_crash_batch.py` (create) | batch build/collect unit tests |
| `tests/test_crash_parsers.py` (create) | parser unit tests |
| `tests/test_debug_postmortem_crash.py` (create) | handler tests |
| `tests/test_postmortem_crash_integration.py` (create) | env-gated real-crash test |

**Guardrails to run after each task:** `uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q`.

---

## Task 1: VMCOREINFO build-id reader (`symbols/vmcore_build_id.py`)

**Files:**
- Create: `src/linux_debug_mcp/symbols/vmcore_build_id.py`
- Modify: `src/linux_debug_mcp/symbols/__init__.py`
- Test: `tests/test_vmcore_build_id.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_vmcore_build_id.py`:

```python
from __future__ import annotations

import struct

import pytest

from linux_debug_mcp.symbols.vmcore_build_id import (
    VmcoreBuildIdAbsent,
    VmcoreBuildIdError,
    VmcoreFormatUnsupported,
    read_vmcore_build_id,
)

BUILD_ID = "abcdef0123456789abcdef0123456789abcdef01"  # pragma: allowlist secret


def _note(name: bytes, ntype: int, desc: bytes, endian: str = "<") -> bytes:
    # ELF note: namesz, descsz, type, name (padded to 4), desc (padded to 4).
    body = struct.pack(endian + "III", len(name), len(desc), ntype)
    body += name + b"\x00" * (-len(name) % 4)
    body += desc + b"\x00" * (-len(desc) % 4)
    return body


def _elf64_with_notes(note_blob: bytes, endian: str = "<") -> bytes:
    # Minimal ELF64 with one PT_NOTE program header pointing at note_blob.
    ei = b"\x7fELF" + bytes([2, 1 if endian == "<" else 2, 1]) + b"\x00" * 9
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 1
    ehdr = ei + struct.pack(
        endian + "HHIQQQIHHHHHH",
        4, 62, 1, 0, e_phoff, 0, 0, 64, e_phentsize, e_phnum, 0, 0, 0,
    )
    note_off = e_phoff + e_phentsize
    phdr = struct.pack(
        endian + "IIQQQQQQ",
        4, 0, note_off, 0, 0, len(note_blob), len(note_blob), 0,
    )
    return ehdr + phdr + note_blob


def test_reads_vmcoreinfo_build_id(tmp_path) -> None:
    vmcoreinfo = f"OSRELEASE=6.1.0\nBUILD-ID={BUILD_ID}\nPAGESIZE=4096\n".encode()
    blob = _note(b"VMCOREINFO", 0, vmcoreinfo)
    p = tmp_path / "vmcore"
    p.write_bytes(_elf64_with_notes(blob))
    assert read_vmcore_build_id(p) == BUILD_ID


def test_absent_build_id_raises_absent(tmp_path) -> None:
    blob = _note(b"VMCOREINFO", 0, b"OSRELEASE=6.1.0\nPAGESIZE=4096\n")
    p = tmp_path / "vmcore"
    p.write_bytes(_elf64_with_notes(blob))
    with pytest.raises(VmcoreBuildIdAbsent):
        read_vmcore_build_id(p)


def test_non_elf_raises_unsupported(tmp_path) -> None:
    p = tmp_path / "vmcore"
    p.write_bytes(b"KDUMP   " + b"\x00" * 64)
    with pytest.raises(VmcoreFormatUnsupported):
        read_vmcore_build_id(p)


def test_truncated_elf_raises_error(tmp_path) -> None:
    p = tmp_path / "vmcore"
    p.write_bytes(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 5)  # header cut short
    with pytest.raises(VmcoreBuildIdError):
        read_vmcore_build_id(p)


def test_uppercase_build_id_is_lowercased(tmp_path) -> None:
    vmcoreinfo = b"BUILD-ID=ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"
    blob = _note(b"VMCOREINFO", 0, vmcoreinfo)
    p = tmp_path / "vmcore"
    p.write_bytes(_elf64_with_notes(blob))
    assert read_vmcore_build_id(p) == BUILD_ID
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_vmcore_build_id.py -q`
Expected: FAIL — `ModuleNotFoundError: linux_debug_mcp.symbols.vmcore_build_id`.

- [ ] **Step 3: Implement the reader**

Create `src/linux_debug_mcp/symbols/vmcore_build_id.py`:

```python
"""Host-side VMCOREINFO build-id extraction from an ELF vmcore. ADR 0026 / spec §5.2.

Parses the ELF header -> program-header table -> PT_NOTE segments, locating the
``VMCOREINFO`` note and reading its ``BUILD-ID=<hex>`` line. This is the same
kernel id drgn exposes as ``main_module().build_id`` for a vmcore, so the crash
and drgn offline tiers compare the same value. Pure-Python ``struct`` parse, no
drgn/crash/pyelftools dependency; only the ELF header, program headers, and each
PT_NOTE segment are read via ``seek``.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import BinaryIO

PT_NOTE = 4
_BUILD_ID_LINE = re.compile(rb"^BUILD-ID=([0-9A-Fa-f]+)\s*$", re.MULTILINE)


class VmcoreBuildIdError(Exception):
    """The vmcore is an ELF but is truncated or otherwise unreadable."""


class VmcoreFormatUnsupported(Exception):
    """The vmcore is not an ELF container (e.g. compressed-kdump). Host build-id
    extraction is ELF-only in this PR; a non-ELF container fails loud rather than
    silently skipping the §4.2 build-id check (spec §5.3)."""


class VmcoreBuildIdAbsent(Exception):
    """The vmcore is a readable ELF but carries no ``VMCOREINFO BUILD-ID`` —
    provenance cannot be verified (spec §5.2: ``provenance_unverifiable``)."""


def _read_exact(fh: BinaryIO, offset: int, size: int) -> bytes:
    fh.seek(offset)
    blob = fh.read(size)
    if len(blob) != size:
        raise VmcoreBuildIdError(f"vmcore truncated reading {size} bytes at offset {offset}")
    return blob


def _scan_vmcoreinfo(blob: bytes, endian: str) -> str | None:
    off = 0
    while off + 12 <= len(blob):
        namesz, descsz, _ntype = struct.unpack_from(endian + "III", blob, off)
        off += 12
        name_end = off + namesz
        desc_start = name_end + (-name_end % 4)
        desc_end = desc_start + descsz
        if desc_end > len(blob):
            return None
        if blob[off:name_end].rstrip(b"\x00") == b"VMCOREINFO":
            match = _BUILD_ID_LINE.search(blob[desc_start:desc_end])
            if match is not None:
                return match.group(1).decode("ascii").lower()
        off = desc_end + (-desc_end % 4)
    return None


def read_vmcore_build_id(path: Path) -> str:
    """Return the lower-case hex kernel build-id from an ELF vmcore's VMCOREINFO.

    Raises:
        VmcoreFormatUnsupported: the file is not an ELF container.
        VmcoreBuildIdError: the ELF is truncated/unreadable.
        VmcoreBuildIdAbsent: the ELF carries no ``VMCOREINFO BUILD-ID``.
    """
    try:
        with path.open("rb") as fh:
            ident = fh.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                raise VmcoreFormatUnsupported("vmcore is not an ELF container")
            ei_class, ei_data = ident[4], ident[5]
            if ei_class not in (1, 2) or ei_data not in (1, 2):
                raise VmcoreBuildIdError("unsupported ELF class/endianness")
            endian = "<" if ei_data == 1 else ">"
            is64 = ei_class == 2
            if is64:
                ehdr = _read_exact(fh, 0, 64)
                (e_phoff,) = struct.unpack_from(endian + "Q", ehdr, 32)
                e_phentsize, e_phnum = struct.unpack_from(endian + "HH", ehdr, 54)
            else:
                ehdr = _read_exact(fh, 0, 52)
                (e_phoff,) = struct.unpack_from(endian + "I", ehdr, 28)
                e_phentsize, e_phnum = struct.unpack_from(endian + "HH", ehdr, 42)
            if e_phnum == 0:
                raise VmcoreBuildIdAbsent("vmcore has no program headers")
            phdrs = _read_exact(fh, e_phoff, e_phentsize * e_phnum)
            for i in range(e_phnum):
                ph = i * e_phentsize
                (p_type,) = struct.unpack_from(endian + "I", phdrs, ph)
                if p_type != PT_NOTE:
                    continue
                if is64:
                    (p_offset,) = struct.unpack_from(endian + "Q", phdrs, ph + 8)
                    (p_filesz,) = struct.unpack_from(endian + "Q", phdrs, ph + 32)
                else:
                    (p_offset,) = struct.unpack_from(endian + "I", phdrs, ph + 4)
                    (p_filesz,) = struct.unpack_from(endian + "I", phdrs, ph + 16)
                found = _scan_vmcoreinfo(_read_exact(fh, p_offset, p_filesz), endian)
                if found is not None:
                    return found
    except OSError as exc:
        raise VmcoreBuildIdError(f"cannot read {path}: {exc}") from exc
    raise VmcoreBuildIdAbsent("no VMCOREINFO BUILD-ID note found")
```

- [ ] **Step 4: Export from the package**

Edit `src/linux_debug_mcp/symbols/__init__.py` — add the import and `__all__` entries:

```python
from linux_debug_mcp.symbols.vmcore_build_id import (
    VmcoreBuildIdAbsent,
    VmcoreBuildIdError,
    VmcoreFormatUnsupported,
    read_vmcore_build_id,
)
```

Add `"VmcoreBuildIdAbsent"`, `"VmcoreBuildIdError"`, `"VmcoreFormatUnsupported"`, `"read_vmcore_build_id"` to `__all__` (keep it sorted).

- [ ] **Step 5: Run to verify pass**

Run: `uv run python -m pytest tests/test_vmcore_build_id.py -q`
Expected: PASS (5 passed).

- [ ] **Step 6: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_vmcore_build_id.py -q
git add src/linux_debug_mcp/symbols/ tests/test_vmcore_build_id.py
git commit -m "feat(postmortem): add VMCOREINFO build-id reader"
```

---

## Task 2: command validation (`postmortem/crash_commands.py`)

**Files:**
- Create: `src/linux_debug_mcp/postmortem/__init__.py`, `src/linux_debug_mcp/postmortem/crash_commands.py`
- Test: `tests/test_crash_commands.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_crash_commands.py`:

```python
from __future__ import annotations

import pytest

from linux_debug_mcp.postmortem.crash_commands import (
    validate_crash_command,
    validate_modules_path,
)

ALLOW = {"bt", "ps", "log", "kmem", "sys", "mod"}


@pytest.mark.parametrize("cmd", ["bt", "ps -A", "kmem -i", "sys", "log"])
def test_allowed_commands_pass(cmd: str) -> None:
    assert validate_crash_command(cmd, ALLOW) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "!cat /etc/shadow",
        "bt | sh",
        "sys > /tmp/x",
        "log < /etc/passwd",
        "ps; quit",
        "bt && rm -rf /",
        "p `id`",
        "p $(id)",
    ],
)
def test_shell_reaching_commands_rejected(cmd: str) -> None:
    assert validate_crash_command(cmd, ALLOW) is not None


def test_embedded_newline_rejected() -> None:
    assert validate_crash_command("bt\nps", ALLOW) is not None


def test_non_allowlisted_verb_rejected() -> None:
    reason = validate_crash_command("gdb foo", ALLOW)
    assert reason is not None and "allowlist" in reason


def test_empty_command_rejected() -> None:
    assert validate_crash_command("   ", ALLOW) is not None


@pytest.mark.parametrize("path", ["/run/r1/target/mods", "build/mods_v2.1", "a/b-c/d.e"])
def test_safe_modules_path(path: str) -> None:
    assert validate_modules_path(path) is True


@pytest.mark.parametrize("path", ["/run/r1/m od", "/run/r1/m\nod", "/run/r1/m;od", "a b"])
def test_unsafe_modules_path(path: str) -> None:
    assert validate_modules_path(path) is False
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_crash_commands.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

Create `src/linux_debug_mcp/postmortem/__init__.py`:

```python
"""Host-side postmortem (crash-utility) tooling. Spec/ADR: debug.postmortem.crash."""
```

Create `src/linux_debug_mcp/postmortem/crash_commands.py`:

```python
"""Validation of caller crash command strings. ADR 0026 decision 2a / spec §3.4.

This is the load-bearing security control: the path is never gated, so every
command is sanitised (deny shell-reaching metacharacters/newlines) and checked
against an allowlist of read-only verbs before any crash invocation.
"""

from __future__ import annotations

import re

# Pipe-to-shell, redirection, command substitution, chaining, backgrounding.
_DENY_CHARS = ("|", ">", "<", "`", "$(", ";", "&")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MODULES_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def validate_crash_command(command: str, allowlist: set[str]) -> str | None:
    """Return ``None`` if the command is permitted, else a human-readable reason.

    Two layers (spec §3.4): a security-critical denylist (newline/control chars,
    leading ``!`` shell escape, and the ``_DENY_CHARS`` metacharacters) and an
    allowlist of read-only leading verbs.
    """
    stripped = command.strip()
    if not stripped:
        return "empty command"
    if _CONTROL.search(command):
        return "command contains a newline or control character"
    if stripped[0] == "!":
        return "shell escape ('!') is not permitted"
    for token in _DENY_CHARS:
        if token in command:
            return f"disallowed metacharacter {token!r}"
    verb = stripped.split()[0].lower()
    if verb not in allowlist:
        return f"verb {verb!r} is not in the crash command allowlist"
    return None


def validate_modules_path(path: str) -> bool:
    """True iff ``path`` is safe to interpolate into a crash ``mod -S`` command
    line (no whitespace/newline/metacharacters). Spec §6 step 8."""
    return bool(_MODULES_PATH_RE.match(path))
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_crash_commands.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_crash_commands.py -q
git add src/linux_debug_mcp/postmortem/ tests/test_crash_commands.py
git commit -m "feat(postmortem): add crash command sanitise+allowlist validation"
```

---

## Task 3: batch script build + output collection (`postmortem/crash_batch.py`)

**Files:**
- Create: `src/linux_debug_mcp/postmortem/crash_batch.py`
- Test: `tests/test_crash_batch.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_crash_batch.py`:

```python
from __future__ import annotations

from linux_debug_mcp.postmortem.crash_batch import (
    build_command_script,
    collect_command_outputs,
    redirect_filename,
)


def test_build_script_appends_redirects_and_exit(tmp_path) -> None:
    script = build_command_script(["bt", "ps"], tmp_path, modules_path=None)
    lines = script.splitlines()
    assert lines[0] == f"bt > {tmp_path / 'cmd-0000.out'}"
    assert lines[1] == f"ps > {tmp_path / 'cmd-0001.out'}"
    assert lines[-1] == "exit"


def test_build_script_prepends_mod_load(tmp_path) -> None:
    script = build_command_script(["bt"], tmp_path, modules_path="/run/r1/mods")
    lines = script.splitlines()
    assert lines[0] == f"mod -S /run/r1/mods > {tmp_path / 'mod-load.out'}"
    assert lines[1] == f"bt > {tmp_path / 'cmd-0000.out'}"


def test_collect_present_and_missing(tmp_path) -> None:
    (tmp_path / redirect_filename(0)).write_text("bt output", encoding="utf-8")
    # cmd 1 file absent (crash aborted)
    segs, truncated = collect_command_outputs(
        tmp_path, ["bt", "ps"], per_cmd_cap=1024, total_cap=4096
    )
    assert truncated is False
    assert segs[0] == {"command": "bt", "raw": "bt output", "capture": "ok"}
    assert segs[1] == {"command": "ps", "raw": None, "capture": "not_captured"}


def test_collect_per_cmd_truncation(tmp_path) -> None:
    (tmp_path / redirect_filename(0)).write_text("x" * 50, encoding="utf-8")
    segs, truncated = collect_command_outputs(
        tmp_path, ["bt"], per_cmd_cap=10, total_cap=4096
    )
    assert segs[0]["capture"] == "output_truncated"
    assert len(segs[0]["raw"]) == 10
    assert truncated is True


def test_collect_total_cap_marks_rest_truncated(tmp_path) -> None:
    (tmp_path / redirect_filename(0)).write_text("a" * 30, encoding="utf-8")
    (tmp_path / redirect_filename(1)).write_text("b" * 30, encoding="utf-8")
    segs, truncated = collect_command_outputs(
        tmp_path, ["bt", "ps"], per_cmd_cap=1024, total_cap=40
    )
    assert segs[0]["capture"] == "ok"
    assert segs[1]["capture"] == "output_truncated"
    assert truncated is True
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_crash_batch.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

Create `src/linux_debug_mcp/postmortem/crash_batch.py`:

```python
"""Crash batch stdin-script build + per-command output-file collection.

ADR 0026 decision 2 / spec §4.1: each command's output is redirected to its own
server-minted ``cmd-NNNN.out`` file, so the per-command boundary is set by the
filesystem rather than by parsing a shared stream (race-free framing).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MOD_LOAD_FILENAME = "mod-load.out"


def redirect_filename(index: int) -> str:
    """The per-command output filename for the zero-based command index."""
    return f"cmd-{index:04d}.out"


def build_command_script(
    commands: list[str], output_dir: Path, modules_path: str | None
) -> str:
    """Build the crash stdin script: an optional ``mod -S`` load, then each
    command redirected to its own file, then ``exit``. ``output_dir`` is the
    absolute sensitive call dir; callers must have validated each command and
    ``modules_path`` first (Task 2)."""
    lines: list[str] = []
    if modules_path is not None:
        lines.append(f"mod -S {modules_path} > {output_dir / MOD_LOAD_FILENAME}")
    for index, command in enumerate(commands):
        lines.append(f"{command} > {output_dir / redirect_filename(index)}")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def _read_capped(path: Path, cap: int) -> tuple[str, bool]:
    data = path.read_bytes()[: cap + 1]
    if len(data) > cap:
        return data[:cap].decode("utf-8", errors="replace"), True
    return data.decode("utf-8", errors="replace"), False


def collect_command_outputs(
    output_dir: Path, commands: list[str], *, per_cmd_cap: int, total_cap: int
) -> tuple[list[dict[str, Any]], bool]:
    """Read each ``cmd-NNNN.out`` back into a per-command segment.

    A missing file -> ``not_captured``; a file past ``per_cmd_cap`` or once the
    running total passes ``total_cap`` -> ``output_truncated``. Returns the
    segments and whether anything was truncated (spec §4.1)."""
    segments: list[dict[str, Any]] = []
    running = 0
    truncated = False
    for index, command in enumerate(commands):
        path = output_dir / redirect_filename(index)
        if not path.is_file():
            segments.append({"command": command, "raw": None, "capture": "not_captured"})
            continue
        if running >= total_cap:
            segments.append({"command": command, "raw": None, "capture": "output_truncated"})
            truncated = True
            continue
        text, hit_cap = _read_capped(path, min(per_cmd_cap, total_cap - running))
        running += len(text.encode("utf-8"))
        if hit_cap:
            truncated = True
            segments.append({"command": command, "raw": text, "capture": "output_truncated"})
        else:
            segments.append({"command": command, "raw": text, "capture": "ok"})
    return segments, truncated
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_crash_batch.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_crash_batch.py -q
git add src/linux_debug_mcp/postmortem/crash_batch.py tests/test_crash_batch.py
git commit -m "feat(postmortem): add crash batch script build + output collection"
```

---

## Task 4: parsers (`postmortem/crash_parsers.py`)

**Files:**
- Create: `src/linux_debug_mcp/postmortem/crash_parsers.py`
- Test: `tests/test_crash_parsers.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_crash_parsers.py`:

```python
from __future__ import annotations

from linux_debug_mcp.postmortem.crash_parsers import parse_command

BT = """PID: 0      TASK: ffffffff81c1a8c0  CPU: 0   COMMAND: "swapper/0"
 #0 [ffff8881] machine_kexec at ffffffff81051d4e
 #1 [ffff8882] __crash_kexec at ffffffff811a3b2c
"""

PS = """   PID    PPID  CPU       TASK        ST  %MEM     VSZ    RSS  COMM
>     0       0   0  ffffffff81c1a8c0  RU   0.0       0      0  [swapper/0]
      1       0   1  ffff888100a40000  IN   0.1  167404  11600  systemd
"""

SYS = """      KERNEL: vmlinux
    DUMPFILE: vmcore
        CPUS: 4
     RELEASE: 6.1.0
     MACHINE: x86_64
       PANIC: "Kernel panic - not syncing: sysrq triggered crash"
"""

LOG = """[    0.000000] Linux version 6.1.0
[    1.234567] Call Trace:
"""


def test_parse_bt() -> None:
    out = parse_command("bt", BT)
    assert out["parsed"] is True
    assert out["pid"] == 0
    assert out["command"] == "swapper/0"
    assert out["frames"][0]["symbol"] == "machine_kexec"
    assert out["frames"][1]["level"] == 1


def test_parse_ps() -> None:
    out = parse_command("ps", PS)
    assert out["parsed"] is True
    assert out["processes"][1]["pid"] == 1
    assert out["processes"][1]["comm"] == "systemd"


def test_parse_sys() -> None:
    out = parse_command("sys", SYS)
    assert out["parsed"] is True
    assert out["system"]["RELEASE"] == "6.1.0"
    assert out["system"]["CPUS"] == "4"


def test_parse_log() -> None:
    out = parse_command("log", LOG)
    assert out["parsed"] is True
    assert out["lines"][0]["ts"] == 0.0
    assert "Linux version" in out["lines"][0]["text"]


def test_kmem_i_dispatch() -> None:
    out = parse_command("kmem -i", "TOTAL MEM  1000000  3.8 GB\nFREE  500000  1.9 GB\n")
    assert out["parsed"] is True
    assert "TOTAL MEM" in out["memory"]


def test_unknown_command_raw() -> None:
    out = parse_command("vtop 0xffff", "some text")
    assert out == {"parsed": False, "reason": "unknown_command", "raw": "some text"}


def test_parser_exception_falls_back_to_raw(monkeypatch) -> None:
    import linux_debug_mcp.postmortem.crash_parsers as mod

    def boom(_text: str) -> dict:
        raise ValueError("kaboom")

    monkeypatch.setitem(mod._PARSERS, "sys", boom)
    out = parse_command("sys", "anything")
    assert out["parsed"] is False
    assert out["reason"] == "parse_failed"
    assert out["raw"] == "anything"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_crash_parsers.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

Create `src/linux_debug_mcp/postmortem/crash_parsers.py`:

```python
"""Best-effort, total parsers for crash command output. ADR 0026 decision 3.

``parse_command`` dispatches on the command's leading token(s). Any command
without a parser, or whose parser raises, yields the raw-passthrough form. No
parser raises out of ``parse_command``; redaction is the handler's job, not the
parser's.
"""

from __future__ import annotations

import re
from typing import Any, Callable

_BT_HEADER = re.compile(r'PID:\s*(\d+).*?COMMAND:\s*"([^"]*)"')
_BT_FRAME = re.compile(r"#(\d+)\s+\[\w+\]\s+(\S+)\s+at\s+(\S+)")
_LOG_LINE = re.compile(r"^\[\s*(\d+\.\d+)\]\s?(.*)$")


def parse_bt(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"parsed": True, "frames": []}
    header = _BT_HEADER.search(text)
    if header is not None:
        result["pid"] = int(header.group(1))
        result["command"] = header.group(2)
    for line in text.splitlines():
        frame = _BT_FRAME.search(line)
        if frame is not None:
            result["frames"].append(
                {"level": int(frame.group(1)), "symbol": frame.group(2), "pc_addr": frame.group(3)}
            )
    return result


def parse_ps(text: str) -> dict[str, Any]:
    processes: list[dict[str, Any]] = []
    for line in text.splitlines():
        body = line.lstrip(">").strip()
        fields = body.split()
        if len(fields) < 9 or not fields[0].isdigit():
            continue
        processes.append(
            {
                "pid": int(fields[0]),
                "ppid": int(fields[1]),
                "cpu": fields[2],
                "task_addr": fields[3],
                "st": fields[4],
                "comm": fields[-1].strip("[]"),
            }
        )
    return {"parsed": True, "processes": processes}


def parse_sys(text: str) -> dict[str, Any]:
    system: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key:
            system[key] = value.strip().strip('"')
    return {"parsed": True, "system": system}


def parse_log(text: str) -> dict[str, Any]:
    lines: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _LOG_LINE.match(line)
        if match is not None:
            lines.append({"ts": float(match.group(1)), "text": match.group(2)})
        elif line:
            lines.append({"ts": None, "text": line})
    return {"parsed": True, "lines": lines}


def parse_kmem_i(text: str) -> dict[str, Any]:
    memory: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        # Row label is the leading alphabetic words; the first numeric field is pages.
        label_parts = []
        rest = fields
        for token in fields:
            if token.replace(",", "").isdigit():
                break
            label_parts.append(token)
            rest = fields[len(label_parts):]
        if not label_parts or not rest:
            continue
        memory[" ".join(label_parts)] = {"pages": rest[0], "detail": " ".join(rest[1:])}
    return {"parsed": True, "memory": memory}


_PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "bt": parse_bt,
    "ps": parse_ps,
    "sys": parse_sys,
    "log": parse_log,
}


def _dispatch_key(command: str) -> str | None:
    tokens = command.strip().split()
    if not tokens:
        return None
    verb = tokens[0].lower()
    if verb == "kmem" and len(tokens) > 1 and tokens[1] == "-i":
        return "kmem -i"
    return verb if verb in _PARSERS else None


def parse_command(command: str, raw_text: str) -> dict[str, Any]:
    """Parse ``raw_text`` for ``command`` into a typed dict, or the raw-passthrough
    form (``parsed: False``) for an unknown verb or a parser exception."""
    if _dispatch_key(command) == "kmem -i":
        parser: Callable[[str], dict[str, Any]] | None = parse_kmem_i
    else:
        parser = _PARSERS.get(_dispatch_key(command) or "")
    if parser is None:
        return {"parsed": False, "reason": "unknown_command", "raw": raw_text}
    try:
        return parser(raw_text)
    except Exception:  # noqa: BLE001 - best-effort: any parser failure -> raw passthrough
        return {"parsed": False, "reason": "parse_failed", "raw": raw_text}
```

Note: the `noqa: BLE001` is justified — parser totality (never raising out of `parse_command`) is the contract (ADR 0026 decision 3); a narrower except would let an unforeseen parser bug crash the handler.

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_crash_parsers.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_crash_parsers.py -q
git add src/linux_debug_mcp/postmortem/crash_parsers.py tests/test_crash_parsers.py
git commit -m "feat(postmortem): add best-effort crash output parsers"
```

---

## Task 5: config (operation + caps + allowlist)

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Test: `tests/test_crash_config.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_crash_config.py`:

```python
from __future__ import annotations

from linux_debug_mcp.config import (
    ALLOWED_DEBUG_OPERATIONS,
    CRASH_COMMAND_ALLOWLIST,
    CRASH_PER_CMD_CAP,
    CRASH_SCRIPT_BYTE_CAP,
    CRASH_STDOUT_CAP,
    MAX_CRASH_COMMANDS,
    MAX_POSTMORTEM_CRASH_CALLS_PER_RUN,
)


def test_operation_registered() -> None:
    assert "debug.postmortem.crash" in ALLOWED_DEBUG_OPERATIONS


def test_allowlist_has_read_only_verbs() -> None:
    assert {"bt", "ps", "log", "kmem", "sys", "mod"} <= CRASH_COMMAND_ALLOWLIST


def test_caps_are_sane() -> None:
    assert 0 < CRASH_PER_CMD_CAP <= CRASH_STDOUT_CAP
    assert MAX_CRASH_COMMANDS > 0
    assert MAX_POSTMORTEM_CRASH_CALLS_PER_RUN > 0
    assert CRASH_SCRIPT_BYTE_CAP > 0
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_crash_config.py -q`
Expected: FAIL — ImportError on the new names.

- [ ] **Step 3: Implement**

Edit `src/linux_debug_mcp/config.py`. Add `"debug.postmortem.crash"` to `ALLOWED_DEBUG_OPERATIONS` (after the `from_vmcore_helper` entry, before the `debug.introspect.write` capability token), with a comment:

```python
    # Host-side crash-utility postmortem (#92). Listed for enumerability; never
    # gated (no DebugProfile in the request) — §5.6 rule 3 / ADR 0010 item 7.
    "debug.postmortem.crash",
```

After `MAX_INTROSPECT_CALLS_PER_RUN = 1000`, add:

```python
# debug.postmortem.crash bounds (#92 / spec §10).
MAX_POSTMORTEM_CRASH_CALLS_PER_RUN = 1000
MAX_CRASH_COMMANDS = 64
CRASH_SCRIPT_BYTE_CAP = 64 * 1024
CRASH_PER_CMD_CAP = 1 * 1024 * 1024
CRASH_STDOUT_CAP = 8 * 1024 * 1024
CRASH_COMMAND_ALLOWLIST: set[str] = {
    "bt", "ps", "log", "kmem", "sys", "mod", "struct", "union", "p", "rd",
    "vtop", "task", "files", "vm", "net", "dev", "irq", "mach", "runq",
    "mount", "swap", "timer", "dis", "sym", "list", "tree", "search",
    "foreach", "help",
}
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_crash_config.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_crash_config.py -q
git add src/linux_debug_mcp/config.py tests/test_crash_config.py
git commit -m "feat(postmortem): register crash operation + caps + allowlist"
```

---

## Task 6: request model (`domain.py`)

**Files:**
- Modify: `src/linux_debug_mcp/domain.py`
- Test: `tests/test_debug_postmortem_crash.py` (create — first tests)

- [ ] **Step 1: Write the failing test**

Create `tests/test_debug_postmortem_crash.py`:

```python
from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import DebugPostmortemCrashRequest


def test_request_defaults() -> None:
    r = DebugPostmortemCrashRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", commands=["bt"]
    )
    assert r.modules_ref is None
    assert r.timeout_seconds == 60


def test_request_forbids_extra() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemCrashRequest(
            run_id="r1",
            vmcore_ref="c",
            vmlinux_ref="v",
            commands=["bt"],
            target_ref="nope",
        )
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_debug_postmortem_crash.py -q`
Expected: FAIL — `ImportError: DebugPostmortemCrashRequest`.

- [ ] **Step 3: Implement**

Edit `src/linux_debug_mcp/domain.py`. After `DebugIntrospectFromVmcoreHelperRequest` (ends near line 188), add:

```python
class DebugPostmortemCrashRequest(Model):
    """Request payload for ``debug.postmortem.crash``. Spec §3.1.

    No ``target_ref``/``*_profile``: the offline crash path names no live target.
    ``vmcore_ref``/``vmlinux_ref``/``modules_ref`` are run-relative and confined
    to the run dir. ``commands`` is validated (sanitise + allowlist) and the
    ``[5, 300]`` timeout / command-count / script-size bounds are enforced by the
    handler so they surface as ``ToolResponse.failure(...)`` with the spec's exact
    codes.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    commands: list[str]
    timeout_seconds: int = 60
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_debug_postmortem_crash.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_debug_postmortem_crash.py -q
git add src/linux_debug_mcp/domain.py tests/test_debug_postmortem_crash.py
git commit -m "feat(postmortem): add DebugPostmortemCrashRequest model"
```

---

## Task 7: provider capability

**Files:**
- Create: `src/linux_debug_mcp/providers/local_crash_postmortem.py`
- Modify: `src/linux_debug_mcp/providers/plugins.py`
- Test: `tests/test_crash_capability.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_crash_capability.py`:

```python
from __future__ import annotations

from linux_debug_mcp.providers.local_crash_postmortem import local_crash_postmortem_capability
from linux_debug_mcp.providers.plugins import local_provider_plugin_specs


def test_capability_advertises_operation() -> None:
    cap = local_crash_postmortem_capability()
    assert cap.provider_name == "local-crash-postmortem"
    assert cap.operations == ["debug.postmortem.crash"]
    assert "crash" in cap.required_host_tools
    assert cap.semantics.concurrent_safe is True


def test_capability_registered_in_local_specs() -> None:
    names = {
        cap().provider_name
        for spec in local_provider_plugin_specs()
        for cap in spec.provider_capability_factories
    }
    assert "local-crash-postmortem" in names
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_crash_capability.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the capability**

Create `src/linux_debug_mcp/providers/local_crash_postmortem.py`:

```python
"""local-crash-postmortem capability. Spec §10 / ADR 0026.

Offline, concurrent-safe crash-utility postmortem; needs neither ssh nor drgn,
so it is a separate capability from local-drgn-introspect (which requires ssh).
"""

from __future__ import annotations

from linux_debug_mcp.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)


def local_crash_postmortem_capability() -> ProviderCapability:
    semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=True,
    )
    return ProviderCapability(
        provider_name="local-crash-postmortem",
        provider_version="0.1.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["filesystem"],
        operations=["debug.postmortem.crash"],
        required_host_tools=["crash", "timeout", "prlimit"],
        destructive_permissions=[],
        access_methods=["subprocess", "filesystem"],
        semantics=semantics,
    )
```

Verify the `ProviderCapability` field names against `local_drgn_introspect_capability` in `src/linux_debug_mcp/providers/local_drgn_introspect.py:657-677` — they must match exactly (`provider_version`, `target_kinds`, `destructive_permissions`, etc.).

- [ ] **Step 4: Register in plugins**

Edit `src/linux_debug_mcp/providers/plugins.py`. Add the import near the other capability imports (line ~10):

```python
from linux_debug_mcp.providers.local_crash_postmortem import local_crash_postmortem_capability
```

In `local_provider_plugin_specs`, append to the `provider_capability_factories` list after `local_drgn_introspect_capability,`:

```python
                local_crash_postmortem_capability,
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run python -m pytest tests/test_crash_capability.py -q`
Expected: PASS.

- [ ] **Step 6: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_crash_capability.py -q
git add src/linux_debug_mcp/providers/local_crash_postmortem.py src/linux_debug_mcp/providers/plugins.py tests/test_crash_capability.py
git commit -m "feat(postmortem): add local-crash-postmortem capability"
```

---

## Task 8: prerequisite check

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/checks.py`
- Test: `tests/test_crash_prereq.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_crash_prereq.py`:

```python
from __future__ import annotations

from linux_debug_mcp.domain import PrerequisiteStatus
from linux_debug_mcp.prereqs.checks import check_prerequisites


class _FakeRunner:
    def __init__(self, present: bool) -> None:
        self._present = present

    def which(self, command: str) -> str | None:
        if command == "crash":
            return "/usr/bin/crash" if self._present else None
        return "/usr/bin/" + command  # everything else present

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        return (0, "", "")


def _crash_check(present: bool):
    checks = check_prerequisites(
        artifact_root=__import__("pathlib").Path("/tmp"),
        source_path=None,
        enable_libvirt_check=False,
        runner=_FakeRunner(present),
    )
    return next(c for c in checks if c.check_id == "tool.crash")


def test_crash_present_passes() -> None:
    assert _crash_check(True).status == PrerequisiteStatus.PASSED


def test_crash_absent_fails() -> None:
    check = _crash_check(False)
    assert check.status == PrerequisiteStatus.FAILED
    assert check.suggested_fix is not None
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_crash_prereq.py -q`
Expected: FAIL — no `tool.crash` check exists.

- [ ] **Step 3: Implement**

Edit `src/linux_debug_mcp/prereqs/checks.py`. Add `"crash"` to the tool loop in `check_prerequisites` (line 53), so it reads:

```python
    for tool in ["make", "bash", "git", "qemu-system-x86_64", "virsh", "gdb", "crash"]:
        checks.append(_tool_check(tool, runner))
```

The existing `_tool_check` already produces a `tool.<name>` PASSED/FAILED check with a "Install … with your distribution package manager." suggested fix, which satisfies the test. No new function is needed.

- [ ] **Step 4: Run to verify pass**

Run: `uv run python -m pytest tests/test_crash_prereq.py -q`
Expected: PASS.

- [ ] **Step 5: Guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest tests/test_crash_prereq.py -q
git add src/linux_debug_mcp/prereqs/checks.py tests/test_crash_prereq.py
git commit -m "feat(postmortem): add crash tool prerequisite check"
```

---

## Task 9: handler + orchestrator + tool registration (`server.py`)

This is the integrating task. Read `_execute_vmcore_introspect_call`
(`server.py:3613-3872`) first — the structure (manifest load, sensitive preflight,
`resolve_symbols`, `confine_run_relative`, runner call, terminal step record) is the
template.

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Test: `tests/test_debug_postmortem_crash.py` (extend Task 6's file)

- [ ] **Step 1: Write the failing handler tests**

Append to `tests/test_debug_postmortem_crash.py`:

```python
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import debug_postmortem_crash_handler


def _run(tmp_path: Path) -> ArtifactStore:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    (rd / "inputs" / "vmcore").write_bytes(b"core")
    (rd / "build" / "vmlinux").write_bytes(b"elf")
    return store


GOOD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


class _FakeRunner:
    """Writes a cmd-NNNN.out per command by parsing the redirect targets out of
    the stdin script, then returns a clean exit."""

    def __init__(self, *, outputs: dict[int, str], exit_status: int = 0, **flags) -> None:
        self.outputs = outputs
        self.exit_status = exit_status
        self.flags = flags
        self.calls = 0

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None,
            max_stdout_bytes=None) -> SshCommandResult:
        self.calls += 1
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        for line in (stdin or "").splitlines():
            if " > " not in line or not line.split(" > ")[0].strip():
                continue
            target = Path(line.split(" > ", 1)[1])
            if target.name.startswith("cmd-"):
                idx = int(target.stem.split("-")[1])
                if idx in self.outputs:
                    target.write_text(self.outputs[idx], encoding="utf-8")
        return SshCommandResult(exit_status=self.exit_status, **self.flags)


def test_happy_path_keys_results_by_command(tmp_path) -> None:
    store = _run(tmp_path)
    runner = _FakeRunner(outputs={0: 'KERNEL: vmlinux\nRELEASE: 6.1.0\n', 1: "raw text"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["sys", "vtop 0x0"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["results"]["sys"]["system"]["RELEASE"] == "6.1.0"
    assert resp.data["results"]["vtop 0x0"]["parsed"] is False
    assert any(name.startswith("postmortem.crash:") for name in
               store.load_manifest("r1").step_results)


def test_build_id_mismatch_fails_loud_no_run(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: "a" * 40,
        vmlinux_build_id_reader=lambda _p: "b" * 40,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert runner.calls == 0


def _raising_reader(exc: Exception):
    def _reader(_path):
        raise exc

    return _reader


@pytest.mark.parametrize(
    "exc_name, expected_code",
    [
        ("VmcoreFormatUnsupported", "vmcore_format_unsupported"),
        ("VmcoreBuildIdAbsent", "provenance_unverifiable"),
        ("VmcoreBuildIdError", "vmcore_build_id_unreadable"),
    ],
)
def test_vmcore_reader_failures_fail_loud(tmp_path, exc_name, expected_code) -> None:
    import linux_debug_mcp.symbols as symbols

    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    exc = getattr(symbols, exc_name)("crafted")
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=_raising_reader(exc),
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == expected_code
    assert runner.calls == 0


def test_vmlinux_build_id_unreadable_fails_loud(tmp_path) -> None:
    from linux_debug_mcp.symbols import BuildIdReadError

    _run(tmp_path)
    runner = _FakeRunner(outputs={})

    def _raise(_p):
        raise BuildIdReadError("not an ELF")

    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=_raise,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "vmlinux_build_id_unreadable"
    assert runner.calls == 0


def test_crash_open_failure_no_output_nonzero_exit(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={}, exit_status=1)  # no cmd-*.out written, clean nonzero exit
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "crash_open_failure"


@pytest.mark.parametrize(
    "kwargs, code",
    [
        ({"commands": ["bt"], "timeout_seconds": 4}, "invalid_timeout"),
        ({"commands": ["bt", "bt"]}, "invalid_commands"),
        ({"commands": []}, "invalid_commands"),
    ],
)
def test_input_validation_codes(tmp_path, kwargs, code) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", **kwargs,
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == code
    assert runner.calls == 0


def test_disallowed_command_rejected_no_run(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["bt | sh"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "command_not_permitted"
    assert runner.calls == 0


def test_lifecycle_independent_no_admission_injected(tmp_path) -> None:
    # No admission service parameter exists on the handler at all — calling it
    # proves the gate is not in the path (AC).
    store = _run(tmp_path)
    runner = _FakeRunner(outputs={0: "PID: 0  TASK: ff  CPU: 0   COMMAND: \"x\"\n"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True


def test_timeout_beats_partial_files(tmp_path) -> None:
    _run(tmp_path)
    runner = _FakeRunner(outputs={0: "PID: 0\n"}, exit_status=124, timed_out=True)
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["bt", "ps"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert resp.error.details["code"] == "crash_timeout"


def test_redaction_masks_secret_in_output(tmp_path) -> None:
    _run(tmp_path)
    # The default Redactor (src/linux_debug_mcp/safety/redaction.py) masks
    # `key=value` pairs whose key matches password|passwd|token|api_key|secret.
    # Use such a key so the test exercises a real default pattern (not a bare
    # token, which the default set does NOT mask).
    secret_value = "hunter2trustno1xyz"  # pragma: allowlist secret
    runner = _FakeRunner(outputs={0: f"[ 0.1] db_password={secret_value} loaded\n"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["log"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    blob = repr(resp.data["results"])
    assert secret_value not in blob
    assert "[REDACTED]" in blob
    # And the persisted parsed.json is redacted too (AC: persisted + response).
    rd = ArtifactStore(artifact_root=tmp_path).run_dir("r1")
    parsed_on_disk = (rd / "debug" / "postmortem" / "crash").glob("*/parsed.json")
    assert all(secret_value not in p.read_text(encoding="utf-8") for p in parsed_on_disk)


def test_argv_carries_prlimit_disk_bound(tmp_path) -> None:
    from linux_debug_mcp.config import CRASH_PER_CMD_CAP

    _run(tmp_path)

    class _ArgvCapturingRunner(_FakeRunner):
        def run(self, argv, **kwargs):  # type: ignore[override]
            self.argv = argv
            return super().run(argv, **kwargs)

    runner = _ArgvCapturingRunner(outputs={0: "PID: 0\n"})
    debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert runner.argv[:2] == ["prlimit", f"--fsize={CRASH_PER_CMD_CAP}"]
    assert "crash" in runner.argv and "-s" in runner.argv


def test_modules_path_unsafe_rejected_no_run(tmp_path, monkeypatch) -> None:
    import linux_debug_mcp.server as server
    from linux_debug_mcp.symbols import ResolvedSymbols

    store = _run(tmp_path)
    rd = store.run_dir("r1")
    (rd / "build" / "mods").mkdir(parents=True, exist_ok=True)

    def _fake_resolve(_prov, *, run_dir):
        return ResolvedSymbols(
            vmlinux_path=run_dir / "build" / "vmlinux",
            modules_path=run_dir / "build" / "mo ds",  # space -> unsafe
            warnings=[],
        )

    monkeypatch.setattr(server, "resolve_symbols", _fake_resolve)
    runner = _FakeRunner(outputs={})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            modules_ref="build/mods", commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "modules_path_unsafe"
    assert runner.calls == 0


def test_module_symbols_status_reported(tmp_path, monkeypatch) -> None:
    import linux_debug_mcp.server as server
    from linux_debug_mcp.symbols import ResolvedSymbols

    store = _run(tmp_path)
    rd = store.run_dir("r1")
    (rd / "build" / "mods").mkdir(parents=True, exist_ok=True)

    def _fake_resolve(_prov, *, run_dir):
        return ResolvedSymbols(
            vmlinux_path=run_dir / "build" / "vmlinux",
            modules_path=run_dir / "build" / "mods",
            warnings=[],
        )

    monkeypatch.setattr(server, "resolve_symbols", _fake_resolve)

    class _ModRunner(_FakeRunner):
        def run(self, argv, *, stdin=None, **kwargs):  # type: ignore[override]
            # Write a successful mod-load.out, plus the bt output.
            for line in (stdin or "").splitlines():
                if " > " not in line:
                    continue
                target = __import__("pathlib").Path(line.split(" > ", 1)[1])
                if target.name == "mod-load.out":
                    target.write_text("MODULE  NAME  loaded\n", encoding="utf-8")
            return super().run(argv, stdin=stdin, **kwargs)

    runner = _ModRunner(outputs={0: "PID: 0\n"})
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            modules_ref="build/mods", commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=runner,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["module_symbols"]["status"] == "loaded"


def test_module_symbols_load_failed(tmp_path, monkeypatch) -> None:
    import linux_debug_mcp.server as server
    from linux_debug_mcp.symbols import ResolvedSymbols

    store = _run(tmp_path)
    rd = store.run_dir("r1")
    (rd / "build" / "mods").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        server, "resolve_symbols",
        lambda _prov, *, run_dir: ResolvedSymbols(
            vmlinux_path=run_dir / "build" / "vmlinux",
            modules_path=run_dir / "build" / "mods", warnings=[],
        ),
    )

    class _BadModRunner(_FakeRunner):
        def run(self, argv, *, stdin=None, **kwargs):  # type: ignore[override]
            for line in (stdin or "").splitlines():
                if " > " in line and line.split(" > ", 1)[1].endswith("mod-load.out"):
                    __import__("pathlib").Path(line.split(" > ", 1)[1]).write_text(
                        "mod: cannot find module debuginfo\n", encoding="utf-8"
                    )
            return super().run(argv, stdin=stdin, **kwargs)

    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            modules_ref="build/mods", commands=["bt"],
        ),
        artifact_root=tmp_path,
        runner=_BadModRunner(outputs={0: "PID: 0\n"}),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["module_symbols"]["status"] == "load_failed"
```

Note: the default `Redactor` masks registry-registered secret values and `key=value` pairs whose **key** matches `password|passwd|token|api[_-]?key|secret` — confirmed in `src/linux_debug_mcp/safety/redaction.py:30-37`. A bare token (e.g. `AKIA…`) is NOT masked, so the redaction fixture must use such a key. The `modules_path_unsafe`/`module_symbols` tests inject a `ResolvedSymbols` with a hostile/known `modules_path` directly (a real `confine_run_relative` path cannot easily contain a space), per the spec §11 next-step.

- [ ] **Step 2: Run to verify failure**

Run: `uv run python -m pytest tests/test_debug_postmortem_crash.py -q`
Expected: FAIL — `ImportError: debug_postmortem_crash_handler`.

- [ ] **Step 3: Implement the orchestrator + handler**

Edit `src/linux_debug_mcp/server.py`. Add imports near the existing symbols/postmortem imports (top of file, by `from linux_debug_mcp.symbols.build_id import ...`):

```python
from linux_debug_mcp.symbols.vmcore_build_id import (
    VmcoreBuildIdAbsent,
    VmcoreBuildIdError,
    VmcoreFormatUnsupported,
    read_vmcore_build_id,
)
from linux_debug_mcp.postmortem.crash_batch import build_command_script, collect_command_outputs
from linux_debug_mcp.postmortem.crash_commands import validate_crash_command, validate_modules_path
from linux_debug_mcp.postmortem.crash_parsers import parse_command
from linux_debug_mcp.config import (
    CRASH_COMMAND_ALLOWLIST,
    CRASH_PER_CMD_CAP,
    CRASH_SCRIPT_BYTE_CAP,
    CRASH_STDOUT_CAP,
    MAX_CRASH_COMMANDS,
    MAX_POSTMORTEM_CRASH_CALLS_PER_RUN,
)
```

(Confirm whether `config` symbols are imported individually or via a module alias elsewhere in `server.py` and match that style.)

Add a module-level step-name regex near `_INTROSPECT_STEP_NAME_RE`:

```python
_POSTMORTEM_CRASH_STEP_RE = re.compile(r"^postmortem\.crash:[0-9a-f]{32}$")
```

Add the request-validation helper, the build-id helper, the orchestrator, and the handler. Place them after `debug_introspect_from_vmcore_helper_handler` (around line 3945):

```python
def _crash_config_failure(run_id: str, code: str, message: str) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        run_id=run_id,
        message=message,
        details={"code": code},
        suggested_next_actions=["artifacts.get_manifest", "debug.postmortem.crash"],
    )


def _validate_crash_commands(run_id: str, commands: list[str]) -> ToolResponse | None:
    """Spec §3.4 / §6 step 2. Returns a failure response or None if all pass."""
    if not commands or len(commands) > MAX_CRASH_COMMANDS:
        return _crash_config_failure(
            run_id, "invalid_commands", f"commands must be 1..{MAX_CRASH_COMMANDS}"
        )
    stripped = [c.strip() for c in commands]
    if len(set(stripped)) != len(stripped):
        return _crash_config_failure(run_id, "invalid_commands", "duplicate command")
    script_bytes = sum(len(c.encode("utf-8")) for c in stripped)
    if script_bytes > CRASH_SCRIPT_BYTE_CAP:
        return _crash_config_failure(run_id, "invalid_commands", "command script too large")
    for command in stripped:
        reason = validate_crash_command(command, CRASH_COMMAND_ALLOWLIST)
        if reason is not None:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=f"command not permitted: {reason}",
                details={"code": "command_not_permitted", "command": command, "reason": reason},
                suggested_next_actions=["debug.postmortem.crash"],
            )
    return None


def _crash_buildid_failloud(
    run_id: str,
    vmcore_path: Path,
    vmlinux_path: Path,
    vmcore_reader: Callable[[Path], str],
    vmlinux_reader: Callable[[Path], str],
) -> tuple[str, ToolResponse | None]:
    """Spec §5. Returns (vmcore_build_id, None) on a verified match, else
    ("", failure)."""
    try:
        expected = vmlinux_reader(vmlinux_path)
    except BuildIdReadError as exc:
        return "", _crash_config_failure(
            run_id, "vmlinux_build_id_unreadable", f"vmlinux build-id unreadable: {exc}"
        )
    if not BUILD_ID_RE.match(expected):
        return "", _crash_config_failure(run_id, "vmlinux_build_id_unreadable", "malformed vmlinux build-id")
    try:
        observed = vmcore_reader(vmcore_path)
    except VmcoreFormatUnsupported as exc:
        return "", _crash_config_failure(run_id, "vmcore_format_unsupported", str(exc))
    except VmcoreBuildIdAbsent as exc:
        return "", _crash_config_failure(run_id, "provenance_unverifiable", str(exc))
    except VmcoreBuildIdError as exc:
        return "", _crash_config_failure(run_id, "vmcore_build_id_unreadable", str(exc))
    if observed != expected:
        return "", _crash_config_failure(
            run_id, "provenance_mismatch", "vmcore build-id does not match the supplied vmlinux"
        )
    return observed, None


def debug_postmortem_crash_handler(
    request: DebugPostmortemCrashRequest,
    *,
    artifact_root: Path,
    runner: SshRunner | None = None,
    vmcore_build_id_reader: Callable[[Path], str] = read_vmcore_build_id,
    vmlinux_build_id_reader: Callable[[Path], str] = read_elf_build_id,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
    """Spec §6 / ADR 0026. Host-side crash batch runner; no admission gate."""
    run_id = request.run_id
    now = clock or _utcnow
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        if not (store.run_dir(run_id) / "manifest.json").is_file():
            return _crash_config_failure(run_id, "run_not_found", f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if not (5 <= request.timeout_seconds <= 300):
        return _crash_config_failure(
            run_id, "invalid_timeout", f"timeout_seconds must be in [5, 300]; got {request.timeout_seconds}"
        )
    bad_commands = _validate_crash_commands(run_id, request.commands)
    if bad_commands is not None:
        return bad_commands
    if sum(1 for n in manifest.step_results if _POSTMORTEM_CRASH_STEP_RE.match(n)) >= MAX_POSTMORTEM_CRASH_CALLS_PER_RUN:
        return _crash_config_failure(
            run_id, "manifest_call_budget_exhausted", "crash call budget exhausted; start a new run"
        )

    run_dir = store.run_dir(run_id)
    sensitive_dir = run_dir / "sensitive"
    try:
        mode = sensitive_dir.stat().st_mode & 0o777
    except FileNotFoundError:
        return _crash_config_failure(run_id, "sensitive_dir_missing", f"{sensitive_dir} is missing")
    if mode & 0o077:
        return _crash_config_failure(run_id, "sensitive_dir_too_permissive", f"{sensitive_dir} mode is {oct(mode)}")

    provenance_shell = KernelProvenance(
        build_id="", release="", vmlinux_ref=request.vmlinux_ref,
        modules_ref=request.modules_ref, cmdline="", config_ref=None,
    )
    try:
        resolved = resolve_symbols(provenance_shell, run_dir=run_dir)
    except SymbolResolutionError as exc:
        return _crash_config_failure(run_id, "symbol_resolution_failed", str(exc))
    try:
        vmcore_path = confine_run_relative(request.vmcore_ref, run_dir=run_dir)
    except PathSafetyError as exc:
        return _crash_config_failure(run_id, "vmcore_not_found", str(exc))
    if not vmcore_path.is_file():
        return _crash_config_failure(run_id, "vmcore_not_found", f"vmcore not found at {request.vmcore_ref!r}")

    modules_path = str(resolved.modules_path) if resolved.modules_path is not None else None
    if modules_path is not None and not validate_modules_path(modules_path):
        return _crash_config_failure(run_id, "modules_path_unsafe", "resolved modules path has unsafe characters")

    vmcore_build_id, failure = _crash_buildid_failloud(
        run_id, vmcore_path, resolved.vmlinux_path, vmcore_build_id_reader, vmlinux_build_id_reader
    )
    if failure is not None:
        return failure

    call_id = uuid.uuid4().hex
    agent_dir = run_dir / "debug" / "postmortem" / "crash" / call_id
    sensitive_call_dir = run_dir / "sensitive" / "debug" / "postmortem" / "crash" / call_id
    agent_dir.mkdir(parents=True, mode=0o700)
    sensitive_call_dir.mkdir(parents=True, mode=0o700)

    cmd_script = build_command_script([c.strip() for c in request.commands], sensitive_call_dir, modules_path)
    redactor = Redactor(secret_values=[])
    (agent_dir / "request.json").write_text(
        json.dumps(redactor.redact_value(request.model_dump(mode="json"))), encoding="utf-8"
    )

    stdout_path = sensitive_call_dir / "stdout.raw"
    stderr_path = sensitive_call_dir / "stderr.raw"
    active_runner: SshRunner = runner or SubprocessSshRunner()
    argv = [
        "prlimit", f"--fsize={CRASH_PER_CMD_CAP}", "timeout", "--kill-after=2s",
        f"{request.timeout_seconds}s", "crash", "-s",
        str(resolved.vmlinux_path), str(vmcore_path),
    ]
    started_at = now()
    started_monotonic = time.monotonic()
    ssh_result = active_runner.run(
        argv, timeout=request.timeout_seconds + 10, stdout_path=stdout_path,
        stderr_path=stderr_path, cancel=threading.Event(), stdin=cmd_script,
        max_stdout_bytes=CRASH_STDOUT_CAP,
    )
    for raw_path in (stdout_path, stderr_path):
        with contextlib.suppress(FileNotFoundError):
            raw_path.chmod(0o600)
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    return _finalize_crash_call(
        store=store, run_id=run_id, call_id=call_id, ssh_result=ssh_result,
        sensitive_call_dir=sensitive_call_dir, agent_dir=agent_dir, redactor=redactor,
        commands=[c.strip() for c in request.commands], modules_requested=modules_path is not None,
        vmcore_build_id=vmcore_build_id, started_at=started_at, finished_at=now(),
        duration_ms=duration_ms,
    )
```

- [ ] **Step 4: Implement `_finalize_crash_call`**

Add right after the handler:

```python
def _finalize_crash_call(
    *,
    store: ArtifactStore,
    run_id: str,
    call_id: str,
    ssh_result: SshCommandResult,
    sensitive_call_dir: Path,
    agent_dir: Path,
    redactor: Redactor,
    commands: list[str],
    modules_requested: bool,
    vmcore_build_id: str,
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
) -> ToolResponse:
    """Spec §4.1 / §6 step 9. Runner-terminal failures win over the file-count
    rule; a clean run with >=1 output file is a success with per-command markers."""
    step_name = f"postmortem.crash:{call_id}"

    def _infra_fail(code: str, message: str) -> ToolResponse:
        store_step = StepResult(
            step_name=step_name, status=StepStatus.FAILED, summary=message,
            artifacts=[], details={"call_id": call_id, "code": code, "duration_ms": duration_ms},
        )
        _record_terminal_introspect_result(store, run_id, store_step)
        return ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE, run_id=run_id, message=message,
            details={"code": code, "call_id": call_id},
            suggested_next_actions=["artifacts.get_manifest"],
        )

    if ssh_result.oversized_output:
        return _infra_fail("oversized_output", "crash session stdout exceeded the cap")
    if ssh_result.cancelled:
        return _infra_fail("crash_cancelled", "crash call cancelled")
    if ssh_result.stdin_failed:
        return _infra_fail("crash_stdin_failure", "crash command script not fully written")
    if ssh_result.timed_out or ssh_result.exit_status == 124:
        return _infra_fail("crash_timeout", "crash run exceeded the timeout")

    segments, truncated = collect_command_outputs(
        sensitive_call_dir, commands, per_cmd_cap=CRASH_PER_CMD_CAP, total_cap=CRASH_STDOUT_CAP
    )
    if all(seg["capture"] == "not_captured" for seg in segments) and ssh_result.exit_status != 0:
        return _infra_fail("crash_open_failure", "crash produced no command output (could not open the pair)")

    results: dict[str, Any] = {}
    transcript_parts: list[str] = []
    for seg in segments:
        command = seg["command"]
        if seg["capture"] == "not_captured":
            results[command] = {"parsed": False, "reason": "not_captured", "raw": None}
            continue
        raw = redactor.redact_text(seg["raw"] or "")
        transcript_parts.append(f"$ {command}\n{raw}")
        if seg["capture"] == "output_truncated":
            results[command] = {"parsed": False, "reason": "output_truncated", "raw": raw}
            continue
        parsed = parse_command(command, raw)
        results[command] = redactor.redact_value(parsed)

    module_symbols = None
    if modules_requested:
        mod_file = sensitive_call_dir / "mod-load.out"
        mod_text = mod_file.read_text(encoding="utf-8", errors="replace") if mod_file.is_file() else ""
        status = "loaded" if mod_file.is_file() and "cannot" not in mod_text.lower() else "load_failed"
        module_symbols = {"requested": True, "status": status, "detail": redactor.redact_text(mod_text[:512])}

    transcript_path = agent_dir / "transcript.txt"
    parsed_path = agent_dir / "parsed.json"
    transcript_path.write_text(redactor.redact_text("\n\n".join(transcript_parts)), encoding="utf-8")
    parsed_path.write_text(json.dumps(results), encoding="utf-8")
    artifacts = [
        ArtifactRef(path=str(transcript_path.relative_to(store.run_dir(run_id))), kind="crash_transcript"),
        ArtifactRef(path=str(parsed_path.relative_to(store.run_dir(run_id))), kind="crash_parsed_json"),
    ]
    step = StepResult(
        step_name=step_name, status=StepStatus.SUCCEEDED,
        summary=f"crash batch: {len(commands)} command(s)", artifacts=artifacts,
        details={"call_id": call_id, "vmcore_build_id": vmcore_build_id, "duration_ms": duration_ms},
    )
    _record_terminal_introspect_result(store, run_id, step)
    data: dict[str, Any] = {
        "call_id": call_id, "vmcore_build_id": vmcore_build_id, "results": results,
        "truncated": truncated, "crash_exit_code": ssh_result.exit_status,
        "started_at": started_at.isoformat(), "finished_at": finished_at.isoformat(),
        "duration_ms": duration_ms,
    }
    if module_symbols is not None:
        data["module_symbols"] = module_symbols
    return ToolResponse.success(
        summary=f"crash batch over {len(commands)} command(s)", run_id=run_id, data=data,
        artifacts=artifacts, suggested_next_actions=["artifacts.get_manifest", "debug.postmortem.crash"],
    )
```

Confirm `DebugPostmortemCrashRequest`, `KernelProvenance`, `SymbolResolutionError`, `confine_run_relative`, `PathSafetyError`, `ArtifactRef`, `SubprocessSshRunner`, `BUILD_ID_RE` are all already imported in `server.py` (most are — only the new `postmortem`/`vmcore_build_id`/`config` imports from Step 3 are added). If `DebugPostmortemCrashRequest` is not yet in the domain import block, add it.

- [ ] **Step 5: Register the MCP tool**

In `create_app()`, alongside the `@app.tool(name="debug.introspect.from_vmcore")` registrations (line ~7718), add:

```python
    @app.tool(name="debug.postmortem.crash")
    def debug_postmortem_crash(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        commands: list[str],
        modules_ref: str | None = None,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        return debug_postmortem_crash_handler(
            DebugPostmortemCrashRequest(
                run_id=run_id, vmcore_ref=vmcore_ref, vmlinux_ref=vmlinux_ref,
                commands=commands, modules_ref=modules_ref, timeout_seconds=timeout_seconds,
            ),
            artifact_root=artifact_root,
        ).model_dump(mode="json")
```

Match the exact wrapper style of the adjacent `debug.introspect.from_vmcore` registration (how `artifact_root` is captured, and `.model_dump(mode="json")`).

- [ ] **Step 6: Run to verify pass**

Run: `uv run python -m pytest tests/test_debug_postmortem_crash.py -q`
Expected: PASS (all handler tests, including the `prlimit` argv, `modules_path_unsafe`, `module_symbols`, and redaction tests).

- [ ] **Step 7: Full guardrails + commit**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q
git add src/linux_debug_mcp/server.py tests/test_debug_postmortem_crash.py
git commit -m "feat(postmortem): wire debug.postmortem.crash handler + tool"
```

---

## Task 10: documentation (`docs/debug-postmortem.md`)

**Files:**
- Create: `docs/debug-postmortem.md`

- [ ] **Step 1: Write the doc**

Create `docs/debug-postmortem.md` covering: the tool signature and request fields; the run-relative ref / staging requirement; the command allowlist + denied metacharacters (with the security rationale); the per-command `results` keying and the typed shapes for `bt`/`ps`/`log`/`kmem -i`/`sys`; the raw-passthrough behaviour for unknown/unparseable commands; the build-id contract (VMCOREINFO source, `provenance_mismatch` / `provenance_unverifiable` / `vmcore_format_unsupported` / `vmlinux_build_id_unreadable`); the timeout/output caps; and that the path is never gated and concurrent-safe. Do not use the word "sprint" (the `just check-docs` guard fails on it).

- [ ] **Step 2: Run the doc guard**

Run: `just check-docs`
Expected: PASS (no "sprint" tokens).

- [ ] **Step 3: Commit**

```bash
git add docs/debug-postmortem.md
git commit -m "docs(postmortem): document debug.postmortem.crash usage and contract"
```

---

## Task 11: env-gated integration test

**Files:**
- Create: `tests/test_postmortem_crash_integration.py`

- [ ] **Step 1: Write the gated test**

Create `tests/test_postmortem_crash_integration.py`. Gate exactly like the existing
integration suites (`test_vmcore_introspect_integration.py`): skip unless `crash` is on
PATH and `LDM_VMCORE` / `LDM_VMLINUX` env vars point at a captured core + matching
vmlinux. The test stages the core+vmlinux into a run dir, calls
`debug_postmortem_crash_handler` with the real `SubprocessSshRunner` (default runner),
and asserts: a multi-command batch (`["sys", "log", "bt"]`, plus one command producing
large output to cross the libc buffer) returns `ok`, each command has a populated
`cmd-NNNN.out` (framing holds over a pipe), `sys` parses with a `RELEASE`, and the
returned `vmcore_build_id` is non-empty:

```python
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import DebugPostmortemCrashRequest, RunRequest
from linux_debug_mcp.server import debug_postmortem_crash_handler

pytestmark = pytest.mark.skipif(
    shutil.which("crash") is None or not os.environ.get("LDM_VMCORE") or not os.environ.get("LDM_VMLINUX"),
    reason="requires crash + LDM_VMCORE + LDM_VMLINUX",
)


def test_real_crash_batch(tmp_path: Path) -> None:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(run_id="r1", source_path="/s", build_profile="x86_64-default",
                   target_profile="local-qemu", rootfs_profile="minimal")
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    shutil.copy(os.environ["LDM_VMCORE"], rd / "inputs" / "vmcore")
    shutil.copy(os.environ["LDM_VMLINUX"], rd / "build" / "vmlinux")
    resp = debug_postmortem_crash_handler(
        DebugPostmortemCrashRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux",
            commands=["sys", "log", "bt"], timeout_seconds=120,
        ),
        artifact_root=tmp_path,
    )
    assert resp.ok is True, resp.error
    assert resp.data["vmcore_build_id"]
    assert resp.data["results"]["sys"]["system"].get("RELEASE")
    # Framing held: each command produced its own output file.
    for cmd in ("sys", "log", "bt"):
        assert cmd in resp.data["results"]
```

- [ ] **Step 2: Confirm it skips cleanly (no fixture present)**

Run: `uv run python -m pytest tests/test_postmortem_crash_integration.py -q`
Expected: `s` (skipped) — never fail in CI without the fixture.

- [ ] **Step 3: Commit**

```bash
git add tests/test_postmortem_crash_integration.py
git commit -m "test(postmortem): add env-gated real-crash integration test"
```

---

## Task 12: final sweep

- [ ] **Step 1: Full guardrails**

Run: `uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q`
Expected: all pass, zero warnings.

- [ ] **Step 2: Provider list smoke**

Confirm `providers.list` advertises the new op:

Run: `uv run python -c "from linux_debug_mcp.providers.plugins import local_provider_plugin_specs; print([o for s in local_provider_plugin_specs() for c in s.provider_capability_factories for o in c().operations])"`
Expected: the printed list contains `debug.postmortem.crash`.

- [ ] **Step 3: Stdio smoke**

Run: `timeout 2 uv run linux-debug-mcp || test $? -eq 124`
Expected: exit 124 (server started and was killed by timeout) — proves tool registration imports cleanly.

---

## Self-review notes (spec coverage)

- AC "batch ⇒ JSON keyed by command, typed `bt`/`ps`/`log`/`kmem -i`/`sys`, transcript by `ArtifactRef`" → Tasks 3,4,9 (`results`, `transcript.txt`/`parsed.json` artifacts).
- AC "unknown/unparseable ⇒ raw, never dropped" → Task 4 (`parse_command` raw passthrough) + Task 3 (`not_captured`) + Task 9 test.
- AC "build_id mismatch fails loud, no crash run" → Task 1 + Task 9 `_crash_buildid_failloud` + `test_build_id_mismatch_fails_loud_no_run`, `test_vmcore_reader_failures_fail_loud` (3 codes), `test_vmlinux_build_id_unreadable_fails_loud` (all assert `runner.calls == 0`).
- §4.1 boundary + input validation → Task 9 `test_crash_open_failure_no_output_nonzero_exit`, `test_input_validation_codes` (invalid_timeout / duplicate / empty).
- AC "timeout cuts cleanly; oversize truncated with indicator" → Task 9 (`prlimit`+`timeout`, `crash_timeout`, `truncated` flag) + Task 3 caps.
- AC "unaffected by target lifecycle (no gate)" → Task 9 (no admission parameter) + lifecycle test.
- AC "all persisted + response through `Redactor()`" → Task 9 `_finalize_crash_call` (redact every value + transcript) + `test_redaction_masks_secret_in_output` (response + persisted `parsed.json`).
- AC "real-crash test env-gated" → Task 11.
- Security control (ADR 0026 2a) → Task 2 + Task 9 `command_not_permitted` test.
- Disk bound (spec §4.1) → Task 9 `prlimit --fsize` argv + `test_argv_carries_prlimit_disk_bound`; real `SIGXFSZ` exercised in Task 11.
- Path-injection guard (spec §6 step 8) → Task 2 `validate_modules_path` + Task 9 `test_modules_path_unsafe_rejected_no_run`.
- Module-load status (spec §3.3) → Task 9 `_finalize_crash_call` `module_symbols` + `test_module_symbols_status_reported`.
