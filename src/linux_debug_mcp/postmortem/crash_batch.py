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


def build_command_script(commands: list[str], output_dir: Path, modules_path: str | None) -> str:
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
    # Bounded read (cap+1 bytes), so an oversize file is never slurped into RAM
    # even if the prlimit RLIMIT_FSIZE write-bound were ever absent.
    with path.open("rb") as fh:
        data = fh.read(cap + 1)
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
