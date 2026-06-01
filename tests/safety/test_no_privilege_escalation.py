"""Guard: no host-side privilege-escalation command invocation in scripts/ or justfile.

Mirrors the `just check-no-sudo` recipe so the invariant holds under pytest/CI even when `just`
is absent. Scoped to scripts/ + justfile only: the ~20 `sudo` references in src/ are in-guest SSH
privilege prefixes (ADR 0011/0028), a distinct concern out of this guard's scope.
"""

from __future__ import annotations

import re
from pathlib import Path

ESCALATION = re.compile(r"(^|\s)(sudo|pkexec|doas)\s")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _targets() -> list[Path]:
    targets = sorted((REPO_ROOT / "scripts").rglob("*"))
    files = [path for path in targets if path.is_file()]
    justfile = REPO_ROOT / "justfile"
    if justfile.is_file():
        files.append(justfile)
    return files


def test_no_host_side_privilege_escalation() -> None:
    offenders: list[str] = []
    for path in _targets():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if ESCALATION.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "host-side privilege escalation found:\n" + "\n".join(offenders)
