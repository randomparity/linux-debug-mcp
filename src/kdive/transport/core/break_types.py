from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol


class BreakProxy(Protocol):
    # BreakResources intentionally erases the concrete proxy handle type at the transport
    # boundary; each proxy backend owns validation of the opaque value it receives.
    def send_break(self, handle: Any) -> None: ...


class BreakSshResult(Protocol):
    exit_status: int
    timed_out: bool
    cancelled: bool
    stdin_failed: bool
    oversized_output: bool
    stdout_snippet: str
    stderr_snippet: str


class BreakSshRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
    ) -> BreakSshResult: ...
