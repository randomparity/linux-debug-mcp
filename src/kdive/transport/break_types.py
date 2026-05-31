from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol


class BreakProxy(Protocol):
    # BreakResources intentionally erases the concrete proxy handle type at the transport
    # boundary; each proxy backend owns validation of the opaque value it receives.
    def send_break(self, handle: Any) -> None: ...


class BreakSshResult(Protocol):
    returncode: int


class BreakSshRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
    ) -> BreakSshResult: ...
