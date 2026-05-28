from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from linux_debug_mcp.seams.target import TargetKey


class GuardConflict(RuntimeError):
    """Raised when acquire() fails because the target already has a stop-capable holder
    (spec §4.4/§4.6: one stop-capable session per TargetKey, target-wide)."""


@dataclass(frozen=True)
class GuardToken:
    """Fenced single-holder token. `fence` is monotonic across the guard so a token from a
    revoked/superseded holder can never release or act on a later holder."""

    target_key: TargetKey
    fence: int
    secret: str


@runtime_checkable
class StopCapableGuard(Protocol):
    def acquire(self, target_key: TargetKey) -> GuardToken: ...

    def release(self, target_key: TargetKey, token: GuardToken) -> bool: ...

    def revoke(self, target_key: TargetKey) -> None: ...


class InProcessStopCapableGuard:
    """Minimal in-process impl of the #08-owned `StopCapableGuard` interface. One holder per
    TargetKey, target-wide — both `debug.gdb` (RSP) and `debug.kdb` (console) acquire it, so
    a single stop-capable session is enforced even with no console lease. #08 later swaps this
    impl behind the same Protocol and must pass these same tests (roadmap seam-ownership rule)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._holders: dict[TargetKey, GuardToken] = {}
        self._fence = 0

    def acquire(self, target_key: TargetKey) -> GuardToken:
        with self._lock:
            if target_key in self._holders:
                raise GuardConflict(f"stop-capable session already held for {target_key}")
            self._fence += 1
            token = GuardToken(target_key=target_key, fence=self._fence, secret=uuid.uuid4().hex)
            self._holders[target_key] = token
            return token

    def release(self, target_key: TargetKey, token: GuardToken) -> bool:
        """Idempotent, **TargetKey-fenced** by-token release (contract §5.6: `release(target_key,
        token)`). Returns True iff `token` is the current holder of `target_key`. A token whose
        `target_key` does not match the argument (a misrouted token from another target), or a
        stale/fenced token (post-revoke or post-release), is a no-op returning False — so cleanup
        keyed on the wrong target can never release another target's live stop-capable guard."""
        with self._lock:
            if token.target_key != target_key:
                return False
            current = self._holders.get(target_key)
            if current is None or current != token:
                return False
            del self._holders[target_key]
            return True

    def revoke(self, target_key: TargetKey) -> None:
        """Force-free the holder (only from §4.5 invalidation). The outstanding token is
        fenced: a subsequent release(old_token) is a no-op."""
        with self._lock:
            self._holders.pop(target_key, None)
