from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import TransportSession


@dataclass(frozen=True)
class RecoveryTombstone:
    """Durable `recovery_required` marker (ADR 0005 / spec §4.7). Persisted beside the
    ownership record; survives a server restart so a crashed-while-halted target stays
    gated until an explicit clearance path runs."""

    target_key: TargetKey
    generation: int
    reason: str


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write-tmp → fsync → os.replace, so a crash mid-write never leaves a torn record
    (ADR 0005). The rename is atomic on the same filesystem; readers see old or new, never
    partial."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


class InstanceLockError(RuntimeError):
    """Raised when the host-global single-instance flock is already held — a second server
    process must fail loud, never admit alongside the first (ADR 0005, spec §10.2)."""


class SessionRegistry:
    """Durable, host-global ownership store (ADR 0005). One JSON record + optional tombstone
    per TargetKey, filenames derived from `TargetKey.recovery_key()` so opaque key parts are
    never path segments. Atomic writes; the flock + reaper live in later tasks (A3/A4)."""

    def __init__(self, *, directory: Path) -> None:
        self._dir = directory
        self._lock_fd: int | None = None

    def acquire_instance_lock(self) -> None:
        path = self._dir / "instance.lock"
        self._lock_fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._lock_fd)
            self._lock_fd = None
            raise InstanceLockError("another linux-debug-mcp server already holds the registry instance lock") from exc

    def release_instance_lock(self) -> None:
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None

    def _record_path(self, target_key: TargetKey) -> Path:
        return self._dir / f"owner-{target_key.recovery_key()}.json"

    def _tomb_path(self, target_key: TargetKey) -> Path:
        return self._dir / f"tomb-{target_key.recovery_key()}.json"

    def write_record(self, session: TransportSession) -> None:
        _atomic_write_json(self._record_path(session.target_key), session.model_dump(mode="json"))

    def read_record(self, target_key: TargetKey) -> TransportSession | None:
        path = self._record_path(target_key)
        if not path.exists():
            return None
        return TransportSession.model_validate_json(path.read_text(encoding="utf-8"))

    def delete_record(self, target_key: TargetKey) -> None:
        self._record_path(target_key).unlink(missing_ok=True)

    def list_records(self) -> list[TransportSession]:
        records: list[TransportSession] = []
        for path in self._dir.glob("owner-*.json"):
            records.append(TransportSession.model_validate_json(path.read_text(encoding="utf-8")))
        return records

    def write_tombstone(self, tombstone: RecoveryTombstone) -> None:
        _atomic_write_json(
            self._tomb_path(tombstone.target_key),
            {
                "provisioner": tombstone.target_key.provisioner,
                "target_id": tombstone.target_key.target_id,
                "generation": tombstone.generation,
                "reason": tombstone.reason,
            },
        )

    def read_tombstone(self, target_key: TargetKey) -> RecoveryTombstone | None:
        path = self._tomb_path(target_key)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return RecoveryTombstone(
            target_key=TargetKey(provisioner=data["provisioner"], target_id=data["target_id"]),
            generation=data["generation"],
            reason=data["reason"],
        )

    def clear_tombstone(self, target_key: TargetKey, *, expected_generation: int) -> None:
        existing = self.read_tombstone(target_key)
        if existing is not None and existing.generation == expected_generation:
            self._tomb_path(target_key).unlink(missing_ok=True)
