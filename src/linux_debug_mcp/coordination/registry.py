from __future__ import annotations

import contextlib
import fcntl
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import ExecutionState, TransportSession


class _ReapProxy(Protocol):
    def stop_by_identity(self, pid: int, start_time: str | None) -> None: ...


class _RecoveryMarker(Protocol):
    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None: ...


@dataclass(frozen=True)
class OrphanReap:
    """Per-reap callback payload (Finding #3 / ADR 0006). One record reaped by
    `SessionRegistry.reconcile()`: a durable record whose `backend_pid` either did not match a
    live process by start-time fingerprint, or whose `execution_state` was HALTED/UNKNOWN. The
    server's `_build_transport_machinery` closure consumes this and drives
    `admission.invalidate_lifecycle(target_key, CRASHED)` — the production source of `LifecycleEvent`
    in #10. Carries the durable record itself so the callback can read any field (backend_pid,
    backend_start_time, etc.) without re-loading from disk."""

    target_key: TargetKey
    session_id: str
    record: TransportSession
    reason: str = "backend_died"


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
    never path segments. Atomic writes; the flock + reaper live in later tasks (A3/A4).

    `on_orphan_reaped` is the optional production lifecycle-source callback (Finding #3 /
    ADR 0006): every successful reap inside `reconcile()` invokes it BEFORE the record is
    deleted, so the closure can drive `admission.invalidate_lifecycle(..., CRASHED)` and run
    the §4.5 chain end-to-end. Defaults to `None` (tests that don't need the production
    lifecycle source omit the parameter and behavior is unchanged)."""

    def __init__(
        self,
        *,
        directory: Path,
        on_orphan_reaped: Callable[[OrphanReap], None] | None = None,
    ) -> None:
        self._dir = directory
        self._lock_fd: int | None = None
        self._on_orphan_reaped = on_orphan_reaped

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

    def reconcile(self, *, proxy: _ReapProxy, admission: _RecoveryMarker) -> None:
        """Crash reconciliation (ADR 0005, spec §4.7/§10.2). MUST run after
        acquire_instance_lock() and BEFORE admission accepts its first admit. Reaps live
        orphan backends (start-time fenced — never a foreign pid), re-asserts every durable
        tombstone into admission, and tombstones any record left HALTED/UNKNOWN.

        When `on_orphan_reaped` was wired at construction (Finding #3), every record reaped
        here fires the callback BEFORE deletion — that is the production source of
        `LifecycleEvent` in #10, so `admission.invalidate_lifecycle(target_key, CRASHED)` runs
        the §4.5 close+emit chain against this same admission/dispatcher pair.
        """
        # 1. re-assert persisted tombstones (durable across restarts)
        for path in self._dir.glob("tomb-*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            key = TargetKey(provisioner=data["provisioner"], target_id=data["target_id"])
            admission.mark_recovery_required(key, data["generation"])
        # 2. reap orphan records
        for record in self.list_records():
            if record.backend_pid is not None:
                # start-time fence lives inside stop_by_identity (ADR 0004): a pid whose live
                # start-time != record.backend_start_time is never signalled.
                proxy.stop_by_identity(record.backend_pid, record.backend_start_time)
            if record.execution_state in (ExecutionState.HALTED, ExecutionState.UNKNOWN):
                self.write_tombstone(
                    RecoveryTombstone(
                        target_key=record.target_key,
                        generation=record.generation,
                        reason=f"reconciled_{record.execution_state.value}",
                    )
                )
                admission.mark_recovery_required(record.target_key, record.generation)
            # The production lifecycle-source callback (Finding #3): notify BEFORE the record is
            # deleted so the consumer can read `backend_pid`/etc. off the snapshot if it needs
            # them. Suppressed: a buggy/raising callback must never block the remaining reap
            # work — the durable record delete below must always run.
            if self._on_orphan_reaped is not None:
                with contextlib.suppress(Exception):
                    self._on_orphan_reaped(
                        OrphanReap(
                            target_key=record.target_key,
                            session_id=record.session_id,
                            record=record,
                        )
                    )
            self.delete_record(record.target_key)
