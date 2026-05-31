from __future__ import annotations

import errno
import fcntl
import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from kdive.seams.target import TargetKey
from kdive.transport.base import ExecutionState, TransportSession

logger = logging.getLogger(__name__)


class _ReapProxy(Protocol):
    def stop_by_identity(self, pid: int, start_time: str | None) -> bool: ...


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
    backend_start_time, etc.) without re-loading from disk.

    `close_admission_required` (Finding F1) is True iff `proxy.stop_by_identity(...)` actually
    killed a fingerprint-matched live backend during this reap — i.e. there was a live orphan that
    a still-active subscriber might want to tear down. False when the durable record was present
    but the backend was already dead, fingerprint-unverifiable, or `backend_pid is None` (the
    qemu-gdbstub case): nothing alive was reaped, so admission must NOT be locked-closed (no
    production reopen() caller exists; closing admission here permanently bricks the target until
    process restart)."""

    target_key: TargetKey
    session_id: str
    record: TransportSession
    reason: str = "backend_died"
    close_admission_required: bool = False


@dataclass(frozen=True)
class OrphanReapReport:
    """Aggregated outcome of one `SessionRegistry.reconcile()` (Finding F9). `reaped` lists every
    record reaped this pass; `failures` lists `(record, exception)` pairs for callback dispatches
    that raised, so the caller can log them via the project logger instead of the original
    `contextlib.suppress` silently swallowing the error. Reconcile completes its work even if a
    subset of callbacks raise — a buggy callback must not block the remaining reap work."""

    reaped: list[OrphanReap] = field(default_factory=list)
    failures: list[tuple[TransportSession, BaseException]] = field(default_factory=list)


@dataclass(frozen=True)
class RecoveryTombstone:
    """Durable `recovery_required` marker (ADR 0005 / spec §4.7). Persisted beside the
    ownership record; survives a server restart so a crashed-while-halted target stays
    gated until an explicit clearance path runs."""

    target_key: TargetKey
    generation: int
    reason: str


def _fsync_dir(path: Path) -> None:
    """Fsync a directory so a prior os.replace into it is durable on disk (Finding F4). On power
    loss the rename can otherwise be lost, leaving the stale prior record. Best-effort: a
    filesystem that rejects directory fsync (EINVAL) is logged and ignored; other OSErrors
    likewise — durability is the goal but a fsync failure must not crash the caller."""
    try:
        fd = os.open(path, os.O_DIRECTORY)
    except OSError as exc:
        logger.warning("registry: cannot open dir %s for fsync: %s", path, exc)
        return
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno != errno.EINVAL:
            logger.warning("registry: dir fsync(%s) failed: %s", path, exc)
    finally:
        os.close(fd)


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write-tmp → fsync → os.replace → fsync parent dir, so a crash mid-write never leaves a
    torn record (ADR 0005) AND the rename itself is durable across power loss (Finding F4). The
    rename is atomic on the same filesystem; readers see old or new, never partial."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


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
            raise InstanceLockError("another kdive server already holds the registry instance lock") from exc

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

    def delete_record(self, target_key: TargetKey, *, expected_session_id: str | None = None) -> None:
        """Delete the durable ownership record for `target_key`.

        When `expected_session_id` is set, the on-disk record is read first and only unlinked
        if its `session_id` matches. This prevents a stale subscriber (e.g. one whose session
        already cleanly closed but whose dispatcher binding lingered) or a wedge-tail unblock
        from erasing the FRESH session's record after a new incarnation has written its own
        owner-*.json at the same target_key path. Without the fence, `delete_record` is keyed
        only by `target_key` and a stale caller has no way to express "delete only if it's
        still mine".

        Read→check→unlink is not atomic, so a concurrent `write_record` between the read and
        the unlink could be lost. The window is microseconds (an in-memory check between two
        syscalls); the alternative — per-target locking in the registry itself — is a much
        larger refactor that would also need to cover `write_record`, `reconcile`, and
        `list_records`. The narrow residual TOCTOU is documented and accepted; it is orders of
        magnitude smaller than the original race ("stale subscriber unconditionally erases a
        fresh session's record").
        """
        if expected_session_id is not None:
            existing = self.read_record(target_key)
            if existing is None or existing.session_id != expected_session_id:
                return
        path = self._record_path(target_key)
        existed = path.exists()
        path.unlink(missing_ok=True)
        if existed:
            # Finding F4: a deletion is also an inode-tree mutation; fsync the parent so power
            # loss after delete does not resurrect the stale record on next mount.
            _fsync_dir(path.parent)

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

    @staticmethod
    def _load_tombstone(path: Path) -> RecoveryTombstone | None:
        """Parse a ``tomb-*.json`` file, returning None (with a logged warning) when it is
        missing, truncated, or otherwise malformed. A corrupted recovery marker — e.g. a partial
        write before a crash — must not raise out of read/reconcile at startup; it is skipped and
        logged so the server still comes up. Orphan-record reconciliation re-tombstones any target
        whose durable record is still HALTED/UNKNOWN, so a dropped standalone marker self-heals."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return RecoveryTombstone(
                target_key=TargetKey(provisioner=data["provisioner"], target_id=data["target_id"]),
                generation=data["generation"],
                reason=data["reason"],
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValidationError) as exc:
            logger.warning("registry: skipping malformed tombstone %s: %r", path, exc)
            return None

    def read_tombstone(self, target_key: TargetKey) -> RecoveryTombstone | None:
        path = self._tomb_path(target_key)
        if not path.exists():
            return None
        return self._load_tombstone(path)

    def clear_tombstone(self, target_key: TargetKey, *, expected_generation: int) -> None:
        existing = self.read_tombstone(target_key)
        if existing is not None and existing.generation == expected_generation:
            path = self._tomb_path(target_key)
            existed = path.exists()
            path.unlink(missing_ok=True)
            if existed:
                _fsync_dir(path.parent)  # Finding F4: durable deletion

    def reconcile(self, *, proxy: _ReapProxy, admission: _RecoveryMarker) -> OrphanReapReport:
        """Crash reconciliation (ADR 0005, spec §4.7/§10.2). MUST run after
        acquire_instance_lock() and BEFORE admission accepts its first admit. Reaps live
        orphan backends (start-time fenced — never a foreign pid), re-asserts every durable
        tombstone into admission, and tombstones any record left HALTED/UNKNOWN.

        When `on_orphan_reaped` was wired at construction (Finding #3), every record reaped
        here fires the callback BEFORE deletion — that is the production source of
        `LifecycleEvent` in #10, so `admission.invalidate_lifecycle(target_key, CRASHED)` runs
        the §4.5 close+emit chain against this same admission/dispatcher pair. The callback's
        `OrphanReap.close_admission_required` field (Finding F1) tells the consumer whether to
        pass `close_admission=True`: True iff `proxy.stop_by_identity()` actually killed a live
        backend this pass. False when the record was present but the backend was dead, the pid
        was unfenceable, or `backend_pid is None` (qemu-gdbstub) — closing admission then would
        permanently lock the target (no production code path calls `reopen()`).

        Returns an `OrphanReapReport` listing every reap and any callback failure (Finding F9).
        Callback exceptions are collected, not silently swallowed; the caller logs the failures
        via the project logger. A buggy callback still does not block remaining reap work — the
        durable record delete still runs for every record.
        """
        report = OrphanReapReport()
        # 1. re-assert persisted tombstones (durable across restarts). A malformed marker is
        #    logged and skipped (TD-17) rather than aborting reconcile and blocking startup.
        for path in self._dir.glob("tomb-*.json"):
            tombstone = self._load_tombstone(path)
            if tombstone is None:
                continue
            admission.mark_recovery_required(tombstone.target_key, tombstone.generation)
        # 2. reap orphan records
        for record in self.list_records():
            # F1: did stop_by_identity actually kill a fingerprint-matched live backend?
            #  * backend_pid is None (qemu-gdbstub) ⇒ nothing to reap ⇒ no close_admission.
            #  * backend_pid set + identity matches + we signaled ⇒ live orphan ⇒ close_admission.
            #  * backend_pid set + identity mismatch / dead / unfenceable ⇒ no close_admission.
            killed_live_backend = False
            if record.backend_pid is not None:
                # start-time fence lives inside stop_by_identity (ADR 0004): a pid whose live
                # start-time != record.backend_start_time is never signalled. Returns True iff
                # we issued SIGTERM against a fingerprint-matched live backend.
                killed_live_backend = bool(proxy.stop_by_identity(record.backend_pid, record.backend_start_time))
            if record.execution_state in (ExecutionState.HALTED, ExecutionState.UNKNOWN):
                self.write_tombstone(
                    RecoveryTombstone(
                        target_key=record.target_key,
                        generation=record.generation,
                        reason=f"reconciled_{record.execution_state.value}",
                    )
                )
                admission.mark_recovery_required(record.target_key, record.generation)
            reap = OrphanReap(
                target_key=record.target_key,
                session_id=record.session_id,
                record=record,
                close_admission_required=killed_live_backend,
            )
            report.reaped.append(reap)
            # The production lifecycle-source callback (Finding #3 / F9): notify BEFORE the
            # record is deleted so the consumer can read `backend_pid`/etc. off the snapshot if
            # it needs them. A raising callback is COLLECTED into the report (logged by the
            # caller) — the durable record delete below must always run, so a buggy callback
            # cannot block remaining reap work.
            if self._on_orphan_reaped is not None:
                try:
                    self._on_orphan_reaped(reap)
                except Exception as exc:  # noqa: BLE001 — collect; caller logs every failure
                    report.failures.append((record, exc))
                    logger.exception(
                        "registry.reconcile: on_orphan_reaped callback raised for session %s (target %s)",
                        record.session_id,
                        record.target_key,
                    )
            self.delete_record(record.target_key, expected_session_id=record.session_id)
        return report
