# tests/test_session_registry.py
from datetime import UTC, datetime

import pytest

from linux_debug_mcp.coordination.registry import InstanceLockError, RecoveryTombstone, SessionRegistry
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import ExecutionState, RecordState, TransportSession, new_session_id


def _key() -> TargetKey:
    return TargetKey(provisioner="local-qemu", target_id="run-abc")


def _session(key: TargetKey, **over) -> TransportSession:
    base = dict(
        session_id=new_session_id(),
        target_key=key,
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.PENDING,
        created_at=datetime.now(UTC),
    )
    base.update(over)
    return TransportSession(**base)


def test_record_round_trip(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    session = _session(key)
    reg.write_record(session)
    loaded = reg.read_record(key)
    assert loaded is not None
    assert loaded.session_id == session.session_id
    assert loaded.record_state is RecordState.PENDING


def test_record_filename_uses_recovery_key(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key))
    # opaque key parts never appear as path segments (spec §4.7)
    assert (tmp_path / f"owner-{key.recovery_key()}.json").exists()
    assert not any("run-abc" in p.name for p in tmp_path.iterdir())


def test_write_is_atomic_no_partial_files(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(_session(_key()))
    assert not list(tmp_path.glob("*.tmp"))  # tmp renamed away


def test_tombstone_round_trip_and_clear(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_tombstone(RecoveryTombstone(target_key=key, generation=4, reason="halted_on_close"))
    tomb = reg.read_tombstone(key)
    assert tomb is not None and tomb.generation == 4
    reg.clear_tombstone(key, expected_generation=4)
    assert reg.read_tombstone(key) is None


def test_clear_tombstone_is_generation_fenced(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_tombstone(RecoveryTombstone(target_key=key, generation=5, reason="halted"))
    reg.clear_tombstone(key, expected_generation=4)  # stale clear → no-op
    assert reg.read_tombstone(key) is not None


def test_second_instance_fails_loud(tmp_path):
    first = SessionRegistry(directory=tmp_path)
    first.acquire_instance_lock()
    second = SessionRegistry(directory=tmp_path)
    with pytest.raises(InstanceLockError):
        second.acquire_instance_lock()
    first.release_instance_lock()
    # once released, a new instance may acquire
    third = SessionRegistry(directory=tmp_path)
    third.acquire_instance_lock()
    third.release_instance_lock()


class _FakeProxy:
    def __init__(self, *, kills_live_backend: bool = False) -> None:
        self.reaped: list[tuple[int, str | None]] = []
        self._kills_live_backend = kills_live_backend

    def stop_by_identity(self, pid: int, start_time: str | None) -> bool:
        self.reaped.append((pid, start_time))
        return self._kills_live_backend


class _RecordingAdmission:
    def __init__(self) -> None:
        self.marked: list[tuple[TargetKey, int]] = []

    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None:
        self.marked.append((target_key, generation))


def test_reconcile_reaps_live_orphan_and_clears_record(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(
        _session(key, backend_pid=4321, backend_start_time="999", execution_state=ExecutionState.EXECUTING)
    )
    proxy, admission = _FakeProxy(), _RecordingAdmission()
    reg.reconcile(proxy=proxy, admission=admission)
    assert proxy.reaped == [(4321, "999")]
    assert reg.read_record(key) is None
    assert admission.marked == []  # EXECUTING/no-halt → no recovery tombstone


def test_reconcile_tombstones_halted_record(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key, generation=7, backend_pid=None, execution_state=ExecutionState.HALTED))
    proxy, admission = _FakeProxy(), _RecordingAdmission()
    reg.reconcile(proxy=proxy, admission=admission)
    tomb = reg.read_tombstone(key)
    assert tomb is not None and tomb.generation == 7
    assert admission.marked == [(key, 7)]
    assert reg.read_record(key) is None


def test_reconcile_is_idempotent_across_two_restarts(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key, generation=7, execution_state=ExecutionState.HALTED))
    reg.reconcile(proxy=_FakeProxy(), admission=_RecordingAdmission())
    # second "restart": fresh registry, same dir; tombstone persists, no record to re-tombstone
    reg2 = SessionRegistry(directory=tmp_path)
    admission2 = _RecordingAdmission()
    reg2.reconcile(proxy=_FakeProxy(), admission=admission2)
    assert reg2.read_tombstone(key) is not None
    assert admission2.marked == [(key, 7)]  # re-marked from the durable tombstone, idempotent


def test_atomic_write_fsyncs_parent_dir_for_durability(tmp_path, monkeypatch):
    """Finding F4: `_atomic_write_json` (and tombstone/delete paths) must fsync the parent
    directory after `os.replace`, otherwise the rename can be lost on power loss and a stale
    prior record survives. Monkeypatch `os.fsync` to record the fds it was called with; the
    test asserts BOTH the regular file fd AND the parent directory fd were fsynced."""
    import os as _os

    fsynced_fds: list[int] = []
    dir_fds: set[int] = set()
    real_open = _os.open
    real_fsync = _os.fsync

    def recording_open(path, flags, *a, **kw):
        fd = real_open(path, flags, *a, **kw)
        if flags & _os.O_DIRECTORY:
            dir_fds.add(fd)
        return fd

    def recording_fsync(fd):
        fsynced_fds.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(_os, "open", recording_open)
    monkeypatch.setattr(_os, "fsync", recording_fsync)

    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(_session(_key(), backend_pid=None, execution_state=ExecutionState.EXECUTING))
    # At least one fd was a directory fd and at least one fd was a regular file fd.
    assert len(fsynced_fds) >= 2, fsynced_fds
    assert dir_fds & set(fsynced_fds), (
        f"parent dir was NOT fsynced after os.replace: dir_fds={dir_fds}, fsynced={fsynced_fds}"
    )


def test_reconcile_logs_callback_exceptions(tmp_path, caplog):
    """Finding F9: a buggy `on_orphan_reaped` callback no longer silently disappears via
    `contextlib.suppress`. It is collected into the `OrphanReapReport.failures` list AND logged
    through the project logger, so an operator can triage the missing lifecycle event. The
    remaining reap work (durable record delete) still runs — a buggy callback cannot block
    cleanup."""
    import logging

    captured: list[str] = []

    def boom(reap):
        captured.append(reap.session_id)
        raise RuntimeError("subscriber raised intentionally")

    reg = SessionRegistry(directory=tmp_path, on_orphan_reaped=boom)
    key = _key()
    record = _session(key, backend_pid=4321, backend_start_time="ABC", execution_state=ExecutionState.EXECUTING)
    reg.write_record(record)

    with caplog.at_level(logging.ERROR, logger="linux_debug_mcp.coordination.registry"):
        report = reg.reconcile(proxy=_FakeProxy(), admission=_RecordingAdmission())

    # The callback ran exactly once …
    assert captured == [record.session_id]
    # … its failure was collected, not swallowed …
    assert len(report.failures) == 1
    failed_record, failed_exc = report.failures[0]
    assert failed_record.session_id == record.session_id
    assert isinstance(failed_exc, RuntimeError)
    # … logged at ERROR via the project logger …
    assert any("on_orphan_reaped" in entry.message for entry in caplog.records)
    # … and the durable record was STILL deleted — buggy callback never blocks reap work.
    assert reg.read_record(key) is None
