"""Unit tests for the extracted coordination-teardown helpers (issue #127).

`_best_effort_reap` (TD-07) and `_write_backend_partial` (TD-25) were pulled out of the
`TransportTransaction` open/teardown closures so their contracts are directly testable.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import _best_effort_reap, _OpenState, _write_backend_partial
from kdive.seams.target import TargetKey
from kdive.transport.core.base import RecordState, Transport, TransportSession, new_session_id


def _key() -> TargetKey:
    return TargetKey(provisioner="local-qemu", target_id="run-127")


def _record(key: TargetKey) -> TransportSession:
    return TransportSession(
        session_id=new_session_id(),
        target_key=key,
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.OPENING,
        created_at=datetime.now(UTC),
    )


# --- TD-07: _best_effort_reap ----------------------------------------------------------------
class _RecordingTransport(Transport):
    def __init__(self, *, raises: bool = False) -> None:
        self.reaped: list[tuple[int, str | None]] = []
        self._raises = raises

    @property
    def capability(self):  # pragma: no cover - not exercised here
        raise NotImplementedError

    def attach(self, request, *, cancel, deadline, on_partial, secrets=...):  # pragma: no cover
        raise NotImplementedError

    def close(self, session) -> None:  # pragma: no cover
        raise NotImplementedError

    def health(self, session) -> str:  # pragma: no cover
        raise NotImplementedError

    def reap_backend(self, pid: int, start_time: str | None) -> None:
        self.reaped.append((pid, start_time))
        if self._raises:
            raise RuntimeError("reap boom")


def test_best_effort_reap_noop_when_no_backend_pid() -> None:
    transport = _RecordingTransport()
    _best_effort_reap(transport, _OpenState(backend_pid=None))
    assert transport.reaped == []


def test_best_effort_reap_delegates_to_hook() -> None:
    transport = _RecordingTransport()
    _best_effort_reap(transport, _OpenState(backend_pid=4321, backend_start="t9"))
    assert transport.reaped == [(4321, "t9")]


def test_best_effort_reap_suppresses_and_logs_failure(caplog) -> None:
    transport = _RecordingTransport(raises=True)
    with caplog.at_level(logging.WARNING):
        _best_effort_reap(transport, _OpenState(backend_pid=7, backend_start="t"))  # must not raise
    assert "reap_backend" in caplog.text


def test_default_reap_backend_is_noop() -> None:
    # A transport that does not override the hook (no supervised backend) must not error.
    class _Bare(_RecordingTransport):
        reap_backend = Transport.reap_backend  # use the ABC default

    bare = _Bare()
    _best_effort_reap(bare, _OpenState(backend_pid=1, backend_start="t"))
    assert bare.reaped == []  # default no-op never recorded a reap


# --- TD-25: _write_backend_partial -----------------------------------------------------------
def test_write_backend_partial_writes_through_and_returns_identity(tmp_path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    record = _record(key)
    reg.write_record(record)
    result = _write_backend_partial(reg, record, {"pid": 4321, "start_time": "999"})
    assert result == (4321, "999")
    assert reg.read_record(key).backend_pid == 4321  # durable write-through happened


def test_write_backend_partial_ignores_non_dict(tmp_path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    record = _record(_key())
    reg.write_record(record)
    assert _write_backend_partial(reg, record, "not-a-dict") is None
    assert reg.read_record(_key()).backend_pid is None  # no write on a malformed partial


def test_write_backend_partial_ignores_missing_or_bad_pid(tmp_path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    record = _record(_key())
    reg.write_record(record)
    assert _write_backend_partial(reg, record, {"start_time": "9"}) is None  # missing pid -> no KeyError
    assert _write_backend_partial(reg, record, {"pid": "notint"}) is None  # bad pid type
    assert reg.read_record(_key()).backend_pid is None
