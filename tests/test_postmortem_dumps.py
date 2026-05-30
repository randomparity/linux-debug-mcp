from __future__ import annotations

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import (
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DumpEntry,
    FetchedFile,
)


def test_list_request_defaults() -> None:
    req = DebugPostmortemListDumpsRequest(run_id="r1", target_ref="local-qemu")
    assert req.timeout_seconds == 20
    assert req.dump_dir is None


def test_fetch_request_defaults() -> None:
    req = DebugPostmortemFetchRequest(run_id="r1", target_ref="local-qemu", dump_ref="/var/crash/d1")
    assert req.timeout_seconds == 300
    assert req.force is False
    assert req.max_bytes is None


def test_models_forbid_extra() -> None:
    with pytest.raises(ValidationError):
        DebugPostmortemListDumpsRequest(run_id="r1", target_ref="x", bogus=1)
    with pytest.raises(ValidationError):
        DumpEntry(path="/d", kernel=None, capture_time=None, size_bytes=1, incomplete=False, bogus=1)


def test_dump_entry_and_fetched_file_shape() -> None:
    e = DumpEntry(
        path="/var/crash/d1",
        kernel="6.8.0",
        capture_time="2026-05-30T00:00:00+00:00",
        size_bytes=1024,
        incomplete=False,
        available_files=["vmcore-dmesg.txt"],
        file_sizes={"vmcore": 1024, "vmcore-dmesg.txt": 32},
    )
    assert e.available_files == ["vmcore-dmesg.txt"]
    f = FetchedFile(name="vmcore", ref="debug/postmortem/dumps/d1/vmcore", sha256="ab", size_bytes=1024)
    assert f.name == "vmcore"


def test_ops_and_bounds_registered() -> None:
    from linux_debug_mcp.config import (
        ALLOWED_DEBUG_OPERATIONS,
        DEFAULT_FETCH_MAX_BYTES,
        FETCH_DISK_HEADROOM_BYTES,
        FETCH_TIMEOUT_BAND,
    )

    assert "debug.postmortem.list_dumps" in ALLOWED_DEBUG_OPERATIONS
    assert "debug.postmortem.fetch" in ALLOWED_DEBUG_OPERATIONS
    assert DEFAULT_FETCH_MAX_BYTES > 0
    assert FETCH_DISK_HEADROOM_BYTES > 0
    assert FETCH_TIMEOUT_BAND == (5, 3600)
