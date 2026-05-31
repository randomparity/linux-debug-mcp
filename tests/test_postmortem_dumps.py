from __future__ import annotations

import pytest
from pydantic import ValidationError

from kdive.postmortem.models import (
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DumpEntry,
    FetchedFile,
)


def test_list_request_defaults() -> None:
    req = DebugPostmortemListDumpsRequest(run_id="r1", target_ref="local-qemu")
    assert req.timeout_seconds == 20
    assert req.dump_dir is None
    assert req.manifest_target_profile == "local-qemu"


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
    from kdive.config import (
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


def test_parse_dump_listing_empty() -> None:
    from kdive.postmortem.dumps import parse_dump_listing

    assert parse_dump_listing({"dump_dir": "/var/crash", "exists": False, "dumps": []}) == []


def test_parse_dump_listing_one() -> None:
    from kdive.postmortem.dumps import parse_dump_listing

    probe = {
        "dump_dir": "/var/crash",
        "exists": True,
        "dumps": [
            {
                "dir": "/var/crash/d1",
                "vmcore_name": "vmcore",
                "size": 2048,
                "mtime": 1717027200.0,
                "kernel": "Linux version 6.8.0",
                "incomplete": False,
                "present": ["vmcore-dmesg.txt", "vmlinux"],
                "file_sizes": {"vmcore": 2048, "vmcore-dmesg.txt": 16, "vmlinux": 99},
            }
        ],
    }
    entries = parse_dump_listing(probe)
    assert len(entries) == 1
    e = entries[0]
    assert e.path == "/var/crash/d1"
    assert e.kernel == "Linux version 6.8.0"
    assert e.size_bytes == 2048
    assert e.capture_time == "2024-05-30T00:00:00+00:00"
    assert e.available_files == ["vmcore-dmesg.txt", "vmlinux"]
    assert e.file_sizes["vmcore"] == 2048


def test_parse_dump_listing_sort_and_missing_mtime() -> None:
    from kdive.postmortem.dumps import parse_dump_listing

    probe = {
        "dump_dir": "/var/crash",
        "exists": True,
        "dumps": [
            {
                "dir": "/var/crash/a",
                "vmcore_name": "vmcore",
                "size": 1,
                "mtime": 1.0,
                "kernel": None,
                "incomplete": False,
                "present": [],
                "file_sizes": {"vmcore": 1},
            },
            {
                "dir": "/var/crash/b",
                "vmcore_name": "vmcore",
                "size": 1,
                "mtime": 100.0,
                "kernel": None,
                "incomplete": False,
                "present": [],
                "file_sizes": {"vmcore": 1},
            },
            {
                "dir": "/var/crash/c",
                "vmcore_name": "vmcore",
                "size": 1,
                "mtime": None,
                "kernel": None,
                "incomplete": True,
                "present": [],
                "file_sizes": {"vmcore": 1},
            },
        ],
    }
    entries = parse_dump_listing(probe)
    # newest capture_time first; null capture_time sorts last; tie-break by path
    assert [e.path for e in entries] == ["/var/crash/b", "/var/crash/a", "/var/crash/c"]
    assert entries[-1].capture_time is None
    assert entries[-1].incomplete is True


def test_derive_dump_id_stable_and_slugged() -> None:
    from kdive.postmortem.dumps import derive_dump_id

    a = derive_dump_id("/var/crash/127.0.0.1-2026-05-30-12:00:00")
    b = derive_dump_id("/var/crash/127.0.0.1-2026-05-30-12:00:00")
    assert a == b
    assert ":" not in a and "/" not in a
    assert a != derive_dump_id("/var/crash/other-2026-05-30-12:00:00")


def test_derive_dump_id_disambiguates_collision() -> None:
    from kdive.postmortem.dumps import derive_dump_id

    # basenames slug identically but full paths differ -> different ids
    assert derive_dump_id("/var/crash/a:b") != derive_dump_id("/other/a:b")


def test_plan_fetch_maps_files_to_refs() -> None:
    from kdive.postmortem.dumps import plan_fetch

    entry = DumpEntry(
        path="/var/crash/d1",
        kernel=None,
        capture_time=None,
        size_bytes=2048,
        incomplete=False,
        available_files=["vmcore-dmesg.txt", "vmlinux"],
        file_sizes={"vmcore": 2048, "vmcore-dmesg.txt": 16, "vmlinux": 99},
    )
    specs = plan_fetch(entry, vmcore_name="vmcore")
    by_name = {s.local_name: s for s in specs}
    assert by_name["vmcore"].ref_key == "vmcore_ref"
    assert by_name["vmcore"].expected_size == 2048
    assert by_name["vmcore"].remote_path == "/var/crash/d1/vmcore"
    assert by_name["vmlinux"].ref_key == "vmlinux_ref"
    assert by_name["vmcore-dmesg.txt"].ref_key == "vmcore_dmesg_ref"
    # vmcoreinfo absent -> not planned
    assert "vmcoreinfo" not in by_name


def test_render_dump_list_script_substitutes_dir() -> None:
    from kdive.postmortem.dumps import render_dump_list_script

    script = render_dump_list_script(dump_dir="/var/crash")
    assert "/var/crash" in script
    assert "json.dumps" in script
