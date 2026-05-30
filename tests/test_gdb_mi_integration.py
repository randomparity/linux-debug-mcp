"""Gated end-to-end gdb/MI engine integration test (#79, Phase A).

Drives the REAL GdbMiEngine against the rsp_endpoint that a real transaction.open() (via the full
build -> boot -> debug.start_session flow) returns: attach over RSP, read one MI record as typed
JSON (the ^connected attach proof), detach cleanly, and confirm resume returns promptly (the live
counterpart to the unit-test mi-async-before-continue ordering proxy).

Gate: KDIVE_LIVE_GDBSTUB=1 + companion envs + virsh + gdb (mirrors
test_transport_open_close_integration.py). Skipped cleanly with no live env, like the sibling.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

_GDBSTUB_REQUIRED_ENV = [
    "KDIVE_LIVE_GDBSTUB",
    "KDIVE_SOURCE",
    "KDIVE_ROOTFS",
    "KDIVE_DOMAIN",
    "KDIVE_LIBVIRT_URI",
    "KDIVE_READINESS_MARKER",
]
_MANAGED_DOMAIN_PREFIX = "kdive-"


def _live() -> bool:
    if os.environ.get("KDIVE_LIVE_GDBSTUB") != "1":
        return False
    return all(os.environ.get(name) for name in _GDBSTUB_REQUIRED_ENV)


def _skip_reason() -> str:
    missing = [name for name in _GDBSTUB_REQUIRED_ENV if not os.environ.get(name)]
    return (
        "live gdbstub integration test skipped; set "
        f"{', '.join(missing) if missing else 'KDIVE_LIVE_GDBSTUB=1'} to run it "
        "(see tests/test_transport_open_close_integration.py for the full env example)."
    )


@pytest.mark.skipif(not _live(), reason=_skip_reason())
def test_engine_attaches_reads_one_record_and_detaches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Build -> boot -> debug.start_session through the wired machinery to obtain a READY transport
    session, then drive the real GdbMiEngine against its durable rsp_endpoint: attach, read the
    ^connected MI record as typed JSON, and resume/detach promptly."""
    env = {name: os.environ[name] for name in _GDBSTUB_REQUIRED_ENV}
    source = Path(env["KDIVE_SOURCE"]).expanduser()
    rootfs_path = Path(env["KDIVE_ROOTFS"]).expanduser()
    vmlinux = source / "vmlinux"
    gdbstub_endpoint = os.environ.get("KDIVE_GDBSTUB_ENDPOINT", "127.0.0.1:1234")

    assert source.is_dir(), f"KDIVE_SOURCE must be a Linux source directory: {source}"
    assert vmlinux.is_file(), f"unstripped vmlinux is required at {vmlinux}"
    assert env["KDIVE_DOMAIN"].startswith(_MANAGED_DOMAIN_PREFIX), (
        f"KDIVE_DOMAIN must start with {_MANAGED_DOMAIN_PREFIX!r}: {env['KDIVE_DOMAIN']}"
    )

    from kdive import server
    from kdive.config import RootfsProfile, TargetProfile
    from kdive.providers.gdb_mi import CANONICAL_PROBE_SYMBOL, GdbMiEngine, MiRecord
    from kdive.seams.target import TargetKey
    from kdive.server import (
        _build_transport_machinery,
        create_run_handler,
        debug_start_session_handler,
        kernel_build_handler,
        target_boot_handler,
    )

    monkeypatch.setitem(
        server.DEFAULT_TARGET_PROFILES,
        "live-qemu-debug",
        TargetProfile(
            name="live-qemu-debug",
            architecture="x86_64",
            target_ref=env["KDIVE_DOMAIN"],
            managed_domain=True,
            managed_domain_prefix=_MANAGED_DOMAIN_PREFIX,
            libvirt_uri=env["KDIVE_LIBVIRT_URI"],
            timeout_seconds=300,
            debug_gdbstub=True,
            gdbstub_endpoint=gdbstub_endpoint,
        ),
    )
    monkeypatch.setitem(
        server.DEFAULT_ROOTFS_PROFILES,
        "live-rootfs",
        RootfsProfile(
            name="live-rootfs",
            source=str(rootfs_path),
            source_type="disk_image",
            mutability="read_only",
            readiness_marker=env["KDIVE_READINESS_MARKER"],
        ),
    )

    machinery = _build_transport_machinery(session_registry=None, transport_registry=None)
    artifact_root = tmp_path / "runs"

    create_resp = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        debug_profile="qemu-gdbstub-default",
    )
    assert create_resp.ok is True, create_resp.model_dump(mode="json")
    run_id = create_resp.data["run_id"]

    assert (
        kernel_build_handler(
            artifact_root=artifact_root, run_id=run_id, build_profile="x86_64-default", force_rebuild=False
        ).ok
        is True
    )

    assert (
        target_boot_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            target_profile="live-qemu-debug",
            rootfs_profile="live-rootfs",
            force_reboot=True,
            admission=machinery.admission,
        ).ok
        is True
    )

    # debug.start_session opens the guard-protected transport session (and, with the engine wired,
    # runs the probe itself). We then drive a fresh engine against the durable rsp_endpoint to assert
    # the foundation contract directly.
    debug_resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_profile="qemu-gdbstub-default",
        new_session=True,
        transaction=machinery.transaction,
        admission=machinery.admission,
        session_registry=machinery.session_registry,
        gdb_mi_engine=GdbMiEngine(),
    )
    assert debug_resp.ok is True, debug_resp.model_dump(mode="json")
    # AC#1: the wired probe surfaced a typed ^connected MI record.
    assert debug_resp.data["mi_probe"]["record"]["message"] == "connected"
    # AC2: the wired probe resolved the canonical symbol by name against the loaded vmlinux symbols.
    assert debug_resp.data["mi_probe"]["symbol"]["name"] == CANONICAL_PROBE_SYMBOL
    assert debug_resp.data["mi_probe"]["symbol"]["value"]  # a non-empty gdb-rendered address string

    record = machinery.session_registry.read_record(TargetKey(provisioner="local-qemu", target_id=run_id))
    assert record is not None and record.rsp_endpoint is not None

    # Drive a fresh engine directly against the durable rsp_endpoint: attach, read one record, resume.
    engine = GdbMiEngine()
    attachment = engine.attach(
        rsp_endpoint=record.rsp_endpoint, vmlinux_path=vmlinux, transcript_path=tmp_path / "mi-direct.log"
    )
    mi_record = engine.probe_read(attachment)
    assert isinstance(mi_record, MiRecord) and mi_record.message == "connected"

    resolved = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert resolved.name == CANONICAL_PROBE_SYMBOL and resolved.value, "linux_banner must resolve by name"

    # Anti-hang regression guard (the live counterpart to the unit-test ordering proxy): the async
    # continue must NOT block on a free-running kernel, so resume must return promptly. A sync
    # `-exec-continue` regression would blow past this bound (~10s/command).
    started = time.monotonic()
    assert engine.resume_and_detach(attachment) is True
    assert time.monotonic() - started < 5.0, "resume must not block on a free-running kernel"
