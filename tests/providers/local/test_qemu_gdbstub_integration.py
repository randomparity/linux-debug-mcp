import os
from pathlib import Path

import pytest

from kdive import server
from kdive.config import RootfsProfile, TargetProfile
from kdive.debug.bound_handlers import debug_continue_handler, debug_read_symbol_handler, debug_set_breakpoint_handler
from kdive.debug.handlers import DebugRuntime
from kdive.debug.session_handlers import debug_start_session_handler
from kdive.providers.local.debug.gdb_mi import GdbMiEngine, GdbMiSessionRegistry
from kdive.server import _workflow_handler_dependencies, workflow_build_boot_debug_handler

MANAGED_DOMAIN_PREFIX = "kdive-"
REQUIRED_ENV = [
    "KDIVE_LIVE_GDBSTUB",
    "KDIVE_SOURCE",
    "KDIVE_ROOTFS",
    "KDIVE_DOMAIN",
    "KDIVE_LIBVIRT_URI",
    "KDIVE_READINESS_MARKER",
]


def require_live_gdbstub_env() -> dict[str, str]:
    values = {name: value for name in REQUIRED_ENV if (value := os.environ.get(name))}
    missing = [name for name in REQUIRED_ENV if name not in values]
    if "KDIVE_LIVE_GDBSTUB" in values and values["KDIVE_LIVE_GDBSTUB"] != "1":
        missing.append("KDIVE_LIVE_GDBSTUB=1")
    if missing:
        pytest.skip(
            "live gdbstub integration test skipped; set "
            f"{', '.join(missing)} to run it. Example: "
            "KDIVE_LIVE_GDBSTUB=1 "
            "KDIVE_SOURCE=/path/to/linux "
            "KDIVE_ROOTFS=/var/lib/kdive/rootfs/minimal.qcow2 "
            "KDIVE_DOMAIN=kdive-dev-debug "
            "KDIVE_LIBVIRT_URI=qemu:///system "
            "KDIVE_READINESS_MARKER=kdive-ready "
            "pytest tests/test_qemu_gdbstub_integration.py -q"
        )
    return values


def test_live_build_boot_debug_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = require_live_gdbstub_env()
    source = Path(env["KDIVE_SOURCE"]).expanduser()
    rootfs = Path(env["KDIVE_ROOTFS"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    vmlinux = source / "vmlinux"
    gdbstub_endpoint = os.environ.get("KDIVE_GDBSTUB_ENDPOINT", "127.0.0.1:1234")

    assert source.is_dir(), f"KDIVE_SOURCE must be a Linux source directory: {source}"
    assert rootfs.is_file(), f"KDIVE_ROOTFS must be a disk image file: {rootfs}"
    assert kernel_image.is_file(), f"built kernel image is required at {kernel_image}"
    assert vmlinux.is_file(), f"unstripped vmlinux is required at {vmlinux}"
    assert env["KDIVE_DOMAIN"].startswith(MANAGED_DOMAIN_PREFIX), (
        "KDIVE_DOMAIN must be a dedicated managed domain starting with "
        f"{MANAGED_DOMAIN_PREFIX!r}: {env['KDIVE_DOMAIN']}"
    )

    monkeypatch.setitem(
        server.DEFAULT_TARGET_PROFILES,
        "live-qemu-debug",
        TargetProfile(
            name="live-qemu-debug",
            architecture="x86_64",
            target_ref=env["KDIVE_DOMAIN"],
            managed_domain=True,
            managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
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
            source=str(rootfs),
            source_type="disk_image",
            mutability="read_only",
            readiness_marker=env["KDIVE_READINESS_MARKER"],
        ),
    )

    # The live debug attach drives the persistent gdb/MI engine over the guard-protected transport,
    # exactly as create_app wires it: build the Layer-4 machinery and a real engine + live-session
    # registry and thread them through the workflow.
    machinery = server._build_transport_machinery(session_registry=None, transport_registry=None)
    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        debug_profile="qemu-gdbstub-default",
        force_rebuild=True,
        force_reboot=True,
        new_session=True,
        admission=machinery.admission,
        session_registry=machinery.session_registry,
        transaction=machinery.transaction,
        session_guard=machinery.session_guard,
        gdb_mi_engine=GdbMiEngine(),
        gdb_mi_sessions=GdbMiSessionRegistry(),
        dependencies=_workflow_handler_dependencies(),
    )

    assert response.ok is True, response.model_dump(mode="json")
    assert response.data["steps"]["build"]["ok"] is True
    assert response.data["steps"]["boot"]["ok"] is True
    assert response.data["steps"]["debug"]["ok"] is True


def test_live_frozen_boot_hits_early_breakpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptance for #104: wait_for_debugger freezes the boot at the reset vector so a
    breakpoint set before the debugger releases the CPU is hit deterministically in early init.

    Gated behind the same live-gdbstub env guard as test_live_build_boot_debug_workflow; skipped
    in CI. Requires a real QEMU+KVM guest, a built kernel, and a managed debug domain.
    """
    from kdive.artifacts.handlers import create_run_handler
    from kdive.config import BootOverrides
    from kdive.kernel.handlers import kernel_build_handler
    from kdive.target.handlers import target_boot_handler

    env = require_live_gdbstub_env()
    source = Path(env["KDIVE_SOURCE"]).expanduser()
    rootfs = Path(env["KDIVE_ROOTFS"]).expanduser()
    vmlinux = source / "vmlinux"
    gdbstub_endpoint = os.environ.get("KDIVE_GDBSTUB_ENDPOINT", "127.0.0.1:1234")
    early_symbol = os.environ.get("KDIVE_EARLY_SYMBOL", "start_kernel")

    assert source.is_dir(), f"KDIVE_SOURCE must be a Linux source directory: {source}"
    assert rootfs.is_file(), f"KDIVE_ROOTFS must be a disk image file: {rootfs}"
    assert vmlinux.is_file(), f"unstripped vmlinux is required at {vmlinux}"
    assert env["KDIVE_DOMAIN"].startswith(MANAGED_DOMAIN_PREFIX)

    monkeypatch.setitem(
        server.DEFAULT_TARGET_PROFILES,
        "live-qemu-debug",
        TargetProfile(
            name="live-qemu-debug",
            architecture="x86_64",
            target_ref=env["KDIVE_DOMAIN"],
            managed_domain=True,
            managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
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
            source=str(rootfs),
            source_type="disk_image",
            mutability="read_only",
            readiness_marker=env["KDIVE_READINESS_MARKER"],
        ),
    )

    artifact_root = tmp_path / "runs"
    machinery = server._build_transport_machinery(session_registry=None, transport_registry=None)
    engine = GdbMiEngine()
    sessions = GdbMiSessionRegistry()

    # Freeze the boot via a create-time boot override (becomes the manifest request override).
    created = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="live-qemu-debug",
        rootfs_profile="live-rootfs",
        debug_profile="qemu-gdbstub-default",
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )
    assert created.ok is True, created.model_dump(mode="json")
    run_id = created.data["run_id"]

    built = kernel_build_handler(artifact_root=artifact_root, run_id=run_id, force_rebuild=True)
    assert built.ok is True, built.model_dump(mode="json")

    boot_resp = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_reboot=True,
        admission=machinery.admission,
    )
    assert boot_resp.ok is True, boot_resp.model_dump(mode="json")
    # The frozen boot returns SUCCEEDED without a readiness wait and steers to the debugger.
    assert boot_resp.data["console_status"] == "frozen"
    assert boot_resp.data["wait_for_debugger"] is True
    assert boot_resp.suggested_next_actions == ["debug.start_session"]

    session_resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        new_session=True,
        admission=machinery.admission,
        session_registry=machinery.session_registry,
        transaction=machinery.transaction,
        session_guard=machinery.session_guard,
        gdb_mi_engine=engine,
        gdb_mi_sessions=sessions,
    )
    assert session_resp.ok is True, session_resp.model_dump(mode="json")
    session_id = session_resp.data["debug_session_id"]

    debug_kwargs = {
        "artifact_root": artifact_root,
        "run_id": run_id,
        "debug_session_id": session_id,
        "runtime": DebugRuntime(
            admission=machinery.admission,
            transaction=machinery.transaction,
            session_registry=machinery.session_registry,
            session_guard=machinery.session_guard,
            gdb_mi_engine=engine,
            gdb_mi_sessions=sessions,
        ),
    }

    bp_resp = debug_set_breakpoint_handler(symbol=early_symbol, **debug_kwargs)
    assert bp_resp.ok is True, bp_resp.model_dump(mode="json")

    cont_resp = debug_continue_handler(**debug_kwargs)
    assert cont_resp.ok is True, cont_resp.model_dump(mode="json")

    # The CPU ran from the reset vector into the early-init breakpoint; the symbol is inspectable.
    read_resp = debug_read_symbol_handler(symbol=early_symbol, **debug_kwargs)
    assert read_resp.ok is True, read_resp.model_dump(mode="json")
