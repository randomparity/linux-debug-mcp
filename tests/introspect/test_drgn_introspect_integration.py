"""Integration tests for debug.introspect.run. Spec §9.3.

Gated on:
  - ``drgn`` installed target-side (the rootfs must include it)
  - ``qemu-system-x86_64`` on the host
  - ``virsh`` on the host
  - ``KDIVE_LIBVIRT_TEST=1`` environment variable

The bootstrap (kernel.create_run → kernel.build → target.boot) is reused
from ``tests/test_libvirt_boot_integration.py``. Tests opt-in via the
same env-gate as the boot integration test.
"""

import os
import shutil
from pathlib import Path
from typing import NamedTuple

import pytest
from handler_call_helpers import target_boot_handler

from kdive.artifacts.handlers import create_run_handler
from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile, TargetProfile
from kdive.coordination.admission import AdmissionService, SnapshotStore
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from kdive.introspect.handlers import debug_introspect_run_handler
from kdive.introspect.models import DebugIntrospectRunRequest
from kdive.providers.local.test.local_ssh_tests import SubprocessSshRunner, build_ssh_argv

MANAGED_DOMAIN_PREFIX = "kdive-"


def _require_integration_env() -> None:
    missing = []
    if shutil.which("drgn") is None:
        missing.append("drgn (target-side; rootfs must include it)")
    if shutil.which("qemu-system-x86_64") is None:
        missing.append("qemu-system-x86_64")
    if shutil.which("virsh") is None:
        missing.append("virsh")
    if os.environ.get("KDIVE_LIBVIRT_TEST") != "1":
        missing.append("KDIVE_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            "drgn introspect integration test skipped; set "
            f"{', '.join(missing)} to run it. Example: "
            "KDIVE_LIBVIRT_TEST=1 "
            "KDIVE_ROOTFS=/var/lib/kdive/rootfs/minimal.qcow2 "
            "KDIVE_SOURCE=/path/to/linux "
            "KDIVE_DOMAIN=kdive-dev "
            "KDIVE_LIBVIRT_URI=qemu:///system "
            "KDIVE_READINESS_MARKER=kdive-ready "
            "pytest tests/test_drgn_introspect_integration.py -q"
        )


class BootstrapResult(NamedTuple):
    """Full context returned by _bootstrap_booted_run.

    Fields:
        run_id: the run identifier created by create_run_handler.
        store: ArtifactStore bound to the run's artifact_root.
        admission: AdmissionService populated with the boot's READY snapshot.
        session_registry: SessionRegistry for this run.
        target_profiles: dict passed to boot/introspect handlers.
        rootfs_profiles: dict passed to boot/introspect handlers.
        rootfs_profile: resolved RootfsProfile for use with _guest_ssh.
    """

    run_id: str
    store: ArtifactStore
    admission: AdmissionService
    session_registry: SessionRegistry
    target_profiles: dict[str, TargetProfile]
    rootfs_profiles: dict[str, RootfsProfile]
    rootfs_profile: RootfsProfile


def _bootstrap_booted_run(tmp_path: Path) -> BootstrapResult:
    """Run the kernel.create_run → kernel.build → target.boot bootstrap.

    Mirrors the canonical sequence from ``tests/test_libvirt_boot_integration.py``.
    Constructs and returns an ``AdmissionService`` (seeded via the boot step) and
    ``SessionRegistry`` for use with introspect handlers.

    The ``AdmissionService`` uses an in-process ``SnapshotStore``; the boot handler
    publishes the READY snapshot when boot succeeds, which is exactly what the
    introspect execution path reads at the admission gate.

    The ``SessionRegistry`` is created with a scratch directory under ``tmp_path``
    (no instance lock acquired — single-process integration tests do not need it).

    NOTE: this function skips if the required env vars are absent; callers that
    invoke ``_require_integration_env()`` first will skip there, but the fallback
    skip here is a safety net.
    """
    env_source = os.environ.get("KDIVE_SOURCE")
    env_rootfs = os.environ.get("KDIVE_ROOTFS")
    env_domain = os.environ.get("KDIVE_DOMAIN")
    env_libvirt_uri = os.environ.get("KDIVE_LIBVIRT_URI")
    env_readiness = os.environ.get("KDIVE_READINESS_MARKER")
    if not all([env_source, env_rootfs, env_domain, env_libvirt_uri, env_readiness]):
        pytest.skip(
            "bootstrap helper skipped: KDIVE_SOURCE, KDIVE_ROOTFS, "
            "KDIVE_DOMAIN, KDIVE_LIBVIRT_URI, "
            "KDIVE_READINESS_MARKER are all required."
        )

    source = Path(env_source).expanduser()  # type: ignore[arg-type]
    rootfs_path = Path(env_rootfs).expanduser()  # type: ignore[arg-type]
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    artifact_root = tmp_path / "runs"
    run_id = "run-introspect-integration"

    assert source.is_dir(), f"KDIVE_SOURCE must be a Linux source directory: {source}"
    assert rootfs_path.is_file(), f"KDIVE_ROOTFS must be a disk image file: {rootfs_path}"
    assert env_domain.startswith(MANAGED_DOMAIN_PREFIX), (  # type: ignore[union-attr]
        f"KDIVE_DOMAIN must start with {MANAGED_DOMAIN_PREFIX!r}: {env_domain}"
    )
    assert kernel_image.is_file(), (
        f"KDIVE_SOURCE must contain a built x86_64 kernel image at {kernel_image}; "
        "build bzImage before running this integration test"
    )

    create_response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="pilot-libvirt",
        rootfs_profile="pilot-rootfs",
        run_id=run_id,
    )
    assert create_response.ok is True, create_response.model_dump(mode="json")

    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="seeded integration build result",
            artifacts=[ArtifactRef(path=str(kernel_image), kind="kernel-image")],
            details={"architecture": "x86_64", "output_path": str(kernel_image.parent)},
        ),
    )

    pilot_target = TargetProfile(
        name="pilot-libvirt",
        architecture="x86_64",
        manifest_target_profile=env_domain,
        managed_domain=True,
        managed_domain_prefix=MANAGED_DOMAIN_PREFIX,
        libvirt_uri=env_libvirt_uri,
        timeout_seconds=300,
    )
    pilot_rootfs = RootfsProfile(
        name="pilot-rootfs",
        source=str(rootfs_path),
        source_type="disk_image",
        mutability="read_only",
        readiness_marker=env_readiness,
    )
    target_profiles = {"pilot-libvirt": pilot_target}
    rootfs_profiles = {"pilot-rootfs": pilot_rootfs}

    # Build the in-process admission service and session registry.  The
    # target_boot_handler publishes the READY snapshot to ``admission`` when the
    # boot step succeeds, which is exactly what the introspect execution path
    # reads at the admission gate.
    admission = AdmissionService(SnapshotStore())
    reg_dir = tmp_path / "registry"
    reg_dir.mkdir(parents=True, exist_ok=True)
    session_registry = SessionRegistry(directory=reg_dir)

    boot_response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        force_reboot=True,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        admission=admission,
    )
    assert boot_response.ok is True, boot_response.model_dump(mode="json")

    return BootstrapResult(
        run_id=run_id,
        store=store,
        admission=admission,
        session_registry=session_registry,
        target_profiles=target_profiles,
        rootfs_profiles=rootfs_profiles,
        rootfs_profile=pilot_rootfs,
    )


def _guest_ssh(
    run_id: str,
    store: ArtifactStore,
    rootfs_profile: RootfsProfile,
    command: list[str],
    timeout: int = 10,
) -> str:
    """Execute ``command`` on the guest via SSH and return stdout.

    Uses the known_hosts file written by target.boot under
    ``<run>/sensitive/known_hosts``.

    Reads stdout from the on-disk ``stdout_path`` rather than
    ``SshCommandResult.stdout``: the runner writes full output to the file and
    only populates ``.stdout_snippet`` (capped at 4096 bytes), so heartbeat
    output that exceeds the cap would be lost via the result object.  The
    subprocess timeout is set above ``command_timeout`` so a command running
    for ~``timeout`` seconds is not killed before returning.
    """
    argv = build_ssh_argv(
        rootfs_profile=rootfs_profile,
        known_hosts_path=store.run_dir(run_id) / "sensitive" / "known_hosts",
        command=command,
        command_timeout=timeout,
    )
    out = store.run_dir(run_id) / "logs" / "guest_ssh.stdout"
    err = store.run_dir(run_id) / "logs" / "guest_ssh.stderr"
    SubprocessSshRunner().run(argv, timeout=timeout + 5, stdout_path=out, stderr_path=err)
    return out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""


def test_introspect_emit_roundtrip(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        manifest_target_profile="pilot-libvirt",
        script='emit({"pid": 1})',
        timeout_seconds=30,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert response.ok is True, response.error
    assert response.data["status"] == "ok"
    assert response.data["emits"] == [{"pid": 1}]


def test_introspect_target_side_timeout(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        manifest_target_profile="pilot-libvirt",
        script="while True:\n    pass\n",
        timeout_seconds=5,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.INFRASTRUCTURE_FAILURE
    assert response.error.details["code"] == "introspect_timeout"


def test_introspect_build_id_round_trips(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        manifest_target_profile="pilot-libvirt",
        script="emit({})",
        timeout_seconds=30,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert response.ok is True, response.error
    manifest = ctx.store.load_manifest(ctx.run_id)
    recorded = manifest.step_results["build"].details["build_id"]
    assert response.data["build_id"] == recorded


# ---------------------------------------------------------------------------
# #56 write-mode round trips (env-gated)
# ---------------------------------------------------------------------------

_WRITE_PERM = "mutate live kernel state via drgn write APIs"


def test_introspect_allow_write_false_blocks_prog_write(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        manifest_target_profile="pilot-libvirt",
        script='prog.write(0, b"\\x00")',
        timeout_seconds=30,
        allow_write=False,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "write_mode_disabled"


def test_introspect_allow_write_true_reaches_drgn(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        manifest_target_profile="pilot-libvirt",
        script='prog.write(0, b"\\x00"); emit({"reached": True})',
        timeout_seconds=30,
        allow_write=True,
        acknowledged_permissions=[_WRITE_PERM],
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    # Under write mode the guard is absent, so prog.write reaches drgn, which
    # fails on today's read-only live target (no writable target exists yet).
    # The contract asserted here: the call is NOT rejected as write_mode_disabled,
    # proving the guard is not installed under write mode. A drgn-level write
    # failure surfaces as a script error outcome (ok=True, status="script_error").
    if response.ok:
        assert response.data["status"] in {"ok", "script_error"}
    else:
        assert response.error.details.get("code") != "write_mode_disabled"
