"""Env-gated unprivileged-build integration tests (two tiers).

Tier 1 (no KVM): build the image and assert the boot-contract precondition — single whole-disk
ext4 with no partition table, a normalized /etc/fstab (no non-"/" entries) with no /etc/crypttab,
file mode 0644, caller ownership, and no escalation in the script/argv. Gated on tools + the opt-in
env var; runs under TCG when /dev/kvm is absent.

Tier 2 (capable host): boot the built image to the kdive-ready serial marker. Gated additionally on
the libvirt boot env (adapts the qemu:///system harness shape from test_libvirt_boot_integration).
Tier 2 builds the base image into, and runs its copy-on-write overlay under, the operator's
pre-prepared virt_image_t-labeled directory (located via KDIVE_ROOTFS) so the separate qemu user can
read both the overlay and its read-only backing file under qemu:///system; it cleans both up afterward.

Neither tier runs in default CI (no network/tools/KVM). The always-on protection is the
check-no-sudo guard + the prereqs unit tests + the documented boot-contract precondition.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-rootfs.sh"
BUILD_TOOLS = ["virt-builder", "virt-tar-out", "virt-make-fs", "guestfish", "qemu-img", "virt-filesystems"]
ESCALATION = re.compile(r"(^|\s)(sudo|pkexec|doas)\s")


def require_build_tier() -> None:
    if os.environ.get("KDIVE_BUILD_TEST") != "1":
        pytest.skip("unprivileged-build integration test skipped; set KDIVE_BUILD_TEST=1 to run it.")
    missing = [tool for tool in BUILD_TOOLS if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"missing build tools: {', '.join(missing)} (install libguestfs-tools).")


def build_image(target: Path, *, key_dir: Path | None = None, ssh_user: str | None = None) -> None:
    key = (key_dir or target.parent) / "id_ed25519.pub"
    key.write_text("ssh-ed25519 AAAATESTKEYONLY test@kdive\n", encoding="utf-8")
    env = {
        **os.environ,
        "KDIVE_ROOTFS": str(target),
        "KDIVE_ROOTFS_RELEASEVER": os.environ.get("KDIVE_ROOTFS_RELEASEVER", "43"),
        "KDIVE_ROOTFS_AUTHORIZED_KEY": str(key),
    }
    if ssh_user is not None:
        env["KDIVE_ROOTFS_SSH_USER"] = ssh_user
    subprocess.run(["bash", str(BUILD_SCRIPT)], check=True, env=env, timeout=1800)


def guestfish_cat(image: Path, guest_path: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "-i", "cat", guest_path],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return completed.returncode, completed.stdout


def test_tier1_layout_and_permissions(tmp_path: Path) -> None:
    require_build_tier()
    image = tmp_path / "minimal.qcow2"
    build_image(image)

    # Owned by the caller; group/other-readable (0644) so qemu can read it under qemu:///system.
    stat = image.stat()
    assert stat.st_uid == os.getuid(), "image must be owned by the caller"
    assert stat.st_mode & 0o077 == 0o044, f"image must be 0644-readable, got {oct(stat.st_mode & 0o777)}"

    # No partition table: a whole-disk filesystem reports no partitions.
    partitions = subprocess.run(
        ["virt-filesystems", "--partitions", "-a", str(image)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    assert partitions.strip() == "", f"expected no partition table, got:\n{partitions}"

    # Exactly one whole-disk filesystem, and it is ext4 (parse "device: type" lines; do not
    # hard-code the device node).
    filesystems = subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "run", ":", "list-filesystems"],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    entries = [line.split(":", 1) for line in filesystems.splitlines() if ":" in line]
    assert len(entries) == 1, f"expected exactly one filesystem, got:\n{filesystems}"
    assert entries[0][1].strip() == "ext4", f"expected ext4, got:\n{filesystems}"

    # Normalized /etc/fstab: only the root entry; /etc/crypttab absent.
    code, fstab = guestfish_cat(image, "/etc/fstab")
    assert code == 0
    mount_entries = [
        line.split()[1]
        for line in fstab.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and len(line.split()) >= 2
    ]
    assert mount_entries == ["/"], f"fstab must contain only the root mount, got {mount_entries}:\n{fstab}"
    crypttab_code, _ = guestfish_cat(image, "/etc/crypttab")
    assert crypttab_code != 0, "/etc/crypttab must be absent in the repacked image"

    # No escalation in the script source.
    script_text = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert not ESCALATION.search(script_text), "build script must contain no sudo/pkexec/doas"


def test_tier1_nonroot_ssh_user_gets_key(tmp_path: Path) -> None:
    require_build_tier()
    image = tmp_path / "minimal.qcow2"
    build_image(image, ssh_user="kdivetest")

    # The key landing in /home/kdivetest/.ssh/authorized_keys proves the useradd --run-command ran
    # before --ssh-inject (command-line order, virt-builder(1)); otherwise --ssh-inject would have
    # failed against a not-yet-existent user.
    code, authorized_keys = guestfish_cat(image, "/home/kdivetest/.ssh/authorized_keys")
    assert code == 0, "expected an authorized_keys for the non-root user"
    assert "AAAATESTKEYONLY" in authorized_keys, f"injected key missing:\n{authorized_keys}"


def require_boot_tier() -> dict[str, str]:
    require_build_tier()
    needed = ["KDIVE_LIBVIRT_TEST", "KDIVE_SOURCE", "KDIVE_DOMAIN", "KDIVE_LIBVIRT_URI", "KDIVE_ROOTFS"]
    values = {name: os.environ[name] for name in needed if name in os.environ}
    missing = [name for name in needed if name not in values]
    if "KDIVE_LIBVIRT_TEST" in values and values["KDIVE_LIBVIRT_TEST"] != "1":
        missing.append("KDIVE_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            f"boot tier skipped; set {', '.join(missing)} (KVM-capable libvirt host). "
            "KDIVE_ROOTFS must point into a pre-prepared, virt_image_t-labeled, qemu-traversable "
            "directory (the §5 host-prep dir): Tier 2 builds and boots there under qemu:///system."
        )
    return values


def test_tier2_boot_reaches_readiness_marker(tmp_path: Path) -> None:
    env = require_boot_tier()
    # KDIVE_ROOTFS locates the operator's pre-prepared, virt_image_t-labeled, qemu-traversable dir.
    # Both the base image and the run tree (overlay) must live here so the separate qemu user can
    # read the overlay AND its read-only backing file under qemu:///system (libvirt relabels only the
    # writable overlay, not the backing file — local_libvirt_qemu.py:380-381,377-394).
    prepared_dir = Path(env["KDIVE_ROOTFS"]).expanduser().parent
    base_image = prepared_dir / "kdive-build-test.qcow2"
    artifact_root = prepared_dir / "kdive-build-test-runs"

    from handler_call_helpers import target_boot_handler

    from kdive.artifacts.handlers import create_run_handler
    from kdive.artifacts.store import ArtifactStore
    from kdive.config import RootfsProfile, TargetProfile
    from kdive.domain import ArtifactRef, StepResult, StepStatus

    source = Path(env["KDIVE_SOURCE"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    assert kernel_image.is_file(), f"build a bzImage at {kernel_image} before running Tier 2"

    run_id = "run-unprivileged-build-tier2"
    # The copy_on_write overlay lands under artifact_root (local_libvirt_qemu.py:377-394); its ancestor
    # dirs are created with umask-masked mkdir() (store.py:68-71), so under qemu:///system the
    # separate qemu user can only traverse them if they are 0755. Force a 0022 umask for the run
    # tree (and the build) so the chain is qemu-traversable regardless of the operator's login umask.
    previous_umask = os.umask(0o022)
    try:
        # A prior run killed before the finally below would wedge create_run with "run already
        # exists" because artifact_root persists in the prepared dir — pre-clean both artifacts.
        shutil.rmtree(artifact_root, ignore_errors=True)
        base_image.unlink(missing_ok=True)

        build_image(base_image, key_dir=tmp_path)  # built file inherits virt_image_t; builder chmods 0644

        create_response = create_run_handler(
            artifact_root=artifact_root,
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            run_id=run_id,
        )
        assert create_response.ok is True, create_response.model_dump(mode="json")

        # Boot reads the kernel image from a recorded build StepResult, not a boot arg — seed it.
        ArtifactStore(artifact_root, create_root=False).record_step_result(
            run_id,
            StepResult(
                step_name="build",
                status=StepStatus.SUCCEEDED,
                summary="seeded",
                artifacts=[ArtifactRef(path=str(kernel_image), kind="kernel-image")],
                details={"architecture": "x86_64", "output_path": str(kernel_image.parent)},
            ),
        )

        boot_response = target_boot_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            force_reboot=True,
            target_profiles={
                "local-qemu": TargetProfile(
                    name="local-qemu",
                    architecture="x86_64",
                    target_ref=env["KDIVE_DOMAIN"],
                    managed_domain=True,
                    managed_domain_prefix="kdive-",
                    libvirt_uri=env["KDIVE_LIBVIRT_URI"],
                    timeout_seconds=600,
                )
            },
            rootfs_profiles={
                "minimal": RootfsProfile(
                    name="minimal",
                    source=str(base_image),
                    source_type="disk_image",
                    source_kind="builder",
                    mutability="copy_on_write",
                    readiness_marker="kdive-ready",
                )
            },
        )

        assert boot_response.ok is True, boot_response.model_dump(mode="json")
        assert boot_response.data["matched_marker"] == "kdive-ready"
    finally:
        shutil.rmtree(artifact_root, ignore_errors=True)
        base_image.unlink(missing_ok=True)
        os.umask(previous_umask)
