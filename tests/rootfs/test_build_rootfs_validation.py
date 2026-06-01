"""Non-gated unit tests for the input-validation guards in scripts/build-rootfs.sh (ADR 0038).

These exercise the early fail-fast guards (KDIVE_ROOTFS_SSH_USER allowlist and KDIVE_ROOTFS
symlink refusal), which run before any libguestfs tool is required — so they are deterministic
in default CI without virt-builder/guestfish installed. Each asserts the script exits non-zero
with the expected message; the positive control asserts a valid input is NOT rejected by a guard.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / "scripts").is_dir())
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-rootfs.sh"


def _run(env_overrides: dict[str, str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(BUILD_SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", "HOME": str(cwd), **env_overrides},
    )


@pytest.mark.parametrize(
    "bad_user",
    [
        "evil$(touch /tmp/pwned)",  # command substitution
        "a;b",  # statement separator
        "root extra",  # whitespace
        "root:extra",  # colon would misparse --ssh-inject "user:file:key"
        "Root",  # uppercase start (outside useradd NAME_REGEX)
        "-leading",  # leading dash
        "u" * 33,  # over the 32-char cap
    ],
)
def test_rejects_invalid_ssh_user(bad_user: str, tmp_path: Path) -> None:
    result = _run(
        {"KDIVE_ROOTFS_SSH_USER": bad_user, "KDIVE_ROOTFS": str(tmp_path / "img.qcow2")},
        cwd=tmp_path,
    )
    assert result.returncode == 1, result.stderr
    assert "is not a valid username" in result.stderr


def test_rejects_symlink_output_path(tmp_path: Path) -> None:
    link = tmp_path / "link.qcow2"
    link.symlink_to("/etc/passwd")
    result = _run({"KDIVE_ROOTFS": str(link)}, cwd=tmp_path)
    assert result.returncode == 1, result.stderr
    assert "is a symlink" in result.stderr


def test_valid_inputs_pass_the_guards(tmp_path: Path) -> None:
    # A valid username and a regular-file output path must not be rejected by either guard. We force
    # an early NON-validation failure (a non-existent authorized key) so the script stops before any
    # real build regardless of whether libguestfs is installed.
    result = _run(
        {
            "KDIVE_ROOTFS_SSH_USER": "kdivetest",
            "KDIVE_ROOTFS": str(tmp_path / "img.qcow2"),
            "KDIVE_ROOTFS_AUTHORIZED_KEY": str(tmp_path / "does-not-exist.pub"),
        },
        cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "is not a valid username" not in result.stderr
    assert "is a symlink" not in result.stderr
