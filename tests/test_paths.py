from pathlib import Path

import pytest

from kdive.safety.paths import (
    PathSafetyError,
    validate_artifact_root,
    validate_guest_path,
    validate_rootfs_source,
    validate_run_id,
    validate_secret_file_reference,
    validate_source_path,
)
from kdive.safety.secrets import SecretReference, SecretReferenceKind


def test_artifact_root_allows_creatable_child_of_existing_parent(tmp_path: Path) -> None:
    root = validate_artifact_root(tmp_path / "runs", source_paths=[], sensitive_paths=[])

    assert root == (tmp_path / "runs").resolve()


def test_artifact_root_rejects_filesystem_root() -> None:
    with pytest.raises(PathSafetyError, match="artifact root is too broad"):
        validate_artifact_root(Path("/"), source_paths=[], sensitive_paths=[])


def test_artifact_root_rejects_source_checkout(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()

    with pytest.raises(PathSafetyError, match="artifact root overlaps source path"):
        validate_artifact_root(source, source_paths=[source], sensitive_paths=[])


def test_artifact_root_rejects_parent_of_source_checkout(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()

    with pytest.raises(PathSafetyError, match="artifact root overlaps source path"):
        validate_artifact_root(tmp_path, source_paths=[source], sensitive_paths=[])


def test_run_id_rejects_path_traversal_and_leading_dot() -> None:
    for value in ["../x", ".hidden", "run/123", "run;rm", "run-x\n", "run-x\r"]:
        with pytest.raises(PathSafetyError):
            validate_run_id(value)


def test_run_id_accepts_simple_identifier() -> None:
    assert validate_run_id("run-20260522-abc123") == "run-20260522-abc123"


def test_source_path_must_look_like_linux_tree(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()

    with pytest.raises(PathSafetyError, match="missing Linux tree marker"):
        validate_source_path(source)

    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    assert validate_source_path(source) == source.resolve()


def test_guest_path_requires_absolute_safe_posix_path() -> None:
    assert validate_guest_path("/tmp/linux-debug") == "/tmp/linux-debug"

    for value in ["tmp", "/tmp/../etc", "/tmp//x", "/tmp/has;semi"]:
        with pytest.raises(PathSafetyError):
            validate_guest_path(value)


def test_validate_rootfs_source_accepts_regular_file(tmp_path: Path) -> None:
    image = tmp_path / "rootfs.qcow2"
    image.write_bytes(b"x")
    resolved = validate_rootfs_source(image, source_paths=[], sensitive_paths=[])
    assert resolved == image.resolve()


def test_validate_rootfs_source_rejects_missing(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(tmp_path / "missing.qcow2", source_paths=[], sensitive_paths=[])


def test_validate_rootfs_source_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(tmp_path, source_paths=[], sensitive_paths=[])


def test_validate_rootfs_source_rejects_source_overlap(tmp_path: Path) -> None:
    src = tmp_path / "linux"
    src.mkdir()
    image = src / "rootfs.qcow2"
    image.write_bytes(b"x")
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(image, source_paths=[src], sensitive_paths=[])


def test_validate_rootfs_source_rejects_shell_metacharacters(tmp_path: Path) -> None:
    image = tmp_path / "rootfs.qcow2"
    image.write_bytes(b"x")
    with pytest.raises(PathSafetyError):
        validate_rootfs_source(Path(f"{image};rm"), source_paths=[], sensitive_paths=[])


def test_secret_file_reference_validates_shape_and_optional_existence(tmp_path: Path) -> None:
    secret_file = tmp_path / "id_ed25519"
    secret_file.write_text("fake-key", encoding="utf-8")
    ref = SecretReference(kind=SecretReferenceKind.FILE, label="ssh-key", reference=str(secret_file))

    assert validate_secret_file_reference(ref, must_exist=True) == secret_file.resolve()

    unsafe = SecretReference(kind=SecretReferenceKind.FILE, label="ssh-key", reference="../id_ed25519")
    with pytest.raises(PathSafetyError, match="secret file reference must be absolute"):
        validate_secret_file_reference(unsafe)
