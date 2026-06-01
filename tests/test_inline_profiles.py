from dataclasses import dataclass
from pathlib import Path

from conftest import make_source_tree
from handler_call_helpers import target_boot_handler

from kdive.artifacts.handlers import create_run_handler
from kdive.artifacts.store import ArtifactStore
from kdive.config import TARGET_DESTRUCTIVE_PERMISSIONS, RootfsProfile, TargetProfile
from kdive.domain import ArtifactRef, StepResult, StepStatus
from kdive.providers.local.target.libvirt_qemu import BootExecutionResult


def build_spec() -> dict[str, object]:
    return {"name": "inline-build", "architecture": "x86_64"}


def target_spec() -> dict[str, object]:
    return {
        "name": "inline-target",
        "architecture": "x86_64",
        "target_ref": "inline-vm",
        "managed_domain": True,
        "libvirt_uri": "qemu:///system",
    }


def rootfs_spec(source: str) -> dict[str, object]:
    return {"name": "inline-rootfs", "source": source, "ssh_host": "127.0.0.1", "ssh_user": "root"}


def make_rootfs_file(tmp_path: Path, name: str = "inline.qcow2") -> Path:
    """Create a real rootfs image file outside the source tree (passes path-safety guards)."""
    rootfs = tmp_path / "images" / name
    rootfs.parent.mkdir(parents=True, exist_ok=True)
    rootfs.write_text("disk image", encoding="utf-8")
    return rootfs


def load(artifact_root: Path, run_id: str):
    return ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)


def test_create_run_with_inline_build_freezes_profile_and_records_name(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"

    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile_spec=build_spec(),
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-inline-build",
    )

    assert response.ok is True
    manifest = load(artifact_root, "run-inline-build")
    assert manifest.resolved_build_profile is not None
    assert manifest.resolved_build_profile.name == "inline-build"
    assert manifest.request.build_profile == "inline-build"
    # Named target/rootfs are not frozen — resolved by name at boot.
    assert manifest.resolved_target_profile is None
    assert manifest.resolved_rootfs_profile is None


def test_create_run_with_inline_target_and_rootfs_freezes_them(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    rootfs = make_rootfs_file(tmp_path)

    response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile_spec=target_spec(),
        rootfs_profile_spec=rootfs_spec(str(rootfs)),
        run_id="run-inline-tr",
    )

    assert response.ok is True
    manifest = load(artifact_root, "run-inline-tr")
    assert manifest.resolved_target_profile is not None
    assert manifest.resolved_target_profile.target_ref == "inline-vm"
    assert manifest.resolved_rootfs_profile is not None
    assert manifest.resolved_rootfs_profile.source == str(rootfs.resolve())
    assert manifest.request.target_profile == "inline-target"
    assert manifest.request.rootfs_profile == "inline-rootfs"


def test_create_run_inline_rootfs_source_overlapping_sensitive_path_is_rejected(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    sensitive_dir = tmp_path / "secrets"
    sensitive_dir.mkdir()
    rootfs = sensitive_dir / "secret-rootfs.qcow2"
    rootfs.write_text("disk image", encoding="utf-8")

    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile_spec=rootfs_spec(str(rootfs)),
        sensitive_paths=[sensitive_dir],
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "sensitive" in response.error.message


def test_create_run_inline_rootfs_source_with_shell_metachar_is_rejected(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile_spec=rootfs_spec(f"{tmp_path}/img.qcow2;rm -rf /"),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_create_run_rejects_both_name_and_spec(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        build_profile_spec=build_spec(),
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "not both" in response.error.message


def test_create_run_rejects_neither_name_nor_spec(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "build_profile" in response.error.message


def test_create_run_rejects_invalid_inline_spec(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile_spec={"name": "bad"},  # missing required 'architecture'
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "invalid build_profile_spec" in response.error.message


def test_create_run_rejects_unknown_named_profile(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="nope",
        rootfs_profile="minimal",
    )
    assert response.ok is False
    assert response.error is not None
    assert "unknown profile: nope" in response.error.message


@dataclass
class _Plan:
    run_id: str
    domain_name: str
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    debug_gdbstub: bool = False
    gdbstub_endpoint: dict[str, object] | None = None
    nokaslr_source: str = "not_applicable"


class RecordingBootProvider:
    name = "local-libvirt-qemu"

    def __init__(self) -> None:
        self.planned_target: TargetProfile | None = None
        self.planned_rootfs: RootfsProfile | None = None

    def plan_boot(self, *, run_id, run_dir, kernel_image_path, target_profile, rootfs_profile, attempt=1) -> _Plan:
        self.planned_target = target_profile
        self.planned_rootfs = rootfs_profile
        return _Plan(
            run_id=run_id,
            domain_name=target_profile.target_ref or target_profile.name,
            boot_log_path=run_dir / "boot" / f"attempt-{attempt}" / "boot.log",
            boot_plan_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-plan.json",
            boot_summary_path=run_dir / "boot" / f"attempt-{attempt}" / "boot-summary.json",
        )

    def execute_boot(self, plan: _Plan, *, force_reboot=False, retrying_after_failure=False) -> BootExecutionResult:
        for path in (plan.boot_log_path, plan.boot_plan_path, plan.boot_summary_path):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        return BootExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="target booted",
            details={"domain": plan.domain_name},
            artifacts=[ArtifactRef(path=str(plan.boot_log_path), kind="boot-log")],
        )


def _record_build(artifact_root: Path, run_id: str) -> None:
    build_dir = artifact_root / run_id / "build"
    kernel = build_dir / "arch" / "x86" / "boot" / "bzImage"
    kernel.parent.mkdir(parents=True, exist_ok=True)
    kernel.write_text("kernel\n", encoding="utf-8")
    ArtifactStore(artifact_root, create_root=False).record_step_result(
        run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="build ok",
            artifacts=[ArtifactRef(path=str(kernel), kind="kernel-image")],
            details={"architecture": "x86_64", "output_path": str(build_dir)},
        ),
    )


def test_boot_uses_inline_frozen_target_and_rootfs(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    run_id = "run-inline-boot"
    rootfs = make_rootfs_file(tmp_path)
    create_response = create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile_spec=target_spec(),
        rootfs_profile_spec=rootfs_spec(str(rootfs)),
        run_id=run_id,
    )
    assert create_response.ok is True
    _record_build(artifact_root, run_id)
    provider = RecordingBootProvider()

    response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        acknowledged_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"],
    )

    assert response.ok is True
    assert provider.planned_target is not None
    assert provider.planned_target.target_ref == "inline-vm"
    assert provider.planned_rootfs is not None
    assert provider.planned_rootfs.source == str(rootfs.resolve())
