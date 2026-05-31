from __future__ import annotations

from kdive.domain import ArtifactRef, StepResult, StepStatus
from kdive.target.handlers import _capture_kernel_provenance

FULL = "a" * 40


def _build_step(tmp_path, *, with_vmlinux=True, build_id=FULL, release="6.9.0-test"):
    out = tmp_path / "build"
    out.mkdir(parents=True, exist_ok=True)
    (out / ".config").write_text("CONFIG_X=y", encoding="utf-8")
    artifacts = [ArtifactRef(path=str(out / ".config"), kind="kernel-config")]
    if with_vmlinux:
        (out / "vmlinux").write_text("elf", encoding="utf-8")
        artifacts.append(ArtifactRef(path=str(out / "vmlinux"), kind="vmlinux"))
    details = {}
    if build_id is not None:
        details["build_id"] = build_id
    if release is not None:
        details["kernel_release"] = release
    return StepResult(
        step_name="build",
        status=StepStatus.SUCCEEDED,
        summary="ok",
        details=details,
        artifacts=artifacts,
    )


def test_successful_capture_has_run_relative_refs_and_cmdline(tmp_path):
    build = _build_step(tmp_path)
    boot_details = {"kernel_args": ["root=/dev/vda", "console=ttyS0", "nokaslr"]}
    result = _capture_kernel_provenance(build_step=build, boot_details=boot_details, run_dir=tmp_path)
    prov = result["kernel_provenance"]
    assert prov["build_id"] == FULL
    assert prov["release"] == "6.9.0-test"
    assert prov["vmlinux_ref"] == "build/vmlinux"
    assert prov["config_ref"] == "build/.config"
    assert prov["cmdline"] == "root=/dev/vda console=ttyS0 nokaslr"
    assert prov["modules_ref"] is None
    assert "kernel_provenance_capture_error" not in result


def test_missing_vmlinux_records_conventional_ref_plus_note(tmp_path):
    build = _build_step(tmp_path, with_vmlinux=False)
    result = _capture_kernel_provenance(build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path)
    assert result["kernel_provenance"]["vmlinux_ref"] == "build/vmlinux"
    assert "vmlinux_artifact_missing" in result["kernel_provenance_capture_notes"]


def test_missing_config_artifact_records_note(tmp_path):
    build = _build_step(tmp_path)
    build.artifacts = [a for a in build.artifacts if a.kind != "kernel-config"]
    result = _capture_kernel_provenance(build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path)
    assert result["kernel_provenance"]["config_ref"] is None
    assert "config_artifact_missing" in result["kernel_provenance_capture_notes"]


def test_missing_build_id_is_typed_capture_error(tmp_path):
    build = _build_step(tmp_path, build_id=None)
    result = _capture_kernel_provenance(build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path)
    assert result["kernel_provenance_capture_error"]["code"] == "build_id_unavailable"
    assert "kernel_provenance" not in result


def test_missing_release_is_typed_capture_error(tmp_path):
    build = _build_step(tmp_path, release=None)
    result = _capture_kernel_provenance(build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path)
    assert result["kernel_provenance_capture_error"]["code"] == "release_unavailable"


def test_relocated_config_artifact_is_capture_error(tmp_path):
    build = _build_step(tmp_path)
    # Point the kernel-config artifact outside run_dir.
    outside = tmp_path.parent / "stray.config"
    outside.write_text("x", encoding="utf-8")
    build.artifacts = [
        ArtifactRef(path=str(outside), kind="kernel-config"),
        *[a for a in build.artifacts if a.kind != "kernel-config"],
    ]
    result = _capture_kernel_provenance(build_step=build, boot_details={"kernel_args": []}, run_dir=tmp_path)
    assert result["kernel_provenance_capture_error"]["code"] == "artifact_path_unexpected"
