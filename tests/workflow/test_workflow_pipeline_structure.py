from dataclasses import fields

from kdive.workflow import handlers


def test_build_boot_workflow_request_groups_shared_inputs() -> None:
    assert [field.name for field in fields(handlers.BuildBootWorkflowRequest)] == [
        "artifact_root",
        "source_path",
        "build_profile",
        "target_profile",
        "rootfs_profile",
        "run_id",
        "force_rebuild",
        "force_reboot",
        "force_recollect",
        "build_overrides",
        "boot_overrides",
        "sensitive_paths",
        "build_profile_spec",
        "target_profile_spec",
        "rootfs_profile_spec",
        "acknowledged_permissions",
        "admission",
    ]
