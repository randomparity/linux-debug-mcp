import inspect
from typing import get_type_hints

from kdive.workflow import handlers


def test_workflow_handlers_share_build_boot_runner() -> None:
    assert hasattr(handlers, "_run_build_boot_workflow")


def test_build_boot_runner_uses_named_request_boundary() -> None:
    signature = inspect.signature(handlers._run_build_boot_workflow)
    hints = get_type_hints(handlers._run_build_boot_workflow)

    assert hints["request"] is handlers.BuildBootWorkflowRequest
    for shared_input in (
        "artifact_root",
        "source_path",
        "build_profile",
        "target_profile",
        "rootfs_profile",
        "run_id",
        "force_rebuild",
        "force_reboot",
        "force_recollect",
        "acknowledged_permissions",
        "admission",
    ):
        assert shared_input not in signature.parameters
