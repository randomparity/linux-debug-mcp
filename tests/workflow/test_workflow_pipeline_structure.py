import inspect
from dataclasses import fields
from typing import get_type_hints

from kdive.debug.tools import DebugStartSessionRequest, DebugToolContext
from kdive.kernel.tools import CreateRunHandlerRequest, KernelBuildHandlerRequest, KernelToolRuntime
from kdive.target.tools import TargetBootHandlerRequest, TargetRunTestsHandlerRequest, TargetToolRuntime
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


def test_workflow_handler_dependencies_use_tool_request_runtime_contracts() -> None:
    expected_contracts = {
        handlers.CreateRunHandler: (CreateRunHandlerRequest, KernelToolRuntime),
        handlers.KernelBuildHandler: (KernelBuildHandlerRequest, KernelToolRuntime),
        handlers.TargetBootHandler: (TargetBootHandlerRequest, TargetToolRuntime),
        handlers.TargetRunTestsHandler: (TargetRunTestsHandlerRequest, TargetToolRuntime),
        handlers.DebugStartSessionHandler: (DebugStartSessionRequest, DebugToolContext),
    }

    for protocol, (expected_request, expected_runtime) in expected_contracts.items():
        signature = inspect.signature(protocol.__call__)
        annotations = get_type_hints(protocol.__call__)
        assert annotations["request"] is expected_request
        assert annotations["runtime"] is expected_runtime
        assert list(signature.parameters) == ["self", "request", "runtime"]
