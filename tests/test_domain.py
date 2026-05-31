import pytest
from pydantic import ValidationError

from kdive import __version__, domain
from kdive.config import BootOverrides, BuildOverrides
from kdive.domain import (
    ArtifactRef,
    DebugIntrospectRunRequest,
    ErrorCategory,
    OperationSemantics,
    PrerequisiteCheck,
    PrerequisiteStatus,
    ProviderCapability,
    RunRequest,
    TargetKind,
    ToolResponse,
)


def test_package_exports_version() -> None:
    assert __version__ == "0.1.0"


def test_postmortem_models_live_in_postmortem_package() -> None:
    assert not hasattr(domain, "DebugPostmortemCrashRequest")


def test_debug_request_rejects_deprecated_target_ref_alias() -> None:
    with pytest.raises(ValidationError):
        DebugIntrospectRunRequest(run_id="r1", target_ref="local-qemu", script="print(1)")


def test_success_response_serializes_with_shared_envelope() -> None:
    response = ToolResponse.success(
        summary="run created",
        run_id="run-123",
        data={"manifest_path": "/tmp/runs/run-123/manifest.json"},
        artifacts=[ArtifactRef(path="/tmp/runs/run-123/manifest.json", kind="manifest")],
        suggested_next_actions=["kernel.build"],
    )

    payload = response.model_dump(mode="json")

    assert payload["ok"] is True
    assert payload["status"] == "succeeded"
    assert payload["run_id"] == "run-123"
    assert payload["data"]["manifest_path"].endswith("manifest.json")
    assert payload["artifacts"][0]["kind"] == "manifest"
    assert payload["suggested_next_actions"] == ["kernel.build"]


def test_error_response_uses_nested_error_contract() -> None:
    response = ToolResponse.failure(
        category=ErrorCategory.NOT_IMPLEMENTED,
        message="kernel.build is implemented in Sprint 1",
        run_id="run-123",
        details={"tool": "kernel.build"},
        artifacts=[ArtifactRef(path="/tmp/runs/run-123/logs/build.log", kind="build-log")],
        suggested_next_actions=["workflow.build_boot_test after Sprint 3"],
    )

    payload = response.model_dump(mode="json")

    assert payload["ok"] is False
    assert payload["status"] == "failed"
    assert payload["error"] == {
        "category": "not_implemented",
        "message": "kernel.build is implemented in Sprint 1",
        "details": {"tool": "kernel.build"},
    }
    assert payload["artifacts"] == [
        {
            "path": "/tmp/runs/run-123/logs/build.log",
            "kind": "build-log",
            "sensitive": False,
            "description": None,
        }
    ]


def test_provider_capability_records_semantics() -> None:
    capability = ProviderCapability(
        provider_name="local-artifacts",
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["artifacts.create_run"],
        required_host_tools=[],
        destructive_permissions=[],
        access_methods=["filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=False,
        ),
    )

    assert capability.semantics.idempotent is True
    assert capability.target_kinds == [TargetKind.LOCAL]


def test_run_request_overrides_default_none():
    request = RunRequest(
        source_path="/src",
        build_profile="b",
        target_profile="t",
        rootfs_profile="r",
    )
    assert request.build_overrides is None
    assert request.boot_overrides is None


def test_run_request_accepts_overrides_round_trip():
    request = RunRequest(
        source_path="/src",
        build_profile="b",
        target_profile="t",
        rootfs_profile="r",
        build_overrides=BuildOverrides(make_variables={"CC": "clang"}),
        boot_overrides=BootOverrides(kernel_args=["dhash_entries=1"]),
    )
    reparsed = RunRequest.model_validate_json(request.model_dump_json())
    assert reparsed.boot_overrides.kernel_args == ["dhash_entries=1"]
    assert reparsed.build_overrides.make_variables == {"CC": "clang"}


def test_prerequisite_check_serializes_status_and_fix() -> None:
    check = PrerequisiteCheck(
        check_id="tool.gdb",
        status=PrerequisiteStatus.FAILED,
        message="gdb was not found",
        suggested_fix="Install gdb with your distro package manager.",
    )

    assert check.model_dump(mode="json") == {
        "check_id": "tool.gdb",
        "status": "failed",
        "message": "gdb was not found",
        "details": {},
        "suggested_fix": "Install gdb with your distro package manager.",
    }


def test_debug_introspect_run_request_minimal() -> None:
    req = DebugIntrospectRunRequest(run_id="r1", manifest_target_profile="local-qemu", script="print(1)")
    assert req.timeout_seconds == 30
    assert req.allow_write is False
    assert req.acknowledged_permissions == []
    assert req.debug_profile is None
    assert req.target_profile is None
    assert req.rootfs_profile is None


def test_debug_introspect_run_request_acknowledged_permissions() -> None:
    req = DebugIntrospectRunRequest(
        run_id="r1",
        manifest_target_profile="local-qemu",
        script="pass",
        acknowledged_permissions=["x"],
    )
    assert req.acknowledged_permissions == ["x"]


def test_debug_introspect_run_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugIntrospectRunRequest(run_id="r1", manifest_target_profile="t", script="s", unknown=1)
