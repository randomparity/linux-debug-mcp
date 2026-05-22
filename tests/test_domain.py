from linux_debug_mcp import __version__
from linux_debug_mcp.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    PrerequisiteCheck,
    PrerequisiteStatus,
    ProviderCapability,
    TargetKind,
    ToolResponse,
)


def test_package_exports_version() -> None:
    assert __version__ == "0.1.0"


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
