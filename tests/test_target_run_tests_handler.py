from pathlib import Path

from conftest import FakeTestProvider, create_booted_run, make_source_tree, rootfs

from linux_debug_mcp.artifacts.manifest import BootAttempt
from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile, TargetProfile, TestCommand, TestSuiteProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import LocalSshTestProvider, TestExecutionResult
from linux_debug_mcp.server import create_run_handler, target_run_tests_handler


class PlanRejectingProvider(FakeTestProvider):
    def plan_tests(self, **kwargs: object) -> object:
        self.plans.append(kwargs)
        raise ValueError("ConnectTimeout cannot exceed command timeout")


def suites() -> dict[str, TestSuiteProfile]:
    return {
        "smoke-basic": TestSuiteProfile(
            name="smoke-basic",
            commands=[TestCommand(name="uname", argv=["uname", "-a"])],
        )
    }


def test_run_tests_requires_existing_run(tmp_path: Path) -> None:
    response = target_run_tests_handler(artifact_root=tmp_path / "runs", run_id="run-missing")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_run_tests_requires_succeeded_boot(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    artifact_root = tmp_path / "runs"
    create_run_handler(
        artifact_root=artifact_root,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    response = target_run_tests_handler(artifact_root=artifact_root, run_id="run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert "succeeded boot" in response.error.message


def test_run_tests_executes_default_suite_after_boot(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert response.suggested_next_actions == ["artifacts.collect"]
    assert provider.plans[0]["suite"].name == "smoke-basic"
    assert provider.executions == 1


def test_run_tests_adhoc_only_does_not_add_default_suite(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        commands=[["id"]],
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.plans[0]["suite"] is None
    assert [command.argv for command in provider.plans[0]["adhoc_commands"]] == [["id"]]


def test_run_tests_rejects_manifest_test_suite_mismatch(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path, test_suite="smoke-basic")

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        test_suite="other-suite",
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
        provider=FakeTestProvider(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "test_suite must match" in response.error.message


def test_run_tests_returns_recorded_success_without_force_rerun(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()
    first = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )
    second = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert first.ok is True
    assert second.ok is True
    assert provider.executions == 1


def test_run_tests_force_rerun_replaces_success(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider()

    target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )
    target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        force_rerun=True,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert provider.executions == 2


def test_run_tests_maps_provider_failure_to_test_failure(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider(
        result=TestExecutionResult(
            status=StepStatus.FAILED,
            summary="test suite smoke-basic failed: 0 passed, 1 failed",
            artifacts=[
                ArtifactRef(
                    path=str(artifact_root / "run-abc123" / "tests" / "attempt-001" / "001-uname" / "stderr.txt"),
                    kind="test-stderr",
                )
            ],
            details={"counts": {"passed": 0, "failed": 1}, "commands": [{"label": "001-uname"}]},
            error_category=ErrorCategory.TEST_FAILURE,
            diagnostic="failed",
        )
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "test_failure"
    assert response.suggested_next_actions == ["artifacts.collect"]


def test_run_tests_rejects_rootfs_missing_ssh_endpoint_as_configuration_error(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=LocalSshTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path).model_copy(update={"ssh_host": None})},
        test_suites=suites(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "ssh_host and ssh_user" in response.error.message


def test_run_tests_rejects_empty_adhoc_argv_entry(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        commands=[[""]],
        provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "test command argv entries" in response.error.message


def test_run_tests_maps_provider_planning_value_error_to_configuration_error(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = PlanRejectingProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "ConnectTimeout" in response.error.message
    assert "run_tests" not in manifest.step_results
    assert provider.executions == 0


def test_run_tests_response_redacts_secret_like_snippets(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider(
        result=TestExecutionResult(
            status=StepStatus.FAILED,
            summary="test failed token=secret-token-value",
            details={
                "counts": {"passed": 0, "failed": 1},
                "commands": [
                    {
                        "label": "001-uname",
                        "stdout_snippet": "API_TOKEN=secret-token-value",
                        "stderr_snippet": "password=hunter2",
                    }
                ],
            },
            error_category=ErrorCategory.TEST_FAILURE,
            diagnostic="password=hunter2",
        )
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    payload = response.model_dump(mode="json")
    assert "secret-token-value" not in str(payload)
    assert "hunter2" not in str(payload)
    assert "[REDACTED]" in str(payload)


def test_run_tests_success_response_redacts_secret_like_snippets(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    provider = FakeTestProvider(
        result=TestExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="test passed token=secret-token-value",
            details={
                "counts": {"passed": 1, "failed": 0},
                "commands": [
                    {
                        "label": "001-uname",
                        "stdout_snippet": "API_TOKEN=secret-token-value",
                        "stderr_snippet": "password=hunter2",
                    }
                ],
            },
        )
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    payload = response.model_dump(mode="json")
    assert response.ok is True
    assert "secret-token-value" not in str(payload)
    assert "hunter2" not in str(payload)
    assert "[REDACTED]" in str(payload)


def test_run_tests_uses_boot_attempt_rootfs_profile(tmp_path: Path) -> None:
    """run_tests must bind to the latest boot attempt's resolved_rootfs_profile."""
    artifact_root = create_booted_run(tmp_path)
    run_id = "run-abc123"
    store = ArtifactStore(artifact_root, create_root=False)

    # Record a boot attempt whose rootfs source differs from the base minimal profile.
    swapped = RootfsProfile(
        name="minimal",
        source="/alt/rootfs.qcow2",
        ssh_host="127.0.0.1",
        ssh_user="root",
    )
    attempt = BootAttempt(
        attempt=1,
        resolved_target_profile=TargetProfile(name="local-qemu", architecture="x86_64"),
        resolved_rootfs_profile=swapped,
        status=StepStatus.SUCCEEDED,
    )
    store.record_boot_attempt(
        run_id,
        attempt=attempt,
        boot_result=StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="booted"),
    )

    provider = FakeTestProvider()
    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs is not None
    assert provider.planned_rootfs.source == "/alt/rootfs.qcow2"


def _record_two_succeeded_attempts(artifact_root: Path, run_id: str) -> None:
    """Record attempt 1 (source /first) then attempt 2 (source /second), both succeeded."""
    store = ArtifactStore(artifact_root, create_root=False)
    for index, source in ((1, "/first/rootfs.qcow2"), (2, "/second/rootfs.qcow2")):
        store.record_boot_attempt(
            run_id,
            attempt=BootAttempt(
                attempt=index,
                resolved_target_profile=TargetProfile(name="local-qemu", architecture="x86_64"),
                resolved_rootfs_profile=RootfsProfile(
                    name="minimal", source=source, ssh_host="127.0.0.1", ssh_user="root"
                ),
                status=StepStatus.SUCCEEDED,
            ),
            boot_result=StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="booted"),
        )


def test_run_tests_attempt_selector_binds_to_chosen_attempt(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _record_two_succeeded_attempts(artifact_root, "run-abc123")
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        attempt=1,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs is not None
    assert provider.planned_rootfs.source == "/first/rootfs.qcow2"


def test_run_tests_attempt_omitted_binds_to_latest(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _record_two_succeeded_attempts(artifact_root, "run-abc123")
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs is not None
    assert provider.planned_rootfs.source == "/second/rootfs.qcow2"


def test_run_tests_rejects_nonexistent_attempt(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _record_two_succeeded_attempts(artifact_root, "run-abc123")
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        attempt=99,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert provider.executions == 0


def test_run_tests_rejects_non_succeeded_attempt(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    run_id = "run-abc123"
    store = ArtifactStore(artifact_root, create_root=False)
    # Attempt 1 failed, attempt 2 succeeded: the boot step is SUCCEEDED (latest), but
    # selecting the failed attempt 1 must be rejected.
    for index, status in ((1, StepStatus.FAILED), (2, StepStatus.SUCCEEDED)):
        store.record_boot_attempt(
            run_id,
            attempt=BootAttempt(
                attempt=index,
                resolved_target_profile=TargetProfile(name="local-qemu", architecture="x86_64"),
                resolved_rootfs_profile=RootfsProfile(
                    name="minimal", source=f"/r{index}.qcow2", ssh_host="127.0.0.1", ssh_user="root"
                ),
                status=status,
            ),
            boot_result=StepResult(step_name="boot", status=status, summary="boot"),
        )
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        attempt=1,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert provider.executions == 0
