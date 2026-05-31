from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from kdive.config import TARGET_DESTRUCTIVE_PERMISSIONS, RootfsProfile, TestCommand, TestSuiteProfile
from kdive.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    ProviderCapability,
    StepStatus,
    TargetKind,
)
from kdive.providers.ssh import (
    SshCommandResult,
    SshRunner,
    SubprocessSshRunner,
    TestExecutionResult,
    build_ssh_argv,
)
from kdive.safety.redaction import Redactor

_SNIPPET_LIMIT = 4096


@dataclass(frozen=True)
class PlannedTestCommand:
    label: str
    argv: list[str]
    ssh_argv: list[str]
    timeout_seconds: int
    required: bool
    stdout_path: Path
    stderr_path: Path
    metadata_path: Path


@dataclass(frozen=True)
class TestPlan:
    run_id: str
    provider_name: str
    suite_name: str
    attempt: int
    attempt_dir: Path
    known_hosts_path: Path
    summary_path: Path
    commands: list[PlannedTestCommand]
    dmesg_command: PlannedTestCommand | None
    stop_on_failure: bool
    redactor: Redactor


class LocalSshTestProvider:
    name = "local-ssh-tests"

    def __init__(self, *, runner: SshRunner | None = None) -> None:
        self.runner = runner or SubprocessSshRunner()

    def plan_tests(
        self,
        *,
        run_id: str,
        run_dir: Path,
        rootfs_profile: RootfsProfile,
        suite: TestSuiteProfile | None,
        adhoc_commands: list[TestCommand],
        attempt: int,
    ) -> TestPlan:
        if rootfs_profile.access_method not in {"ssh", "ssh_and_serial"}:
            raise ValueError("rootfs profile requires SSH access for test execution")
        if not rootfs_profile.ssh_host or not rootfs_profile.ssh_user:
            raise ValueError("rootfs profile requires ssh_host and ssh_user for SSH test execution")

        known_hosts_path = run_dir / "target" / "known_hosts"
        attempt_dir = run_dir / "tests" / f"attempt-{attempt:03d}"
        summary_path = run_dir / "summaries" / "test-summary.json"
        redactor = Redactor(secret_values=[rootfs_profile.ssh_key_ref] if rootfs_profile.ssh_key_ref else [])

        suite_commands = suite.commands if suite is not None else []
        suite_name = suite.name if suite is not None else "adhoc"
        suite_timeout = suite.timeout_seconds if suite is not None else 30
        stop_on_failure = suite.stop_on_failure if suite is not None else True
        collect_dmesg = suite.collect_dmesg if suite is not None else True

        planned: list[PlannedTestCommand] = []
        for index, command in enumerate(suite_commands, start=1):
            label = f"{index:03d}-{command.name}"
            planned.append(
                self._plan_command(
                    label=label,
                    command=command,
                    rootfs_profile=rootfs_profile,
                    known_hosts_path=known_hosts_path,
                    attempt_dir=attempt_dir,
                    default_timeout=suite_timeout,
                )
            )
        for index, command in enumerate(adhoc_commands, start=1):
            planned.append(
                self._plan_command(
                    label=f"adhoc-{index:03d}",
                    command=command.model_copy(update={"required": True}),
                    rootfs_profile=rootfs_profile,
                    known_hosts_path=known_hosts_path,
                    attempt_dir=attempt_dir,
                    default_timeout=suite_timeout,
                )
            )

        dmesg_command = None
        if collect_dmesg:
            dmesg_command = self._planned_dmesg_command(
                rootfs_profile=rootfs_profile,
                known_hosts_path=known_hosts_path,
                attempt_dir=attempt_dir,
            )

        return TestPlan(
            run_id=run_id,
            provider_name=self.name,
            suite_name=suite_name,
            attempt=attempt,
            attempt_dir=attempt_dir,
            known_hosts_path=known_hosts_path,
            summary_path=summary_path,
            commands=planned,
            dmesg_command=dmesg_command,
            stop_on_failure=stop_on_failure,
            redactor=redactor,
        )

    def execute_tests(self, plan: TestPlan, *, cancel: threading.Event | None = None) -> TestExecutionResult:
        started_at = datetime.now(UTC)
        plan.attempt_dir.mkdir(parents=True, exist_ok=True)
        plan.summary_path.parent.mkdir(parents=True, exist_ok=True)
        if self.runner.which("ssh") is None:
            artifacts = [ArtifactRef(path=str(plan.summary_path), kind="test-summary")]
            payload = {
                "run_id": plan.run_id,
                "provider": plan.provider_name,
                "suite": plan.suite_name,
                "attempt": plan.attempt,
                "started_at": started_at.isoformat(),
                "ended_at": datetime.now(UTC).isoformat(),
                "status": StepStatus.FAILED,
                "error_category": ErrorCategory.MISSING_DEPENDENCY,
                "missing_tools": ["ssh"],
                "commands": [],
                "dmesg": None,
                "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
            }
            self._write_json(plan.summary_path, plan.redactor.redact_value(payload))
            return TestExecutionResult(
                status=StepStatus.FAILED,
                summary="missing required SSH tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": ["ssh"]},
                artifacts=artifacts,
            )

        command_results = []
        required_failed = False
        for command in plan.commands:
            started = datetime.now(UTC)
            start_time = monotonic()
            result = self.runner.run(
                command.ssh_argv,
                timeout=command.timeout_seconds,
                stdout_path=command.stdout_path,
                stderr_path=command.stderr_path,
                cancel=cancel,
            )
            ended = datetime.now(UTC)
            metadata = self._command_metadata(
                command=command,
                result=result,
                started_at=started,
                ended_at=ended,
                elapsed_seconds=monotonic() - start_time,
                redactor=plan.redactor,
            )
            self._write_json(command.metadata_path, metadata)
            command_results.append(metadata)
            if command.required and (result.exit_status != 0 or result.timed_out):
                required_failed = True
                if plan.stop_on_failure:
                    break

        dmesg_result = self._run_dmesg(plan) if plan.dmesg_command is not None else None
        artifacts = self._existing_artifacts(plan)
        ended_at = datetime.now(UTC)
        status = StepStatus.FAILED if required_failed else StepStatus.SUCCEEDED
        payload = {
            "run_id": plan.run_id,
            "provider": plan.provider_name,
            "suite": plan.suite_name,
            "attempt": plan.attempt,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "status": status,
            "commands": command_results,
            "dmesg": dmesg_result,
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
        }
        self._write_json(plan.summary_path, plan.redactor.redact_value(payload))
        passed = sum(1 for item in command_results if item["exit_status"] == 0 and not item["timed_out"])
        failed = len(command_results) - passed
        outcome = "passed" if status == StepStatus.SUCCEEDED else "failed"
        return TestExecutionResult(
            status=status,
            summary=f"test suite {plan.suite_name} {outcome}: {passed} passed, {failed} failed",
            artifacts=artifacts,
            details={
                "suite": plan.suite_name,
                "attempt": plan.attempt,
                "counts": {"passed": passed, "failed": failed},
                "commands": command_results,
                "dmesg": dmesg_result,
            },
            error_category=ErrorCategory.TEST_FAILURE if status == StepStatus.FAILED else None,
            diagnostic=self._first_failure_snippet(command_results),
        )

    def _plan_command(
        self,
        *,
        label: str,
        command: TestCommand,
        rootfs_profile: RootfsProfile,
        known_hosts_path: Path,
        attempt_dir: Path,
        default_timeout: int,
    ) -> PlannedTestCommand:
        timeout = command.timeout_seconds or default_timeout
        command_dir = attempt_dir / label
        return PlannedTestCommand(
            label=label,
            argv=command.argv,
            ssh_argv=build_ssh_argv(
                rootfs_profile=rootfs_profile,
                known_hosts_path=known_hosts_path,
                command=command.argv,
                command_timeout=timeout,
            ),
            timeout_seconds=timeout,
            required=command.required,
            stdout_path=command_dir / "stdout.txt",
            stderr_path=command_dir / "stderr.txt",
            metadata_path=command_dir / "command.json",
        )

    def _planned_dmesg_command(
        self,
        *,
        rootfs_profile: RootfsProfile,
        known_hosts_path: Path,
        attempt_dir: Path,
    ) -> PlannedTestCommand:
        argv = ["dmesg"]
        timeout = 10
        return PlannedTestCommand(
            label="dmesg",
            argv=argv,
            ssh_argv=build_ssh_argv(
                rootfs_profile=rootfs_profile,
                known_hosts_path=known_hosts_path,
                command=argv,
                command_timeout=timeout,
            ),
            timeout_seconds=timeout,
            required=False,
            stdout_path=attempt_dir / "dmesg.txt",
            stderr_path=attempt_dir / "dmesg.stderr.txt",
            metadata_path=attempt_dir / "dmesg.command.json",
        )

    def _run_dmesg(self, plan: TestPlan) -> dict[str, object]:
        command = plan.dmesg_command
        if command is None:
            return {}
        started = datetime.now(UTC)
        start_time = monotonic()
        result = self.runner.run(
            command.ssh_argv,
            timeout=command.timeout_seconds,
            stdout_path=command.stdout_path,
            stderr_path=command.stderr_path,
        )
        ended = datetime.now(UTC)
        return self._command_metadata(
            command=command,
            result=result,
            started_at=started,
            ended_at=ended,
            elapsed_seconds=monotonic() - start_time,
            redactor=plan.redactor,
        )

    def _command_metadata(
        self,
        *,
        command: PlannedTestCommand,
        result: SshCommandResult,
        started_at: datetime,
        ended_at: datetime,
        elapsed_seconds: float,
        redactor: Redactor,
    ) -> dict[str, object]:
        metadata = {
            "label": command.label,
            "argv": command.argv,
            "ssh_argv": command.ssh_argv,
            "required": command.required,
            "timeout_seconds": command.timeout_seconds,
            "exit_status": result.exit_status,
            "timed_out": result.timed_out,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "elapsed_seconds": round(elapsed_seconds, 6),
            "stdout_path": str(command.stdout_path),
            "stderr_path": str(command.stderr_path),
            "stdout_snippet": result.stdout_snippet or self._snippet(result.stdout),
            "stderr_snippet": result.stderr_snippet or self._snippet(result.stderr),
        }
        return redactor.redact_value(metadata)

    def _existing_artifacts(self, plan: TestPlan) -> list[ArtifactRef]:
        artifacts: list[ArtifactRef] = []
        for command in plan.commands:
            artifacts.extend(
                [
                    ArtifactRef(path=str(command.stdout_path), kind="test-stdout"),
                    ArtifactRef(path=str(command.stderr_path), kind="test-stderr"),
                    ArtifactRef(path=str(command.metadata_path), kind="test-command"),
                ]
            )
        if plan.dmesg_command is not None:
            artifacts.extend(
                [
                    ArtifactRef(path=str(plan.dmesg_command.stdout_path), kind="dmesg"),
                    ArtifactRef(path=str(plan.dmesg_command.stderr_path), kind="dmesg-stderr"),
                ]
            )
        artifacts.append(ArtifactRef(path=str(plan.summary_path), kind="test-summary"))
        return [artifact for artifact in artifacts if Path(artifact.path).is_file() or artifact.kind == "test-summary"]

    def _first_failure_snippet(self, command_results: list[dict[str, object]]) -> str | None:
        for item in command_results:
            if item["exit_status"] != 0 or item["timed_out"]:
                stderr = str(item.get("stderr_snippet") or "")
                stdout = str(item.get("stdout_snippet") or "")
                return stderr or stdout or f"{item['label']} failed"
        return None

    def _snippet(self, value: str) -> str:
        return value[:_SNIPPET_LIMIT]

    def _write_json(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def local_ssh_tests_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-ssh-tests",
        provider_version="0.1.0",
        provider_family="test",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh", "filesystem"],
        operations=["target.run_tests"],
        required_host_tools=["ssh"],
        destructive_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.run_tests"],
        access_methods=["ssh", "filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=True,
            cancelable=False,
            concurrent_safe=False,
        ),
    )
