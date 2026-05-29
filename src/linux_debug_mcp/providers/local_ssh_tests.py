from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Protocol

from linux_debug_mcp.config import RootfsProfile, TestCommand, TestSuiteProfile
from linux_debug_mcp.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    ProviderCapability,
    StepStatus,
    TargetKind,
)
from linux_debug_mcp.safety.redaction import Redactor

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


@dataclass(frozen=True)
class SshCommandResult:
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    timed_out: bool = False
    cancelled: bool = False
    # True when the stdin writer thread observed BrokenPipeError / OSError
    # before delivering the full payload. The caller cannot trust that the
    # remote process saw the complete script — surface as a transport failure.
    stdin_failed: bool = False
    # True when the streaming stdout cap (max_stdout_bytes) was exceeded and the
    # process group was killed mid-run. The caller surfaces this as an
    # oversized-output transport failure rather than parsing a truncated stream.
    oversized_output: bool = False


@dataclass(frozen=True)
class TestExecutionResult:
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None


class SshRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
        cancel: threading.Event | None = None,
        stdin: str | None = None,
        max_stdout_bytes: int | None = None,
    ) -> SshCommandResult:
        raise NotImplementedError


class SubprocessSshRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
        cancel: threading.Event | None = None,
        stdin: str | None = None,
        max_stdout_bytes: int | None = None,
    ) -> SshCommandResult:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        cancelled_flag = False
        timed_out_flag = False
        oversized_flag = False
        with (
            stdout_path.open("w", encoding="utf-8") as stdout_file,
            stderr_path.open("w", encoding="utf-8") as stderr_file,
        ):
            proc = subprocess.Popen(
                argv,
                stdout=stdout_file,
                stderr=stderr_file,
                stdin=subprocess.PIPE if stdin is not None else None,
                text=True,
                shell=False,
                start_new_session=True,
            )
            stdin_thread: threading.Thread | None = None
            # The writer thread records partial-write/EPIPE failures here so
            # the caller can distinguish a transport failure (truncated wrapper
            # payload) from a clean wrapper run that emitted a non-JSON crash.
            stdin_write_error: list[BaseException] = []
            if stdin is not None:
                # R6-F4 + iter-1 finding 4: the wrapper payload can be ~264 KiB,
                # which exceeds Linux's default 64 KiB pipe buffer. Writing in
                # the main thread would block until the remote drains the
                # buffer, neutering the cancel/timeout poll below. Pushing the
                # write into a daemon thread keeps the poll loop responsive;
                # killing the process group closes the pipe so the writer
                # observes BrokenPipeError and exits.
                assert proc.stdin is not None
                stdin_handle = proc.stdin
                payload = stdin

                def _write_stdin() -> None:
                    try:
                        stdin_handle.write(payload)
                    except (BrokenPipeError, ValueError, OSError) as exc:
                        stdin_write_error.append(exc)
                    finally:
                        with contextlib.suppress(Exception):
                            stdin_handle.close()

                stdin_thread = threading.Thread(target=_write_stdin, daemon=True)
                stdin_thread.start()
            ticks = 0
            while True:
                try:
                    proc.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    ticks += 1
                    if cancel is not None and cancel.is_set():
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                        cancelled_flag = True
                        break
                    if ticks * 0.1 >= timeout:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                        timed_out_flag = True
                        break
                    if max_stdout_bytes is not None and self._stdout_size(stdout_path) > max_stdout_bytes:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                        oversized_flag = True
                        break
            if stdin_thread is not None:
                stdin_thread.join(timeout=2)
        # -1 sentinel: process was killed (cancel/timeout/oversized), so there is no real exit code.
        exit_status = -1 if (cancelled_flag or timed_out_flag or oversized_flag) else proc.returncode
        return SshCommandResult(
            exit_status=exit_status,
            stdout_snippet=self._read_snippet(stdout_path),
            stderr_snippet=self._read_snippet(stderr_path),
            timed_out=timed_out_flag,
            cancelled=cancelled_flag,
            stdin_failed=bool(stdin_write_error),
            oversized_output=oversized_flag,
        )

    def _stdout_size(self, path: Path) -> int:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return 0

    def _read_snippet(self, path: Path) -> str:
        if not path.exists():
            return ""
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(_SNIPPET_LIMIT)


def build_ssh_argv(
    *,
    rootfs_profile: RootfsProfile,
    known_hosts_path: Path,
    command: list[str],
    command_timeout: int,
) -> list[str]:
    """Construct the canonical ``ssh`` argv for invoking *command* on the
    rootfs's remote shell.

    Single source of truth for SSH argv shape — both
    ``LocalSshTestProvider`` (test-run paths, dmesg) and
    ``debug_introspect_run_handler`` (sudo preflight, wrapper invocation)
    call this. R6-F5: the introspect handler previously referenced
    ``RootfsProfile.ssh_args()`` / ``.ssh_argv()`` methods that do not
    exist on the Pydantic model (config.py:254-277); lifting this helper
    to module scope eliminates that fictional API.
    """
    configured_timeout = rootfs_profile.ssh_options.get("ConnectTimeout")
    if configured_timeout is not None and int(configured_timeout) > command_timeout:
        raise ValueError("ConnectTimeout cannot exceed command timeout")
    connect_timeout = configured_timeout or str(min(command_timeout, 10))
    strict_host_key_checking = rootfs_profile.ssh_options.get("StrictHostKeyChecking", "accept-new")
    ssh_argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        f"StrictHostKeyChecking={strict_host_key_checking}",
    ]
    for key in sorted(rootfs_profile.ssh_options):
        if key in {"ConnectTimeout", "StrictHostKeyChecking"}:
            continue
        ssh_argv.extend(["-o", f"{key}={rootfs_profile.ssh_options[key]}"])
    ssh_argv.extend(["-p", str(rootfs_profile.ssh_port)])
    if rootfs_profile.ssh_key_ref:
        ssh_argv.extend(["-i", rootfs_profile.ssh_key_ref])
    remote_command = " ".join(shlex.quote(item) for item in command)
    ssh_argv.extend(["--", f"{rootfs_profile.ssh_user}@{rootfs_profile.ssh_host}", remote_command])
    return ssh_argv


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
        destructive_permissions=[],
        access_methods=["ssh", "filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=False,
        ),
    )
