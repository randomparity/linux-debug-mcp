import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from kdive.config import RootfsProfile, TestCommand, TestSuiteProfile
from kdive.domain import ErrorCategory, StepStatus
from kdive.providers.local.local_ssh_tests import (
    _SNIPPET_LIMIT,
    LocalSshTestProvider,
    SshCommandResult,
    SubprocessSshRunner,
)


@dataclass
class FakeSshRunner:
    available: bool = True
    results: list[SshCommandResult] | None = None
    calls: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.results = self.results or []
        self.calls = []

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}" if self.available else None

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
        cancel: threading.Event | None = None,
        stdin: str | None = None,
    ) -> SshCommandResult:
        self.calls.append(
            {
                "argv": argv,
                "timeout": timeout,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "stdin": stdin,
            }
        )
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="ok\n", stderr="")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


def rootfs(**kwargs: object) -> RootfsProfile:
    defaults = {
        "name": "minimal",
        "source": "/tmp/rootfs.qcow2",
        "access_method": "ssh_and_serial",
        "ssh_host": "127.0.0.1",
        "ssh_port": 2222,
        "ssh_user": "root",
    }
    defaults.update(kwargs)
    return RootfsProfile(**defaults)


def suite(**kwargs: object) -> TestSuiteProfile:
    return TestSuiteProfile(
        name="smoke-basic",
        commands=[TestCommand(name="uname", argv=["uname", "-a"])],
        **kwargs,
    )


def test_plan_rejects_rootfs_without_ssh_access(tmp_path: Path) -> None:
    provider = LocalSshTestProvider(runner=FakeSshRunner())

    with pytest.raises(ValueError, match="SSH access"):
        provider.plan_tests(
            run_id="run-abc123",
            run_dir=tmp_path,
            rootfs_profile=rootfs(access_method="serial"),
            suite=suite(),
            adhoc_commands=[],
            attempt=1,
        )


def test_plan_builds_ssh_argv_with_quoted_remote_command_and_provider_defaults(tmp_path: Path) -> None:
    provider = LocalSshTestProvider(runner=FakeSshRunner())
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(ssh_key_ref="/tmp/id_ed25519"),
        suite=suite(),
        adhoc_commands=[],
        attempt=1,
    )

    command = plan.commands[0]
    assert command.ssh_argv[:2] == ["ssh", "-o"]
    assert "BatchMode=yes" in command.ssh_argv
    assert "UserKnownHostsFile=" + str(tmp_path / "target" / "known_hosts") in command.ssh_argv
    assert "-i" in command.ssh_argv
    assert command.ssh_argv[-3:] == ["--", "root@127.0.0.1", "uname -a"]


def test_plan_allows_adhoc_only_without_default_suite_commands(tmp_path: Path) -> None:
    provider = LocalSshTestProvider(runner=FakeSshRunner())
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=None,
        adhoc_commands=[TestCommand(name="adhoc-001", argv=["id"], required=True)],
        attempt=1,
    )

    assert plan.suite_name == "adhoc"
    assert [command.label for command in plan.commands] == ["adhoc-001"]
    assert plan.commands[0].argv == ["id"]


def test_execute_success_writes_per_command_artifacts_and_summary(tmp_path: Path) -> None:
    runner = FakeSshRunner(results=[SshCommandResult(exit_status=0, stdout="Linux test\n", stderr="")])
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert (tmp_path / "tests" / "attempt-001" / "001-uname" / "stdout.txt").read_text() == "Linux test\n"
    assert (tmp_path / "tests" / "attempt-001" / "001-uname" / "command.json").is_file()
    assert (tmp_path / "summaries" / "test-summary.json").is_file()
    assert any(artifact.kind == "test-summary" for artifact in result.artifacts)


def test_execute_truncates_snippets_but_preserves_full_stdout_artifact(tmp_path: Path) -> None:
    long_stdout = "x" * (_SNIPPET_LIMIT + 25)
    runner = FakeSshRunner(
        results=[
            SshCommandResult(
                exit_status=0,
                stdout=long_stdout,
                stderr="",
                stdout_snippet="x" * _SNIPPET_LIMIT,
                stderr_snippet="",
            )
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    stdout_path = tmp_path / "tests" / "attempt-001" / "001-uname" / "stdout.txt"
    assert stdout_path.read_text(encoding="utf-8") == long_stdout
    assert result.details["commands"][0]["stdout_snippet"] == "x" * _SNIPPET_LIMIT


def test_execute_missing_ssh_writes_failed_summary(tmp_path: Path) -> None:
    runner = FakeSshRunner(available=False)
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY
    assert (tmp_path / "summaries" / "test-summary.json").is_file()
    assert any(artifact.kind == "test-summary" for artifact in result.artifacts)


def test_execute_required_failure_stops_when_stop_on_failure_is_true(tmp_path: Path) -> None:
    runner = FakeSshRunner(
        results=[
            SshCommandResult(exit_status=1, stdout="", stderr="failed\n"),
            SshCommandResult(exit_status=0, stdout="should not run\n", stderr=""),
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=TestSuiteProfile(
            name="smoke-basic",
            commands=[
                TestCommand(name="first", argv=["false"]),
                TestCommand(name="second", argv=["true"]),
            ],
            stop_on_failure=True,
            collect_dmesg=False,
        ),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.TEST_FAILURE
    assert len(runner.calls) == 1


def test_execute_collects_dmesg_without_failing_smoke_result(tmp_path: Path) -> None:
    runner = FakeSshRunner(
        results=[
            SshCommandResult(exit_status=0, stdout="ok\n", stderr=""),
            SshCommandResult(exit_status=1, stdout="", stderr="permission denied\n"),
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(),
        suite=suite(collect_dmesg=True),
        adhoc_commands=[],
        attempt=1,
    )

    result = provider.execute_tests(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert (tmp_path / "tests" / "attempt-001" / "dmesg.txt").is_file()
    assert result.details["dmesg"]["exit_status"] == 1


def test_summary_redacts_key_path_and_secret_like_output(tmp_path: Path) -> None:
    runner = FakeSshRunner(
        results=[
            SshCommandResult(exit_status=0, stdout="API_TOKEN=secret-token-value password=hunter2\n", stderr=""),
        ]
    )
    provider = LocalSshTestProvider(runner=runner)
    key_path = "/tmp/id_ed25519"
    plan = provider.plan_tests(
        run_id="run-abc123",
        run_dir=tmp_path,
        rootfs_profile=rootfs(ssh_key_ref=key_path),
        suite=suite(collect_dmesg=False),
        adhoc_commands=[],
        attempt=1,
    )

    provider.execute_tests(plan)

    command_metadata = (tmp_path / "tests" / "attempt-001" / "001-uname" / "command.json").read_text(encoding="utf-8")
    summary = (tmp_path / "summaries" / "test-summary.json").read_text(encoding="utf-8")
    combined = command_metadata + summary
    assert key_path not in combined
    assert "secret-token-value" not in combined
    assert "hunter2" not in combined
    assert "[REDACTED]" in combined


def test_run_is_killed_on_cancel(tmp_path: Path) -> None:
    runner = SubprocessSshRunner()
    cancel = threading.Event()
    out, err = tmp_path / "o", tmp_path / "e"
    ready_path = tmp_path / "ready"
    program = (
        "from pathlib import Path\n"
        "import signal\n"
        f"Path({str(ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        "signal.pause()\n"
    )
    result_holder: list[SshCommandResult] = []
    run_done = threading.Event()

    def run_command() -> None:
        result_holder.append(
            runner.run(["python3", "-c", program], timeout=30, stdout_path=out, stderr_path=err, cancel=cancel)
        )
        run_done.set()

    thread = threading.Thread(target=run_command)
    thread.start()
    assert _wait_for_file(ready_path)
    cancel.set()
    assert run_done.wait(timeout=5)
    thread.join()
    result = result_holder[0]

    assert result.cancelled is True


def test_run_is_killed_when_stdout_exceeds_cap(tmp_path: Path) -> None:
    runner = SubprocessSshRunner()
    out, err = tmp_path / "o", tmp_path / "e"
    ready_path = tmp_path / "ready"
    cap = 4096
    program = (
        "from pathlib import Path\n"
        "import signal\n"
        "import sys\n"
        f"Path({str(ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        f"sys.stdout.write('x' * {cap + 1})\n"
        "sys.stdout.flush()\n"
        "signal.pause()\n"
    )
    result = runner.run(
        ["python3", "-c", program],
        timeout=30,
        stdout_path=out,
        stderr_path=err,
        max_stdout_bytes=cap,
    )
    assert ready_path.read_text(encoding="utf-8") == "ready"
    assert result.oversized_output is True
    assert result.timed_out is False
    assert result.exit_status == -1
    assert out.stat().st_size > cap


def _wait_for_file(path: Path, *, attempts: int = 500) -> bool:
    for _ in range(attempts):
        if path.exists():
            return True
        threading.Event().wait(0.01)
    return path.exists()
