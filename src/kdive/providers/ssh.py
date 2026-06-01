from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import signal
import subprocess  # nosec B404
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from kdive.config import RootfsProfile
from kdive.domain import ArtifactRef, ErrorCategory, StepStatus

_SNIPPET_LIMIT = 4096
SSH_TIMEOUT_GRACE_SECONDS = 10


@dataclass(frozen=True)
class SshCommandResult:
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    timed_out: bool = False
    cancelled: bool = False
    stdin_failed: bool = False
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
            proc = subprocess.Popen(  # nosec B603
                argv,
                stdout=stdout_file,
                stderr=stderr_file,
                stdin=subprocess.PIPE if stdin is not None else None,
                text=True,
                shell=False,
                start_new_session=True,
            )
            stdin_thread: threading.Thread | None = None
            stdin_write_error: list[BaseException] = []
            if stdin is not None:
                if proc.stdin is None:
                    raise RuntimeError("stdin pipe was not created for ssh subprocess")
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


CommandResult = SshCommandResult
CommandRunner = SshRunner
SubprocessCommandRunner = SubprocessSshRunner


def build_ssh_argv(
    *,
    rootfs_profile: RootfsProfile,
    known_hosts_path: Path,
    command: list[str],
    command_timeout: int,
) -> list[str]:
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
