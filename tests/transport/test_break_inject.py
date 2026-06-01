from collections.abc import Sequence
from pathlib import Path

import pytest

from kdive.domain import ErrorCategory
from kdive.transport.core.base import BreakMethod, BreakPlan
from kdive.transport.core.break_inject import InjectBreakError, inject_break


class _RecordingProxy:
    def __init__(self) -> None:
        self.breaks = 0
        self.handle = None

    def send_break(self, handle: object) -> None:
        self.breaks += 1
        self.handle = handle


class _RecordingSsh:
    def __init__(self) -> None:
        self.argv: Sequence[str] | None = None
        self.timeout: int | None = None
        self.stdout_path: Path | None = None
        self.stderr_path: Path | None = None

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
    ):
        self.argv = argv
        self.timeout = timeout
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path

        class _R:
            returncode = 0

        return _R()


def _plan(method):
    return BreakPlan(method=method, channel_id="c0", rationale="test")


def test_auto_dispatches_uart_break_to_proxy_send_break():
    proxy = _RecordingProxy()
    handle = object()
    inject_break(
        method="auto",
        break_plan=_plan(BreakMethod.UART_BREAK),
        proxy=proxy,
        proxy_handle=handle,
        ssh_runner=None,
        ssh_argv_prefix=(),
    )
    assert proxy.breaks == 1
    assert proxy.handle is handle


def test_agent_proxy_break_also_uses_send_break():
    proxy = _RecordingProxy()
    handle = object()
    inject_break(
        method=BreakMethod.AGENT_PROXY_BREAK,
        break_plan=_plan(BreakMethod.AGENT_PROXY_BREAK),
        proxy=proxy,
        proxy_handle=handle,
        ssh_runner=None,
        ssh_argv_prefix=(),
    )
    assert proxy.breaks == 1
    assert proxy.handle is handle


def test_uart_break_without_proxy_raises_unavailable_not_attributeerror():
    with pytest.raises(InjectBreakError) as exc:
        inject_break(
            method=BreakMethod.UART_BREAK,
            break_plan=_plan(BreakMethod.UART_BREAK),
            proxy=None,
            proxy_handle=None,
            ssh_runner=None,
            ssh_argv_prefix=(),
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert exc.value.details.get("code") == "break_inject_unavailable"


def test_sysrq_g_writes_g_to_sysrq_trigger_over_ssh(tmp_path):
    ssh = _RecordingSsh()
    inject_break(
        method=BreakMethod.SYSRQ_G,
        break_plan=_plan(BreakMethod.SYSRQ_G),
        proxy=None,
        proxy_handle=None,
        ssh_runner=ssh,
        ssh_argv_prefix=("ssh", "vm1"),
        work_dir=tmp_path,
    )
    assert ssh.argv is not None
    assert ssh.timeout == 10
    assert ssh.stdout_path == tmp_path / "sysrq.out"
    assert ssh.stderr_path == tmp_path / "sysrq.err"
    assert tuple(ssh.argv[:2]) == ("ssh", "vm1")
    assert any("/proc/sysrq-trigger" in part for part in ssh.argv)
    assert ssh.argv[-2:] == ["sysrq-g", "g"]


def test_sysrq_g_without_ssh_runner_raises_unavailable_not_attributeerror():
    # A sysrq_g plan whose transport handed no ssh_runner (e.g. serial-local break_resources) must
    # fail with a structured break_inject_unavailable, never dereference None and raise AttributeError.
    with pytest.raises(InjectBreakError) as exc:
        inject_break(
            method=BreakMethod.SYSRQ_G,
            break_plan=_plan(BreakMethod.SYSRQ_G),
            proxy=None,
            proxy_handle=None,
            ssh_runner=None,
            ssh_argv_prefix=(),
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert exc.value.details.get("code") == "break_inject_unavailable"


def test_requested_method_not_in_admitted_plan_is_rejected():
    with pytest.raises(InjectBreakError) as exc:
        inject_break(
            method=BreakMethod.SYSRQ_G,
            break_plan=_plan(BreakMethod.UART_BREAK),
            proxy=_RecordingProxy(),
            proxy_handle=object(),
            ssh_runner=_RecordingSsh(),
            ssh_argv_prefix=("ssh", "vm1"),
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_gdbstub_native_is_not_an_inject_break_argument():
    with pytest.raises(InjectBreakError):
        inject_break(
            method=BreakMethod.GDBSTUB_NATIVE,
            break_plan=_plan(BreakMethod.GDBSTUB_NATIVE),
            proxy=None,
            proxy_handle=None,
            ssh_runner=None,
            ssh_argv_prefix=(),
        )
