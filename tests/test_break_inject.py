import pytest

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan
from linux_debug_mcp.transport.break_inject import InjectBreakError, inject_break


class _RecordingProxy:
    def __init__(self):
        self.breaks = 0

    def send_break(self, handle):
        self.breaks += 1


class _RecordingSsh:
    def __init__(self):
        self.argv = None

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
        # Plan review finding 4: this fake was missing both `cancel` and
        # `stdin` — the audit added them at once so ty check accepts the
        # SshRunner protocol assignment in server.py.
        self.argv = argv

        class _R:
            returncode = 0

        return _R()


def _plan(method):
    return BreakPlan(method=method, channel_id="c0", rationale="test")


def test_auto_dispatches_uart_break_to_proxy_send_break():
    proxy = _RecordingProxy()
    inject_break(
        method="auto",
        break_plan=_plan(BreakMethod.UART_BREAK),
        proxy=proxy,
        proxy_handle=object(),
        ssh_runner=None,
        ssh_argv_prefix=None,
    )
    assert proxy.breaks == 1


def test_agent_proxy_break_also_uses_send_break():
    proxy = _RecordingProxy()
    inject_break(
        method="agent_proxy_break",
        break_plan=_plan(BreakMethod.AGENT_PROXY_BREAK),
        proxy=proxy,
        proxy_handle=object(),
        ssh_runner=None,
        ssh_argv_prefix=None,
    )
    assert proxy.breaks == 1


def test_sysrq_g_writes_g_to_sysrq_trigger_over_ssh(tmp_path):
    ssh = _RecordingSsh()
    inject_break(
        method="sysrq_g",
        break_plan=_plan(BreakMethod.SYSRQ_G),
        proxy=None,
        proxy_handle=None,
        ssh_runner=ssh,
        ssh_argv_prefix=["ssh", "vm1"],
        work_dir=tmp_path,
    )
    assert any("/proc/sysrq-trigger" in part for part in ssh.argv)
    assert "g" in ssh.argv


def test_sysrq_g_without_ssh_runner_raises_unavailable_not_attributeerror():
    # A sysrq_g plan whose transport handed no ssh_runner (e.g. serial-local break_resources) must
    # fail with a structured break_inject_unavailable, never dereference None and raise AttributeError.
    with pytest.raises(InjectBreakError) as exc:
        inject_break(
            method="sysrq_g",
            break_plan=_plan(BreakMethod.SYSRQ_G),
            proxy=None,
            proxy_handle=None,
            ssh_runner=None,
            ssh_argv_prefix=[],
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert exc.value.details.get("code") == "break_inject_unavailable"


def test_requested_method_not_in_admitted_plan_is_rejected():
    with pytest.raises(InjectBreakError) as exc:
        inject_break(
            method="sysrq_g",
            break_plan=_plan(BreakMethod.UART_BREAK),
            proxy=_RecordingProxy(),
            proxy_handle=object(),
            ssh_runner=_RecordingSsh(),
            ssh_argv_prefix=["ssh", "vm1"],
        )
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_gdbstub_native_is_not_an_inject_break_argument():
    with pytest.raises(InjectBreakError):
        inject_break(
            method="gdbstub_native",
            break_plan=_plan(BreakMethod.GDBSTUB_NATIVE),
            proxy=None,
            proxy_handle=None,
            ssh_runner=None,
            ssh_argv_prefix=None,
        )
