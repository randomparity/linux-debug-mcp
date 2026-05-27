from __future__ import annotations

from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan


class InjectBreakError(Exception):
    def __init__(self, message: str, *, category: ErrorCategory) -> None:
        super().__init__(message)
        self.category = category


_REQUESTABLE = {"auto", "uart_break", "agent_proxy_break", "sysrq_g"}


def inject_break(
    *,
    method: str,
    break_plan: BreakPlan,
    proxy,
    proxy_handle,
    ssh_runner,
    ssh_argv_prefix,
    work_dir: Path | None = None,
) -> None:
    """Execute the admitted break plan (§6.4). gdbstub_native is not a valid argument
    (gdb interrupts directly). A requested method not equal to the admitted plan's method
    is rejected, not attempted. No kernel is halted in tests — proxy/ssh are fakes."""
    if method == "gdbstub_native" or break_plan.method is BreakMethod.GDBSTUB_NATIVE:
        raise InjectBreakError("gdbstub_native needs no break injection", category=ErrorCategory.CONFIGURATION_ERROR)
    if method not in _REQUESTABLE:
        raise InjectBreakError(f"unknown break method: {method}", category=ErrorCategory.CONFIGURATION_ERROR)
    resolved = break_plan.method if method == "auto" else BreakMethod(method)
    if resolved is not break_plan.method:
        raise InjectBreakError(
            f"requested {resolved.value} is not the admitted plan method {break_plan.method.value}",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    if resolved in (BreakMethod.UART_BREAK, BreakMethod.AGENT_PROXY_BREAK):
        proxy.send_break(proxy_handle)
        return
    if resolved is BreakMethod.SYSRQ_G:
        base = work_dir or Path(".")
        argv = [*ssh_argv_prefix, "sh", "-c", 'echo "$1" > /proc/sysrq-trigger', "--", "g"]
        result = ssh_runner.run(argv, timeout=10, stdout_path=base / "sysrq.out", stderr_path=base / "sysrq.err")
        if getattr(result, "returncode", 0) != 0:
            raise InjectBreakError("sysrq-g write failed", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        return
    raise InjectBreakError(f"unsupported method {resolved.value}", category=ErrorCategory.CONFIGURATION_ERROR)
