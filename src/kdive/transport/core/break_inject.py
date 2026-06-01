from __future__ import annotations

from pathlib import Path
from typing import Literal

from kdive.domain import ErrorCategory
from kdive.transport.core.base import BreakMethod, BreakPlan
from kdive.transport.core.break_types import BreakProxy, BreakSshRunner

BreakRequestMethod = Literal["auto"] | BreakMethod


class InjectBreakError(Exception):
    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        # Optional structured details carried into the failure response. The handler passes the dict
        # through `Redactor.redact_value` before surfacing it, so a mechanism that attaches an
        # endpoint path or secret-looking value to context never leaks raw.
        self.details: dict[str, object] = dict(details or {})


_REQUESTABLE = frozenset(method for method in BreakMethod if method is not BreakMethod.GDBSTUB_NATIVE)
_SYSRQ_G_WRITE_TIMEOUT_SECONDS = 10


def _normalize_break_request_method(method: BreakRequestMethod) -> BreakMethod | None:
    return None if method == "auto" else BreakMethod(method)


def _sysrq_g_failed(result: object) -> bool:
    return (
        getattr(result, "exit_status", -1) != 0
        or bool(getattr(result, "timed_out", False))
        or bool(getattr(result, "cancelled", False))
        or bool(getattr(result, "stdin_failed", False))
        or bool(getattr(result, "oversized_output", False))
    )


def _sysrq_g_failure_details(result: object) -> dict[str, object]:
    return {
        "code": "sysrq_g_write_failed",
        "exit_status": getattr(result, "exit_status", None),
        "timed_out": bool(getattr(result, "timed_out", False)),
        "cancelled": bool(getattr(result, "cancelled", False)),
        "stdin_failed": bool(getattr(result, "stdin_failed", False)),
        "oversized_output": bool(getattr(result, "oversized_output", False)),
        "stdout_snippet": getattr(result, "stdout_snippet", ""),
        "stderr_snippet": getattr(result, "stderr_snippet", ""),
    }


def inject_break(
    *,
    method: BreakRequestMethod,
    break_plan: BreakPlan,
    proxy: BreakProxy | None,
    proxy_handle: object | None,
    ssh_runner: BreakSshRunner | None,
    ssh_argv_prefix: tuple[str, ...],
    work_dir: Path | None = None,
) -> None:
    """Execute the admitted break plan (§6.4). gdbstub_native is not a valid argument
    (gdb interrupts directly). A requested method not equal to the admitted plan's method
    is rejected, not attempted. No kernel is halted in tests — proxy/ssh are fakes."""
    if method == BreakMethod.GDBSTUB_NATIVE or break_plan.method is BreakMethod.GDBSTUB_NATIVE:
        raise InjectBreakError("gdbstub_native needs no break injection", category=ErrorCategory.CONFIGURATION_ERROR)
    try:
        resolved = _normalize_break_request_method(method) or break_plan.method
    except ValueError as exc:
        raise InjectBreakError(f"unknown break method: {method}", category=ErrorCategory.CONFIGURATION_ERROR) from exc
    if resolved not in _REQUESTABLE:
        raise InjectBreakError(f"unsupported method {resolved.value}", category=ErrorCategory.CONFIGURATION_ERROR)
    if resolved is not break_plan.method:
        raise InjectBreakError(
            f"requested {resolved.value} is not the admitted plan method {break_plan.method.value}",
            category=ErrorCategory.CONFIGURATION_ERROR,
        )
    if resolved in (BreakMethod.UART_BREAK, BreakMethod.AGENT_PROXY_BREAK):
        if proxy is None:
            raise InjectBreakError(
                f"{resolved.value} break requires a proxy handle, but none is wired for this transport",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"code": "break_inject_unavailable"},
            )
        proxy.send_break(proxy_handle)
        return
    if resolved is BreakMethod.SYSRQ_G:
        if ssh_runner is None:
            # The transport admitted a sysrq_g plan but handed no ssh runner (e.g. serial-local
            # break_resources, which wires only the agent-proxy). Fail with a structured
            # break_inject_unavailable rather than dereferencing None into an AttributeError that a
            # caller would misclassify as an engine fault.
            raise InjectBreakError(
                "sysrq_g break requires an ssh runner, but none is wired for this transport",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"code": "break_inject_unavailable"},
            )
        base = work_dir or Path(".")
        # sh -c SCRIPT $0 $1 ...: pass "g" as a discrete argv token ($1), not embedded in the
        # script string, so the trigger char is never shell-interpolated. $0 is just a label.
        argv = [*ssh_argv_prefix, "sh", "-c", 'echo "$1" > /proc/sysrq-trigger', "sysrq-g", "g"]
        result = ssh_runner.run(
            argv,
            timeout=_SYSRQ_G_WRITE_TIMEOUT_SECONDS,
            stdout_path=base / "sysrq.out",
            stderr_path=base / "sysrq.err",
        )
        if _sysrq_g_failed(result):
            raise InjectBreakError(
                "sysrq-g write failed",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details=_sysrq_g_failure_details(result),
            )
        return
    raise InjectBreakError(f"unsupported method {resolved.value}", category=ErrorCategory.CONFIGURATION_ERROR)
