from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.providers.gdb_mi import (
    BreakpointRef,
    Frame,
    GdbMiEngine,
    GdbMiError,
    MiController,
    StopRecord,
    Variable,
)
from linux_debug_mcp.transport.base import TcpEndpoint


class FakeController:
    """Scripted MiController: write() pops the next write-response; read() pops the next
    read-response (default empty). Each item is a list of raw pygdbmi dicts or an Exception."""

    def __init__(self, writes: list[object], reads: list[object] | None = None) -> None:
        self._writes = list(writes)
        self._reads = list(reads or [])
        self.commands: list[str] = []
        self.exited = False

    def write(self, command: str, *, timeout_sec: float) -> list[dict[str, object]]:
        self.commands.append(command)
        item = self._writes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def read(self, *, timeout_sec: float) -> list[dict[str, object]]:
        if not self._reads:
            return []
        item = self._reads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def exit(self) -> None:
        self.exited = True


_DONE: list[dict[str, object]] = [{"type": "result", "message": "done", "payload": None, "token": None}]
_CONNECTED: list[dict[str, object]] = [{"type": "result", "message": "connected", "payload": None, "token": None}]
_RUNNING: list[dict[str, object]] = [{"type": "result", "message": "running", "payload": None, "token": None}]
# attach() issues six commands: confirm off, pagination off, mi-async on, file-exec-and-symbols,
# remotetimeout (ADR 0023), then the connect (^connected).
_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _DONE, _CONNECTED]


def _stopped(reason: str) -> list[dict[str, object]]:
    return [
        {
            "type": "notify",
            "message": "stopped",
            "payload": {"reason": reason, "bkptno": "1", "frame": {"func": "do_sys_open", "level": "0"}},
            "token": None,
        }
    ]


def _engine(controller: FakeController, redactor: object | None = None) -> GdbMiEngine:
    return GdbMiEngine(
        controller_factory=lambda command: controller,
        gdb_path_finder=lambda _: "/usr/bin/gdb",
        redactor=redactor,  # None => default Redactor
    )


def _attached(tmp_path: Path, writes: list[object], reads: list[object] | None = None, redactor: object | None = None):
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([*_ATTACH_OK, *writes], reads=reads)
    engine = _engine(controller, redactor=redactor)
    attachment = engine.attach(
        rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),
        vmlinux_path=vmlinux,
        transcript_path=tmp_path / "mi.log",
    )
    return engine, controller, attachment


# --- Task 2: read() seam --------------------------------------------------------------------------


def test_fakecontroller_with_read_satisfies_protocol() -> None:
    controller = FakeController([[{"type": "result", "message": "done", "payload": None, "token": None}]])
    assert isinstance(controller, MiController)


# --- Task 3: typed records ------------------------------------------------------------------------


def test_typed_records_construct_and_forbid_extra() -> None:
    frame = Frame(level=0, func="do_sys_open", addr="0xffffffff81234560", file="open.c", line=1234)
    stop = StopRecord(reason="breakpoint-hit", bkptno="1", frame=frame, stopped_thread="1")
    assert stop.reason == "breakpoint-hit"
    assert stop.frame is not None and stop.frame.func == "do_sys_open"
    var = Variable(name="fd", value="3")
    assert var.value == "3"
    bp = BreakpointRef(number="1", type="breakpoint", addr="0xffffffff81234560", func="do_sys_open")
    assert bp.number == "1"
    with pytest.raises(ValidationError):
        StopRecord(reason="x", bogus_extra="nope")  # type: ignore[call-arg]


# --- Task 4: wait_for_stop + interrupt ------------------------------------------------------------


def test_wait_for_stop_returns_deferred_stopped_record(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[], reads=[[], _stopped("breakpoint-hit")])
    stop = engine.wait_for_stop(attachment, timeout_sec=5)
    assert isinstance(stop, StopRecord)
    assert stop.reason == "breakpoint-hit"
    assert stop.frame is not None and stop.frame.func == "do_sys_open"


def test_wait_for_stop_times_out_to_none(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[], reads=[[]])
    assert engine.wait_for_stop(attachment, timeout_sec=0) is None


def test_wait_for_stop_on_exited_inferior_raises_session_exited(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[], reads=[_stopped("exited-normally")])
    with pytest.raises(GdbMiError) as exc:
        engine.wait_for_stop(attachment, timeout_sec=5)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    assert exc.value.details.get("code") == "session_exited"


def test_interrupt_on_stopped_engine_tolerates_error(tmp_path: Path) -> None:
    err = [{"type": "result", "message": "error", "payload": {"msg": "not being run"}, "token": None}]
    engine, controller, attachment = _attached(tmp_path, writes=[err], reads=[[]])
    stop = engine.interrupt(attachment)
    assert stop is None or isinstance(stop, StopRecord)
    assert "-exec-interrupt" in controller.commands


# --- Task 5: resume (continue) --------------------------------------------------------------------


def test_continue_waits_for_deferred_stopped_record(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_RUNNING], reads=[[], _stopped("breakpoint-hit")])
    stop = engine.resume(attachment, "-exec-continue", timeout_sec=5)
    assert isinstance(stop, StopRecord)
    assert stop.reason == "breakpoint-hit"
    assert stop.timed_out is False
    assert "-exec-continue" in controller.commands


def test_continue_timeout_interrupts_and_marks_timed_out(tmp_path: Path) -> None:
    # No breakpoint fires, so the continue wait drains to None (timeout) after its 3 read slices
    # (timeout_sec=1); resume then issues -exec-interrupt and the kernel answers with a SIGINT stop,
    # so it reports timed_out=True (benign) with the target back at a known stop. The SIGINT stop is
    # placed AFTER the continue wait's empties so only the interrupt wait observes it.
    engine, controller, attachment = _attached(
        tmp_path,
        writes=[_RUNNING, _DONE],  # continue ^running, then interrupt ^done
        reads=[[], [], [], _stopped("signal-received")],
    )
    stop = engine.resume(attachment, "-exec-continue", timeout_sec=1)
    assert stop.timed_out is True
    assert "-exec-interrupt" in controller.commands


# --- Task 7: breakpoints / watchpoints ------------------------------------------------------------

_BKPT_OK = [
    {
        "type": "result",
        "message": "done",
        "payload": {"bkpt": {"number": "1", "type": "breakpoint", "addr": "0xffffffff81234560", "func": "do_sys_open"}},
        "token": None,
    }
]
_WPT_OK = [{"type": "result", "message": "done", "payload": {"wpt": {"number": "2", "exp": "jiffies"}}, "token": None}]


def test_set_breakpoint_returns_typed_ref(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_BKPT_OK])
    bp = engine.set_breakpoint(attachment, "do_sys_open")
    assert isinstance(bp, BreakpointRef)
    assert bp.number == "1" and bp.func == "do_sys_open"
    # Hardware breakpoint (-h): a software breakpoint does not survive a frozen boot's reset-vector
    # insertion and can fail on read-only kernel .text (ADR 0036).
    assert controller.commands[-1] == "-break-insert -h do_sys_open"


def test_set_breakpoint_rejects_non_identifier(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.set_breakpoint(attachment, "do_sys_open; call panic")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before


def test_set_watchpoint_issues_break_watch(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_WPT_OK])
    bp = engine.set_watchpoint(attachment, "jiffies")
    assert bp.number == "2"
    assert controller.commands[-1] == "-break-watch jiffies"


def test_clear_breakpoint_issues_break_delete(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_DONE])
    engine.clear_breakpoint(attachment, "1")
    assert controller.commands[-1] == "-break-delete 1"


def test_clear_breakpoint_rejects_non_numeric_id(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    with pytest.raises(GdbMiError) as exc:
        engine.clear_breakpoint(attachment, "1; quit")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_clear_watchpoint_uses_break_delete(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_DONE])
    engine.clear_watchpoint(attachment, "2")
    assert controller.commands[-1] == "-break-delete 2"


# --- Task 8: backtrace / list_variables -----------------------------------------------------------

# pygdbmi flattens `stack=[frame={...},frame={...}]` to a list of the frame dicts directly (no
# "frame" wrapper) — this is the real shape gdb/MI emits (verified against pygdbmi).
_FRAMES_FLAT = [
    {
        "type": "result",
        "message": "done",
        "payload": {
            "stack": [
                {"level": "0", "func": "do_sys_open", "addr": "0x1"},
                {"level": "1", "func": "__x64_sys_open", "addr": "0x2"},
            ]
        },
        "token": None,
    }
]
# Defensive: a pygdbmi variant that preserves the `{"frame": {...}}` wrapper must still parse.
_FRAMES_WRAPPED = [
    {
        "type": "result",
        "message": "done",
        "payload": {
            "stack": [
                {"frame": {"level": "0", "func": "do_sys_open", "addr": "0x1"}},
                {"frame": {"level": "1", "func": "__x64_sys_open", "addr": "0x2"}},
            ]
        },
        "token": None,
    }
]
_VARS = [
    {
        "type": "result",
        "message": "done",
        "payload": {"variables": [{"name": "fd", "value": "3"}, {"name": "token", "value": "secret-value"}]},
        "token": None,
    }
]


class _StubRedactor:
    """Proves the redaction PATH is wired without depending on the default Redactor's patterns:
    every string value is replaced with a sentinel."""

    def redact_value(self, value: object) -> object:
        if isinstance(value, dict):
            return {key: self.redact_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, str):
            return "[REDACTED]"
        return value

    def redact_text(self, value: str) -> str:
        return "[REDACTED]"


@pytest.mark.parametrize("frames_response", [_FRAMES_FLAT, _FRAMES_WRAPPED])
def test_backtrace_returns_typed_frames(tmp_path: Path, frames_response: list[object]) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[frames_response])
    frames = engine.backtrace(attachment)
    assert [frame.func for frame in frames] == ["do_sys_open", "__x64_sys_open"]
    assert [frame.level for frame in frames] == [0, 1]
    assert controller.commands[-1] == "-stack-list-frames"


def test_list_variables_passes_values_through_redactor(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_VARS], redactor=_StubRedactor())
    variables = engine.list_variables(attachment)
    names = {variable.name for variable in variables}
    assert names == {"[REDACTED]"}  # stub masks the names too
    masked = next(variable for variable in variables if variable.value is not None)
    assert masked.value == "[REDACTED]"  # the value went through the injected redactor
    assert controller.commands[-1] == "-stack-list-variables --all-values"


# --- Task 9: registers / memory / symbol / evaluate -----------------------------------------------

_REG_NAMES = [{"type": "result", "message": "done", "payload": {"register-names": ["rax", "rbx", "pc"]}, "token": None}]
_REG_VALUES = [
    {
        "type": "result",
        "message": "done",
        "payload": {
            "register-values": [
                {"number": "0", "value": "0x10"},
                {"number": "1", "value": "0x20"},
                {"number": "2", "value": "0xffffffff81000000"},
            ]
        },
        "token": None,
    }
]
_MEM = [
    {
        "type": "result",
        "message": "done",
        "payload": {"memory": [{"begin": "0x1000", "contents": "deadbeef"}]},
        "token": None,
    }
]
_EVAL_BANNER = [{"type": "result", "message": "done", "payload": {"value": "Linux version 6.9.0 ..."}, "token": None}]
_EVAL_ADDR = [
    {"type": "result", "message": "done", "payload": {"value": "0xffffffff82000000 <jiffies>"}, "token": None}
]


def test_read_registers_returns_only_requested(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_REG_NAMES, _REG_VALUES])
    result = engine.read_registers(attachment, ["pc"])
    assert set(result["registers"].keys()) == {"pc"}  # not rax/rbx
    assert result["registers"]["pc"] == "0xffffffff81000000"


def test_read_memory_rejects_over_cap_without_touching_gdb(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.read_memory(attachment, address=0x1000, byte_count=4097)
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before


def test_read_memory_within_cap_issues_data_read(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_MEM])
    result = engine.read_memory(attachment, address=0x1000, byte_count=4)
    assert controller.commands[-1] == "-data-read-memory-bytes 0x1000 4"
    assert result["byte_count"] == 4


def test_evaluate_kernel_version_uses_banner(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_EVAL_BANNER])
    value = engine.evaluate_inspector(attachment, inspector="kernel_version", arguments={})
    assert "Linux version" in value["kernel_version"]
    assert controller.commands[-1] == '-data-evaluate-expression "linux_banner"'


def test_evaluate_symbol_address_resolves_name(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_EVAL_ADDR])
    value = engine.evaluate_inspector(attachment, inspector="symbol_address", arguments={"symbol": "jiffies"})
    assert value["symbol"] == "jiffies"
    assert controller.commands[-1] == '-data-evaluate-expression "&jiffies"'


def test_evaluate_unknown_inspector_rejected_before_gdb(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[])
    before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.evaluate_inspector(attachment, inspector="$(rm -rf)", arguments={})
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == before


def test_read_symbol_evaluates_validated_name(tmp_path: Path) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_EVAL_BANNER])
    value = engine.read_symbol(attachment, "linux_banner")
    assert "Linux version" in value["value"]
    assert controller.commands[-1] == '-data-evaluate-expression "linux_banner"'


# --- Task 10: step / next / finish ----------------------------------------------------------------


@pytest.mark.parametrize(
    "method,verb",
    [("step", "-exec-step"), ("next", "-exec-next"), ("finish", "-exec-finish")],
)
def test_step_family_issues_verb_and_returns_stop(tmp_path: Path, method: str, verb: str) -> None:
    engine, controller, attachment = _attached(tmp_path, writes=[_RUNNING], reads=[_stopped("end-stepping-range")])
    stop = getattr(engine, method)(attachment, timeout_sec=5)
    assert stop.reason == "end-stepping-range"
    assert verb in controller.commands
