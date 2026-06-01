from __future__ import annotations

from functools import partial
from typing import cast

from kdive.debug.handlers import (
    debug_backtrace_handler as _debug_backtrace_handler,
)
from kdive.debug.handlers import (
    debug_clear_breakpoint_handler as _debug_clear_breakpoint_handler,
)
from kdive.debug.handlers import (
    debug_clear_watchpoint_handler as _debug_clear_watchpoint_handler,
)
from kdive.debug.handlers import (
    debug_continue_handler as _debug_continue_handler,
)
from kdive.debug.handlers import (
    debug_evaluate_handler as _debug_evaluate_handler,
)
from kdive.debug.handlers import (
    debug_finish_handler as _debug_finish_handler,
)
from kdive.debug.handlers import (
    debug_interrupt_handler as _debug_interrupt_handler,
)
from kdive.debug.handlers import (
    debug_list_breakpoints_handler as _debug_list_breakpoints_handler,
)
from kdive.debug.handlers import (
    debug_list_variables_handler as _debug_list_variables_handler,
)
from kdive.debug.handlers import (
    debug_next_handler as _debug_next_handler,
)
from kdive.debug.handlers import (
    debug_read_memory_handler as _debug_read_memory_handler,
)
from kdive.debug.handlers import (
    debug_read_registers_handler as _debug_read_registers_handler,
)
from kdive.debug.handlers import (
    debug_read_symbol_handler as _debug_read_symbol_handler,
)
from kdive.debug.handlers import (
    debug_set_breakpoint_handler as _debug_set_breakpoint_handler,
)
from kdive.debug.handlers import (
    debug_set_watchpoint_handler as _debug_set_watchpoint_handler,
)
from kdive.debug.handlers import (
    debug_step_handler as _debug_step_handler,
)
from kdive.debug.module_symbols import debug_load_module_symbols_handler
from kdive.debug.operations import _debug_operation_response
from kdive.debug.session_end import debug_end_session_handler
from kdive.debug.session_handlers import debug_start_session_handler
from kdive.debug.tools import (
    DebugBreakpointIdControlHandler,
    DebugEvaluateHandler,
    DebugExecutionControlHandler,
    DebugReadMemoryHandler,
    DebugReadRegistersHandler,
    DebugReadSymbolHandler,
    DebugSessionQueryHandler,
    DebugSymbolControlHandler,
    DebugToolHandlers,
)

debug_read_registers_handler = cast(
    DebugReadRegistersHandler, partial(_debug_read_registers_handler, operation_core=_debug_operation_response)
)
debug_read_symbol_handler = cast(
    DebugReadSymbolHandler, partial(_debug_read_symbol_handler, operation_core=_debug_operation_response)
)
debug_read_memory_handler = cast(
    DebugReadMemoryHandler, partial(_debug_read_memory_handler, operation_core=_debug_operation_response)
)
debug_evaluate_handler = cast(
    DebugEvaluateHandler, partial(_debug_evaluate_handler, operation_core=_debug_operation_response)
)
debug_set_breakpoint_handler = cast(
    DebugSymbolControlHandler, partial(_debug_set_breakpoint_handler, operation_core=_debug_operation_response)
)
debug_set_watchpoint_handler = cast(
    DebugSymbolControlHandler, partial(_debug_set_watchpoint_handler, operation_core=_debug_operation_response)
)
debug_clear_breakpoint_handler = cast(
    DebugBreakpointIdControlHandler, partial(_debug_clear_breakpoint_handler, operation_core=_debug_operation_response)
)
debug_clear_watchpoint_handler = cast(
    DebugBreakpointIdControlHandler, partial(_debug_clear_watchpoint_handler, operation_core=_debug_operation_response)
)
debug_list_breakpoints_handler = cast(
    DebugSessionQueryHandler, partial(_debug_list_breakpoints_handler, operation_core=_debug_operation_response)
)
debug_backtrace_handler = cast(
    DebugSessionQueryHandler, partial(_debug_backtrace_handler, operation_core=_debug_operation_response)
)
debug_list_variables_handler = cast(
    DebugSessionQueryHandler, partial(_debug_list_variables_handler, operation_core=_debug_operation_response)
)
debug_continue_handler = cast(
    DebugExecutionControlHandler, partial(_debug_continue_handler, operation_core=_debug_operation_response)
)
debug_step_handler = cast(
    DebugExecutionControlHandler, partial(_debug_step_handler, operation_core=_debug_operation_response)
)
debug_next_handler = cast(
    DebugExecutionControlHandler, partial(_debug_next_handler, operation_core=_debug_operation_response)
)
debug_finish_handler = cast(
    DebugExecutionControlHandler, partial(_debug_finish_handler, operation_core=_debug_operation_response)
)
debug_interrupt_handler = cast(
    DebugExecutionControlHandler, partial(_debug_interrupt_handler, operation_core=_debug_operation_response)
)


def debug_tool_handlers() -> DebugToolHandlers:
    return DebugToolHandlers(
        start_session=debug_start_session_handler,
        read_registers=debug_read_registers_handler,
        read_symbol=debug_read_symbol_handler,
        read_memory=debug_read_memory_handler,
        evaluate=debug_evaluate_handler,
        load_module_symbols=debug_load_module_symbols_handler,
        set_breakpoint=debug_set_breakpoint_handler,
        set_watchpoint=debug_set_watchpoint_handler,
        clear_breakpoint=debug_clear_breakpoint_handler,
        clear_watchpoint=debug_clear_watchpoint_handler,
        list_breakpoints=debug_list_breakpoints_handler,
        backtrace=debug_backtrace_handler,
        list_variables=debug_list_variables_handler,
        continue_execution=debug_continue_handler,
        step=debug_step_handler,
        next=debug_next_handler,
        finish=debug_finish_handler,
        interrupt=debug_interrupt_handler,
        end_session=debug_end_session_handler,
    )
