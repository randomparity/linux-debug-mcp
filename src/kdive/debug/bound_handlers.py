from __future__ import annotations

from functools import partial

from kdive.debug.handlers import (
    debug_backtrace_handler,
    debug_clear_breakpoint_handler,
    debug_clear_watchpoint_handler,
    debug_continue_handler,
    debug_evaluate_handler,
    debug_finish_handler,
    debug_interrupt_handler,
    debug_list_breakpoints_handler,
    debug_list_variables_handler,
    debug_next_handler,
    debug_read_memory_handler,
    debug_read_registers_handler,
    debug_read_symbol_handler,
    debug_set_breakpoint_handler,
    debug_set_watchpoint_handler,
    debug_step_handler,
)
from kdive.debug.operations import _debug_operation_response

debug_read_registers_handler = partial(debug_read_registers_handler, operation_core=_debug_operation_response)
debug_read_symbol_handler = partial(debug_read_symbol_handler, operation_core=_debug_operation_response)
debug_read_memory_handler = partial(debug_read_memory_handler, operation_core=_debug_operation_response)
debug_evaluate_handler = partial(debug_evaluate_handler, operation_core=_debug_operation_response)
debug_set_breakpoint_handler = partial(debug_set_breakpoint_handler, operation_core=_debug_operation_response)
debug_set_watchpoint_handler = partial(debug_set_watchpoint_handler, operation_core=_debug_operation_response)
debug_clear_breakpoint_handler = partial(debug_clear_breakpoint_handler, operation_core=_debug_operation_response)
debug_clear_watchpoint_handler = partial(debug_clear_watchpoint_handler, operation_core=_debug_operation_response)
debug_list_breakpoints_handler = partial(debug_list_breakpoints_handler, operation_core=_debug_operation_response)
debug_backtrace_handler = partial(debug_backtrace_handler, operation_core=_debug_operation_response)
debug_list_variables_handler = partial(debug_list_variables_handler, operation_core=_debug_operation_response)
debug_continue_handler = partial(debug_continue_handler, operation_core=_debug_operation_response)
debug_step_handler = partial(debug_step_handler, operation_core=_debug_operation_response)
debug_next_handler = partial(debug_next_handler, operation_core=_debug_operation_response)
debug_finish_handler = partial(debug_finish_handler, operation_core=_debug_operation_response)
debug_interrupt_handler = partial(debug_interrupt_handler, operation_core=_debug_operation_response)
