"""Compatibility re-exports for postmortem handlers."""

from kdive.postmortem.crash.handler import resolve_postmortem_vmcore_context
from kdive.postmortem.dump_handlers import (
    build_scp_argv,
    debug_postmortem_check_prereqs_handler,
    debug_postmortem_fetch_handler,
    debug_postmortem_list_dumps_handler,
)
from kdive.postmortem.triage_handlers import debug_postmortem_triage_handler

__all__ = (
    "build_scp_argv",
    "debug_postmortem_check_prereqs_handler",
    "debug_postmortem_fetch_handler",
    "debug_postmortem_list_dumps_handler",
    "debug_postmortem_triage_handler",
    "resolve_postmortem_vmcore_context",
)
