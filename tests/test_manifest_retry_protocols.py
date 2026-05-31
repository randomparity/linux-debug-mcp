from kdive import server
from kdive.introspect import execution as introspect_execution
from kdive.postmortem import crash_handler
from kdive.postmortem import handlers as postmortem_handlers


def test_path_specific_manifest_retry_helpers_do_not_reuse_generic_name() -> None:
    assert hasattr(introspect_execution, "_record_introspect_step_with_retry")
    assert hasattr(crash_handler, "_record_postmortem_crash_step_with_retry")
    assert not hasattr(introspect_execution, "_record_step_with_retry")
    assert not hasattr(crash_handler, "_record_step_with_retry")


def test_server_reuses_extracted_introspect_rollback_helper() -> None:
    assert server._rollback_introspect_admission is introspect_execution._rollback_introspect_admission


def test_postmortem_dump_handlers_are_owned_by_postmortem_module() -> None:
    assert postmortem_handlers.debug_postmortem_check_prereqs_handler.__module__ == "kdive.postmortem.handlers"
    assert postmortem_handlers.debug_postmortem_list_dumps_handler.__module__ == "kdive.postmortem.handlers"
    assert postmortem_handlers.debug_postmortem_fetch_handler.__module__ == "kdive.postmortem.handlers"
    assert server.debug_postmortem_check_prereqs_handler is postmortem_handlers.debug_postmortem_check_prereqs_handler
    assert server.debug_postmortem_list_dumps_handler is postmortem_handlers.debug_postmortem_list_dumps_handler
    assert server.debug_postmortem_fetch_handler is postmortem_handlers.debug_postmortem_fetch_handler
