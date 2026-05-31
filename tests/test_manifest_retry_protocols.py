from kdive import server
from kdive.debug import session_handlers
from kdive.introspect import execution as introspect_execution
from kdive.postmortem import crash_handler
from kdive.postmortem import handlers as postmortem_handlers
from kdive.transport.base import Transport


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


def test_debug_start_session_handler_is_owned_by_debug_module() -> None:
    assert session_handlers.debug_start_session_handler.__module__ == "kdive.debug.session_handlers"
    assert server.debug_start_session_handler is session_handlers.debug_start_session_handler


def test_default_transport_reap_backend_is_bare_noop() -> None:
    import inspect

    assert "return None" not in inspect.getsource(Transport.reap_backend)
