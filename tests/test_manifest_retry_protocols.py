from kdive import server
from kdive.introspect import execution as introspect_execution
from kdive.postmortem import crash_handler


def test_path_specific_manifest_retry_helpers_do_not_reuse_generic_name() -> None:
    assert hasattr(introspect_execution, "_record_introspect_step_with_retry")
    assert hasattr(crash_handler, "_record_postmortem_crash_step_with_retry")
    assert not hasattr(introspect_execution, "_record_step_with_retry")
    assert not hasattr(crash_handler, "_record_step_with_retry")


def test_server_reuses_extracted_introspect_rollback_helper() -> None:
    assert server._rollback_introspect_admission is introspect_execution._rollback_introspect_admission
