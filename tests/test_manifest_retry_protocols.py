from kdive.introspect import execution as introspect_execution
from kdive.postmortem import crash_handler


def test_path_specific_manifest_retry_helpers_do_not_reuse_generic_name() -> None:
    assert hasattr(introspect_execution, "_record_introspect_step_with_retry")
    assert hasattr(crash_handler, "_record_postmortem_crash_step_with_retry")
    assert not hasattr(introspect_execution, "_record_step_with_retry")
    assert not hasattr(crash_handler, "_record_step_with_retry")
