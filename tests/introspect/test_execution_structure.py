import inspect

from kdive.introspect import execution


def test_introspect_finalizer_delegates_terminal_phases() -> None:
    helper_names = [
        "_triage_introspect_runner_output",
        "_map_introspect_wrapper_failure",
        "_record_introspect_success",
    ]
    for helper_name in helper_names:
        assert hasattr(execution, helper_name)

    finalizer_source = inspect.getsource(execution._finalize_introspect_call)
    for helper_name in helper_names:
        assert finalizer_source.count(helper_name) == 1
