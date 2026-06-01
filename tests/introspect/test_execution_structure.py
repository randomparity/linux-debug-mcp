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


def test_introspect_finalizer_accepts_workspace_and_run_bundles() -> None:
    signature = inspect.signature(execution._finalize_introspect_call)
    params = set(signature.parameters)

    assert {"workspace", "run"}.issubset(params)
    assert {
        "call_id",
        "ssh_result",
        "stdout_path",
        "stderr_path",
        "agent_dir",
        "sensitive_call_dir",
        "started_at",
        "finished_at",
        "duration_ms",
    }.isdisjoint(params)
