import inspect

from kdive.introspect import execution


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
