import inspect

from kdive.introspect import context, execution, result, runner


def test_introspect_execution_delegates_stable_pipeline_stages() -> None:
    assert execution._resolve_pre_admission_introspect_context is context._resolve_pre_admission_introspect_context
    assert execution._execute_admitted_introspect_ssh is runner._execute_admitted_introspect_ssh
    assert execution._finalize_introspect_call is result._finalize_introspect_call


def test_introspect_finalizer_accepts_workspace_and_run_bundles() -> None:
    signature = inspect.signature(execution._finalize_introspect_call)
    params = set(signature.parameters)

    assert set(params) == {"context"}
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
        "store",
        "run_id",
        "redactor",
        "expected_build_id",
        "request_timeout_seconds",
        "operation_name",
        "drgn_open_message",
        "exec_principal",
        "post_validator",
        "allow_write",
        "acknowledged_permissions",
    }.isdisjoint(params)
