import inspect

from kdive.introspect import execution, handlers, result, vmcore_execution


def test_introspect_execution_does_not_reexport_private_pipeline_stages() -> None:
    assert not hasattr(execution, "_resolve_pre_admission_introspect_context")
    assert not hasattr(execution, "_execute_admitted_introspect_ssh")
    assert not hasattr(execution, "_finalize_introspect_call")
    assert "_execute_introspect_call" in execution.__all__


def test_introspect_finalizer_accepts_workspace_and_run_bundles() -> None:
    signature = inspect.signature(result._finalize_introspect_call)
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


def test_vmcore_execution_lives_outside_public_handler_adapters() -> None:
    assert handlers._execute_vmcore_introspect_call is vmcore_execution._execute_vmcore_introspect_call
    assert not hasattr(handlers, "VmcoreIntrospectRun")
