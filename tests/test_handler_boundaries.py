from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
SERVER_SOURCE = ROOT / "src" / "kdive" / "server.py"
INTROSPECT_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "introspect" / "handlers.py"
INTROSPECT_EXECUTION_SOURCE = ROOT / "src" / "kdive" / "introspect" / "execution.py"
POSTMORTEM_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "postmortem" / "handlers.py"
SHARED_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "handlers" / "shared.py"


def test_extracted_handler_modules_do_not_import_server_module() -> None:
    handler_sources = [
        path
        for path in (ROOT / "src" / "kdive").rglob("*.py")
        if path.name in {"handlers.py", "session_handlers.py", "crash_handler.py"}
    ]

    offenders = [
        path.relative_to(ROOT) for path in handler_sources if "kdive.server" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_server_does_not_own_shared_probe_helpers() -> None:
    server_source = SERVER_SOURCE.read_text(encoding="utf-8")

    assert "PROBE_STDOUT_CAP =" not in server_source

    duplicated_helpers = [
        "_resolve_probe_context",
        "_reject_if_target_halted",
        "_prepare_probe_dirs",
        "_parse_probe_stdout",
        "_no_json_response",
        "_assemble_probe_response",
        "_probe_success",
        "_assemble_kdump_response",
    ]

    assert [helper for helper in duplicated_helpers if f"def {helper}(" in server_source] == []


def test_live_introspection_does_not_keep_passthrough_wrappers() -> None:
    handler_source = INTROSPECT_HANDLERS_SOURCE.read_text(encoding="utf-8")
    execution_source = INTROSPECT_EXECUTION_SOURCE.read_text(encoding="utf-8")

    assert "def _execute_live_introspect_call(" not in handler_source
    assert "def _prepare_live_wrapper(" not in execution_source


def test_target_probe_helpers_live_in_domain_named_module() -> None:
    shared_source = SHARED_HANDLERS_SOURCE.read_text(encoding="utf-8")
    introspect_source = INTROSPECT_HANDLERS_SOURCE.read_text(encoding="utf-8")
    postmortem_source = POSTMORTEM_HANDLERS_SOURCE.read_text(encoding="utf-8")

    assert "def _resolve_probe_context(" not in shared_source
    assert "def _parse_probe_stdout(" not in shared_source
    assert "from kdive.target.probes import" in introspect_source
    assert "from kdive.target.probes import" in postmortem_source


def test_server_does_not_reexport_private_feature_helpers() -> None:
    import kdive.server as server

    private_feature_helpers = {
        "_admit_run_tests_ssh_tier",
        "_artifact_run_relative_ref",
        "_boot_under_locks",
        "_break_entry_method",
        "_build_profile_from_manifest",
        "_capture_kernel_provenance",
        "_engine_op_data",
        "_find_artifact",
        "_find_kernel_image",
        "_halt_debug_transport",
        "_interrupt_op_data",
        "_publish_boot_ready_snapshot",
        "_record_introspect_failure",
        "_resolve_boot_inputs",
        "_rollback_introspect_admission",
        "_ssh_host_is_unset_or_loopback",
        "_target_python_remote_argv",
        "_validated_guest_ip",
    }

    leaked = sorted(name for name in private_feature_helpers if hasattr(server, name))

    assert leaked == []
