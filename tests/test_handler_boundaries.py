from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
SERVER_SOURCE = ROOT / "src" / "kdive" / "server.py"
INTROSPECT_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "introspect" / "handlers.py"
INTROSPECT_EXECUTION_SOURCE = ROOT / "src" / "kdive" / "introspect" / "execution.py"
POSTMORTEM_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "postmortem" / "handlers.py"
SHARED_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "handlers" / "shared.py"
PROBE_SEAM_SOURCE = ROOT / "src" / "kdive" / "seams" / "probes.py"


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


def test_shared_probe_helpers_live_in_public_boundary_module() -> None:
    shared_source = SHARED_HANDLERS_SOURCE.read_text(encoding="utf-8")
    introspect_source = INTROSPECT_HANDLERS_SOURCE.read_text(encoding="utf-8")
    postmortem_source = POSTMORTEM_HANDLERS_SOURCE.read_text(encoding="utf-8")

    assert "def _resolve_probe_context(" not in shared_source
    assert "def _parse_probe_stdout(" not in shared_source
    assert PROBE_SEAM_SOURCE.is_file()
    assert "from kdive.seams.probes import" in introspect_source
    assert "from kdive.seams.probes import" in postmortem_source
    assert "from kdive.target.probes import" not in introspect_source
    assert "from kdive.target.probes import" not in postmortem_source


def test_target_probe_substrate_does_not_own_feature_response_assembly() -> None:
    target_source = PROBE_SEAM_SOURCE.read_text(encoding="utf-8")
    introspect_source = INTROSPECT_HANDLERS_SOURCE.read_text(encoding="utf-8")
    postmortem_source = POSTMORTEM_HANDLERS_SOURCE.read_text(encoding="utf-8")

    assert "kdive.prereqs.drgn_probe" not in target_source
    assert "kdive.prereqs.kdump_probe" not in target_source
    assert "kdive.postmortem.dumps" not in target_source
    assert "def assemble_introspect_probe_response(" not in target_source
    assert "def assemble_kdump_probe_response(" not in target_source
    assert "from kdive.introspect.probes import assemble_introspect_probe_response" in introspect_source
    assert "from kdive.postmortem.probes import assemble_kdump_probe_response" in postmortem_source


def test_feature_probe_handlers_import_public_target_probe_substrate() -> None:
    for source_path in (INTROSPECT_HANDLERS_SOURCE, POSTMORTEM_HANDLERS_SOURCE):
        source = source_path.read_text(encoding="utf-8")
        assert "from kdive.seams.probes import (" in source
        assert "    _" not in source.split("from kdive.seams.probes import (", 1)[1].split(")", 1)[0]


def test_shared_probe_boundary_does_not_import_private_transport_handlers() -> None:
    probe_source = PROBE_SEAM_SOURCE.read_text(encoding="utf-8")
    target_source = (ROOT / "src" / "kdive" / "target" / "handlers.py").read_text(encoding="utf-8")
    debug_session_source = (ROOT / "src" / "kdive" / "debug" / "session_handlers.py").read_text(encoding="utf-8")

    assert "from kdive.transport.handlers import _require_snapshot" not in probe_source
    assert "from kdive.transport.handlers import _require_snapshot" not in target_source
    assert "_require_snapshot" not in debug_session_source
    assert "require_target_snapshot" in probe_source


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


def test_generic_tools_package_only_contains_shared_adapter_boundary() -> None:
    import kdive.tools as tools

    package_dir = Path(tools.__file__).parent
    module_names = {path.stem for path in package_dir.glob("*.py")}

    assert module_names == {"__init__", "adapter_boundary"}


def test_server_public_api_is_explicit_and_composition_scoped() -> None:
    import kdive.server as server

    assert set(server.__all__) == {
        "DEFAULT_ARTIFACT_ROOT",
        "DEFAULT_BUILD_PROFILES",
        "DEFAULT_DEBUG_PROFILES",
        "DEFAULT_ROOTFS_PROFILES",
        "DEFAULT_TARGET_PROFILES",
        "DEFAULT_TEST_SUITES",
        "RUN_STDOUT_CAP",
        "SERVER_CONFIG_ENV_VAR",
        "SSH_TIMEOUT_GRACE_SECONDS",
        "create_app",
        "load_server_config",
        "main",
    }
    assert not any(name.endswith("_handler") for name in server.__all__)
    assert not any(name.endswith(("Context", "Options", "Profiles")) for name in server.__all__)


def test_transport_machinery_startup_uses_named_phase_helpers() -> None:
    server_source = SERVER_SOURCE.read_text(encoding="utf-8")
    builder_source = server_source.split("def _build_transport_machinery(", 1)[1].split("\ndef create_app(", 1)[0]

    for helper in (
        "_bind_transport_lifecycle",
        "_build_transport_secrets",
        "_reconcile_transport_before_serve",
    ):
        assert f"def {helper}(" in server_source
        assert f"{helper}(" in builder_source

    assert "SecretsStore(" not in builder_source
    assert "session_registry.reconcile(" not in builder_source


def test_server_does_not_expose_capability_model_or_helper_aliases() -> None:
    import kdive.server as server

    compatibility_aliases = {
        "CreateRunContext",
        "CreateRunOptions",
        "CreateRunProfiles",
        "_overrides_from_tool_args",
        "build_scp_argv",
    }

    assert sorted(name for name in compatibility_aliases if hasattr(server, name)) == []
