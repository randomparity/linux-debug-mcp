from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
SERVER_SOURCE = ROOT / "src" / "kdive" / "server.py"
INTROSPECT_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "introspect" / "handlers.py"
INTROSPECT_EXECUTION_SOURCE = ROOT / "src" / "kdive" / "introspect" / "execution.py"
POSTMORTEM_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "postmortem" / "handlers.py"
SHARED_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "handlers" / "shared.py"
PROBE_SEAM_SOURCE = ROOT / "src" / "kdive" / "seams" / "probes.py"


def _module_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _defined_functions(path: Path) -> set[str]:
    return {node.name for node in ast.walk(_module_ast(path)) if isinstance(node, ast.FunctionDef)}


def _assigned_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(_module_ast(path)):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _imported_modules(path: Path) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(_module_ast(path)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


def _imported_names(path: Path, module: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(_module_ast(path)):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


def _function_node(path: Path, name: str) -> ast.FunctionDef:
    for node in ast.walk(_module_ast(path)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not defined in {path.relative_to(ROOT)}")


def _called_names(node: ast.AST) -> set[str]:
    calls: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            calls.add(child.func.id)
        elif isinstance(child.func, ast.Attribute) and isinstance(child.func.value, ast.Name):
            calls.add(f"{child.func.value.id}.{child.func.attr}")
    return calls


def test_extracted_handler_modules_do_not_import_server_module() -> None:
    handler_sources = [
        path
        for path in (ROOT / "src" / "kdive").rglob("*.py")
        if path.name in {"handlers.py", "session_handlers.py", "crash_handler.py"}
    ]

    offenders = [path.relative_to(ROOT) for path in handler_sources if "kdive.server" in _imported_modules(path)]

    assert offenders == []


def test_server_does_not_own_shared_probe_helpers() -> None:
    server_definitions = _defined_functions(SERVER_SOURCE)

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

    assert "PROBE_STDOUT_CAP" not in _assigned_names(SERVER_SOURCE)
    assert [helper for helper in duplicated_helpers if helper in server_definitions] == []


def test_live_introspection_does_not_keep_passthrough_wrappers() -> None:
    assert "_execute_live_introspect_call" not in _defined_functions(INTROSPECT_HANDLERS_SOURCE)
    assert "_prepare_live_wrapper" not in _defined_functions(INTROSPECT_EXECUTION_SOURCE)


def test_shared_probe_helpers_live_in_public_boundary_module() -> None:
    shared_definitions = _defined_functions(SHARED_HANDLERS_SOURCE)

    assert "_resolve_probe_context" not in shared_definitions
    assert "_parse_probe_stdout" not in shared_definitions
    assert PROBE_SEAM_SOURCE.is_file()
    assert _imported_names(INTROSPECT_HANDLERS_SOURCE, "kdive.seams.probes")
    assert _imported_names(POSTMORTEM_HANDLERS_SOURCE, "kdive.seams.probes")
    assert "kdive.target.probes" not in _imported_modules(INTROSPECT_HANDLERS_SOURCE)
    assert "kdive.target.probes" not in _imported_modules(POSTMORTEM_HANDLERS_SOURCE)


def test_target_probe_substrate_does_not_own_feature_response_assembly() -> None:
    target_imports = _imported_modules(PROBE_SEAM_SOURCE)
    target_definitions = _defined_functions(PROBE_SEAM_SOURCE)

    assert "kdive.prereqs.drgn_probe" not in target_imports
    assert "kdive.prereqs.kdump_probe" not in target_imports
    assert "kdive.postmortem.dumps" not in target_imports
    assert "assemble_introspect_probe_response" not in target_definitions
    assert "assemble_kdump_probe_response" not in target_definitions
    assert "assemble_introspect_probe_response" in _imported_names(
        INTROSPECT_HANDLERS_SOURCE, "kdive.introspect.probes"
    )
    assert "assemble_kdump_probe_response" in _imported_names(POSTMORTEM_HANDLERS_SOURCE, "kdive.postmortem.probes")


def test_feature_probe_handlers_import_public_target_probe_substrate() -> None:
    for source_path in (INTROSPECT_HANDLERS_SOURCE, POSTMORTEM_HANDLERS_SOURCE):
        seam_imports = _imported_names(source_path, "kdive.seams.probes")
        assert seam_imports
        assert not any(name.startswith("_") for name in seam_imports)


def test_shared_probe_boundary_does_not_import_private_transport_handlers() -> None:
    target_handlers = ROOT / "src" / "kdive" / "target" / "handlers.py"
    debug_session_handlers = ROOT / "src" / "kdive" / "debug" / "session_handlers.py"

    assert "_require_snapshot" not in _imported_names(PROBE_SEAM_SOURCE, "kdive.transport.handlers")
    assert "_require_snapshot" not in _imported_names(target_handlers, "kdive.transport.handlers")
    assert "_require_snapshot" not in _imported_names(debug_session_handlers, "kdive.transport.handlers")
    assert "require_target_snapshot" in _imported_names(PROBE_SEAM_SOURCE, "kdive.coordination.admission")


def test_debug_features_do_not_import_private_transport_handler_helpers() -> None:
    feature_sources = [
        ROOT / "src" / "kdive" / "debug" / "operations.py",
        ROOT / "src" / "kdive" / "debug" / "session_end.py",
        ROOT / "src" / "kdive" / "debug" / "session_handlers.py",
        ROOT / "src" / "kdive" / "debug" / "module_symbols.py",
        ROOT / "src" / "kdive" / "introspect" / "execution.py",
    ]

    offenders = {
        str(path.relative_to(ROOT)): sorted(
            name for name in _imported_names(path, "kdive.transport.handlers") if name.startswith("_")
        )
        for path in feature_sources
        if any(name.startswith("_") for name in _imported_names(path, "kdive.transport.handlers"))
    }

    assert offenders == {}


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
    server_definitions = _defined_functions(SERVER_SOURCE)
    builder = _function_node(SERVER_SOURCE, "_build_transport_machinery")
    builder_calls = _called_names(builder)

    for helper in (
        "_bind_transport_lifecycle",
        "_build_transport_secrets",
        "_reconcile_transport_before_serve",
    ):
        assert helper in server_definitions
        assert helper in builder_calls

    assert "SecretsStore" not in builder_calls
    assert "session_registry.reconcile" not in builder_calls


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
