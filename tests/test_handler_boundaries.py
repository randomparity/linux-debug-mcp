from __future__ import annotations

import ast
import inspect
from pathlib import Path

ROOT = Path(__file__).parents[1]
SERVER_SOURCE = ROOT / "src" / "kdive" / "server.py"
TARGET_BOOT_HANDLER_SOURCE = ROOT / "src" / "kdive" / "target" / "boot_handler.py"
TARGET_TEST_HANDLER_SOURCE = ROOT / "src" / "kdive" / "target" / "test_handler.py"
INTROSPECT_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "introspect" / "handlers.py"
INTROSPECT_EXECUTION_SOURCE = ROOT / "src" / "kdive" / "introspect" / "execution.py"
DEBUG_OPERATIONS_SOURCE = ROOT / "src" / "kdive" / "debug" / "operations.py"
POSTMORTEM_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "postmortem" / "handlers.py"
POSTMORTEM_DUMP_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "postmortem" / "dump_handlers.py"
SHARED_HANDLERS_SOURCE = ROOT / "src" / "kdive" / "handlers" / "shared.py"
PROBE_SEAM_SOURCE = ROOT / "src" / "kdive" / "seams" / "probes.py"
CONFIGURATION_FAILURE_DUPLICATE_SOURCES = [
    ROOT / "src" / "kdive" / "artifacts" / "handlers.py",
    ROOT / "src" / "kdive" / "debug" / "operations.py",
    ROOT / "src" / "kdive" / "introspect" / "execution.py",
    ROOT / "src" / "kdive" / "server.py",
    ROOT / "src" / "kdive" / "transport" / "handlers.py",
]


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
        if path.name in {"handlers.py", "session_handlers.py", "handler.py", "boot_handler.py", "test_handler.py"}
    ]

    offenders = [path.relative_to(ROOT) for path in handler_sources if "kdive.server" in _imported_modules(path)]

    assert offenders == []


def test_server_does_not_own_probe_substrate_constants() -> None:
    assert "PROBE_STDOUT_CAP" not in _assigned_names(SERVER_SOURCE)


def test_shared_probe_helpers_live_in_public_boundary_module() -> None:
    assert PROBE_SEAM_SOURCE.is_file()
    assert _imported_names(INTROSPECT_HANDLERS_SOURCE, "kdive.seams.probes")
    assert _imported_names(POSTMORTEM_DUMP_HANDLERS_SOURCE, "kdive.seams.probes")
    assert "kdive.target.probes" not in _imported_modules(INTROSPECT_HANDLERS_SOURCE)
    assert "kdive.target.probes" not in _imported_modules(POSTMORTEM_DUMP_HANDLERS_SOURCE)


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
    assert "assemble_kdump_probe_response" in _imported_names(
        POSTMORTEM_DUMP_HANDLERS_SOURCE, "kdive.postmortem.probes"
    )


def test_feature_probe_handlers_import_public_target_probe_substrate() -> None:
    for source_path in (INTROSPECT_HANDLERS_SOURCE, POSTMORTEM_DUMP_HANDLERS_SOURCE):
        seam_imports = _imported_names(source_path, "kdive.seams.probes")
        assert seam_imports
        assert not any(name.startswith("_") for name in seam_imports)


def test_shared_probe_boundary_does_not_import_private_transport_handlers() -> None:
    debug_session_handlers = ROOT / "src" / "kdive" / "debug" / "session_handlers.py"

    assert "_require_snapshot" not in _imported_names(PROBE_SEAM_SOURCE, "kdive.transport.handlers")
    assert "_require_snapshot" not in _imported_names(TARGET_BOOT_HANDLER_SOURCE, "kdive.transport.handlers")
    assert "_require_snapshot" not in _imported_names(TARGET_TEST_HANDLER_SOURCE, "kdive.transport.handlers")
    assert "_require_snapshot" not in _imported_names(debug_session_handlers, "kdive.transport.handlers")
    assert "require_target_snapshot" in _imported_names(PROBE_SEAM_SOURCE, "kdive.coordination.admission")


def test_postmortem_handlers_do_not_import_introspect_execution_internals() -> None:
    assert "kdive.introspect.execution" not in _imported_modules(POSTMORTEM_HANDLERS_SOURCE)
    assert "kdive.introspect.handlers" not in _imported_modules(POSTMORTEM_HANDLERS_SOURCE)


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


def test_debug_operations_depend_on_neutral_contracts_not_handlers() -> None:
    assert "kdive.debug.contracts" in _imported_modules(DEBUG_OPERATIONS_SOURCE)
    assert "kdive.debug.handlers" not in _imported_modules(DEBUG_OPERATIONS_SOURCE)


def test_transport_and_prereq_handlers_accept_structured_boundaries_only() -> None:
    from kdive.prereqs.handlers import prerequisites_handler
    from kdive.transport.handlers import (
        transport_close_handler,
        transport_inject_break_handler,
        transport_open_handler,
    )

    debug_handlers = [
        transport_open_handler,
        transport_close_handler,
        transport_inject_break_handler,
        prerequisites_handler,
    ]

    for handler in debug_handlers:
        assert list(inspect.signature(handler).parameters) == ["request", "runtime"]


def test_debug_handlers_accept_structured_boundaries_only() -> None:
    from kdive.debug import handlers, module_symbols, session_end, session_handlers

    debug_handlers = [
        session_handlers.debug_start_session_handler,
        handlers.debug_read_registers_handler,
        handlers.debug_read_symbol_handler,
        handlers.debug_read_memory_handler,
        handlers.debug_evaluate_handler,
        module_symbols.debug_load_module_symbols_handler,
        handlers.debug_set_breakpoint_handler,
        handlers.debug_set_watchpoint_handler,
        handlers.debug_clear_breakpoint_handler,
        handlers.debug_clear_watchpoint_handler,
        handlers.debug_list_breakpoints_handler,
        handlers.debug_backtrace_handler,
        handlers.debug_list_variables_handler,
        handlers.debug_continue_handler,
        handlers.debug_step_handler,
        handlers.debug_next_handler,
        handlers.debug_finish_handler,
        handlers.debug_interrupt_handler,
        session_end.debug_end_session_handler,
    ]

    for handler in debug_handlers:
        assert list(inspect.signature(handler).parameters) == ["request", "runtime"]


def test_target_and_kernel_handlers_accept_structured_boundaries_only() -> None:
    from kdive.kernel.handlers import kernel_build_handler
    from kdive.target.boot_handler import target_boot_handler
    from kdive.target.test_handler import target_run_tests_handler

    handlers = [
        kernel_build_handler,
        target_boot_handler,
        target_run_tests_handler,
    ]

    for handler in handlers:
        assert list(inspect.signature(handler).parameters) == ["request", "runtime"]


def test_target_handlers_are_split_by_workflow() -> None:
    target_handlers_source = ROOT / "src" / "kdive" / "target" / "handlers.py"

    assert not target_handlers_source.exists()
    assert TARGET_BOOT_HANDLER_SOURCE.is_file()
    assert TARGET_TEST_HANDLER_SOURCE.is_file()
    assert "target_boot_handler" in _defined_functions(TARGET_BOOT_HANDLER_SOURCE)
    assert "target_run_tests_handler" not in _defined_functions(TARGET_BOOT_HANDLER_SOURCE)
    assert "target_run_tests_handler" in _defined_functions(TARGET_TEST_HANDLER_SOURCE)
    assert "target_boot_handler" not in _defined_functions(TARGET_TEST_HANDLER_SOURCE)


def test_transport_tests_do_not_recreate_public_handler_call_shapes() -> None:
    transport_test_sources = [
        ROOT / "tests" / "server" / "test_server_transport_tools.py",
        ROOT / "tests" / "server" / "test_layer4_conformance.py",
        ROOT / "tests" / "coordination" / "test_error_taxonomy.py",
    ]
    forbidden_helpers = {
        "transport_open_handler",
        "transport_close_handler",
        "transport_inject_break_handler",
    }

    offenders = {
        str(source.relative_to(ROOT)): sorted(forbidden_helpers & _defined_functions(source))
        for source in transport_test_sources
        if forbidden_helpers & _defined_functions(source)
    }

    assert offenders == {}


def test_configuration_failure_response_is_shared() -> None:
    from kdive.handlers.shared import configuration_failure_response

    response = configuration_failure_response(
        run_id="run-1",
        message="bad input",
        details={"code": "bad_input"},
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert response.error.message == "bad input"
    assert response.error.details == {"code": "bad_input"}


def test_generic_tools_package_only_contains_shared_adapter_boundary() -> None:
    import kdive.tools as tools

    package_dir = Path(tools.__file__).parent
    module_names = {path.stem for path in package_dir.glob("*.py")}

    assert module_names == {"__init__", "adapter_boundary"}


def test_coordination_session_state_imports_use_neutral_seam() -> None:
    coordination_sources = list((ROOT / "src" / "kdive" / "coordination").glob("*.py"))
    forbidden_state_names = {
        "DEFAULT_MIN_LEASE_TTL_SECONDS",
        "ExecutionState",
        "OpenRequest",
        "RecordState",
        "TransportRef",
        "TransportSession",
    }

    offenders = {
        str(source.relative_to(ROOT)): sorted(
            forbidden_state_names & _imported_names(source, "kdive.transport.core.base")
        )
        for source in coordination_sources
        if forbidden_state_names & _imported_names(source, "kdive.transport.core.base")
    }

    assert offenders == {}


def test_server_does_not_own_introspect_execution_helpers() -> None:
    forbidden_functions = {
        "_chmod_best_effort",
        "_count_introspect_calls",
        "_head_tail",
        "_record_terminal_introspect_result",
        "_utcnow",
    }
    forbidden_assignments = {
        "RUN_STDOUT_CAP",
        "SSH_TIMEOUT_GRACE_SECONDS",
    }

    assert sorted(forbidden_functions & _defined_functions(SERVER_SOURCE)) == []
    assert sorted(forbidden_assignments & _assigned_names(SERVER_SOURCE)) == []


def test_server_public_api_is_explicit_and_composition_scoped() -> None:
    import kdive.server as server

    assert set(server.__all__) == {
        "DEFAULT_ARTIFACT_ROOT",
        "DEFAULT_BUILD_PROFILES",
        "DEFAULT_DEBUG_PROFILES",
        "DEFAULT_ROOTFS_PROFILES",
        "DEFAULT_TARGET_PROFILES",
        "DEFAULT_TEST_SUITES",
        "SERVER_CONFIG_ENV_VAR",
        "create_app",
        "load_server_config",
        "main",
    }
    assert not any(name.endswith("_handler") for name in server.__all__)
    assert not any(name.endswith(("Context", "Options", "Profiles")) for name in server.__all__)


def test_server_does_not_expose_capability_model_or_helper_aliases() -> None:
    import kdive.server as server

    compatibility_aliases = {
        "CreateRunContext",
        "CreateRunOptions",
        "CreateRunProfiles",
        "build_scp_argv",
    }

    assert sorted(name for name in compatibility_aliases if hasattr(server, name)) == []
