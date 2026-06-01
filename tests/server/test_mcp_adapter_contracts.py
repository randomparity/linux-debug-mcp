from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from kdive.config import BootOverrides, BuildOverrides
from kdive.domain import DebugIntrospectRunRequest, ToolResponse
from kdive.introspect.execution import LiveIntrospectRuntime
from kdive.introspect.tools import IntrospectRunOptions, IntrospectTargetContext, register_introspect_tools
from kdive.kernel.tools import (
    CreateRunContext,
    CreateRunOptions,
    CreateRunProfiles,
    KernelBuildContext,
    KernelBuildOptions,
    register_kernel_tools,
)
from kdive.postmortem.models import DebugPostmortemFetchRequest
from kdive.postmortem.tools import (
    PostmortemFetchOptions,
    PostmortemTargetContext,
    register_postmortem_tools,
)
from kdive.prereqs.tools import (
    HostPrerequisitesContext,
    HostPrerequisitesOptions,
    HostPrerequisitesProfiles,
    register_prereq_tools,
)
from kdive.target.tools import (
    TargetBootContext,
    TargetBootOptions,
    TargetBootProfiles,
    TargetRunContext,
    TargetRunOptions,
    register_target_tools,
)
from kdive.tools.artifacts import (
    ArtifactCollectContext,
    ArtifactCollectOptions,
    register_artifact_tools,
)
from kdive.transport.tools import (
    TransportBreakOptions,
    TransportTargetContext,
    TransportToolContext,
    TransportToolHandlers,
    register_transport_tools,
)
from kdive.workflow.handlers import WorkflowHandlerDependencies
from kdive.workflow.tools import (
    WorkflowBuildBootDebugOptions,
    WorkflowProfileInputs,
    WorkflowRunContext,
    register_workflow_tools,
)


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn


def _success(**data: Any) -> ToolResponse:
    return ToolResponse.success(summary="ok", data=data)


def test_kernel_adapters_forward_grouped_payloads_and_override_models(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    sensitive_paths = [tmp_path / "secret"]
    calls: list[tuple[str, dict[str, Any]]] = []

    def create_handler(**kwargs: Any) -> ToolResponse:
        calls.append(("create", kwargs))
        return _success(run_id=kwargs["run_id"])

    def build_handler(**kwargs: Any) -> ToolResponse:
        calls.append(("build", kwargs))
        return _success(run_id=kwargs["run_id"])

    register_kernel_tools(
        app,
        default_artifact_root=tmp_path / "default",
        sensitive_paths=sensitive_paths,
        create_run_handler=create_handler,
        kernel_build_handler=build_handler,
    )

    raw_create = _tool_fn(app, "kernel.create_run")(
        profiles=CreateRunProfiles(
            source_path="/src/linux",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        context=CreateRunContext(artifact_root=str(tmp_path / "runs"), run_id="run-1"),
        options=CreateRunOptions(
            debug_profile="qemu-gdbstub-default",
            test_suite="smoke",
            build_overrides={"make_variables": {"LOCALVERSION": "-kdive"}},
            boot_overrides={"kernel_args": ["panic=1"]},
            profile_specs={"build": {"name": "inline-build"}, "target": {"name": "inline-target"}},
        ),
    )
    raw_build = _tool_fn(app, "kernel.build")(
        context=KernelBuildContext(run_id="run-1", artifact_root=str(tmp_path / "runs")),
        options=KernelBuildOptions(build_profile="inline-build", force_rebuild=True),
    )

    assert raw_create["ok"] is True
    assert raw_build["ok"] is True
    assert calls == [
        (
            "create",
            {
                "artifact_root": tmp_path / "runs",
                "source_path": "/src/linux",
                "build_profile": "x86_64-default",
                "target_profile": "local-qemu",
                "rootfs_profile": "minimal",
                "run_id": "run-1",
                "debug_profile": "qemu-gdbstub-default",
                "test_suite": "smoke",
                "build_overrides": BuildOverrides(make_variables={"LOCALVERSION": "-kdive"}),
                "boot_overrides": BootOverrides(kernel_args=["panic=1"]),
                "sensitive_paths": sensitive_paths,
                "build_profile_spec": {"name": "inline-build"},
                "target_profile_spec": {"name": "inline-target"},
                "rootfs_profile_spec": None,
            },
        ),
        (
            "build",
            {
                "artifact_root": tmp_path / "runs",
                "run_id": "run-1",
                "build_profile": "inline-build",
                "force_rebuild": True,
            },
        ),
    ]


def test_kernel_adapter_maps_invalid_grouped_payload_to_tool_response(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    register_kernel_tools(
        app,
        default_artifact_root=tmp_path / "default",
        sensitive_paths=[],
        create_run_handler=lambda **_kwargs: _success(),
        kernel_build_handler=lambda **_kwargs: _success(),
    )

    raw = _tool_fn(app, "kernel.create_run")(
        profiles=CreateRunProfiles(source_path="/src/linux"),
        options={"profile_specs": {"debug": {"name": "unsupported"}}},
    )

    assert raw["ok"] is False
    assert raw["error"]["category"] == "configuration_error"


def test_target_adapters_forward_grouped_payloads_and_collaborators(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    admission = object()
    registry = object()
    sensitive_paths = [tmp_path / "secret"]
    calls: list[tuple[str, dict[str, Any]]] = []

    def boot_handler(**kwargs: Any) -> ToolResponse:
        calls.append(("boot", kwargs))
        return _success(run_id=kwargs["run_id"])

    def run_tests_handler(**kwargs: Any) -> ToolResponse:
        calls.append(("run_tests", kwargs))
        return _success(run_id=kwargs["run_id"])

    register_target_tools(
        app,
        default_artifact_root=tmp_path / "default",
        sensitive_paths=sensitive_paths,
        admission=admission,
        session_registry=registry,
        target_boot_handler=boot_handler,
        target_run_tests_handler=run_tests_handler,
    )

    raw_boot = _tool_fn(app, "target.boot")(
        context=TargetBootContext(run_id="run-1", artifact_root=str(tmp_path / "runs")),
        profiles=TargetBootProfiles(target_profile="local-qemu", rootfs_profile="minimal"),
        options=TargetBootOptions(
            force_reboot=True,
            boot_overrides={"kernel_args": ["console=ttyS0"]},
            acknowledged_permissions=["start MCP-owned libvirt domains"],
        ),
    )
    raw_tests = _tool_fn(app, "target.run_tests")(
        context=TargetRunContext(run_id="run-1", artifact_root=str(tmp_path / "runs")),
        options=TargetRunOptions(
            test_suite="smoke",
            commands=[["uname", "-a"]],
            force_rerun=True,
            attempt=2,
            acknowledged_permissions=["execute caller-supplied commands over target SSH"],
        ),
    )

    assert raw_boot["ok"] is True
    assert raw_tests["ok"] is True
    assert calls == [
        (
            "boot",
            {
                "artifact_root": tmp_path / "runs",
                "run_id": "run-1",
                "target_profile": "local-qemu",
                "rootfs_profile": "minimal",
                "force_reboot": True,
                "boot_overrides": BootOverrides(kernel_args=["console=ttyS0"]),
                "acknowledged_permissions": ["start MCP-owned libvirt domains"],
                "sensitive_paths": sensitive_paths,
                "admission": admission,
            },
        ),
        (
            "run_tests",
            {
                "artifact_root": tmp_path / "runs",
                "run_id": "run-1",
                "test_suite": "smoke",
                "commands": [["uname", "-a"]],
                "force_rerun": True,
                "attempt": 2,
                "acknowledged_permissions": ["execute caller-supplied commands over target SSH"],
                "admission": admission,
                "session_registry": registry,
            },
        ),
    ]


def test_target_adapter_maps_invalid_grouped_payload_to_tool_response(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    register_target_tools(
        app,
        default_artifact_root=tmp_path / "default",
        sensitive_paths=[],
        admission=object(),
        session_registry=object(),
        target_boot_handler=lambda **_kwargs: _success(),
        target_run_tests_handler=lambda **_kwargs: _success(),
    )

    raw = _tool_fn(app, "target.boot")(context={})

    assert raw["ok"] is False
    assert raw["error"]["category"] == "configuration_error"


def test_prereq_adapter_forwards_grouped_payloads(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    calls: list[dict[str, Any]] = []

    def prereq_handler(**kwargs: Any) -> ToolResponse:
        calls.append(kwargs)
        return _success()

    register_prereq_tools(
        app,
        default_artifact_root=tmp_path / "default",
        prerequisites_handler=prereq_handler,
    )

    raw = _tool_fn(app, "host.check_prerequisites")(
        context=HostPrerequisitesContext(artifact_root=str(tmp_path / "runs")),
        profiles=HostPrerequisitesProfiles(
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        options=HostPrerequisitesOptions(source_path="/src/linux", enable_libvirt_check=True),
    )

    assert raw["ok"] is True
    assert calls == [
        {
            "artifact_root": tmp_path / "runs",
            "source_path": "/src/linux",
            "enable_libvirt_check": True,
            "build_profile": "x86_64-default",
            "target_profile": "local-qemu",
            "rootfs_profile": "minimal",
        }
    ]


def test_prereq_adapter_maps_invalid_grouped_payload_to_tool_response(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    register_prereq_tools(
        app,
        default_artifact_root=tmp_path / "default",
        prerequisites_handler=lambda **_kwargs: _success(),
    )

    raw = _tool_fn(app, "host.check_prerequisites")(context={"unexpected": "field"})

    assert raw["ok"] is False
    assert raw["error"]["category"] == "configuration_error"


def test_artifact_adapter_uses_grouped_context_and_options(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    calls: list[dict[str, Any]] = []

    def collect_handler(**kwargs: Any) -> ToolResponse:
        calls.append(kwargs)
        return _success(run_id=kwargs["run_id"])

    register_artifact_tools(
        app,
        default_artifact_root=tmp_path / "default",
        collect_handler=collect_handler,
    )

    raw = _tool_fn(app, "artifacts.collect")(
        context=ArtifactCollectContext(run_id="run-1", artifact_root=str(tmp_path / "runs")),
        options=ArtifactCollectOptions(force_recollect=True),
    )

    assert raw["ok"] is True
    assert calls == [
        {
            "artifact_root": tmp_path / "runs",
            "run_id": "run-1",
            "force_recollect": True,
        }
    ]


def test_transport_adapter_forwards_inject_break_collaborators_and_path(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    transaction = object()
    admission = object()
    registry = object()
    calls: list[dict[str, Any]] = []

    def inject_break_handler(**kwargs: Any) -> ToolResponse:
        calls.append(kwargs)
        return _success(session_id=kwargs["session_id"])

    register_transport_tools(
        app,
        context=TransportToolContext(
            default_artifact_root=tmp_path / "default",
            transaction=transaction,
            admission=admission,
            session_registry=registry,
        ),
        handlers=TransportToolHandlers(
            open=lambda **_kwargs: _success(),
            close=lambda **_kwargs: _success(),
            inject_break=inject_break_handler,
        ),
    )

    raw = _tool_fn(app, "transport.inject_break")(
        context=TransportTargetContext(
            run_id="run-1",
            artifact_root=str(tmp_path / "runs"),
        ),
        session_id="session-1",
        options=TransportBreakOptions(
            acknowledged_permissions=["drop target kernel into the debugger"],
        ),
    )

    assert raw["ok"] is True
    assert calls == [
        {
            "run_id": "run-1",
            "session_id": "session-1",
            "acknowledged_permissions": ["drop target kernel into the debugger"],
            "artifact_root": tmp_path / "runs",
            "transaction": transaction,
            "admission": admission,
            "session_registry": registry,
        }
    ]


def test_introspect_adapter_builds_run_request_and_forwards_gate_collaborators(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    admission = object()
    registry = object()
    calls: list[tuple[DebugIntrospectRunRequest, dict[str, Any]]] = []

    def run_handler(request: DebugIntrospectRunRequest, **kwargs: Any) -> ToolResponse:
        calls.append((request, kwargs))
        return _success(call_id="inspect-1")

    register_introspect_tools(
        app,
        default_artifact_root=tmp_path / "default",
        admission=admission,
        session_registry=registry,
        run_handler=run_handler,
        helper_handler=lambda *_args, **_kwargs: _success(),
        check_prereqs_handler=lambda *_args, **_kwargs: _success(),
        from_vmcore_handler=lambda *_args, **_kwargs: _success(),
        from_vmcore_helper_handler=lambda *_args, **_kwargs: _success(),
    )

    raw = _tool_fn(app, "debug.introspect.run")(
        target=IntrospectTargetContext(
            run_id="run-1",
            target_ref="local-qemu",
            artifact_root=str(tmp_path / "runs"),
        ),
        script="print('x')",
        options=IntrospectRunOptions(
            timeout_seconds=9,
            allow_write=True,
            acknowledged_permissions=["read/write target memory"],
            args={"limit": 1},
        ),
    )

    assert raw["ok"] is True
    request, kwargs = calls[0]
    assert request == DebugIntrospectRunRequest(
        run_id="run-1",
        manifest_target_profile="local-qemu",
        script="print('x')",
        timeout_seconds=9,
        allow_write=True,
        acknowledged_permissions=["read/write target memory"],
        args={"limit": 1},
    )
    assert set(kwargs) == {"runtime"}
    assert kwargs["runtime"] == LiveIntrospectRuntime(
        artifact_root=tmp_path / "runs",
        admission=admission,
        session_registry=registry,
    )


def test_introspect_adapter_maps_invalid_grouped_payload_to_tool_response(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    register_introspect_tools(
        app,
        default_artifact_root=tmp_path / "default",
        admission=object(),
        session_registry=object(),
        run_handler=lambda *_args, **_kwargs: _success(),
        helper_handler=lambda *_args, **_kwargs: _success(),
        check_prereqs_handler=lambda *_args, **_kwargs: _success(),
        from_vmcore_handler=lambda *_args, **_kwargs: _success(),
        from_vmcore_helper_handler=lambda *_args, **_kwargs: _success(),
    )

    raw = _tool_fn(app, "debug.introspect.run")(
        target={},
        script="print('x')",
    )

    assert raw["ok"] is False
    assert raw["error"]["category"] == "configuration_error"


def test_postmortem_adapter_builds_fetch_request_and_forwards_gate_collaborators(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    admission = object()
    registry = object()
    calls: list[tuple[DebugPostmortemFetchRequest, dict[str, Any]]] = []

    def fetch_handler(request: DebugPostmortemFetchRequest, **kwargs: Any) -> ToolResponse:
        calls.append((request, kwargs))
        return _success(vmcore_ref="inputs/vmcore")

    register_postmortem_tools(
        app,
        default_artifact_root=tmp_path / "default",
        admission=admission,
        session_registry=registry,
        crash_handler=lambda *_args, **_kwargs: _success(),
        triage_handler=lambda *_args, **_kwargs: _success(),
        check_prereqs_handler=lambda *_args, **_kwargs: _success(),
        list_dumps_handler=lambda *_args, **_kwargs: _success(),
        fetch_handler=fetch_handler,
    )

    raw = _tool_fn(app, "debug.postmortem.fetch")(
        target=PostmortemTargetContext(
            run_id="run-1",
            target_ref="local-qemu",
            artifact_root=str(tmp_path / "runs"),
        ),
        dump_ref="/var/crash/d1",
        options=PostmortemFetchOptions(
            force=True,
            dump_dir="/var/crash",
            max_bytes=123,
            timeout_seconds=17,
        ),
    )

    assert raw["ok"] is True
    request, kwargs = calls[0]
    assert request == DebugPostmortemFetchRequest(
        run_id="run-1",
        manifest_target_profile="local-qemu",
        dump_ref="/var/crash/d1",
        force=True,
        dump_dir="/var/crash",
        max_bytes=123,
        timeout_seconds=17,
    )
    assert kwargs == {
        "artifact_root": tmp_path / "runs",
        "admission": admission,
        "session_registry": registry,
    }


def test_postmortem_adapter_maps_invalid_grouped_payload_to_tool_response(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    register_postmortem_tools(
        app,
        default_artifact_root=tmp_path / "default",
        admission=object(),
        session_registry=object(),
        crash_handler=lambda *_args, **_kwargs: _success(),
        triage_handler=lambda *_args, **_kwargs: _success(),
        check_prereqs_handler=lambda *_args, **_kwargs: _success(),
        list_dumps_handler=lambda *_args, **_kwargs: _success(),
        fetch_handler=lambda *_args, **_kwargs: _success(),
    )

    raw = _tool_fn(app, "debug.postmortem.fetch")(
        target={},
        dump_ref="/var/crash/d1",
    )

    assert raw["ok"] is False
    assert raw["error"]["category"] == "configuration_error"


def test_workflow_adapter_forwards_debug_collaborators_and_converts_artifact_root(tmp_path: Path) -> None:
    app = FastMCP("adapter-test")
    admission = object()
    registry = object()
    transaction = object()
    session_guard = object()
    gdb_mi_engine = object()
    gdb_mi_sessions = object()
    calls: list[dict[str, Any]] = []

    def build_boot_debug_handler(**kwargs: Any) -> ToolResponse:
        calls.append(kwargs)
        return _success(run_id=kwargs["run_id"])

    dependencies = WorkflowHandlerDependencies(
        create_run_handler=lambda **_kwargs: _success(),
        kernel_build_handler=lambda **_kwargs: _success(),
        target_boot_handler=lambda **_kwargs: _success(),
        target_run_tests_handler=lambda **_kwargs: _success(),
        debug_start_session_handler=lambda **_kwargs: _success(),
        artifacts_collect_handler=lambda **_kwargs: _success(),
    )
    register_workflow_tools(
        app,
        default_artifact_root=tmp_path / "default",
        admission=admission,
        session_registry=registry,
        transaction=transaction,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
        dependencies=dependencies,
        build_boot_test_handler=lambda **_kwargs: _success(),
        build_boot_debug_handler=build_boot_debug_handler,
    )

    raw = _tool_fn(app, "workflow.build_boot_debug")(
        profiles=WorkflowProfileInputs(
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        context=WorkflowRunContext(artifact_root=str(tmp_path / "runs"), run_id="run-1"),
        options=WorkflowBuildBootDebugOptions(
            debug_profile="qemu-gdbstub-default",
            force_rebuild=True,
            force_reboot=True,
            new_session=True,
            acknowledged_permissions=["start MCP-owned libvirt domains"],
        ),
    )

    assert raw["ok"] is True
    assert calls == [
        {
            "artifact_root": tmp_path / "runs",
            "source_path": "/src",
            "build_profile": "x86_64-default",
            "target_profile": "local-qemu",
            "rootfs_profile": "minimal",
            "run_id": "run-1",
            "debug_profile": "qemu-gdbstub-default",
            "force_rebuild": True,
            "force_reboot": True,
            "new_session": True,
            "acknowledged_permissions": ["start MCP-owned libvirt domains"],
            "admission": admission,
            "session_registry": registry,
            "transaction": transaction,
            "session_guard": session_guard,
            "gdb_mi_engine": gdb_mi_engine,
            "gdb_mi_sessions": gdb_mi_sessions,
            "dependencies": dependencies,
        }
    ]
