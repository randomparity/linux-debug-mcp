from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from kdive.domain import DebugIntrospectRunRequest, ToolResponse
from kdive.introspect.tools import IntrospectRunOptions, IntrospectTargetContext, register_introspect_tools
from kdive.postmortem.models import DebugPostmortemFetchRequest
from kdive.postmortem.tools import (
    PostmortemFetchOptions,
    PostmortemTargetContext,
    register_postmortem_tools,
)
from kdive.transport.tools import TransportToolContext, TransportToolHandlers, register_transport_tools
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
        run_id="run-1",
        session_id="session-1",
        acknowledged_permissions=["drop target kernel into the debugger"],
        artifact_root=str(tmp_path / "runs"),
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
        run_id="run-1",
        target=IntrospectTargetContext(
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
    assert kwargs == {
        "artifact_root": tmp_path / "runs",
        "admission": admission,
        "session_registry": registry,
    }


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
        run_id="run-1",
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
        run_id="run-1",
        target=PostmortemTargetContext(
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
        run_id="run-1",
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

    register_workflow_tools(
        app,
        default_artifact_root=tmp_path / "default",
        admission=admission,
        session_registry=registry,
        transaction=transaction,
        session_guard=session_guard,
        gdb_mi_engine=gdb_mi_engine,
        gdb_mi_sessions=gdb_mi_sessions,
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
        }
    ]
