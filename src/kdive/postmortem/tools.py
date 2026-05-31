from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.postmortem.models import (
    DebugPostmortemCheckPrereqsRequest,
    DebugPostmortemCrashRequest,
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DebugPostmortemTriageRequest,
)
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


class PostmortemTargetContext(Model):
    run_id: str
    target_ref: str
    artifact_root: str | None = None
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class PostmortemVmcoreInputs(Model):
    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    artifact_root: str | None = None


class PostmortemCrashOptions(Model):
    timeout_seconds: int = 60


class PostmortemProbeOptions(Model):
    timeout_seconds: int = 20


class PostmortemListDumpsOptions(Model):
    dump_dir: str | None = None
    timeout_seconds: int = 20


class PostmortemFetchOptions(Model):
    force: bool = False
    dump_dir: str | None = None
    max_bytes: int | None = None
    timeout_seconds: int = 300


class PostmortemCrashHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemCrashRequest,
        *,
        artifact_root: Path,
    ) -> ToolResponse: ...


class PostmortemTriageHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemTriageRequest,
        *,
        artifact_root: Path,
    ) -> ToolResponse: ...


class PostmortemCheckPrereqsHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemCheckPrereqsRequest,
        *,
        artifact_root: Path,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class PostmortemListDumpsHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemListDumpsRequest,
        *,
        artifact_root: Path,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


class PostmortemFetchHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemFetchRequest,
        *,
        artifact_root: Path,
        admission: AdmissionService,
        session_registry: SessionRegistry,
    ) -> ToolResponse: ...


def register_postmortem_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    admission: AdmissionService,
    session_registry: SessionRegistry,
    crash_handler: PostmortemCrashHandler,
    triage_handler: PostmortemTriageHandler,
    check_prereqs_handler: PostmortemCheckPrereqsHandler,
    list_dumps_handler: PostmortemListDumpsHandler,
    fetch_handler: PostmortemFetchHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    def artifact_root_path(value: str | None) -> Path:
        return Path(value or default_artifact_root_text)

    @app.tool(name="debug.postmortem.crash")
    def debug_postmortem_crash(
        vmcore: PostmortemVmcoreInputs | dict[str, Any],
        commands: list[str],
        options: PostmortemCrashOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            vmcore_model = model_arg(vmcore, PostmortemVmcoreInputs)
            options_model = optional_model_arg(options, PostmortemCrashOptions)
            request = DebugPostmortemCrashRequest(
                run_id=vmcore_model.run_id,
                vmcore_ref=vmcore_model.vmcore_ref,
                vmlinux_ref=vmcore_model.vmlinux_ref,
                commands=commands,
                modules_ref=vmcore_model.modules_ref,
                timeout_seconds=options_model.timeout_seconds,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return crash_handler(
            request,
            artifact_root=artifact_root_path(vmcore_model.artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.triage")
    def debug_postmortem_triage(
        vmcore: PostmortemVmcoreInputs | dict[str, Any],
        options: PostmortemCrashOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            vmcore_model = model_arg(vmcore, PostmortemVmcoreInputs)
            options_model = optional_model_arg(options, PostmortemCrashOptions)
            request = DebugPostmortemTriageRequest(
                run_id=vmcore_model.run_id,
                vmcore_ref=vmcore_model.vmcore_ref,
                vmlinux_ref=vmcore_model.vmlinux_ref,
                modules_ref=vmcore_model.modules_ref,
                timeout_seconds=options_model.timeout_seconds,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return triage_handler(
            request,
            artifact_root=artifact_root_path(vmcore_model.artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.check_prereqs")
    def debug_postmortem_check_prereqs(
        target: PostmortemTargetContext | dict[str, Any],
        options: PostmortemProbeOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            target_model = model_arg(target, PostmortemTargetContext)
            options_model = optional_model_arg(options, PostmortemProbeOptions)
            request = DebugPostmortemCheckPrereqsRequest(
                run_id=target_model.run_id,
                manifest_target_profile=target_model.target_ref,
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return check_prereqs_handler(
            request,
            artifact_root=artifact_root_path(target_model.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.list_dumps")
    def debug_postmortem_list_dumps(
        target: PostmortemTargetContext | dict[str, Any],
        options: PostmortemListDumpsOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            target_model = model_arg(target, PostmortemTargetContext)
            options_model = optional_model_arg(options, PostmortemListDumpsOptions)
            request = DebugPostmortemListDumpsRequest(
                run_id=target_model.run_id,
                manifest_target_profile=target_model.target_ref,
                dump_dir=options_model.dump_dir,
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return list_dumps_handler(
            request,
            artifact_root=artifact_root_path(target_model.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.fetch")
    def debug_postmortem_fetch(
        target: PostmortemTargetContext | dict[str, Any],
        dump_ref: str,
        options: PostmortemFetchOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            target_model = model_arg(target, PostmortemTargetContext)
            options_model = optional_model_arg(options, PostmortemFetchOptions)
            request = DebugPostmortemFetchRequest(
                run_id=target_model.run_id,
                manifest_target_profile=target_model.target_ref,
                dump_ref=dump_ref,
                force=options_model.force,
                dump_dir=options_model.dump_dir,
                max_bytes=options_model.max_bytes,
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return fetch_handler(
            request,
            artifact_root=artifact_root_path(target_model.artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")
