from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.config import RootfsProfile
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ToolResponse
from kdive.introspect.models import DebugIntrospectFromVmcoreHelperRequest
from kdive.model import Model
from kdive.postmortem.models import (
    DebugPostmortemCheckPrereqsRequest,
    DebugPostmortemCrashRequest,
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DebugPostmortemTriageRequest,
)
from kdive.providers.ssh import SshRunner
from kdive.symbols.build_id import read_elf_build_id
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


class PostmortemTargetContext(Model):
    run_id: str
    manifest_target_profile: str
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


@dataclass(frozen=True)
class DrgnHelperRequest:
    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    name: str
    modules_ref: str | None = None
    args: dict[str, Any] | None = None
    timeout_seconds: int = 30


@dataclass(frozen=True)
class PostmortemToolRuntime:
    artifact_root: Path
    admission: AdmissionService | None = None
    session_registry: SessionRegistry | None = None
    rootfs_profiles: Mapping[str, RootfsProfile] | None = None
    ssh_runner: SshRunner | None = None
    crash_handler: PostmortemCrashHandler | None = None
    drgn_helper_handler: PostmortemDrgnHelperHandler | None = None
    vmcore_build_id_reader: Callable[[Path], str] | None = None
    vmlinux_build_id_reader: Callable[[Path], str] | None = None
    clock: Callable[[], datetime] | None = None


class PostmortemCrashHandler(Protocol):
    def __call__(
        self,
        *,
        request: DebugPostmortemCrashRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse: ...


class PostmortemDrgnHelperHandler(Protocol):
    def __call__(
        self,
        *,
        request: DrgnHelperRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse: ...


class RawPostmortemDrgnHelper(Protocol):
    def __call__(
        self,
        request: DebugIntrospectFromVmcoreHelperRequest,
        *,
        artifact_root: Path,
        runner: SshRunner | None = None,
        build_id_reader: Callable[[Path], str] = read_elf_build_id,
        clock: Callable[[], datetime] | None = None,
    ) -> ToolResponse: ...


class PostmortemTriageHandler(Protocol):
    def __call__(
        self,
        *,
        request: DebugPostmortemTriageRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse: ...


class PostmortemCheckPrereqsHandler(Protocol):
    def __call__(
        self,
        *,
        request: DebugPostmortemCheckPrereqsRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse: ...


class PostmortemListDumpsHandler(Protocol):
    def __call__(
        self,
        *,
        request: DebugPostmortemListDumpsRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse: ...


class PostmortemFetchHandler(Protocol):
    def __call__(
        self,
        *,
        request: DebugPostmortemFetchRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse: ...


@dataclass(frozen=True)
class PostmortemToolHandlers:
    crash: PostmortemCrashHandler
    triage: PostmortemTriageHandler
    triage_drgn_helper: RawPostmortemDrgnHelper
    check_prereqs: PostmortemCheckPrereqsHandler
    list_dumps: PostmortemListDumpsHandler
    fetch: PostmortemFetchHandler


@dataclass(frozen=True)
class PostmortemToolContext:
    default_artifact_root: Path
    admission: AdmissionService
    session_registry: SessionRegistry


@dataclass(frozen=True)
class _PostmortemRegistrationContext:
    default_artifact_root: str
    admission: AdmissionService
    session_registry: SessionRegistry
    crash_handler: PostmortemCrashHandler
    drgn_helper_handler: PostmortemDrgnHelperHandler

    def runtime(self, value: str | None) -> PostmortemToolRuntime:
        return PostmortemToolRuntime(
            artifact_root=Path(value or self.default_artifact_root),
            admission=self.admission,
            session_registry=self.session_registry,
            crash_handler=self.crash_handler,
            drgn_helper_handler=self.drgn_helper_handler,
        )


def _tool_response_json(response: ToolResponse) -> dict[str, Any]:
    return response.model_dump(mode="json")


def _adapt_triage_drgn_helper(handler: RawPostmortemDrgnHelper) -> PostmortemDrgnHelperHandler:
    def wrapped(
        *,
        request: DrgnHelperRequest,
        runtime: PostmortemToolRuntime,
    ) -> ToolResponse:
        introspect_request = DebugIntrospectFromVmcoreHelperRequest(
            run_id=request.run_id,
            vmcore_ref=request.vmcore_ref,
            vmlinux_ref=request.vmlinux_ref,
            modules_ref=request.modules_ref,
            name=request.name,
            args=request.args or {},
            timeout_seconds=request.timeout_seconds,
        )
        kwargs: dict[str, Any] = {
            "artifact_root": runtime.artifact_root,
            "runner": runtime.ssh_runner,
            "clock": runtime.clock,
        }
        if runtime.vmlinux_build_id_reader is not None:
            kwargs["build_id_reader"] = runtime.vmlinux_build_id_reader
        return handler(introspect_request, **kwargs)

    return wrapped


def _register_postmortem_crash_tool(
    app: FastMCP,
    *,
    context: _PostmortemRegistrationContext,
    handler: PostmortemCrashHandler,
) -> None:
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
        return _tool_response_json(
            handler(
                request=request,
                runtime=context.runtime(vmcore_model.artifact_root),
            )
        )


def _register_postmortem_triage_tool(
    app: FastMCP,
    *,
    context: _PostmortemRegistrationContext,
    handler: PostmortemTriageHandler,
) -> None:
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
        return _tool_response_json(
            handler(
                request=request,
                runtime=context.runtime(vmcore_model.artifact_root),
            )
        )


def _register_postmortem_check_prereqs_tool(
    app: FastMCP,
    *,
    context: _PostmortemRegistrationContext,
    handler: PostmortemCheckPrereqsHandler,
) -> None:
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
                manifest_target_profile=target_model.manifest_target_profile,
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _tool_response_json(
            handler(
                request=request,
                runtime=context.runtime(target_model.artifact_root),
            )
        )


def _register_postmortem_list_dumps_tool(
    app: FastMCP,
    *,
    context: _PostmortemRegistrationContext,
    handler: PostmortemListDumpsHandler,
) -> None:
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
                manifest_target_profile=target_model.manifest_target_profile,
                dump_dir=options_model.dump_dir,
                timeout_seconds=options_model.timeout_seconds,
                debug_profile=target_model.debug_profile,
                target_profile=target_model.target_profile,
                rootfs_profile=target_model.rootfs_profile,
            )
        except (TypeError, ValueError) as exc:
            return adapter_validation_failure(exc)
        return _tool_response_json(
            handler(
                request=request,
                runtime=context.runtime(target_model.artifact_root),
            )
        )


def _register_postmortem_fetch_tool(
    app: FastMCP,
    *,
    context: _PostmortemRegistrationContext,
    handler: PostmortemFetchHandler,
) -> None:
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
                manifest_target_profile=target_model.manifest_target_profile,
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
        return _tool_response_json(
            handler(
                request=request,
                runtime=context.runtime(target_model.artifact_root),
            )
        )


def register_postmortem_tools(
    app: FastMCP,
    *,
    context: PostmortemToolContext,
    handlers: PostmortemToolHandlers,
) -> None:
    registration_context = _PostmortemRegistrationContext(
        default_artifact_root=str(context.default_artifact_root),
        admission=context.admission,
        session_registry=context.session_registry,
        crash_handler=handlers.crash,
        drgn_helper_handler=_adapt_triage_drgn_helper(handlers.triage_drgn_helper),
    )
    _register_postmortem_crash_tool(
        app,
        context=registration_context,
        handler=handlers.crash,
    )
    _register_postmortem_triage_tool(
        app,
        context=registration_context,
        handler=handlers.triage,
    )
    _register_postmortem_check_prereqs_tool(
        app,
        context=registration_context,
        handler=handlers.check_prereqs,
    )
    _register_postmortem_list_dumps_tool(
        app,
        context=registration_context,
        handler=handlers.list_dumps,
    )
    _register_postmortem_fetch_tool(
        app,
        context=registration_context,
        handler=handlers.fetch,
    )
