from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.domain import ToolResponse
from kdive.postmortem.models import (
    DebugPostmortemCheckPrereqsRequest,
    DebugPostmortemCrashRequest,
    DebugPostmortemFetchRequest,
    DebugPostmortemListDumpsRequest,
    DebugPostmortemTriageRequest,
)


class VmcorePostmortemHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemCrashRequest | DebugPostmortemTriageRequest,
        *,
        artifact_root: Path,
    ) -> ToolResponse: ...


class LivePostmortemHandler(Protocol):
    def __call__(
        self,
        request: DebugPostmortemCheckPrereqsRequest | DebugPostmortemListDumpsRequest | DebugPostmortemFetchRequest,
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
    crash_handler: VmcorePostmortemHandler,
    triage_handler: VmcorePostmortemHandler,
    check_prereqs_handler: LivePostmortemHandler,
    list_dumps_handler: LivePostmortemHandler,
    fetch_handler: LivePostmortemHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="debug.postmortem.crash")
    def debug_postmortem_crash(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        commands: list[str],
        modules_ref: str | None = None,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        request = DebugPostmortemCrashRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            commands=commands,
            modules_ref=modules_ref,
            timeout_seconds=timeout_seconds,
        )
        return crash_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.triage")
    def debug_postmortem_triage(
        run_id: str,
        vmcore_ref: str,
        vmlinux_ref: str,
        modules_ref: str | None = None,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        request = DebugPostmortemTriageRequest(
            run_id=run_id,
            vmcore_ref=vmcore_ref,
            vmlinux_ref=vmlinux_ref,
            modules_ref=modules_ref,
            timeout_seconds=timeout_seconds,
        )
        return triage_handler(
            request,
            artifact_root=Path(artifact_root),
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.check_prereqs")
    def debug_postmortem_check_prereqs(
        run_id: str,
        target_ref: str,
        artifact_root: str = default_artifact_root_text,
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugPostmortemCheckPrereqsRequest(
            run_id=run_id,
            manifest_target_profile=target_ref,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return check_prereqs_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.list_dumps")
    def debug_postmortem_list_dumps(
        run_id: str,
        target_ref: str,
        artifact_root: str = default_artifact_root_text,
        dump_dir: str | None = None,
        timeout_seconds: int = 20,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugPostmortemListDumpsRequest(
            run_id=run_id,
            manifest_target_profile=target_ref,
            dump_dir=dump_dir,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return list_dumps_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")

    @app.tool(name="debug.postmortem.fetch")
    def debug_postmortem_fetch(
        run_id: str,
        target_ref: str,
        dump_ref: str,
        artifact_root: str = default_artifact_root_text,
        force: bool = False,
        dump_dir: str | None = None,
        max_bytes: int | None = None,
        timeout_seconds: int = 300,
        debug_profile: str | None = None,
        target_profile: str | None = None,
        rootfs_profile: str | None = None,
    ) -> dict[str, Any]:
        request = DebugPostmortemFetchRequest(
            run_id=run_id,
            manifest_target_profile=target_ref,
            dump_ref=dump_ref,
            force=force,
            dump_dir=dump_dir,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
            debug_profile=debug_profile,
            target_profile=target_profile,
            rootfs_profile=rootfs_profile,
        )
        return fetch_handler(
            request,
            artifact_root=Path(artifact_root),
            admission=admission,
            session_registry=session_registry,
        ).model_dump(mode="json")
