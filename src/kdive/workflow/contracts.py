from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kdive.config import BootOverrides, BuildOverrides
from kdive.coordination.admission import AdmissionService
from kdive.coordination.registry import SessionRegistry
from kdive.coordination.transaction import TransportTransaction
from kdive.debug.tools import DebugStartSessionRequest, DebugToolContext
from kdive.domain import ToolResponse
from kdive.kernel.tools import CreateRunHandler, KernelBuildHandler
from kdive.providers.debug import GdbMiEngine, GdbMiSessionRegistry
from kdive.seams.guard import SessionGuard
from kdive.target.tools import TargetBootHandler, TargetRunTestsHandler


class DebugStartSessionHandler(Protocol):
    def __call__(
        self,
        *,
        request: DebugStartSessionRequest,
        runtime: DebugToolContext,
    ) -> ToolResponse: ...


class ArtifactsCollectHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        force_recollect: bool = False,
    ) -> ToolResponse: ...


@dataclass(frozen=True)
class WorkflowHandlerDependencies:
    create_run_handler: CreateRunHandler
    kernel_build_handler: KernelBuildHandler
    target_boot_handler: TargetBootHandler
    target_run_tests_handler: TargetRunTestsHandler
    debug_start_session_handler: DebugStartSessionHandler
    artifacts_collect_handler: ArtifactsCollectHandler


@dataclass(frozen=True)
class WorkflowToolRuntime:
    sensitive_paths: list[Path]
    admission: AdmissionService
    session_registry: SessionRegistry
    transaction: TransportTransaction
    session_guard: SessionGuard
    gdb_mi_engine: GdbMiEngine
    gdb_mi_sessions: GdbMiSessionRegistry
    dependencies: WorkflowHandlerDependencies


@dataclass(frozen=True)
class WorkflowBuildBootTestHandlerRequest:
    artifact_root: Path
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    run_id: str | None
    test_suite: str | None
    commands: list[list[str]] | None
    force_rebuild: bool
    force_reboot: bool
    force_rerun_tests: bool
    force_recollect: bool
    build_overrides: BuildOverrides | None
    boot_overrides: BootOverrides | None
    build_profile_spec: dict[str, Any] | None
    target_profile_spec: dict[str, Any] | None
    rootfs_profile_spec: dict[str, Any] | None
    acknowledged_permissions: list[str] | None


@dataclass(frozen=True)
class WorkflowBuildBootDebugHandlerRequest:
    artifact_root: Path
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    run_id: str | None
    debug_profile: str | None
    force_rebuild: bool
    force_reboot: bool
    new_session: bool
    build_overrides: BuildOverrides | None
    boot_overrides: BootOverrides | None
    build_profile_spec: dict[str, Any] | None
    target_profile_spec: dict[str, Any] | None
    rootfs_profile_spec: dict[str, Any] | None
    acknowledged_permissions: list[str] | None
