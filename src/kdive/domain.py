from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kdive.config import BootOverrides, BuildOverrides


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELED = "canceled"


class ErrorCategory(StrEnum):
    CONFIGURATION_ERROR = "configuration_error"
    MISSING_DEPENDENCY = "missing_dependency"
    BUILD_FAILURE = "build_failure"
    BOOT_TIMEOUT = "boot_timeout"
    READINESS_FAILURE = "readiness_failure"
    TEST_FAILURE = "test_failure"
    DEBUG_ATTACH_FAILURE = "debug_attach_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    NOT_IMPLEMENTED = "not_implemented"
    STALE_HANDLE = "stale_handle"
    TRANSPORT_CONFLICT = "transport_conflict"


class TargetKind(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"
    VIRTUAL = "virtual"
    PHYSICAL = "physical"


class ImplementationState(StrEnum):
    IMPLEMENTED = "implemented"
    STUB = "stub"
    EXTERNAL_RESERVED = "external_reserved"


class PrerequisiteStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class KernelSource(Model):
    path: str
    git_revision: str | None = None


class BuildArtifact(Model):
    architecture: str
    kernel_image: str | None = None
    vmlinux: str | None = None
    config: str | None = None


class ArtifactRef(Model):
    path: str
    kind: str
    sensitive: bool = False
    description: str | None = None


class ArtifactBundle(Model):
    run_id: str
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    summary_path: str | None = None


class RunRequest(Model):
    source_path: str
    build_profile: str
    target_profile: str
    rootfs_profile: str
    debug_profile: str | None = None
    test_suite: str | None = None
    run_id: str | None = None
    build_overrides: BuildOverrides | None = None
    boot_overrides: BootOverrides | None = None


class DebugIntrospectRunRequest(Model):
    """Request payload for ``debug.introspect.run``. Spec §3.1.

    ``script`` is the user-supplied drgn Python source. The handler
    base64-encodes it for transport and substitutes it into a
    ``string.Template``-rendered wrapper on the target (spec §4.2).
    ``call_id`` is server-minted, not part of the request.

    The ``[5, 300]`` timeout band and the script-non-empty / ≤256 KiB
    invariants are enforced by the handler (not Pydantic) so they surface
    as ``ToolResponse.failure(...)`` with the spec's exact codes from §3.3.
    """

    run_id: str
    target_ref: str
    script: str
    timeout_seconds: int = 30
    allow_write: bool = False
    acknowledged_permissions: list[str] = Field(default_factory=list)
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)


class DebugIntrospectCheckPrerequisitesRequest(Model):
    """Request payload for ``debug.introspect.check_prerequisites``. Spec §3.

    Run-scoped, read-only target probe. ``timeout_seconds`` defaults to 20 and
    is bounded to [5, 60] by the handler (not Pydantic) so an out-of-range
    value surfaces as ``ToolResponse.failure(CONFIGURATION_ERROR)`` per §6.
    """

    run_id: str
    target_ref: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemCheckPrereqsRequest(Model):
    """Request payload for ``debug.postmortem.check_prereqs``. #94 / ADR 0028.

    Run-scoped, live-target kdump-readiness probe. Field-identical to
    ``DebugIntrospectCheckPrerequisitesRequest`` (a distinct tool gets a distinct
    model). ``timeout_seconds`` defaults to 20 and is handler-bounded to [5, 60] so
    an out-of-range value surfaces as ``ToolResponse.failure(CONFIGURATION_ERROR)``.
    """

    run_id: str
    target_ref: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugIntrospectHelperRequest(Model):
    """Request payload for ``debug.introspect.helper``. Spec §6.1.

    ``args`` is validated against the resolved helper's ``args_model`` by the
    handler (not Pydantic) so an unknown helper / bad args surface as the
    spec's exact failure codes. The ``[5, 300]`` timeout band and
    manifest-immutability of profile fields are enforced by the handler.
    """

    run_id: str
    target_ref: str
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugIntrospectFromVmcoreRequest(Model):
    """Request payload for ``debug.introspect.from_vmcore``. Spec §3.1.

    No ``target_ref``/``*_profile``: the offline path names no live target.
    ``vmcore_ref``/``vmlinux_ref``/``modules_ref`` are run-relative and confined
    to the run dir. The ``[5, 300]`` timeout band and the script non-empty /
    ≤256 KiB invariants are enforced by the handler (not Pydantic) so they
    surface as ``ToolResponse.failure(...)`` with the spec's exact codes.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    script: str
    timeout_seconds: int = 30
    allow_write: bool = False
    args: dict[str, Any] = Field(default_factory=dict)


class DebugIntrospectFromVmcoreHelperRequest(Model):
    """Request payload for ``debug.introspect.from_vmcore_helper``. Spec §3.1.

    Runs a curated ``HELPER_REGISTRY`` helper against the vmcore. ``args`` is
    validated against the resolved helper's ``args_model`` by the handler.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30


class DebugPostmortemCrashRequest(Model):
    """Request payload for ``debug.postmortem.crash``. Spec §3.1.

    No ``target_ref``/``*_profile``: the offline crash path names no live target.
    ``vmcore_ref``/``vmlinux_ref``/``modules_ref`` are run-relative and confined
    to the run dir. ``commands`` is validated (sanitise + allowlist) and the
    ``[5, 300]`` timeout / command-count / script-size bounds are enforced by the
    handler so they surface as ``ToolResponse.failure(...)`` with the spec's exact
    codes.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    commands: list[str]
    timeout_seconds: int = 60


class DebugPostmortemTriageRequest(Model):
    """Request payload for ``debug.postmortem.triage``. Spec §3.1.

    Composes the crash (#92) and drgn (#54/#55) offline tiers into one report.
    No ``commands``/``helpers`` (fixed helper set) and no ``target_ref``/``*_profile``
    (offline, never gated). ``timeout_seconds`` is handler-bounded to ``[5, 300]`` and
    applied to EACH sub-call; ``modules_ref`` is validated up front and threaded to the
    crash sub-call only.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    timeout_seconds: int = 60


class DebugPostmortemListDumpsRequest(Model):
    """Request payload for ``debug.postmortem.list_dumps``. #95 / ADR 0029.

    Live-target SSH enumeration of captured vmcores. ``timeout_seconds`` is
    handler-bounded to ``[5, 60]`` (default 20); ``dump_dir`` overrides the
    ``/var/crash`` default and must be an absolute path (handler-validated).
    """

    run_id: str
    target_ref: str
    dump_dir: str | None = None
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemFetchRequest(Model):
    """Request payload for ``debug.postmortem.fetch``. #95 / ADR 0029.

    Stages a dump enumerated by ``list_dumps`` into the run dir. ``dump_ref`` is a
    ``path`` from ``list_dumps`` re-validated against a fresh enumeration.
    ``timeout_seconds`` is handler-bounded to ``[5, 3600]`` (default 300) and bounds
    each scp subprocess. ``max_bytes`` overrides the default size ceiling; ``force``
    re-transfers and overrides the incomplete-dump refusal.
    """

    run_id: str
    target_ref: str
    dump_ref: str
    force: bool = False
    dump_dir: str | None = None
    max_bytes: int | None = None
    timeout_seconds: int = 300
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DumpEntry(Model):
    """One captured vmcore enumerated by ``debug.postmortem.list_dumps``. #95.

    ``path`` is the remote dump directory (the ``dump_ref`` fetch accepts).
    ``file_sizes`` maps each present file name to its remote ``st_size`` and drives
    the per-file truncation guard in fetch.
    """

    path: str
    kernel: str | None
    capture_time: str | None
    size_bytes: int
    incomplete: bool = False
    available_files: list[str] = Field(default_factory=list)
    file_sizes: dict[str, int] = Field(default_factory=dict)


class FetchedFile(Model):
    """One file staged into the run dir by ``debug.postmortem.fetch``. #95."""

    name: str
    ref: str
    sha256: str
    size_bytes: int


class _TriageSectionBase(Model):
    """Shared per-section status. Spec §3.3 / ADR 0027 decision 3."""

    status: Literal["ok", "failed"]
    reason: str | None = None  # the sub-call's stable error code, set iff status == "failed"


class PanicReasonSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    text: str | None = None  # selected panic line; None when none matched (status may still be "ok")


class FaultingTaskSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    pid: int | None = None
    command: str | None = None


class BacktraceSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    frames: list[dict[str, Any]] = Field(default_factory=list)


class RecentDmesgSection(_TriageSectionBase):
    source: Literal["drgn"] = "drgn"
    entries: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


class ModulesSection(_TriageSectionBase):
    source: Literal["drgn"] = "drgn"
    modules: list[dict[str, Any]] = Field(default_factory=list)
    decode_errors: int = 0


class DebugPostmortemTriageReport(Model):
    """Composite triage report. Spec §3.3. All section payloads are pass-through of the
    already-typed-and-redacted upstream shapes (ADR 0027 decision 8)."""

    vmcore_build_id: str
    panic_reason: PanicReasonSection
    faulting_task: FaultingTaskSection
    backtrace: BacktraceSection
    recent_dmesg: RecentDmesgSection
    modules: ModulesSection


class RunStep(Model):
    name: str
    status: StepStatus = StepStatus.PENDING
    provider: str | None = None


class StepResult(Model):
    step_name: str
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class RunRecord(Model):
    run_id: str
    request: RunRequest
    steps: list[RunStep] = Field(default_factory=list)


class OperationSemantics(Model):
    idempotent: bool
    retryable: bool
    destructive: bool
    cancelable: bool
    concurrent_safe: bool


class ProviderDependency(Model):
    name: str
    kind: str = "host_tool"
    required: bool = True


class ProviderOperationCapability(Model):
    operation: str
    semantics: OperationSemantics
    implementation_state: ImplementationState | None = None
    required_host_tools: list[str] = Field(default_factory=list)
    destructive_permissions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ProviderCapability(Model):
    provider_name: str
    provider_version: str
    provider_family: str = "local"
    implementation_state: ImplementationState = ImplementationState.IMPLEMENTED
    architectures: list[str]
    target_kinds: list[TargetKind]
    transports: list[str] = Field(default_factory=list)
    documentation_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    operations: list[str]
    required_host_tools: list[str]
    destructive_permissions: list[str]
    access_methods: list[str]
    semantics: OperationSemantics
    operation_capabilities: list[ProviderOperationCapability] = Field(default_factory=list)

    @model_validator(mode="after")
    def fill_operation_capabilities(self) -> ProviderCapability:
        if not self.operation_capabilities:
            object.__setattr__(
                self,
                "operation_capabilities",
                [
                    ProviderOperationCapability(
                        operation=operation,
                        semantics=self.semantics,
                        implementation_state=self.implementation_state,
                        required_host_tools=list(self.required_host_tools),
                        destructive_permissions=list(self.destructive_permissions),
                        limitations=list(self.limitations),
                    )
                    for operation in self.operations
                ],
            )
            return self

        operation_names = [capability.operation for capability in self.operation_capabilities]
        if operation_names != self.operations:
            raise ValueError("operations must match operation_capabilities in order")
        if all(capability.implementation_state is not None for capability in self.operation_capabilities):
            return self
        object.__setattr__(
            self,
            "operation_capabilities",
            [
                capability.model_copy(
                    update={
                        "implementation_state": capability.implementation_state or self.implementation_state,
                    }
                )
                for capability in self.operation_capabilities
            ],
        )
        return self


class PrerequisiteCheck(Model):
    check_id: str
    status: PrerequisiteStatus
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    suggested_fix: str | None = None


class ErrorInfo(Model):
    category: ErrorCategory
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ToolResponse(Model):
    ok: bool
    status: StepStatus
    summary: str | None = None
    run_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    error: ErrorInfo | None = None
    suggested_next_actions: list[str] = Field(default_factory=list)

    @classmethod
    def success(
        cls,
        *,
        summary: str,
        run_id: str | None = None,
        status: StepStatus = StepStatus.SUCCEEDED,
        data: dict[str, Any] | None = None,
        artifacts: list[ArtifactRef] | None = None,
        suggested_next_actions: list[str] | None = None,
    ) -> ToolResponse:
        return cls(
            ok=True,
            status=status,
            summary=summary,
            run_id=run_id,
            data=data or {},
            artifacts=artifacts or [],
            suggested_next_actions=suggested_next_actions or [],
        )

    @classmethod
    def failure(
        cls,
        *,
        category: ErrorCategory,
        message: str,
        run_id: str | None = None,
        details: dict[str, Any] | None = None,
        artifacts: list[ArtifactRef] | None = None,
        suggested_next_actions: list[str] | None = None,
    ) -> ToolResponse:
        return cls(
            ok=False,
            status=StepStatus.FAILED,
            run_id=run_id,
            artifacts=artifacts or [],
            error=ErrorInfo(category=category, message=message, details=details or {}),
            suggested_next_actions=suggested_next_actions or [],
        )
