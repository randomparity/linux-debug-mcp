from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from kdive.model import Model


class DebugPostmortemCheckPrereqsRequest(Model):
    """Request payload for ``debug.postmortem.check_prereqs``. #94 / ADR 0028."""

    run_id: str
    manifest_target_profile: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemCrashRequest(Model):
    """Request payload for ``debug.postmortem.crash``. Spec §3.1."""

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    commands: list[str]
    timeout_seconds: int = 60


class DebugPostmortemTriageRequest(Model):
    """Request payload for ``debug.postmortem.triage``. Spec §3.1."""

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    timeout_seconds: int = 60


class DebugPostmortemListDumpsRequest(Model):
    """Request payload for ``debug.postmortem.list_dumps``. #95 / ADR 0029."""

    run_id: str
    manifest_target_profile: str
    dump_dir: str | None = None
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemFetchRequest(Model):
    """Request payload for ``debug.postmortem.fetch``. #95 / ADR 0029."""

    run_id: str
    manifest_target_profile: str
    dump_ref: str
    force: bool = False
    dump_dir: str | None = None
    max_bytes: int | None = None
    timeout_seconds: int = 300
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DumpEntry(Model):
    """One captured vmcore enumerated by ``debug.postmortem.list_dumps``. #95."""

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
    reason: str | None = None


class PanicReasonSection(_TriageSectionBase):
    source: Literal["crash"] = "crash"
    text: str | None = None


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
    """Composite triage report. Spec §3.3."""

    vmcore_build_id: str
    panic_reason: PanicReasonSection
    faulting_task: FaultingTaskSection
    backtrace: BacktraceSection
    recent_dmesg: RecentDmesgSection
    modules: ModulesSection
