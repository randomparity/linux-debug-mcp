from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from kdive.model import Model


class DebugPostmortemCheckPrereqsRequest(Model):
    run_id: str
    manifest_target_profile: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemCrashRequest(Model):
    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    commands: list[str]
    timeout_seconds: int = 60


class DebugPostmortemTriageRequest(Model):
    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    timeout_seconds: int = 60


class DebugPostmortemListDumpsRequest(Model):
    run_id: str
    manifest_target_profile: str
    dump_dir: str | None = None
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugPostmortemFetchRequest(Model):
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
    path: str
    kernel: str | None
    capture_time: str | None
    size_bytes: int
    incomplete: bool = False
    available_files: list[str] = Field(default_factory=list)
    file_sizes: dict[str, int] = Field(default_factory=dict)


class FetchedFile(Model):
    name: str
    ref: str
    sha256: str
    size_bytes: int


class _TriageSectionBase(Model):
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
    vmcore_build_id: str
    panic_reason: PanicReasonSection
    faulting_task: FaultingTaskSection
    backtrace: BacktraceSection
    recent_dmesg: RecentDmesgSection
    modules: ModulesSection
