from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kdive.config import BootOverrides, BuildOverrides


@dataclass(frozen=True)
class CreateRunRuntime:
    sensitive_paths: list[Path]


@dataclass(frozen=True)
class CreateRunHandlerRequest:
    artifact_root: Path
    source_path: str
    build_profile: str | None
    target_profile: str | None
    rootfs_profile: str | None
    run_id: str | None
    debug_profile: str | None
    test_suite: str | None
    build_overrides: BuildOverrides | None
    boot_overrides: BootOverrides | None
    build_profile_spec: dict[str, Any] | None
    target_profile_spec: dict[str, Any] | None
    rootfs_profile_spec: dict[str, Any] | None
