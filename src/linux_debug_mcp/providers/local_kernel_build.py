from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from linux_debug_mcp.config import BuildProfile
from linux_debug_mcp.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    ProviderCapability,
    StepStatus,
    TargetKind,
)
from linux_debug_mcp.safety.redaction import Redactor


@dataclass(frozen=True)
class BuildPlan:
    argv: list[str]
    source_path: Path
    output_path: Path
    architecture: str
    targets: list[str]
    profile_name: str
    timeout_seconds: int
    required_tools: list[str]


class BuildRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        raise NotImplementedError


class SubprocessBuildRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(self, argv: list[str], *, timeout: int, log_path: Path) -> int:
        with log_path.open("w", encoding="utf-8") as log_file:
            completed = subprocess.run(
                argv,
                check=False,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
        return completed.returncode


@dataclass(frozen=True)
class BuildExecutionResult:
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None


class LocalKernelBuildProvider:
    name = "local-kernel-build"
    supported_architectures = ["x86_64"]

    def __init__(self, *, runner: BuildRunner | None = None, redactor: Redactor | None = None) -> None:
        self.runner = runner or SubprocessBuildRunner()
        self.redactor = redactor or Redactor()

    def plan_build(self, *, source_path: Path, output_path: Path, profile: BuildProfile) -> BuildPlan:
        if profile.provider_name != self.name:
            raise ValueError(f"unsupported build provider: {profile.provider_name}")
        if profile.architecture not in self.supported_architectures:
            raise ValueError(f"unsupported architecture: {profile.architecture}")
        if profile.output_policy != "per_run":
            raise ValueError(f"unsupported output policy: {profile.output_policy}")
        if profile.config_fragments:
            raise ValueError("config fragments are not supported by the local Sprint 1 provider")
        argv = ["make", "-C", str(source_path), f"O={output_path}", "ARCH=x86_64"]
        if profile.jobs is not None:
            argv.append(f"-j{profile.jobs}")
        argv.extend(f"{key}={value}" for key, value in profile.make_variables.items())
        argv.extend(profile.targets)
        return BuildPlan(
            argv=argv,
            source_path=source_path,
            output_path=output_path,
            architecture=profile.architecture,
            targets=list(profile.targets),
            profile_name=profile.name,
            timeout_seconds=profile.command_timeout_seconds,
            required_tools=profile.effective_required_tools(),
        )

    def prepare_config(self, *, source_path: Path, output_path: Path) -> Path:
        output_path.mkdir(parents=True, exist_ok=True)
        output_config = output_path / ".config"
        if output_config.exists():
            return output_config
        source_config = source_path / ".config"
        if not source_config.exists():
            raise ValueError("missing developer-prepared .config")
        shutil.copy2(source_config, output_config)
        return output_config

    def detect_source_revision(self, source_path: Path) -> dict[str, object]:
        try:
            commit = subprocess.check_output(
                ["git", "-C", str(source_path), "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            ).strip()
            dirty_status = subprocess.check_output(
                ["git", "-C", str(source_path), "status", "--porcelain"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"commit": None, "dirty": None, "reason": str(exc)}
        return {"commit": commit, "dirty": bool(dirty_status.strip()), "reason": None}

    def execute_build(self, *, plan: BuildPlan, log_path: Path, summary_path: Path) -> BuildExecutionResult:
        started_at = datetime.now(UTC)
        source_revision = self.detect_source_revision(plan.source_path)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return self._infrastructure_failure(
                exc=exc,
                plan=plan,
                log_path=log_path,
                details={"argv": plan.argv, "source_revision": source_revision},
            )
        missing_tools = [tool for tool in plan.required_tools if self.runner.which(tool) is None]
        if missing_tools:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary="missing required build tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": missing_tools, "argv": plan.argv, "source_revision": source_revision},
            )
        try:
            self.prepare_config(source_path=plan.source_path, output_path=plan.output_path)
            exit_status = self.runner.run(plan.argv, timeout=plan.timeout_seconds, log_path=log_path)
        except ValueError as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={"argv": plan.argv, "source_revision": source_revision},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=f"build infrastructure failure: {exc}",
                error_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={"argv": plan.argv, "source_revision": source_revision},
                diagnostic=self._log_tail(log_path),
            )
        ended_at = datetime.now(UTC)
        details = {
            "argv": plan.argv,
            "source_revision": source_revision,
            "source_path": str(plan.source_path),
            "output_path": str(plan.output_path),
            "architecture": plan.architecture,
            "targets": plan.targets,
            "profile": plan.profile_name,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "timeout_seconds": plan.timeout_seconds,
            "exit_status": exit_status,
            "elapsed_seconds": (ended_at - started_at).total_seconds(),
        }
        try:
            artifacts = self._detect_artifacts(plan=plan, log_path=log_path, summary_path=summary_path)
            if not any(
                artifact.path == str(summary_path) and artifact.kind == "build-summary" for artifact in artifacts
            ):
                artifacts.append(ArtifactRef(path=str(summary_path), kind="build-summary"))
        except OSError as exc:
            return self._infrastructure_failure(exc=exc, plan=plan, log_path=log_path, details=details)
        if exit_status != 0:
            artifacts = [artifact for artifact in artifacts if artifact.kind in {"build-log", "build-summary"}]
            summary = "kernel build failed"
            try:
                self._write_summary(summary_path=summary_path, details=details, artifacts=artifacts)
            except OSError as exc:
                return self._infrastructure_failure(exc=exc, plan=plan, log_path=log_path, details=details)
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=summary,
                artifacts=artifacts,
                details=details,
                error_category=ErrorCategory.BUILD_FAILURE,
                diagnostic=self._log_tail(log_path),
            )
        required = {str(plan.output_path / ".config"), str(plan.output_path / "arch" / "x86" / "boot" / "bzImage")}
        present = {artifact.path for artifact in artifacts}
        missing = sorted(required - present)
        if missing:
            details = {**details, "missing_artifacts": missing}
            try:
                self._write_summary(summary_path=summary_path, details=details, artifacts=artifacts)
            except OSError as exc:
                return self._infrastructure_failure(exc=exc, plan=plan, log_path=log_path, details=details)
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary="kernel build did not produce required artifacts",
                artifacts=artifacts,
                details=details,
                error_category=ErrorCategory.BUILD_FAILURE,
                diagnostic=self._log_tail(log_path),
            )
        try:
            self._write_summary(summary_path=summary_path, details=details, artifacts=artifacts)
        except OSError as exc:
            return self._infrastructure_failure(exc=exc, plan=plan, log_path=log_path, details=details)
        return BuildExecutionResult(
            status=StepStatus.SUCCEEDED,
            summary="kernel build succeeded",
            artifacts=artifacts,
            details=details,
        )

    def _detect_artifacts(self, *, plan: BuildPlan, log_path: Path, summary_path: Path) -> list[ArtifactRef]:
        candidates = [
            (log_path, "build-log"),
            (plan.output_path / ".config", "kernel-config"),
            (plan.output_path / "arch" / "x86" / "boot" / "bzImage", "kernel-image"),
            (plan.output_path / "vmlinux", "vmlinux"),
            (summary_path, "build-summary"),
        ]
        return [ArtifactRef(path=str(path), kind=kind) for path, kind in candidates if path.is_file()]

    def _write_summary(self, *, summary_path: Path, details: dict[str, object], artifacts: list[ArtifactRef]) -> None:
        payload = {**details, "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts]}
        summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _infrastructure_failure(
        self, *, exc: OSError, plan: BuildPlan, log_path: Path, details: dict[str, object] | None = None
    ) -> BuildExecutionResult:
        return BuildExecutionResult(
            status=StepStatus.FAILED,
            summary=f"build infrastructure failure: {exc}",
            error_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            details=details or {"argv": plan.argv},
            diagnostic=self._log_tail(log_path),
        )

    def _log_tail(self, log_path: Path, *, limit: int = 4000) -> str | None:
        if not log_path.is_file():
            return None
        text = log_path.read_text(encoding="utf-8", errors="replace")
        return self.redactor.redact_text(text[-limit:])


def local_kernel_build_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-kernel-build",
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        operations=["kernel.build"],
        required_host_tools=["make"],
        destructive_permissions=[],
        access_methods=["filesystem", "subprocess"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=False,
            cancelable=False,
            concurrent_safe=False,
        ),
    )
