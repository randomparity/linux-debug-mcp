from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from kdive.config import BuildProfile
from kdive.domain import ArtifactRef, ErrorCategory, StepStatus
from kdive.providers.models import (
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)
from kdive.safety.redaction import Redactor


class ConfigMergeError(Exception):
    def __init__(self, message: str, *, diagnostic: str | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic


class ConfigGenerationError(Exception):
    """A ``base_config`` make target failed, or the targets ran but left no ``.config``.

    ``diagnostic`` carries the redacted log tail of the failing target; ``log_path`` points at the
    per-target log so the handler can attach it as a ``config-log`` artifact (ADR 0030 decision 7).
    """

    def __init__(self, message: str, *, diagnostic: str | None = None, log_path: Path | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic
        self.log_path = log_path


class MissingConfigError(Exception):
    """No ``.config`` exists and the profile declares no ``base_config`` to generate one.

    ``suggested_fix`` is surfaced through ``BuildExecutionResult.details`` (ADR 0030 decision 6).
    """

    def __init__(self, message: str, *, suggested_fix: str) -> None:
        super().__init__(message)
        self.suggested_fix = suggested_fix


def _sanitize_target(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", target)


class ReadelfUnavailable(Exception):
    """``readelf`` failed — binary missing, non-zero exit, or timed out.

    Spec §7 R2-F6: distinct from ``BuildIdMissing`` so the caller can map
    each to its own ``(ErrorCategory, code)`` without inspecting auxiliary
    state.

    The optional ``artifacts`` payload carries the build artifacts that DID
    get produced (vmlinux may be present, ``.config`` and build log
    certainly are) so the handler can attach them to the FAILED
    ``StepResult`` for forensic recovery. Without this, the operator would
    see a build failure with zero artifacts even though the kernel built
    fine — build_id extraction is the only thing that failed.
    """

    def __init__(self, message: str, *, artifacts: list[ArtifactRef] | None = None) -> None:
        super().__init__(message)
        self.artifacts: list[ArtifactRef] = artifacts or []


class BuildIdMissing(Exception):
    """``readelf`` ran cleanly but the vmlinux carries no ``.note.gnu.build-id``.

    Same ``artifacts`` contract as ``ReadelfUnavailable`` — see that
    docstring.
    """

    def __init__(self, message: str, *, artifacts: list[ArtifactRef] | None = None) -> None:
        super().__init__(message)
        self.artifacts: list[ArtifactRef] = artifacts or []


_BUILD_ID_LINE = re.compile(r"\s*Build ID:\s*([0-9a-fA-F]+)")

# Wall-clock ceiling for the `readelf -n` build-id probe. Reading the note headers of a local
# vmlinux is near-instant; the cap only guards against a hung/blocked subprocess.
READELF_TIMEOUT_SECONDS = 10


def _extract_build_id(vmlinux: Path) -> str:
    """Return the lower-case hex ``.note.gnu.build-id`` of *vmlinux*.

    Spec §7. Raises ``ReadelfUnavailable`` when the binary cannot be
    invoked / returns non-zero / times out. Raises ``BuildIdMissing`` when
    ``readelf`` succeeded but the note is absent.
    """
    try:
        proc = subprocess.run(
            ["readelf", "-n", str(vmlinux)],
            capture_output=True,
            text=True,
            check=False,
            timeout=READELF_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ReadelfUnavailable(str(exc)) from exc
    if proc.returncode != 0:
        raise ReadelfUnavailable(f"readelf exit={proc.returncode}: {proc.stderr[:200]}")
    for line in proc.stdout.splitlines():
        match = _BUILD_ID_LINE.match(line)
        if match:
            return match.group(1).lower()
    raise BuildIdMissing(f"no Build ID note in {vmlinux}")


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
    environment: dict[str, str]
    config_lines: list[str] = field(default_factory=list)
    base_config: list[str] = field(default_factory=list)


class BuildRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        raise NotImplementedError


class SubprocessBuildRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        with log_path.open("w", encoding="utf-8") as log_file:
            completed = subprocess.run(
                argv,
                check=False,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                timeout=timeout,
                cwd=cwd,
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


def _default_job_count() -> int:
    """Default ``make -j`` parallelism when a build profile sets no explicit ``jobs``.

    Returns at least half the CPUs usable by this process (rounded up, floor 1). The count
    comes from the process CPU affinity so it honors ``taskset``/cpuset limits, falling back
    to the reported CPU count on platforms without affinity support. A profile's explicit
    ``jobs`` value overrides this default.
    """
    try:
        usable = len(os.sched_getaffinity(0))
    except AttributeError:  # pragma: no cover - non-Linux platforms lack sched_getaffinity
        usable = os.cpu_count() or 1
    return max(1, (usable + 1) // 2)


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
        argv = ["make", "-C", str(source_path), f"O={output_path}", "ARCH=x86_64"]
        jobs = profile.jobs if profile.jobs is not None else _default_job_count()
        argv.append(f"-j{jobs}")
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
            environment=self._sanitized_environment(),
            config_lines=list(profile.config_lines),
            base_config=list(profile.base_config),
        )

    def prepare_config(self, *, plan: BuildPlan, log_dir: Path) -> Path:
        """Resolve the base ``.config`` via the ADR 0030 precedence ladder.

        1. output-dir ``.config`` exists → use it (idempotent rebuild);
        2. else source-tree ``.config`` exists → copy it (developer-prepared wins);
        3. else ``base_config`` non-empty → generate it via the ordered make targets;
        4. else → ``MissingConfigError`` carrying an actionable ``suggested_fix``.
        """
        output_path = plan.output_path
        output_path.mkdir(parents=True, exist_ok=True)
        output_config = output_path / ".config"
        if output_config.exists():
            return output_config
        source_config = plan.source_path / ".config"
        if source_config.exists():
            shutil.copy2(source_config, output_config)
            return output_config
        if plan.base_config:
            self._generate_base_config(plan=plan, log_dir=log_dir)
            if not output_config.exists():
                raise ConfigGenerationError("base config targets produced no .config")
            return output_config
        raise MissingConfigError(
            "missing developer-prepared .config",
            suggested_fix='Set base_config (e.g. ["defconfig"]) on the build profile, '
            "or provide a .config in the source tree.",
        )

    def _generate_base_config(self, *, plan: BuildPlan, log_dir: Path) -> None:
        log_dir.mkdir(parents=True, exist_ok=True)
        for index, target in enumerate(plan.base_config):
            target_log = log_dir / f"config-base-{index:02d}-{_sanitize_target(target)}.log"
            status = self.runner.run(
                ["make", "-C", str(plan.source_path), f"O={plan.output_path}", "ARCH=x86_64", target],
                timeout=plan.timeout_seconds,
                log_path=target_log,
                env=plan.environment,
                cwd=plan.output_path,
            )
            if status != 0:
                raise ConfigGenerationError(
                    f"base config target {target!r} failed (exit status {status})",
                    diagnostic=self._log_tail(target_log),
                    log_path=target_log,
                )

    def _apply_config_lines(self, *, plan: BuildPlan, base_config: Path, log_dir: Path) -> None:
        if not plan.config_lines:
            return
        merge_script = plan.source_path / "scripts" / "kconfig" / "merge_config.sh"
        if not merge_script.is_file():
            raise ConfigMergeError(f"merge_config.sh not found at {merge_script}")
        inputs_dir = plan.output_path.parent / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        override_config = inputs_dir / "override.config"
        override_config.write_text("\n".join(plan.config_lines) + "\n", encoding="utf-8")
        merge_log = log_dir / "config-merge.log"
        merge_status = self.runner.run(
            [str(merge_script), "-m", "-O", str(plan.output_path), str(base_config), str(override_config)],
            timeout=plan.timeout_seconds,
            log_path=merge_log,
            env=plan.environment,
            cwd=plan.output_path,
        )
        if merge_status != 0:
            raise ConfigMergeError(
                f"kernel config merge failed (exit status {merge_status})",
                diagnostic=self._log_tail(merge_log),
            )
        olddefconfig_log = log_dir / "config-olddefconfig.log"
        olddefconfig_status = self.runner.run(
            ["make", "-C", str(plan.source_path), f"O={plan.output_path}", "ARCH=x86_64", "olddefconfig"],
            timeout=plan.timeout_seconds,
            log_path=olddefconfig_log,
            env=plan.environment,
            cwd=plan.output_path,
        )
        if olddefconfig_status != 0:
            raise ConfigMergeError(
                f"olddefconfig failed (exit status {olddefconfig_status})",
                diagnostic=self._log_tail(olddefconfig_log),
            )

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
            base_config = self.prepare_config(plan=plan, log_dir=log_path.parent)
            self._apply_config_lines(plan=plan, base_config=base_config, log_dir=log_path.parent)
            exit_status = self.runner.run(
                plan.argv, timeout=plan.timeout_seconds, log_path=log_path, env=plan.environment
            )
        except ConfigMergeError as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={"argv": plan.argv, "source_revision": source_revision},
                diagnostic=exc.diagnostic,
            )
        except ConfigGenerationError as exc:
            artifacts = (
                [ArtifactRef(path=str(exc.log_path), kind="config-log")]
                if exc.log_path is not None and exc.log_path.is_file()
                else []
            )
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                artifacts=artifacts,
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={"argv": plan.argv, "source_revision": source_revision},
                diagnostic=exc.diagnostic,
            )
        except MissingConfigError as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=str(exc),
                error_category=ErrorCategory.CONFIGURATION_ERROR,
                details={
                    "argv": plan.argv,
                    "source_revision": source_revision,
                    "suggested_fix": exc.suggested_fix,
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return BuildExecutionResult(
                status=StepStatus.FAILED,
                summary=f"build infrastructure failure: {exc}",
                error_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={"argv": plan.argv, "source_revision": source_revision},
                diagnostic=self._log_tail(log_path),
            )
        return self._assemble_build_result(
            plan=plan,
            log_path=log_path,
            summary_path=summary_path,
            exit_status=exit_status,
            source_revision=source_revision,
            started_at=started_at,
        )

    def _assemble_build_result(
        self,
        *,
        plan: BuildPlan,
        log_path: Path,
        summary_path: Path,
        exit_status: int,
        source_revision: dict[str, object],
        started_at: datetime,
    ) -> BuildExecutionResult:
        ended_at = datetime.now(UTC)
        details: dict[str, object] = {
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
            "environment": {
                "mode": "sanitized",
                "passed_keys": sorted(plan.environment),
            },
        }
        kernel_release = self._detect_kernel_release(plan.output_path)
        if kernel_release is not None:
            details["kernel_release"] = kernel_release
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
            return self._finalize_build_result(
                plan=plan,
                log_path=log_path,
                summary_path=summary_path,
                details=details,
                artifacts=artifacts,
                status=StepStatus.FAILED,
                summary="kernel build failed",
                error_category=ErrorCategory.BUILD_FAILURE,
                diagnostic=self._log_tail(log_path),
            )
        required = {str(plan.output_path / ".config"), str(plan.output_path / "arch" / "x86" / "boot" / "bzImage")}
        present = {artifact.path for artifact in artifacts}
        missing = sorted(required - present)
        if missing:
            details = {**details, "missing_artifacts": missing}
            return self._finalize_build_result(
                plan=plan,
                log_path=log_path,
                summary_path=summary_path,
                details=details,
                artifacts=artifacts,
                status=StepStatus.FAILED,
                summary="kernel build did not produce required artifacts",
                error_category=ErrorCategory.BUILD_FAILURE,
                diagnostic=self._log_tail(log_path),
            )
        # The build succeeded — vmlinux, .config, and build-log all exist. If
        # `_extract_build_id` fails, re-raise with the artifacts attached so the handler can persist
        # them in the FAILED StepResult; operators need them to diagnose why readelf came up empty
        # without re-running the build.
        try:
            details["build_id"] = _extract_build_id(plan.output_path / "vmlinux")
        except ReadelfUnavailable as exc:
            raise ReadelfUnavailable(str(exc), artifacts=self._existing_artifacts(artifacts)) from exc
        except BuildIdMissing as exc:
            raise BuildIdMissing(str(exc), artifacts=self._existing_artifacts(artifacts)) from exc
        return self._finalize_build_result(
            plan=plan,
            log_path=log_path,
            summary_path=summary_path,
            details=details,
            artifacts=artifacts,
            status=StepStatus.SUCCEEDED,
            summary="kernel build succeeded",
        )

    def _existing_artifacts(self, artifacts: list[ArtifactRef]) -> list[ArtifactRef]:
        """Filter to artifacts whose files exist on disk.

        Spec §7 R2-F6: when re-raising on readelf failure, the summary file has
        not been written yet (write happens in ``_finalize_build_result``). Drop
        any ArtifactRef pointing at a non-existent path so the manifest does
        not claim a build-summary that the operator cannot read.
        """
        return [artifact for artifact in artifacts if Path(artifact.path).is_file()]

    def _detect_artifacts(self, *, plan: BuildPlan, log_path: Path, summary_path: Path) -> list[ArtifactRef]:
        candidates = [
            (log_path, "build-log"),
            (plan.output_path / ".config", "kernel-config"),
            (plan.output_path / "arch" / "x86" / "boot" / "bzImage", "kernel-image"),
            (plan.output_path / "vmlinux", "vmlinux"),
            (summary_path, "build-summary"),
        ]
        return [ArtifactRef(path=str(path), kind=kind) for path, kind in candidates if path.is_file()]

    def _detect_kernel_release(self, output_path: Path) -> str | None:
        kernel_release_path = output_path / "include" / "config" / "kernel.release"
        try:
            kernel_release = kernel_release_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return kernel_release or None

    def _write_summary(self, *, summary_path: Path, details: dict[str, object], artifacts: list[ArtifactRef]) -> None:
        payload = {**details, "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts]}
        summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _finalize_build_result(
        self,
        *,
        plan: BuildPlan,
        log_path: Path,
        summary_path: Path,
        details: dict[str, object],
        artifacts: list[ArtifactRef],
        status: StepStatus,
        summary: str,
        error_category: ErrorCategory | None = None,
        diagnostic: str | None = None,
    ) -> BuildExecutionResult:
        try:
            self._write_summary(summary_path=summary_path, details=details, artifacts=artifacts)
        except OSError as exc:
            return self._infrastructure_failure(exc=exc, plan=plan, log_path=log_path, details=details)
        return BuildExecutionResult(
            status=status,
            summary=summary,
            artifacts=artifacts,
            details=details,
            error_category=error_category,
            diagnostic=diagnostic,
        )

    def _sanitized_environment(self) -> dict[str, str]:
        allowed_exact = {"HOME", "LANG", "LOGNAME", "PATH", "TMPDIR", "USER"}
        return {key: value for key, value in os.environ.items() if key in allowed_exact or key.startswith("LC_")}

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
        with log_path.open("rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            size = log_file.tell()
            log_file.seek(max(size - limit, 0))
            text = log_file.read().decode("utf-8", errors="replace")
        return self.redactor.redact_text(text)


def local_kernel_build_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-kernel-build",
        provider_version="0.1.0",
        provider_family="build",
        architectures=["x86_64"],
        target_kinds=[TargetKind.LOCAL],
        transports=["subprocess", "filesystem"],
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
