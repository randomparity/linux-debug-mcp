from __future__ import annotations

import shutil
import subprocess
import sys
from importlib import util as importlib_util
from pathlib import Path
from typing import Protocol

from linux_debug_mcp.domain import PrerequisiteCheck, PrerequisiteStatus
from linux_debug_mcp.safety.paths import PathSafetyError, validate_artifact_root, validate_source_path


class PrerequisiteRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        raise NotImplementedError


class SubprocessPrerequisiteRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout, completed.stderr


def check_prerequisites(
    *,
    artifact_root: Path,
    source_path: Path | None,
    enable_libvirt_check: bool,
    runner: PrerequisiteRunner | None = None,
) -> list[PrerequisiteCheck]:
    runner = runner or SubprocessPrerequisiteRunner()
    checks: list[PrerequisiteCheck] = []
    checks.append(_python_version_check())
    checks.extend(_python_package_checks())
    for tool in ["make", "bash", "git", "qemu-system-x86_64", "virsh", "gdb"]:
        checks.append(_tool_check(tool, runner))
    checks.append(_compiler_check(runner))
    checks.append(_artifact_root_check(artifact_root, source_path))
    checks.append(_source_tree_check(source_path))
    checks.append(_libvirt_check(enable_libvirt_check, runner))
    return checks


def _python_version_check() -> PrerequisiteCheck:
    status = PrerequisiteStatus.PASSED if sys.version_info >= (3, 11) else PrerequisiteStatus.FAILED
    return PrerequisiteCheck(
        check_id="python.version",
        status=status,
        message=f"Python {sys.version_info.major}.{sys.version_info.minor}",
        suggested_fix=None if status == PrerequisiteStatus.PASSED else "Use Python 3.11 or newer.",
    )


def _tool_check(tool: str, runner: PrerequisiteRunner) -> PrerequisiteCheck:
    path = runner.which(tool)
    if path:
        return PrerequisiteCheck(
            check_id=f"tool.{tool}",
            status=PrerequisiteStatus.PASSED,
            message=f"{tool} found",
            details={"path": path},
        )
    return PrerequisiteCheck(
        check_id=f"tool.{tool}",
        status=PrerequisiteStatus.FAILED,
        message=f"{tool} was not found",
        suggested_fix=f"Install {tool} with your distribution package manager.",
    )


def _python_package_checks() -> list[PrerequisiteCheck]:
    checks: list[PrerequisiteCheck] = []
    for package in ["mcp", "pydantic"]:
        found = importlib_util.find_spec(package) is not None
        checks.append(
            PrerequisiteCheck(
                check_id=f"python.package.{package}",
                status=PrerequisiteStatus.PASSED if found else PrerequisiteStatus.FAILED,
                message=f"Python package {package} {'is installed' if found else 'is not installed'}",
                suggested_fix=None if found else "Run: python -m pip install -e '.[test]'",
            )
        )
    return checks


def _compiler_check(runner: PrerequisiteRunner) -> PrerequisiteCheck:
    for command in ["gcc", "clang"]:
        path = runner.which(command)
        if path:
            return PrerequisiteCheck(
                check_id="compiler.c",
                status=PrerequisiteStatus.PASSED,
                message=f"{command} found",
                details={"command": command, "path": path},
            )
    return PrerequisiteCheck(
        check_id="compiler.c",
        status=PrerequisiteStatus.FAILED,
        message="neither gcc nor clang was found",
        suggested_fix="Install gcc or clang with your distribution package manager.",
    )


def _artifact_root_check(artifact_root: Path, source_path: Path | None) -> PrerequisiteCheck:
    try:
        validate_artifact_root(
            artifact_root,
            source_paths=[source_path] if source_path else [],
            sensitive_paths=[],
        )
    except PathSafetyError as exc:
        return PrerequisiteCheck(
            check_id="artifact_root.writable",
            status=PrerequisiteStatus.FAILED,
            message=str(exc),
            suggested_fix="Choose a dedicated writable artifact directory outside the source checkout.",
        )
    return PrerequisiteCheck(
        check_id="artifact_root.writable",
        status=PrerequisiteStatus.PASSED,
        message="artifact root is usable",
    )


def _source_tree_check(source_path: Path | None) -> PrerequisiteCheck:
    if source_path is None:
        return PrerequisiteCheck(
            check_id="source.linux_tree",
            status=PrerequisiteStatus.SKIPPED,
            message="no source path supplied",
        )
    try:
        validate_source_path(source_path)
    except PathSafetyError as exc:
        return PrerequisiteCheck(
            check_id="source.linux_tree",
            status=PrerequisiteStatus.FAILED,
            message=str(exc),
            suggested_fix="Pass a local Linux source checkout containing Kconfig and Makefile.",
        )
    return PrerequisiteCheck(
        check_id="source.linux_tree",
        status=PrerequisiteStatus.PASSED,
        message="source path looks like a Linux tree",
    )


def _libvirt_check(enable_libvirt_check: bool, runner: PrerequisiteRunner) -> PrerequisiteCheck:
    if not enable_libvirt_check:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.SKIPPED,
            message="libvirt check disabled",
        )
    if runner.which("virsh") is None:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.FAILED,
            message="virsh was not found",
            suggested_fix="Install libvirt client tools before enabling the libvirt URI check.",
        )
    code, stdout, stderr = runner.run(["virsh", "uri"], timeout=10)
    if code == 0:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.PASSED,
            message="libvirt client is visible",
            details={"uri": stdout.strip()},
        )
    return PrerequisiteCheck(
        check_id="libvirt.uri",
        status=PrerequisiteStatus.FAILED,
        message="virsh uri failed",
        details={"stderr": stderr.strip()},
        suggested_fix="Confirm libvirt is installed and your user can access the development connection.",
    )
