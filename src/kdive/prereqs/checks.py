from __future__ import annotations

import errno
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib import util as importlib_util
from pathlib import Path
from typing import Literal, Protocol

from kdive.config import BuildProfile, RootfsProfile, TargetProfile
from kdive.domain import PrerequisiteCheck, PrerequisiteStatus
from kdive.rootfs.sources import RootfsSourceError, resolve_rootfs_source
from kdive.safety.paths import PathSafetyError, validate_artifact_root, validate_source_path


class PrerequisiteRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        raise NotImplementedError


class SubprocessPrerequisiteRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        # errors="replace": tool output (e.g. gdb's banner) is not guaranteed clean UTF-8, and a
        # strict decode would raise UnicodeDecodeError out of a prerequisite probe. Replacement keeps
        # the output usable for the substring/version checks the callers perform.
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
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
    for tool in ["make", "bash", "git", "qemu-system-x86_64", "virsh", "gdb", "crash"]:
        checks.append(_tool_check(tool, runner))
    checks.append(_gdb_mi_capability_check(runner))
    checks.append(_agent_proxy_check(runner))
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


_GDB_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.\d+)?")
_MI_MIN_VERSION = (9, 1)


def _parse_gdb_version(text: str) -> tuple[int, int] | None:
    """Parse gdb's OWN version from ``gdb --version``. gdb prints it as the last whitespace-delimited
    token of the first line -- ``GNU gdb (Ubuntu 8.0.1-1ubuntu1) 12.1`` -- so take the LAST
    version-shaped match on the first line, not the first (which may be a distro/package version in
    the parenthetical)."""
    lines = text.splitlines()
    if not lines:
        return None
    matches = list(_GDB_VERSION_RE.finditer(lines[0]))
    if not matches:
        return None
    match = matches[-1]
    return (int(match.group(1)), int(match.group(2)))


def _gdb_mi_capability_check(runner: PrerequisiteRunner) -> PrerequisiteCheck:
    """Verify gdb can drive the mi3 machine interface the debug.gdb tier requires. The behavioral
    probe is authoritative (ADR 0025): a host passes iff gdb is present, the probe runs, and it
    returns ``mi_code == 0`` with a ``^done`` record. The reported version is advisory only --
    recorded in ``details`` and named in messages, never a veto -- because the documented ``9.1``
    minimum is a manual statement, not the exact capability boundary."""
    required = f"{_MI_MIN_VERSION[0]}.{_MI_MIN_VERSION[1]}"
    if runner.which("gdb") is None:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=f"gdb was not found; the debug.gdb tier requires gdb >= {required} with mi3 support",
            suggested_fix=f"Install gdb >= {required} with your distribution package manager.",
        )
    try:
        _code, version_out, _err = runner.run(["gdb", "--version"], 10)
        # Run a real mi3 MI command and require a well-formed `^done`, not merely that the `mi3` name
        # is accepted. `-ex "interpreter-exec mi3 ..."` runs the MI command from CLI mode and prints
        # its MI records to stdout, so no stdin is needed (the runner has no stdin channel). On a gdb
        # without a working mi3 interpreter, interpreter-exec errors and no `^done` is produced.
        mi_code, mi_out, _mi_err = runner.run(
            ["gdb", "-nx", "-q", "-ex", 'interpreter-exec mi3 "-list-features"', "-ex", "quit"], 10
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=f"could not probe gdb mi3 capability: {exc}",
            suggested_fix=f"Confirm gdb >= {required} is installed and runnable.",
        )
    version = _parse_gdb_version(version_out)
    detected = f"{version[0]}.{version[1]}" if version is not None else "unknown"
    if mi_code != 0 or "^done" not in mi_out:
        return PrerequisiteCheck(
            check_id="tool.gdb_mi",
            status=PrerequisiteStatus.FAILED,
            message=(
                f"gdb {detected} did not return a valid mi3 ^done record; the debug.gdb "
                f"tier requires a working mi3 interpreter"
            ),
            suggested_fix=f"Confirm a gdb with mi3 support (>= {required} documents it) is installed.",
        )
    below_minimum = version is None or version < _MI_MIN_VERSION
    message = f"gdb {detected} supports the mi3 machine interface"
    if below_minimum:
        relation = "could not be parsed against" if version is None else "is below"
        message += (
            f" (admitted on the behavioral mi3 probe; reported version {relation} the documented minimum {required})"
        )
    return PrerequisiteCheck(
        check_id="tool.gdb_mi",
        status=PrerequisiteStatus.PASSED,
        message=message,
        details={
            "version": detected,
            "mi3_documented_minimum": required,
            "version_below_documented_minimum": below_minimum,
        },
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


AGENT_PROXY_REMEDIATION = (
    "agent-proxy is optional (needed only for serial/console transports). Build it from the "
    "pinned source: git clone https://git.kernel.org/pub/scm/utils/kernel/kgdb/agent-proxy.git "
    "&& make -C agent-proxy, then put it on PATH."
)


def _agent_proxy_check(runner: PrerequisiteRunner) -> PrerequisiteCheck:
    path = runner.which("agent-proxy")
    if path:
        return PrerequisiteCheck(
            check_id="tool.agent-proxy",
            status=PrerequisiteStatus.PASSED,
            message="agent-proxy found",
            details={"path": path},
        )
    return PrerequisiteCheck(
        check_id="tool.agent-proxy",
        status=PrerequisiteStatus.WARNING,
        message="agent-proxy was not found",
        suggested_fix=AGENT_PROXY_REMEDIATION,
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
    try:
        code, stdout, stderr = runner.run(["virsh", "uri"], timeout=10)
    except subprocess.TimeoutExpired as exc:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.FAILED,
            message=f"virsh uri timed out after {exc.timeout} seconds",
            suggested_fix="Confirm libvirt is responsive or disable the libvirt URI check.",
        )
    except OSError as exc:
        return PrerequisiteCheck(
            check_id="libvirt.uri",
            status=PrerequisiteStatus.FAILED,
            message=f"virsh uri could not run: {exc}",
            suggested_fix="Confirm libvirt client tools are installed and runnable.",
        )
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


def check_kernel_config(source_path: Path | None, build_profile: BuildProfile | None) -> PrerequisiteCheck:
    """Report whether the kernel ``.config`` is present or derivable before a run exists.

    Mirrors the ``kernel.build`` precedence ladder at the two rungs knowable pre-run: a non-empty
    ``base_config`` makes the config derivable; otherwise an existing source ``.config`` is required.
    The per-run output ``.config`` cannot exist yet, so it is not consulted.
    """
    if build_profile is None:
        return PrerequisiteCheck(
            check_id="kernel.config", status=PrerequisiteStatus.SKIPPED, message="no build profile selected"
        )
    if build_profile.base_config:
        targets = " ".join(build_profile.base_config)
        return PrerequisiteCheck(
            check_id="kernel.config",
            status=PrerequisiteStatus.PASSED,
            message=f"kernel .config is derivable via `make {targets}`",
            details={"base_config": list(build_profile.base_config)},
        )
    if source_path is None:
        return PrerequisiteCheck(
            check_id="kernel.config",
            status=PrerequisiteStatus.SKIPPED,
            message="no source path supplied; cannot verify .config presence",
        )
    try:
        resolved_source = validate_source_path(source_path)
    except PathSafetyError:
        # The source path is not a usable Linux tree; defer to the source.linux_tree check rather
        # than stat an unvalidated path or emit a misleading "no .config" verdict.
        return PrerequisiteCheck(
            check_id="kernel.config",
            status=PrerequisiteStatus.SKIPPED,
            message="source path is not a usable Linux tree; see the source.linux_tree check",
        )
    if (resolved_source / ".config").is_file():
        return PrerequisiteCheck(
            check_id="kernel.config", status=PrerequisiteStatus.PASSED, message="source .config is present"
        )
    return PrerequisiteCheck(
        check_id="kernel.config",
        status=PrerequisiteStatus.FAILED,
        message="no .config in the source tree and the build profile has an empty base_config",
        suggested_fix=(
            "Provide a .config in the source tree (e.g. run `make defconfig`) or select a build "
            "profile with a base_config such as x86_64-default."
        ),
    )


_ROOTFS_LOCAL_FIX = "Select a rootfs profile whose source_kind is local_path or builder, or build the image."


def check_rootfs_image(rootfs_profile: RootfsProfile | None) -> PrerequisiteCheck:
    """Report whether the selected rootfs profile resolves to an existing disk image.

    Delegates to ``resolve_rootfs_source`` so the preflight and the boot-time gate share one policy,
    then adds an explicit existence check (the ``local_path`` kind is returned by the resolver without
    one, so a missing image would otherwise only surface at boot).
    """
    if rootfs_profile is None:
        return PrerequisiteCheck(
            check_id="rootfs.image", status=PrerequisiteStatus.SKIPPED, message="no rootfs profile selected"
        )
    try:
        path = resolve_rootfs_source(rootfs_profile)
    except RootfsSourceError as exc:
        return PrerequisiteCheck(
            check_id="rootfs.image",
            status=PrerequisiteStatus.FAILED,
            message=str(exc),
            suggested_fix=exc.suggested_fix or _ROOTFS_LOCAL_FIX,
        )
    if not path.exists():
        return PrerequisiteCheck(
            check_id="rootfs.image",
            status=PrerequisiteStatus.FAILED,
            message=f"rootfs image not found: {path}",
            suggested_fix=_ROOTFS_LOCAL_FIX,
        )
    return PrerequisiteCheck(
        check_id="rootfs.image",
        status=PrerequisiteStatus.PASSED,
        message="rootfs image is present",
        details={"path": str(path)},
    )


@dataclass(frozen=True)
class PortProbeResult:
    """Outcome of a single gdbstub-port bind probe.

    ``state`` is one of ``free``/``in_use``/``error``; ``detail`` carries the OS error string for the
    ``error`` state so the caller can report the actual failure (e.g. permission, address not local)
    instead of misreporting every bind failure as "in use".
    """

    state: Literal["free", "in_use", "error"]
    detail: str = ""


def _default_port_probe(host: str, port: int) -> PortProbeResult:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            return PortProbeResult("in_use")
        return PortProbeResult("error", str(exc))
    return PortProbeResult("free")


def _parse_gdbstub_endpoint(endpoint: str) -> tuple[str, int] | None:
    host, sep, port_text = endpoint.rpartition(":")
    if not sep or not host or not port_text:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def check_gdbstub_port(
    target_profile: TargetProfile | None,
    *,
    port_probe: Callable[[str, int], PortProbeResult] | None = None,
) -> PrerequisiteCheck:
    """Report whether a ``debug_gdbstub`` target's endpoint port is free to bind.

    Advisory only (point-in-time): a PASSED endpoint can be taken before ``target.boot`` binds it, and
    the boot path is the authoritative binder. The probe distinguishes ``EADDRINUSE`` from other bind
    errors so a permission or non-local-address failure is not misreported as "in use".
    """
    if target_profile is None:
        return PrerequisiteCheck(
            check_id="gdbstub.port", status=PrerequisiteStatus.SKIPPED, message="no target profile selected"
        )
    if not target_profile.debug_gdbstub:
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.SKIPPED,
            message="target profile does not enable gdbstub",
        )
    parsed = _parse_gdbstub_endpoint(target_profile.gdbstub_endpoint)
    if parsed is None:
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.FAILED,
            message=f"could not parse gdbstub_endpoint: {target_profile.gdbstub_endpoint}",
            suggested_fix="Set gdbstub_endpoint to host:port, e.g. 127.0.0.1:1234.",
        )
    host, port = parsed
    endpoint = f"{host}:{port}"
    result = (port_probe or _default_port_probe)(host, port)
    if result.state == "in_use":
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.FAILED,
            message=f"gdbstub endpoint {endpoint} is already in use",
            suggested_fix="Stop the process holding it or set a different gdbstub_endpoint.",
        )
    if result.state == "error":
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.FAILED,
            message=f"could not bind gdbstub endpoint {endpoint}: {result.detail}",
            suggested_fix=(
                "For a privileged port (<1024) run with the needed capability or choose a port >=1024; "
                "for a non-local host confirm the address is configured on this machine."
            ),
        )
    return PrerequisiteCheck(
        check_id="gdbstub.port",
        status=PrerequisiteStatus.PASSED,
        message=f"gdbstub endpoint {endpoint} is free",
        details={"host": host, "port": port},
    )
