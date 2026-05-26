from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol
from xml.etree import ElementTree

from linux_debug_mcp.config import RootfsProfile, TargetProfile
from linux_debug_mcp.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    ProviderCapability,
    StepStatus,
    TargetKind,
)

MCP_METADATA_NS = "urn:linux-debug-mcp:domain"
QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
ElementTree.register_namespace("ldmcp", MCP_METADATA_NS)
ElementTree.register_namespace("qemu", QEMU_NS)


@dataclass(frozen=True)
class GdbstubEndpoint:
    host: str
    port: int

    def as_dict(self) -> dict[str, object]:
        return {"host": self.host, "port": self.port}


@dataclass(frozen=True)
class BootPlan:
    run_id: str
    provider_name: str
    target_profile_name: str
    rootfs_profile_name: str
    domain_name: str
    libvirt_uri: str
    kernel_image_path: Path
    rootfs_path: Path
    rootfs_mutability: str
    root_device: str
    serial_device: str
    kernel_args: list[str]
    timeout_seconds: int
    readiness_marker: str
    domain_xml_path: Path
    console_log_path: Path
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    ownership: dict[str, str]
    cleanup_policy: str
    define_argv: list[str]
    start_argv: list[str]
    destroy_argv: list[str]
    dumpxml_argv: list[str]
    debug_gdbstub: bool
    gdbstub_endpoint: GdbstubEndpoint | None
    nokaslr_source: Literal["not_applicable", "profile_supplied", "provider_added"]


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


@dataclass(frozen=True)
class ConsoleResult:
    status: Literal["ready", "timeout", "exited"]
    matched_marker: str | None
    snippet: str
    started_at: datetime
    ended_at: datetime


@dataclass(frozen=True)
class BootExecutionResult:
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None


class ProviderBootError(Exception):
    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory,
        details: dict[str, object] | None = None,
        artifacts: list[ArtifactRef] | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.details = details or {}
        self.artifacts = artifacts or []


class LibvirtRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult:
        raise NotImplementedError

    def stream_console(
        self,
        domain: str,
        *,
        libvirt_uri: str,
        output_path: Path,
        timeout: int,
        readiness_marker: str,
    ) -> ConsoleResult:
        raise NotImplementedError

    def is_tcp_port_available(self, host: str, port: int) -> bool:
        raise NotImplementedError


class SubprocessLibvirtRunner:
    def __init__(self, *, snippet_limit: int = 4096) -> None:
        self.snippet_limit = snippet_limit

    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def is_tcp_port_available(self, host: str, port: int) -> bool:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                return False
        return True

    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult:
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            result = CommandResult(
                argv=list(argv),
                exit_status=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                argv=list(argv),
                exit_status=-1,
                stdout=self._to_text(exc.output),
                stderr=self._to_text(exc.stderr),
                timed_out=True,
            )
        if log_path is not None:
            self._append_command_log(log_path=log_path, result=result, timeout=timeout)
        return result

    def stream_console(
        self,
        domain: str,
        *,
        libvirt_uri: str,
        output_path: Path,
        timeout: int,
        readiness_marker: str,
    ) -> ConsoleResult:
        started_at = datetime.now(UTC)
        argv = ["virsh", "-c", libvirt_uri, "console", "--force", domain]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            bufsize=1,
        )
        snippet = ""
        status: Literal["ready", "timeout", "exited"] = "exited"
        matched_marker: str | None = None
        deadline = time.monotonic() + timeout
        selector: selectors.BaseSelector | None = None
        if process.stdout is not None:
            try:
                selector = selectors.DefaultSelector()
                selector.register(process.stdout.fileno(), selectors.EVENT_READ)
            except (AttributeError, OSError, ValueError):
                if selector is not None:
                    selector.close()
                selector = None
        try:
            with output_path.open("w", encoding="utf-8") as output_file:
                while True:
                    if time.monotonic() >= deadline:
                        status = "timeout"
                        break
                    line = self._read_console_line(process=process, deadline=deadline, selector=selector)
                    if line:
                        output_file.write(line)
                        snippet = self._bounded_snippet(snippet + line)
                        if readiness_marker in line or readiness_marker in snippet:
                            status = "ready"
                            matched_marker = readiness_marker
                            break
                        continue
                    if process.poll() is not None:
                        status = "exited"
                        break
                    time.sleep(0.05)
        finally:
            if selector is not None:
                selector.close()
            self._terminate_process(process)
        return ConsoleResult(
            status=status,
            matched_marker=matched_marker,
            snippet=snippet,
            started_at=started_at,
            ended_at=datetime.now(UTC),
        )

    def _append_command_log(self, *, log_path: Path, result: CommandResult, timeout: int) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(f"$ {' '.join(result.argv)}\n")
            log_file.write(result.stdout)
            log_file.write(result.stderr)
            if result.timed_out:
                log_file.write(f"timed out after {timeout}s\n")

    def _bounded_snippet(self, text: str) -> str:
        return text[-self.snippet_limit :]

    def _read_console_line(
        self,
        *,
        process: subprocess.Popen[str],
        deadline: float,
        selector: selectors.BaseSelector | None,
    ) -> str:
        if process.stdout is None:
            return ""
        timeout = max(min(deadline - time.monotonic(), 0.05), 0)
        if selector is not None:
            if not selector.select(timeout):
                return ""
            return os.read(process.stdout.fileno(), 4096).decode("utf-8", errors="replace")
        try:
            file_number = process.stdout.fileno()
        except (AttributeError, OSError):
            return process.stdout.readline()
        with selectors.DefaultSelector() as fallback_selector:
            fallback_selector.register(file_number, selectors.EVENT_READ)
            if not fallback_selector.select(timeout):
                return ""
            return os.read(file_number, 4096).decode("utf-8", errors="replace")

    def _terminate_process(self, process: subprocess.Popen[str]) -> None:
        try:
            process.terminate()
        except OSError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def _to_text(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value


class LibvirtQemuProvider:
    name = "local-libvirt-qemu"
    supported_architectures = ["x86_64"]
    root_device = "/dev/vda"
    serial_device = "ttyS0"
    default_readiness_marker = "linux-debug-mcp-ready"

    def __init__(self, *, runner: LibvirtRunner | None = None) -> None:
        self.runner = runner or SubprocessLibvirtRunner()

    def plan_boot(
        self,
        *,
        run_id: str,
        run_dir: Path,
        kernel_image_path: Path,
        target_profile: TargetProfile,
        rootfs_profile: RootfsProfile,
        attempt: int = 1,
    ) -> BootPlan:
        self._validate_profiles(target_profile=target_profile, rootfs_profile=rootfs_profile)

        kernel_path = self._resolve_existing_path(kernel_image_path, description="kernel image path")
        rootfs_path = self._resolve_existing_path(rootfs_profile.source, description="rootfs source path")
        resolved_run_dir = self._resolve_existing_path(run_dir, description="run directory")

        kernel_args, nokaslr_source = self._debug_kernel_args(
            target_profile.kernel_args,
            target_profile.debug_gdbstub,
        )
        gdbstub_endpoint = None
        if target_profile.debug_gdbstub:
            gdbstub_endpoint = self._parse_gdbstub_endpoint(target_profile.gdbstub_endpoint)
            if not self.runner.is_tcp_port_available(gdbstub_endpoint.host, gdbstub_endpoint.port):
                raise ProviderBootError(
                    "gdbstub endpoint is already in use",
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                )
        domain_name = target_profile.target_ref
        libvirt_uri = target_profile.libvirt_uri
        if domain_name is None or libvirt_uri is None:
            # Kept for type narrowing; _validate_profiles rejects these before path resolution.
            raise self._configuration_error("target_ref and libvirt_uri are required")

        attempt_dir = resolved_run_dir / "boot" / f"attempt-{attempt}"
        domain_xml_path = attempt_dir / "domain.xml"
        console_log_path = attempt_dir / "console.log"
        boot_log_path = attempt_dir / "boot.log"
        boot_plan_path = attempt_dir / "boot-plan.json"
        boot_summary_path = attempt_dir / "boot-summary.json"
        virsh_prefix = ["virsh", "-c", libvirt_uri]

        return BootPlan(
            run_id=run_id,
            provider_name=self.name,
            target_profile_name=target_profile.name,
            rootfs_profile_name=rootfs_profile.name,
            domain_name=domain_name,
            libvirt_uri=libvirt_uri,
            kernel_image_path=kernel_path,
            rootfs_path=rootfs_path,
            rootfs_mutability=rootfs_profile.mutability,
            root_device=self.root_device,
            serial_device=self.serial_device,
            kernel_args=kernel_args,
            timeout_seconds=target_profile.timeout_seconds,
            readiness_marker=rootfs_profile.readiness_marker,
            domain_xml_path=domain_xml_path,
            console_log_path=console_log_path,
            boot_log_path=boot_log_path,
            boot_plan_path=boot_plan_path,
            boot_summary_path=boot_summary_path,
            ownership={
                "provider": self.name,
                "run_id": run_id,
                "target_profile": target_profile.name,
                "rootfs_profile": rootfs_profile.name,
            },
            cleanup_policy=target_profile.cleanup_policy,
            define_argv=[*virsh_prefix, "define", str(domain_xml_path)],
            start_argv=[*virsh_prefix, "start", domain_name],
            destroy_argv=[*virsh_prefix, "destroy", domain_name],
            dumpxml_argv=[*virsh_prefix, "dumpxml", domain_name],
            debug_gdbstub=target_profile.debug_gdbstub,
            gdbstub_endpoint=gdbstub_endpoint,
            nokaslr_source=nokaslr_source,
        )

    def execute_boot(
        self,
        plan: BootPlan,
        *,
        force_reboot: bool = False,
        retrying_after_failure: bool = False,
    ) -> BootExecutionResult:
        self._ensure_artifact_dirs(plan)
        artifacts = self._artifact_refs(plan)
        if self.runner.which("virsh") is None:
            return self._boot_result(
                plan=plan,
                status=StepStatus.FAILED,
                summary="missing required libvirt tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": ["virsh"]},
                artifacts=[],
            )

        rotated_console_artifact = self._rotate_console_log(plan.console_log_path)
        if rotated_console_artifact is not None:
            artifacts = [*artifacts, rotated_console_artifact]
        self._write_boot_plan(plan)

        dumpxml = self.runner.run(plan.dumpxml_argv, timeout=plan.timeout_seconds, log_path=plan.boot_log_path)
        existing_domain = False
        if dumpxml.exit_status == 0:
            existing_domain = True
            try:
                self.validate_existing_domain_ownership(plan, dumpxml.stdout)
            except ProviderBootError as exc:
                return self._boot_result(
                    plan=plan,
                    status=StepStatus.FAILED,
                    summary=str(exc),
                    error_category=exc.category,
                    details=exc.details,
                    artifacts=self._existing_artifacts(artifacts),
                    diagnostic=dumpxml.stderr or dumpxml.stdout,
                )
        elif not self._is_domain_not_found(dumpxml):
            return self._command_failure_result(plan=plan, command="dumpxml", result=dumpxml, artifacts=artifacts)

        plan.domain_xml_path.write_text(self.render_domain_xml(plan), encoding="utf-8")

        if existing_domain:
            destroy = self.runner.run(plan.destroy_argv, timeout=plan.timeout_seconds, log_path=plan.boot_log_path)
            if (destroy.exit_status != 0 or destroy.timed_out) and not self._is_inactive_destroy_failure(destroy):
                return self._command_failure_result(plan=plan, command="destroy", result=destroy, artifacts=artifacts)

        define = self.runner.run(plan.define_argv, timeout=plan.timeout_seconds, log_path=plan.boot_log_path)
        if define.exit_status != 0 or define.timed_out:
            return self._command_failure_result(plan=plan, command="define", result=define, artifacts=artifacts)

        start = self.runner.run(plan.start_argv, timeout=plan.timeout_seconds, log_path=plan.boot_log_path)
        if start.exit_status != 0 or start.timed_out:
            details: dict[str, object] | None = None
            if plan.cleanup_policy == "stop_on_failure":
                cleanup = self._cleanup_after_failure(plan)
                details = {"cleanup": cleanup}
            return self._command_failure_result(
                plan=plan,
                command="start",
                result=start,
                artifacts=artifacts,
                details=details,
            )

        console = self.runner.stream_console(
            plan.domain_name,
            libvirt_uri=plan.libvirt_uri,
            output_path=plan.console_log_path,
            timeout=plan.timeout_seconds,
            readiness_marker=plan.readiness_marker,
        )
        details = {
            "domain": plan.domain_name,
            "console_status": console.status,
            "matched_marker": console.matched_marker,
            "console_snippet": console.snippet,
            "started_at": console.started_at.isoformat(),
            "ended_at": console.ended_at.isoformat(),
            "debug_boot": plan.debug_gdbstub,
            "gdbstub_endpoint": plan.gdbstub_endpoint.as_dict() if plan.gdbstub_endpoint else None,
            "nokaslr_source": plan.nokaslr_source,
        }
        if console.status == "ready":
            return self._boot_result(
                plan=plan,
                status=StepStatus.SUCCEEDED,
                summary="target booted and reported readiness",
                details=details,
                artifacts=self._existing_artifacts(artifacts),
            )

        error_category = ErrorCategory.BOOT_TIMEOUT if console.status == "timeout" else ErrorCategory.READINESS_FAILURE
        summary = "target boot timed out" if console.status == "timeout" else "target console exited before readiness"
        if plan.cleanup_policy == "stop_on_failure":
            details["cleanup"] = self._cleanup_after_failure(plan)
        return self._boot_result(
            plan=plan,
            status=StepStatus.FAILED,
            summary=summary,
            error_category=error_category,
            details=details,
            artifacts=self._existing_artifacts(artifacts),
            diagnostic=console.snippet,
        )

    def render_domain_xml(self, plan: BootPlan) -> str:
        domain = ElementTree.Element("domain", {"type": "kvm"})
        ElementTree.SubElement(domain, "name").text = plan.domain_name
        ElementTree.SubElement(domain, "memory", {"unit": "MiB"}).text = "1024"
        ElementTree.SubElement(domain, "vcpu").text = "1"

        metadata = ElementTree.SubElement(domain, "metadata")
        ownership = ElementTree.SubElement(metadata, self._metadata_tag("linux-debug-mcp"))
        ElementTree.SubElement(ownership, self._metadata_tag("provider")).text = plan.provider_name
        ElementTree.SubElement(ownership, self._metadata_tag("domain")).text = plan.domain_name
        ElementTree.SubElement(ownership, self._metadata_tag("target_profile")).text = plan.target_profile_name
        ElementTree.SubElement(ownership, self._metadata_tag("run_id")).text = plan.run_id

        os_element = ElementTree.SubElement(domain, "os")
        ElementTree.SubElement(os_element, "type", {"arch": "x86_64"}).text = "hvm"
        ElementTree.SubElement(os_element, "kernel").text = str(plan.kernel_image_path)
        ElementTree.SubElement(os_element, "cmdline").text = " ".join(plan.kernel_args)

        devices = ElementTree.SubElement(domain, "devices")
        disk = ElementTree.SubElement(devices, "disk", {"type": "file", "device": "disk"})
        ElementTree.SubElement(disk, "driver", {"name": "qemu", "type": "qcow2"})
        ElementTree.SubElement(disk, "source", {"file": str(plan.rootfs_path)})
        ElementTree.SubElement(disk, "target", {"dev": "vda", "bus": "virtio"})
        if plan.rootfs_mutability == "read_only":
            ElementTree.SubElement(disk, "readonly")
        serial = ElementTree.SubElement(devices, "serial", {"type": "pty"})
        ElementTree.SubElement(serial, "target", {"port": "0"})
        console = ElementTree.SubElement(devices, "console", {"type": "pty"})
        ElementTree.SubElement(console, "target", {"type": "serial", "port": "0"})

        if plan.debug_gdbstub and plan.gdbstub_endpoint is not None:
            qemu_commandline = ElementTree.SubElement(domain, f"{{{QEMU_NS}}}commandline")
            ElementTree.SubElement(qemu_commandline, f"{{{QEMU_NS}}}arg", {"value": "-gdb"})
            ElementTree.SubElement(
                qemu_commandline,
                f"{{{QEMU_NS}}}arg",
                {"value": f"tcp:{plan.gdbstub_endpoint.host}:{plan.gdbstub_endpoint.port},server=on,wait=off"},
            )

        return ElementTree.tostring(domain, encoding="unicode")

    def validate_existing_domain_ownership(self, plan: BootPlan, domain_xml: str) -> None:
        try:
            root = ElementTree.fromstring(domain_xml)
        except ElementTree.ParseError as exc:
            raise self._configuration_error(f"failed to parse existing domain XML: {exc}") from exc

        metadata_path = f"metadata/{self._metadata_tag('linux-debug-mcp')}"
        actual = {
            "provider": root.findtext(f"{metadata_path}/{self._metadata_tag('provider')}"),
            "domain": root.findtext(f"{metadata_path}/{self._metadata_tag('domain')}"),
            "target_profile": root.findtext(f"{metadata_path}/{self._metadata_tag('target_profile')}"),
        }
        expected = {
            "provider": plan.provider_name,
            "domain": plan.domain_name,
            "target_profile": plan.target_profile_name,
        }
        if actual != expected:
            raise ProviderBootError(
                "existing domain is not owned by this MCP target profile",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"expected": expected, "actual": actual},
            )

    def _validate_profiles(self, *, target_profile: TargetProfile, rootfs_profile: RootfsProfile) -> None:
        if target_profile.provider_name != self.name:
            raise self._configuration_error(f"unsupported target provider: {target_profile.provider_name}")
        if target_profile.architecture not in self.supported_architectures:
            raise self._configuration_error(f"unsupported architecture: {target_profile.architecture}")
        if target_profile.target_ref is None:
            raise self._configuration_error("target_ref is required")
        if not target_profile.managed_domain:
            raise self._configuration_error("managed_domain=True is required")
        if target_profile.managed_domain_prefix is not None and not target_profile.target_ref.startswith(
            target_profile.managed_domain_prefix
        ):
            raise self._configuration_error(
                f"target_ref must start with managed_domain_prefix {target_profile.managed_domain_prefix!r}"
            )
        if target_profile.libvirt_uri is None:
            raise self._configuration_error("libvirt_uri is required")
        if target_profile.cleanup_policy not in {"preserve_on_failure", "stop_on_failure"}:
            raise self._configuration_error(f"cleanup policy is not supported: {target_profile.cleanup_policy}")
        if rootfs_profile.source_type != "disk_image":
            raise self._configuration_error("directory rootfs sources are not supported")
        if rootfs_profile.mutability not in {"read_only", "mutable"}:
            raise self._configuration_error(f"{rootfs_profile.mutability} rootfs mutability is not supported")
        if not rootfs_profile.readiness_marker:
            raise self._configuration_error("readiness_marker is required")
        self._validate_kernel_args(target_profile.kernel_args)

    def _kernel_args(self, configured_args: list[str]) -> list[str]:
        args = list(configured_args)
        if not self._contains_arg(args, "root"):
            args.append(f"root={self.root_device}")
        if not self._contains_arg(args, "console"):
            args.append(f"console={self.serial_device}")
        return args

    def _parse_gdbstub_endpoint(self, endpoint: str) -> GdbstubEndpoint:
        if any(char.isspace() for char in endpoint) or any(char in endpoint for char in "<>$;&|?/#"):
            raise self._configuration_error("unsafe gdbstub endpoint syntax")
        host, separator, port_text = endpoint.rpartition(":")
        if separator == "" or host not in {"127.0.0.1", "localhost"}:
            raise self._configuration_error("gdbstub endpoint must bind to localhost")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise self._configuration_error("gdbstub endpoint port must be an integer") from exc
        if port < 1 or port > 65535:
            raise self._configuration_error("gdbstub endpoint port must be in 1..65535")
        normalized_host = "127.0.0.1" if host == "localhost" else host
        return GdbstubEndpoint(host=normalized_host, port=port)

    def _debug_kernel_args(
        self,
        configured_args: list[str],
        debug_enabled: bool,
    ) -> tuple[list[str], Literal["not_applicable", "profile_supplied", "provider_added"]]:
        args = self._kernel_args(configured_args)
        if not debug_enabled:
            return args, "not_applicable"
        if "nokaslr" in args:
            return args, "profile_supplied"
        return [*args, "nokaslr"], "provider_added"

    def _validate_kernel_args(self, args: list[str]) -> None:
        for arg in args:
            if arg.startswith("root=") and arg != f"root={self.root_device}":
                raise self._configuration_error(f"conflicting root= kernel argument: {arg}")
            if arg.startswith("console=") and self._console_device(arg) != self.serial_device:
                raise self._configuration_error(f"conflicting console= kernel argument: {arg}")

    def _contains_arg(self, args: list[str], key: str) -> bool:
        return any(arg.startswith(f"{key}=") for arg in args)

    def _console_device(self, arg: str) -> str:
        return arg.removeprefix("console=").split(",", maxsplit=1)[0]

    def _configuration_error(self, message: str) -> ProviderBootError:
        return ProviderBootError(message, category=ErrorCategory.CONFIGURATION_ERROR)

    def _ensure_artifact_dirs(self, plan: BootPlan) -> None:
        for path in [
            plan.domain_xml_path,
            plan.console_log_path,
            plan.boot_log_path,
            plan.boot_plan_path,
            plan.boot_summary_path,
        ]:
            path.parent.mkdir(parents=True, exist_ok=True)

    def _write_boot_plan(self, plan: BootPlan) -> None:
        payload = {
            "run_id": plan.run_id,
            "provider_name": plan.provider_name,
            "target_profile_name": plan.target_profile_name,
            "rootfs_profile_name": plan.rootfs_profile_name,
            "domain_name": plan.domain_name,
            "libvirt_uri": plan.libvirt_uri,
            "kernel_image_path": str(plan.kernel_image_path),
            "rootfs_path": str(plan.rootfs_path),
            "rootfs_mutability": plan.rootfs_mutability,
            "root_device": plan.root_device,
            "serial_device": plan.serial_device,
            "kernel_args": plan.kernel_args,
            "timeout_seconds": plan.timeout_seconds,
            "readiness_marker": plan.readiness_marker,
            "cleanup_policy": plan.cleanup_policy,
            "debug_boot": plan.debug_gdbstub,
            "gdbstub_endpoint": plan.gdbstub_endpoint.as_dict() if plan.gdbstub_endpoint else None,
            "nokaslr_source": plan.nokaslr_source,
            "ownership": plan.ownership,
            "define_argv": plan.define_argv,
            "start_argv": plan.start_argv,
            "destroy_argv": plan.destroy_argv,
            "dumpxml_argv": plan.dumpxml_argv,
        }
        plan.boot_plan_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _rotate_console_log(self, console_log_path: Path) -> ArtifactRef | None:
        if not console_log_path.exists():
            return None
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        rotated = console_log_path.with_name(f"console.{timestamp}.log")
        suffix = 1
        while rotated.exists():
            rotated = console_log_path.with_name(f"console.{timestamp}.{suffix}.log")
            suffix += 1
        console_log_path.rename(rotated)
        return ArtifactRef(path=str(rotated), kind="console-log", description="previous console log")

    def _artifact_refs(self, plan: BootPlan) -> list[ArtifactRef]:
        return [
            ArtifactRef(path=str(plan.domain_xml_path), kind="domain-xml"),
            ArtifactRef(path=str(plan.boot_plan_path), kind="boot-plan"),
            ArtifactRef(path=str(plan.console_log_path), kind="console-log"),
            ArtifactRef(path=str(plan.boot_log_path), kind="boot-log"),
            ArtifactRef(path=str(plan.boot_summary_path), kind="boot-summary"),
        ]

    def _existing_artifacts(self, artifacts: list[ArtifactRef]) -> list[ArtifactRef]:
        return [artifact for artifact in artifacts if Path(artifact.path).exists()]

    def _debug_details(self, plan: BootPlan) -> dict[str, object]:
        return {
            "debug_boot": plan.debug_gdbstub,
            "gdbstub_endpoint": plan.gdbstub_endpoint.as_dict() if plan.gdbstub_endpoint else None,
            "nokaslr_source": plan.nokaslr_source,
        }

    def _boot_result(
        self,
        *,
        plan: BootPlan,
        status: StepStatus,
        summary: str,
        details: dict[str, object] | None = None,
        artifacts: list[ArtifactRef] | None = None,
        error_category: ErrorCategory | None = None,
        diagnostic: str | None = None,
    ) -> BootExecutionResult:
        artifact_list = artifacts or []
        if not any(artifact.path == str(plan.boot_summary_path) for artifact in artifact_list):
            artifact_list = [*artifact_list, ArtifactRef(path=str(plan.boot_summary_path), kind="boot-summary")]
        result_details = {**(details or {}), **self._debug_details(plan)}
        payload = {
            "status": status,
            "summary": summary,
            "error_category": error_category,
            "diagnostic": diagnostic,
            "details": result_details,
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifact_list],
        }
        plan.boot_summary_path.parent.mkdir(parents=True, exist_ok=True)
        plan.boot_summary_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return BootExecutionResult(
            status=status,
            summary=summary,
            artifacts=artifact_list,
            details=result_details,
            error_category=error_category,
            diagnostic=diagnostic,
        )

    def _command_failure_result(
        self,
        *,
        plan: BootPlan,
        command: str,
        result: CommandResult,
        artifacts: list[ArtifactRef],
        details: dict[str, object] | None = None,
    ) -> BootExecutionResult:
        result_details = {
            "command": command,
            "argv": result.argv,
            "exit_status": result.exit_status,
            "timed_out": result.timed_out,
        }
        if details:
            result_details.update(details)
        diagnostic = result.stderr or result.stdout
        return self._boot_result(
            plan=plan,
            status=StepStatus.FAILED,
            summary=f"libvirt {command} command failed",
            error_category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            details=result_details,
            artifacts=self._existing_artifacts(artifacts),
            diagnostic=diagnostic,
        )

    def _cleanup_after_failure(self, plan: BootPlan) -> dict[str, object]:
        cleanup = self.runner.run(plan.destroy_argv, timeout=plan.timeout_seconds, log_path=plan.boot_log_path)
        return {
            "argv": cleanup.argv,
            "exit_status": cleanup.exit_status,
            "timed_out": cleanup.timed_out,
        }

    def _is_inactive_destroy_failure(self, result: CommandResult) -> bool:
        if result.timed_out:
            return False
        output = f"{result.stdout}\n{result.stderr}".lower()
        return "not running" in output or "not active" in output

    def _is_domain_not_found(self, result: CommandResult) -> bool:
        if result.timed_out:
            return False
        output = f"{result.stdout}\n{result.stderr}".lower()
        return "domain not found" in output

    def _metadata_tag(self, name: str) -> str:
        return f"{{{MCP_METADATA_NS}}}{name}"

    def _resolve_existing_path(self, path: Path | str, *, description: str) -> Path:
        try:
            return Path(path).expanduser().resolve(strict=True)
        except OSError as exc:
            raise ProviderBootError(
                f"{description} does not exist: {path}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path), "reason": str(exc)},
            ) from exc


def local_libvirt_qemu_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-libvirt-qemu",
        provider_version="0.1.0",
        provider_family="boot",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["libvirt", "serial-console", "filesystem"],
        operations=["target.boot"],
        required_host_tools=["virsh"],
        destructive_permissions=[
            "define MCP-owned libvirt domains",
            "update MCP-owned libvirt domains",
            "start MCP-owned libvirt domains",
            "stop MCP-owned libvirt domains",
            "destroy MCP-owned libvirt domains",
        ],
        access_methods=["libvirt", "serial-console", "filesystem"],
        semantics=OperationSemantics(
            idempotent=True,
            retryable=True,
            destructive=True,
            cancelable=False,
            concurrent_safe=False,
        ),
    )
