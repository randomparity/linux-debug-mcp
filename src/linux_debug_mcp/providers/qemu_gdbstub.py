from __future__ import annotations

import errno
import json
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from linux_debug_mcp.config import SPRINT_4_DEBUG_OPERATIONS, DebugProfile
from linux_debug_mcp.domain import (
    ArtifactRef,
    ErrorCategory,
    OperationSemantics,
    ProviderCapability,
    StepStatus,
    TargetKind,
)
from linux_debug_mcp.safety.redaction import Redactor

MAX_MEMORY_READ_BYTES = 4096
MAX_RESPONSE_SNIPPET = 4096
SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]*$")
REGISTER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
LINUX_BANNER_RELEASE_PATTERN = re.compile(r"Linux version\s+([^\s]+)")
QEMU_GDBSTUB_OPERATIONS = ["workflow.build_boot_debug", *SPRINT_4_DEBUG_OPERATIONS]


def local_qemu_gdbstub_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-qemu-gdbstub",
        provider_version="0.1.0",
        provider_family="debug",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["tcp", "gdb-remote", "filesystem"],
        operations=QEMU_GDBSTUB_OPERATIONS,
        required_host_tools=["gdb"],
        destructive_permissions=[
            "control target execution through QEMU gdbstub",
            "modify debugger breakpoints",
            "terminate MCP-owned debug controller processes",
        ],
        access_methods=["gdbstub", "filesystem", "subprocess"],
        semantics=OperationSemantics(
            idempotent=False,
            retryable=True,
            destructive=True,
            cancelable=True,
            concurrent_safe=False,
        ),
    )


class DebugSession(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    session_id: str
    run_id: str
    provider_name: str
    gdbstub_endpoint: dict[str, object]
    vmlinux_path: str
    selected_debug_profile: str
    attach_status: str
    started_at: str
    ended_at: str | None = None
    current_execution_state: Literal["unknown", "running", "stopped", "ended"] = "unknown"
    breakpoints: dict[str, dict[str, object]] = Field(default_factory=dict)
    controller_mode: Literal["batch", "attached"] = "batch"
    active_controller_pid: int | None = None
    controller_last_observed_state: str = "not_started"
    active_controller_identity: dict[str, object] = Field(default_factory=dict)
    transcript_path: str
    command_metadata_path: str
    latest_summary_path: str
    symbol_identity_validation: dict[str, object] = Field(default_factory=dict)


@dataclass(frozen=True)
class GdbCommandResult:
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


@dataclass(frozen=True)
class DebugProviderResult:
    status: StepStatus
    summary: str
    session: DebugSession
    artifacts: list[ArtifactRef] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None

    @property
    def artifacts_by_kind(self) -> dict[str, Path]:
        return {artifact.kind: Path(artifact.path) for artifact in self.artifacts}


class ProviderDebugError(Exception):
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


class GdbRunner(Protocol):
    def which(self, command: str) -> str | None:
        raise NotImplementedError

    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        raise NotImplementedError


class SubprocessGdbRunner:
    def which(self, command: str) -> str | None:
        return shutil.which(command)

    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            completed = subprocess.run(
                argv,
                check=False,
                shell=False,
                timeout=timeout,
                capture_output=True,
                text=True,
            )
            result = GdbCommandResult(
                exit_status=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
            )
        except subprocess.TimeoutExpired as exc:
            result = GdbCommandResult(
                exit_status=-1,
                stdout=self._to_text(exc.output),
                stderr=self._to_text(exc.stderr),
                timed_out=True,
            )
        self._append_transcript(
            transcript_path=transcript_path,
            argv=argv,
            commands=commands,
            timeout=timeout,
            result=result,
        )
        return result

    def _append_transcript(
        self,
        *,
        transcript_path: Path,
        argv: list[str],
        commands: list[str],
        timeout: int,
        result: GdbCommandResult,
    ) -> None:
        with transcript_path.open("a", encoding="utf-8") as transcript:
            transcript.write(f"$ {' '.join(argv)}\n")
            transcript.write("commands:\n")
            for command in commands:
                transcript.write(f"  {command}\n")
            transcript.write(f"timeout_seconds: {timeout}\n")
            transcript.write(result.stdout)
            if result.stdout and not result.stdout.endswith("\n"):
                transcript.write("\n")
            transcript.write(result.stderr)
            if result.stderr and not result.stderr.endswith("\n"):
                transcript.write("\n")
            transcript.write(f"timed_out: {str(result.timed_out).lower()}\n")
            if result.timed_out:
                transcript.write(f"timed out after {timeout}s\n")
            transcript.write(f"exit_status: {result.exit_status}\n")

    def _to_text(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value


class QemuGdbstubProvider:
    name = "local-qemu-gdbstub"

    def __init__(self, *, runner: GdbRunner | None = None, redactor: Redactor | None = None) -> None:
        self.runner = runner or SubprocessGdbRunner()
        self.redactor = redactor or Redactor()

    def start_session(
        self,
        *,
        run_id: str,
        run_dir: Path,
        vmlinux_path: Path,
        gdbstub_endpoint: dict[str, object],
        debug_profile: DebugProfile,
        build_metadata: dict[str, object],
        boot_metadata: dict[str, object],
    ) -> DebugProviderResult:
        gdb_path = self.runner.which("gdb")
        if gdb_path is None:
            raise ProviderDebugError(
                "missing required GDB tool",
                category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": ["gdb"]},
            )
        resolved_run_dir = run_dir.expanduser().resolve()
        resolved_vmlinux = self._resolve_existing_path(
            vmlinux_path,
            description="vmlinux path",
            required_parent=resolved_run_dir,
        )
        if boot_metadata.get("debug_boot") is not True:
            raise ProviderDebugError(
                "boot metadata does not indicate a debug gdbstub boot",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        same_run_artifact_linkage = self._same_path(
            build_metadata.get("kernel_image_path"),
            boot_metadata.get("kernel_image_path"),
        ) and self._same_path(resolved_vmlinux, build_metadata.get("vmlinux_path"))
        identity = {
            "same_run_artifact_linkage": same_run_artifact_linkage,
            "live_banner_match": None,
            "build_kernel_release": build_metadata.get("kernel_release"),
        }
        if debug_profile.symbol_identity_required and not identity["same_run_artifact_linkage"]:
            raise ProviderDebugError(
                "strict symbol identity requires same-run artifact linkage",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"symbol_identity_validation": identity},
            )

        endpoint = self._validated_endpoint(gdbstub_endpoint)
        started_at = datetime.now(UTC)
        session_id = f"debug-{uuid.uuid4().hex}"
        attempt_dir = self._next_attempt_dir(run_dir)
        sessions_dir = run_dir / "debug" / "sessions"
        transcript_path = attempt_dir / "transcript.txt"
        command_metadata_path = attempt_dir / "commands.jsonl"
        latest_summary_path = attempt_dir / "debug-summary.json"
        session_path = sessions_dir / f"{session_id}.json"

        commands = [
            "set pagination off",
            "set confirm off",
            f"file {self._gdb_path(resolved_vmlinux)}",
            f"target remote {endpoint['host']}:{endpoint['port']}",
            "p linux_banner",
        ]
        argv = [gdb_path, "-nx", "-batch", "-q"]
        for command in commands:
            argv.extend(["-ex", command])

        runner_error_category = None
        try:
            result = self.runner.run_batch(
                argv,
                commands,
                timeout=30,
                transcript_path=transcript_path,
            )
        except (OSError, RuntimeError, UnicodeError) as exc:
            runner_error_category = ErrorCategory.INFRASTRUCTURE_FAILURE
            result = GdbCommandResult(
                exit_status=-1,
                stderr=f"{type(exc).__name__}: {exc}",
            )
            try:
                self._record_failure_transcript(
                    transcript_path=transcript_path,
                    argv=argv,
                    commands=commands,
                    timeout=30,
                    result=result,
                    mode="w",
                )
            except OSError as write_exc:
                raise ProviderDebugError(
                    "failed to write debug transcript",
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    details={"path": str(transcript_path), "error": str(write_exc)},
                ) from write_exc
        ended_at = datetime.now(UTC)
        status = StepStatus.SUCCEEDED if result.exit_status == 0 and not result.timed_out else StepStatus.FAILED
        kernel_release = identity["build_kernel_release"]
        if isinstance(kernel_release, str) and kernel_release:
            identity["live_banner_match"] = self._linux_banner_release(result.stdout) == kernel_release
        strict_identity_failure = debug_profile.symbol_identity_required and (
            status != StepStatus.SUCCEEDED or identity["live_banner_match"] is not True
        )
        effective_status = StepStatus.FAILED if strict_identity_failure else status
        session = DebugSession(
            session_id=session_id,
            run_id=run_id,
            provider_name=self.name,
            gdbstub_endpoint=endpoint,
            vmlinux_path=str(resolved_vmlinux),
            selected_debug_profile=debug_profile.name,
            attach_status="attached" if effective_status == StepStatus.SUCCEEDED else "failed",
            started_at=started_at.isoformat(),
            ended_at=ended_at.isoformat() if effective_status == StepStatus.FAILED else None,
            current_execution_state="stopped" if effective_status == StepStatus.SUCCEEDED else "unknown",
            transcript_path=str(transcript_path),
            command_metadata_path=str(command_metadata_path),
            latest_summary_path=str(latest_summary_path),
            symbol_identity_validation=identity,
        )
        artifacts = [
            ArtifactRef(path=str(transcript_path), kind="debug-transcript", sensitive=True),
            ArtifactRef(path=str(command_metadata_path), kind="debug-command-metadata"),
            ArtifactRef(path=str(latest_summary_path), kind="debug-summary"),
            ArtifactRef(path=str(session_path), kind="debug-session"),
        ]
        command_record = self._command_metadata(
            argv=argv,
            commands=commands,
            result=result,
            started_at=started_at,
            ended_at=ended_at,
            timeout=30,
            transcript_path=transcript_path,
        )
        details = {
            "session_path": str(session_path),
            "gdbstub_endpoint": endpoint,
            "exit_status": result.exit_status,
            "timed_out": result.timed_out,
            "symbol_identity_validation": identity,
        }
        summary_payload = {
            "run_id": run_id,
            "provider": self.name,
            "status": effective_status,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "session_path": str(session_path),
            "session": session.model_dump(mode="json"),
            "build_metadata": build_metadata,
            "boot_metadata": boot_metadata,
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
            "command": command_record,
        }
        try:
            self._append_jsonl(command_metadata_path, command_record)
            self._write_json(session_path, session.model_dump(mode="json"))
            self._write_json(latest_summary_path, self.redactor.redact_value(summary_payload))
        except OSError as exc:
            existing_artifacts = [artifact for artifact in artifacts if Path(artifact.path).is_file()]
            raise ProviderDebugError(
                "failed to write debug session artifacts",
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={**details, "error": str(exc)},
                artifacts=existing_artifacts,
            ) from exc
        existing_artifacts = self._existing_artifacts(artifacts)
        if strict_identity_failure:
            raise ProviderDebugError(
                "strict symbol identity live target check failed",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={
                    **details,
                    "diagnostic": self.redactor.redact_text(self._snippet(result.stderr or result.stdout)),
                },
                artifacts=existing_artifacts,
            )
        return DebugProviderResult(
            status=effective_status,
            summary=(
                "qemu gdbstub session started"
                if effective_status == StepStatus.SUCCEEDED
                else "qemu gdbstub attach failed"
            ),
            session=session,
            artifacts=existing_artifacts,
            details=details,
            error_category=runner_error_category
            or (ErrorCategory.DEBUG_ATTACH_FAILURE if effective_status == StepStatus.FAILED else None),
            diagnostic=self._snippet(result.stderr or result.stdout) if effective_status == StepStatus.FAILED else None,
        )

    def read_registers(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        registers: list[str],
    ) -> DebugProviderResult:
        if type(registers) is not list or not registers:
            raise ProviderDebugError(
                "registers must be a non-empty list",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        validated_registers = [self.validate_register_name(register) for register in registers]
        result = self._run_read_operation(
            run_dir=run_dir,
            session=session,
            operation="read_registers",
            read_command=f"info registers {' '.join(validated_registers)}",
        )
        if result.status == StepStatus.SUCCEEDED:
            result.details["registers"] = self._parse_registers(result.details["stdout_snippet"], validated_registers)
        return result

    def read_symbol(self, *, run_dir: Path, session: DebugSession, symbol: str) -> DebugProviderResult:
        validated_symbol = self.validate_symbol_name(symbol)
        result = self._run_read_operation(
            run_dir=run_dir,
            session=session,
            operation="read_symbol",
            read_command=f"p {validated_symbol}",
        )
        if result.status == StepStatus.SUCCEEDED:
            value = self._parse_gdb_value(result.details["stdout_snippet"])
            result.details.update({"symbol": validated_symbol, "value": value})
        return result

    def read_memory(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        address: int,
        byte_count: int,
    ) -> DebugProviderResult:
        self.validate_memory_read(address=address, byte_count=byte_count)
        result = self._run_read_operation(
            run_dir=run_dir,
            session=session,
            operation="read_memory",
            read_command=f"x/{byte_count}xb 0x{address:x}",
            memory_byte_count=byte_count,
        )
        if result.status == StepStatus.SUCCEEDED:
            result.details.update(
                {
                    "address": f"0x{address:x}",
                    "byte_count": byte_count,
                }
            )
        return result

    def evaluate(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        inspector: str,
        arguments: dict[str, object],
    ) -> DebugProviderResult:
        if inspector == "kernel_version":
            result = self._run_read_operation(
                run_dir=run_dir,
                session=session,
                operation="evaluate.kernel_version",
                read_command="p linux_banner",
            )
            if result.status == StepStatus.SUCCEEDED:
                result.details.update(
                    {
                        "inspector": inspector,
                        "kernel_version": self._parse_gdb_value(result.details["stdout_snippet"]),
                    }
                )
            return result
        if inspector == "symbol_address":
            if type(arguments) is not dict:
                raise ProviderDebugError(
                    "symbol_address arguments must be an object",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                )
            symbol = self.validate_symbol_name(arguments.get("symbol"))  # type: ignore[arg-type]
            result = self._run_read_operation(
                run_dir=run_dir,
                session=session,
                operation="evaluate.symbol_address",
                read_command=f"p &{symbol}",
            )
            if result.status == StepStatus.SUCCEEDED:
                result.details.update(
                    {
                        "inspector": inspector,
                        "symbol": symbol,
                        "address": self._parse_gdb_value(result.details["stdout_snippet"]),
                    }
                )
            return result
        raise ProviderDebugError(
            "unknown debug inspector",
            category=ErrorCategory.CONFIGURATION_ERROR,
            details={"inspector": inspector},
        )

    def ensure_attached_controller(self, session: DebugSession) -> None:
        if session.attach_status != "attached" or session.controller_mode != "attached":
            raise ProviderDebugError(
                "stateful debug operations require an attached controller",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={
                    "debug_session_id": session.session_id,
                    "attach_status": session.attach_status,
                    "controller_mode": session.controller_mode,
                },
            )
        if session.active_controller_pid is None or not self._controller_identity_matches(session):
            raise ProviderDebugError(
                "stateful debug operations require a live attached controller",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={
                    "debug_session_id": session.session_id,
                    "active_controller_pid": session.active_controller_pid,
                    "controller_last_observed_state": (
                        "exited"
                        if session.active_controller_pid is not None
                        and not self._pid_is_alive(session.active_controller_pid)
                        else session.controller_last_observed_state
                    ),
                },
            )

    def set_breakpoint(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        symbol: str,
    ) -> DebugProviderResult:
        self.ensure_attached_controller(session)
        self._ensure_session_not_ended(session)
        validated_symbol = self.validate_symbol_name(symbol)
        next_id = self._next_breakpoint_id(session)
        updated = session.model_copy(
            deep=True,
            update={
                "breakpoints": {
                    **session.breakpoints,
                    next_id: {
                        "id": next_id,
                        "symbol": validated_symbol,
                        "created_at": datetime.now(UTC).isoformat(),
                    },
                }
            },
        )
        return self._record_stateful_operation(
            run_dir=run_dir,
            session=updated,
            operation="set_breakpoint",
            summary=f"debug breakpoint {next_id} set",
            details={"debug_session_id": session.session_id, "breakpoint_id": next_id, "symbol": validated_symbol},
        )

    def clear_breakpoint(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        breakpoint_id: str,
    ) -> DebugProviderResult:
        self.ensure_attached_controller(session)
        self._ensure_session_not_ended(session)
        if type(breakpoint_id) is not str or not breakpoint_id:
            raise ProviderDebugError("invalid breakpoint id", category=ErrorCategory.CONFIGURATION_ERROR)
        if breakpoint_id not in session.breakpoints:
            raise ProviderDebugError(
                "breakpoint not found",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"debug_session_id": session.session_id, "breakpoint_id": breakpoint_id},
            )
        breakpoints = dict(session.breakpoints)
        removed = breakpoints.pop(breakpoint_id)
        updated = session.model_copy(deep=True, update={"breakpoints": breakpoints})
        return self._record_stateful_operation(
            run_dir=run_dir,
            session=updated,
            operation="clear_breakpoint",
            summary=f"debug breakpoint {breakpoint_id} cleared",
            details={"debug_session_id": session.session_id, "breakpoint_id": breakpoint_id, "breakpoint": removed},
        )

    def list_breakpoints(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
    ) -> DebugProviderResult:
        self.ensure_attached_controller(session)
        self._ensure_session_not_ended(session)
        return self._record_stateful_operation(
            run_dir=run_dir,
            session=session,
            operation="list_breakpoints",
            summary="debug breakpoints listed",
            details={"debug_session_id": session.session_id, "breakpoints": session.breakpoints},
        )

    def continue_execution(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        timeout_seconds: int | None = None,
    ) -> DebugProviderResult:
        self.ensure_attached_controller(session)
        self._ensure_session_not_ended(session)
        self._validate_optional_timeout(timeout_seconds)
        updated = session.model_copy(update={"current_execution_state": "running"})
        return self._record_stateful_operation(
            run_dir=run_dir,
            session=updated,
            operation="continue",
            summary="debug session continued",
            details={
                "debug_session_id": session.session_id,
                "current_execution_state": updated.current_execution_state,
                "timeout_seconds": timeout_seconds,
            },
        )

    def interrupt(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        timeout_seconds: int | None = None,
    ) -> DebugProviderResult:
        self.ensure_attached_controller(session)
        self._ensure_session_not_ended(session)
        self._validate_optional_timeout(timeout_seconds)
        updated = session.model_copy(update={"current_execution_state": "stopped"})
        return self._record_stateful_operation(
            run_dir=run_dir,
            session=updated,
            operation="interrupt",
            summary="debug session interrupted",
            details={
                "debug_session_id": session.session_id,
                "current_execution_state": updated.current_execution_state,
                "timeout_seconds": timeout_seconds,
            },
        )

    def end_session(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
    ) -> DebugProviderResult:
        if session.attach_status != "attached":
            self.ensure_attached_controller(session)
        controller_state = session.controller_last_observed_state
        if session.current_execution_state != "ended":
            if session.controller_mode == "attached":
                controller_state = self._terminate_controller_if_safe(session)
            else:
                controller_state = session.controller_last_observed_state
        no_controller = session.controller_mode == "batch" and session.active_controller_pid is None
        if not no_controller and controller_state not in {"exited", "terminate_confirmed"}:
            raise ProviderDebugError(
                "debug controller did not exit",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={
                    "debug_session_id": session.session_id,
                    "active_controller_pid": session.active_controller_pid,
                    "controller_last_observed_state": controller_state,
                },
            )
        final_controller_state = "exited" if controller_state in {"exited", "terminate_confirmed"} else controller_state
        updated = session.model_copy(
            update={
                "current_execution_state": "ended",
                "ended_at": session.ended_at or datetime.now(UTC).isoformat(),
                "controller_last_observed_state": final_controller_state,
            }
        )
        return self._record_stateful_operation(
            run_dir=run_dir,
            session=updated,
            operation="end_session",
            summary="debug session ended",
            details={
                "debug_session_id": session.session_id,
                "current_execution_state": updated.current_execution_state,
                "ended_at": updated.ended_at,
                "controller_last_observed_state": updated.controller_last_observed_state,
            },
        )

    def _run_read_operation(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        operation: str,
        read_command: str,
        memory_byte_count: int | None = None,
    ) -> DebugProviderResult:
        gdb_path = self.runner.which("gdb")
        if gdb_path is None:
            raise ProviderDebugError(
                "missing required GDB tool",
                category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": ["gdb"]},
            )
        if session.current_execution_state == "ended" or session.attach_status != "attached":
            raise ProviderDebugError(
                "debug session is not active",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"debug_session_id": session.session_id},
            )
        resolved_run_dir = run_dir.expanduser().resolve()
        resolved_vmlinux = self._resolve_existing_path(
            Path(session.vmlinux_path),
            description="session vmlinux path",
            required_parent=resolved_run_dir,
        )
        endpoint = self._validated_endpoint(session.gdbstub_endpoint)
        transcript_path = Path(session.transcript_path)
        command_metadata_path = Path(session.command_metadata_path)
        latest_summary_path = Path(session.latest_summary_path)
        debug_dir = resolved_run_dir / "debug"
        self._require_debug_path(transcript_path, debug_dir=debug_dir, description="transcript path")
        self._require_debug_path(command_metadata_path, debug_dir=debug_dir, description="command metadata path")
        self._require_debug_path(latest_summary_path, debug_dir=debug_dir, description="summary path")
        commands = [
            "set pagination off",
            "set confirm off",
            f"file {self._gdb_path(resolved_vmlinux)}",
            f"target remote {endpoint['host']}:{endpoint['port']}",
            read_command,
        ]
        argv = [gdb_path, "-nx", "-batch", "-q"]
        for command in commands:
            argv.extend(["-ex", command])

        started_at = datetime.now(UTC)
        runner_error_category = None
        try:
            command_result = self.runner.run_batch(
                argv,
                commands,
                timeout=30,
                transcript_path=transcript_path,
            )
        except (OSError, RuntimeError, UnicodeError) as exc:
            runner_error_category = ErrorCategory.INFRASTRUCTURE_FAILURE
            command_result = GdbCommandResult(
                exit_status=-1,
                stderr=f"{type(exc).__name__}: {exc}",
            )
            try:
                self._record_failure_transcript(
                    transcript_path=transcript_path,
                    argv=argv,
                    commands=commands,
                    timeout=30,
                    result=command_result,
                    mode="a",
                )
            except OSError as write_exc:
                raise ProviderDebugError(
                    "failed to write debug read transcript",
                    category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                    details={"path": str(transcript_path), "error": str(write_exc)},
                ) from write_exc
        ended_at = datetime.now(UTC)
        status = (
            StepStatus.SUCCEEDED
            if command_result.exit_status == 0 and not command_result.timed_out
            else StepStatus.FAILED
        )
        command_record = self._command_metadata(
            argv=argv,
            commands=commands,
            result=command_result,
            started_at=started_at,
            ended_at=ended_at,
            timeout=30,
            transcript_path=transcript_path,
        )
        details = self.redactor.redact_value(
            {
                "debug_session_id": session.session_id,
                "operation": operation,
                "exit_status": command_result.exit_status,
                "timed_out": command_result.timed_out,
                "stdout_snippet": self._snippet(command_result.stdout),
                "stderr_snippet": self._snippet(command_result.stderr),
            }
        )
        artifacts = self._session_artifacts(session)
        summary_payload = {
            "run_id": session.run_id,
            "provider": self.name,
            "status": status,
            "operation": operation,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "session": session.model_dump(mode="json"),
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
            "command": command_record,
        }
        try:
            self._append_jsonl(command_metadata_path, command_record)
            self._write_json(latest_summary_path, self.redactor.redact_value(summary_payload))
        except OSError as exc:
            raise ProviderDebugError(
                "failed to write debug read artifacts",
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={**details, "error": str(exc)},
                artifacts=self._existing_artifacts(artifacts),
            ) from exc

        error_category = runner_error_category or (
            ErrorCategory.DEBUG_ATTACH_FAILURE if status == StepStatus.FAILED else None
        )
        diagnostic = None
        if status == StepStatus.FAILED:
            diagnostic = self.redactor.redact_text(self._snippet(command_result.stderr or command_result.stdout))
        existing_artifacts = self._existing_artifacts(artifacts)
        if status == StepStatus.SUCCEEDED and memory_byte_count is not None:
            parsed_bytes = self._parse_memory_bytes(command_result.stdout, memory_byte_count)
            if len(parsed_bytes) != memory_byte_count:
                raise ProviderDebugError(
                    "debug memory read returned fewer bytes than requested",
                    category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                    details={
                        "debug_session_id": session.session_id,
                        "operation": operation,
                        "byte_count": memory_byte_count,
                        "parsed_byte_count": len(parsed_bytes),
                    },
                    artifacts=existing_artifacts,
                )
            details["bytes"] = parsed_bytes
        return DebugProviderResult(
            status=status,
            summary=f"debug {operation} {'succeeded' if status == StepStatus.SUCCEEDED else 'failed'}",
            session=session,
            artifacts=existing_artifacts,
            details=details,
            error_category=error_category,
            diagnostic=diagnostic,
        )

    def _record_stateful_operation(
        self,
        *,
        run_dir: Path,
        session: DebugSession,
        operation: str,
        summary: str,
        details: dict[str, object],
    ) -> DebugProviderResult:
        resolved_run_dir = run_dir.expanduser().resolve()
        debug_dir = resolved_run_dir / "debug"
        transcript_path = self._require_debug_path(
            Path(session.transcript_path),
            debug_dir=debug_dir,
            description="transcript path",
        )
        command_metadata_path = self._require_debug_path(
            Path(session.command_metadata_path),
            debug_dir=debug_dir,
            description="command metadata path",
        )
        latest_summary_path = self._require_debug_path(
            Path(session.latest_summary_path),
            debug_dir=debug_dir,
            description="summary path",
        )
        artifacts = self._session_artifacts(session)
        session_artifact = next(artifact for artifact in artifacts if artifact.kind == "debug-session")
        session_path = self._require_debug_path(
            Path(session_artifact.path),
            debug_dir=debug_dir,
            description="session path",
        )
        observed_at = datetime.now(UTC).isoformat()
        record = self.redactor.redact_value(
            {
                "kind": "debug-stateful-operation",
                "operation": operation,
                "debug_session_id": session.session_id,
                "observed_at": observed_at,
                "transcript_path": str(transcript_path),
                "details": details,
            }
        )
        summary_payload = {
            "run_id": session.run_id,
            "provider": self.name,
            "status": StepStatus.SUCCEEDED,
            "operation": operation,
            "observed_at": observed_at,
            "session": session.model_dump(mode="json"),
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
            "command": record,
        }
        try:
            self._append_jsonl(command_metadata_path, record)
            self._write_json(session_path, session.model_dump(mode="json"))
            self._write_json(latest_summary_path, self.redactor.redact_value(summary_payload))
        except OSError as exc:
            raise ProviderDebugError(
                "failed to write debug state artifacts",
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                details={**details, "error": str(exc)},
                artifacts=self._existing_artifacts(artifacts),
            ) from exc
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary=summary,
            session=session,
            artifacts=self._existing_artifacts(artifacts),
            details=self.redactor.redact_value(details),
        )

    def _ensure_session_not_ended(self, session: DebugSession) -> None:
        if session.current_execution_state == "ended":
            raise ProviderDebugError(
                "debug session is not active",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"debug_session_id": session.session_id},
            )

    def _next_breakpoint_id(self, session: DebugSession) -> str:
        numbers = []
        for breakpoint_id in session.breakpoints:
            if breakpoint_id.startswith("bp-"):
                try:
                    numbers.append(int(breakpoint_id.removeprefix("bp-")))
                except ValueError:
                    continue
        return f"bp-{max(numbers, default=0) + 1}"

    def _validate_optional_timeout(self, timeout_seconds: int | None) -> None:
        if timeout_seconds is None:
            return
        if type(timeout_seconds) is not int or timeout_seconds < 1 or timeout_seconds > 3600:
            raise ProviderDebugError(
                "timeout_seconds must be between 1 and 3600",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )

    def _terminate_controller_if_safe(self, session: DebugSession) -> str:
        pid = session.active_controller_pid
        if pid is None:
            return session.controller_last_observed_state
        if type(pid) is not int or pid <= 1 or pid == os.getpid():
            return "invalid"
        if not self._pid_is_alive(pid):
            return "exited"
        if not self._controller_identity_matches(session):
            return "alive_unverified"
        if not self._pid_looks_like_controller(pid):
            return "alive_not_controller"
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return "exited"
        except PermissionError:
            return "alive_permission_denied"
        for _ in range(50):
            if not self._pid_is_alive(pid):
                return "terminate_confirmed"
            time.sleep(0.02)
        return "alive_after_terminate"

    def _pid_is_alive(self, pid: int) -> bool:
        if self._pid_is_zombie(pid):
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError as exc:
            return exc.errno != errno.ESRCH
        return True

    def _pid_is_zombie(self, pid: int) -> bool:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            stat_text = stat_path.read_text(encoding="utf-8")
        except OSError:
            return False
        _prefix, separator, suffix = stat_text.rpartition(") ")
        if not separator:
            return False
        fields = suffix.split()
        return bool(fields and fields[0] == "Z")

    def _pid_looks_like_controller(self, pid: int) -> bool:
        cmdline_path = Path("/proc") / str(pid) / "cmdline"
        try:
            cmdline = cmdline_path.read_bytes()
        except FileNotFoundError:
            return False
        except OSError:
            return False
        if not cmdline:
            return False
        argv0 = cmdline.split(b"\0", 1)[0].decode("utf-8", errors="ignore")
        executable = Path(argv0).name
        return "gdb" in executable

    def _controller_identity(self, pid: int) -> dict[str, object]:
        identity: dict[str, object] = {"pid": pid}
        stat_path = Path("/proc") / str(pid) / "stat"
        cmdline_path = Path("/proc") / str(pid) / "cmdline"
        try:
            stat_text = stat_path.read_text(encoding="utf-8")
            _prefix, _separator, suffix = stat_text.rpartition(") ")
            fields = suffix.split()
            if len(fields) >= 20:
                identity["start_time_ticks"] = fields[19]
        except OSError:
            return identity
        try:
            cmdline = cmdline_path.read_bytes()
        except OSError:
            cmdline = b""
        if cmdline:
            argv0 = cmdline.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            identity["argv0"] = argv0
        return identity

    def _controller_identity_matches(self, session: DebugSession) -> bool:
        pid = session.active_controller_pid
        if type(pid) is not int or pid <= 1 or pid == os.getpid():
            return False
        if not self._pid_is_alive(pid):
            return False
        expected = session.active_controller_identity
        if not expected:
            return False
        observed = self._controller_identity(pid)
        return (
            observed.get("pid") == expected.get("pid")
            and observed.get("start_time_ticks") is not None
            and observed.get("start_time_ticks") == expected.get("start_time_ticks")
        )

    def _session_artifacts(self, session: DebugSession) -> list[ArtifactRef]:
        session_path = Path(session.command_metadata_path).parents[1] / "sessions" / f"{session.session_id}.json"
        return [
            ArtifactRef(path=session.transcript_path, kind="debug-transcript", sensitive=True),
            ArtifactRef(path=session.command_metadata_path, kind="debug-command-metadata"),
            ArtifactRef(path=session.latest_summary_path, kind="debug-summary"),
            ArtifactRef(path=str(session_path), kind="debug-session"),
        ]

    def _existing_artifacts(self, artifacts: list[ArtifactRef]) -> list[ArtifactRef]:
        return [artifact for artifact in artifacts if Path(artifact.path).is_file()]

    def _require_debug_path(self, path: Path, *, debug_dir: Path, description: str) -> Path:
        try:
            resolved = path.expanduser().resolve()
            resolved_debug_dir = debug_dir.expanduser().resolve()
        except OSError as exc:
            raise ProviderDebugError(
                f"{description} is invalid",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path), "error": str(exc)},
            ) from exc
        if not resolved.is_relative_to(resolved_debug_dir):
            raise ProviderDebugError(
                f"{description} must be inside the run debug directory",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path), "debug_dir": str(resolved_debug_dir)},
            )
        return resolved

    def _parse_registers(self, output: object, requested_registers: list[str]) -> dict[str, str]:
        requested = set(requested_registers)
        registers: dict[str, str] = {}
        for line in str(output).splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in requested:
                registers[parts[0]] = parts[1]
        return registers

    def _parse_memory_bytes(self, output: object, byte_count: int) -> list[str]:
        values: list[str] = []
        for line in str(output).splitlines():
            _separator, _colon, payload = line.partition(":")
            for value in re.findall(r"\b0x[0-9a-fA-F]{1,2}\b", payload):
                values.append(value.lower())
                if len(values) == byte_count:
                    return values
        return values

    def _parse_gdb_value(self, output: object) -> str:
        text = str(output).strip()
        _prefix, separator, value = text.partition("=")
        if separator:
            text = value.strip()
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            text = text[1:-1].replace("\\n", "\n").replace('\\"', '"')
        return self.redactor.redact_text(self._snippet(text))

    def validate_symbol_name(self, symbol: str) -> str:
        if type(symbol) is not str:
            raise ProviderDebugError("invalid symbol name", category=ErrorCategory.CONFIGURATION_ERROR)
        if not SYMBOL_PATTERN.match(symbol):
            raise ProviderDebugError("invalid symbol name", category=ErrorCategory.CONFIGURATION_ERROR)
        return symbol

    def validate_register_name(self, register: str) -> str:
        if type(register) is not str:
            raise ProviderDebugError("invalid register name", category=ErrorCategory.CONFIGURATION_ERROR)
        if not REGISTER_PATTERN.match(register):
            raise ProviderDebugError("invalid register name", category=ErrorCategory.CONFIGURATION_ERROR)
        return register

    def validate_memory_read(self, *, address: int, byte_count: int) -> None:
        if type(address) is not int or type(byte_count) is not int:
            raise ProviderDebugError(
                "address and byte_count must be integers",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
            raise ProviderDebugError(
                "address must fit in unsigned 64-bit range",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if byte_count < 1 or byte_count > MAX_MEMORY_READ_BYTES:
            raise ProviderDebugError(
                "byte_count must be between 1 and 4096",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )

    def _validated_endpoint(self, endpoint: dict[str, object]) -> dict[str, object]:
        if type(endpoint) is not dict:
            raise ProviderDebugError(
                "gdbstub endpoint must be an object",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        host = endpoint.get("host")
        port = endpoint.get("port")
        if host not in {"127.0.0.1", "localhost"}:
            raise ProviderDebugError(
                "gdbstub endpoint must use localhost",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if type(port) is not int or port < 1 or port > 65535:
            raise ProviderDebugError(
                "gdbstub endpoint port must be in 1..65535",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return {"host": "127.0.0.1" if host == "localhost" else host, "port": port}

    def _gdb_path(self, path: Path) -> str:
        text = str(path)
        if any(char in text for char in "\t\r\n"):
            raise ProviderDebugError(
                "gdb paths must not contain control whitespace",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return text.replace("\\", "\\\\").replace(" ", "\\ ")

    def _same_path(self, left: object, right: object) -> bool:
        if left is None or right is None:
            return False
        try:
            return Path(left).expanduser().resolve() == Path(right).expanduser().resolve()
        except (OSError, TypeError, ValueError):
            return False

    def _linux_banner_release(self, output: str) -> str | None:
        match = LINUX_BANNER_RELEASE_PATTERN.search(self._snippet(output))
        if match is None:
            return None
        return match.group(1)

    def _next_attempt_dir(self, run_dir: Path) -> Path:
        debug_dir = run_dir / "debug"
        for attempt in range(1, 1000):
            candidate = debug_dir / f"attempt-{attempt:03d}"
            if not candidate.exists():
                return candidate
        raise ProviderDebugError(
            "no available debug attempt directory",
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        )

    def _record_failure_transcript(
        self,
        *,
        transcript_path: Path,
        argv: list[str],
        commands: list[str],
        timeout: int,
        result: GdbCommandResult,
        mode: Literal["w", "a"],
    ) -> None:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open(mode, encoding="utf-8") as transcript:
            transcript.write(f"$ {' '.join(argv)}\n")
            transcript.write("commands:\n")
            for command in commands:
                transcript.write(f"  {command}\n")
            transcript.write(f"timeout_seconds: {timeout}\n")
            transcript.write(f"stderr: {self._snippet(result.stderr)}\n")
            transcript.write(f"timed_out: {str(result.timed_out).lower()}\n")
            transcript.write(f"exit_status: {result.exit_status}\n")

    def _resolve_existing_path(self, path: Path, *, description: str, required_parent: Path | None = None) -> Path:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise ProviderDebugError(
                f"{description} does not exist",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path)},
            )
        if not resolved.is_file():
            raise ProviderDebugError(
                f"{description} must be a regular file",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path)},
            )
        if required_parent is not None and not resolved.is_relative_to(required_parent):
            raise ProviderDebugError(
                f"{description} must be inside the run directory",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path), "run_dir": str(required_parent)},
            )
        return resolved

    def _command_metadata(
        self,
        *,
        argv: list[str],
        commands: list[str],
        result: GdbCommandResult,
        started_at: datetime,
        ended_at: datetime,
        timeout: int,
        transcript_path: Path,
    ) -> dict[str, object]:
        return self.redactor.redact_value(
            {
                "kind": "gdb-batch",
                "argv": argv,
                "commands": commands,
                "timeout_seconds": timeout,
                "exit_status": result.exit_status,
                "timed_out": result.timed_out,
                "started_at": started_at.isoformat(),
                "ended_at": ended_at.isoformat(),
                "transcript_path": str(transcript_path),
                "stdout_snippet": self._snippet(result.stdout),
                "stderr_snippet": self._snippet(result.stderr),
            }
        )

    def _append_jsonl(self, path: Path, payload: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str))
            handle.write("\n")

    def _write_json(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def _snippet(self, value: str) -> str:
        return value[:MAX_RESPONSE_SNIPPET]
