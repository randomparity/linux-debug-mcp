from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, StepStatus
from linux_debug_mcp.safety.redaction import Redactor

MAX_MEMORY_READ_BYTES = 4096
MAX_RESPONSE_SNIPPET = 4096
SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]*$")
REGISTER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


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
        resolved_vmlinux = self._resolve_existing_path(vmlinux_path, description="vmlinux path")
        if boot_metadata.get("debug_boot") is not True:
            raise ProviderDebugError(
                "boot metadata does not indicate a debug gdbstub boot",
                category=ErrorCategory.CONFIGURATION_ERROR,
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
            f"file {resolved_vmlinux}",
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
            self._write_failure_transcript(
                transcript_path=transcript_path,
                argv=argv,
                commands=commands,
                timeout=30,
                result=result,
            )
        ended_at = datetime.now(UTC)
        status = StepStatus.SUCCEEDED if result.exit_status == 0 and not result.timed_out else StepStatus.FAILED
        session = DebugSession(
            session_id=session_id,
            run_id=run_id,
            provider_name=self.name,
            gdbstub_endpoint=endpoint,
            vmlinux_path=str(resolved_vmlinux),
            selected_debug_profile=debug_profile.name,
            attach_status="attached" if status == StepStatus.SUCCEEDED else "failed",
            started_at=started_at.isoformat(),
            ended_at=ended_at.isoformat() if status == StepStatus.FAILED else None,
            current_execution_state="stopped" if status == StepStatus.SUCCEEDED else "unknown",
            transcript_path=str(transcript_path),
            command_metadata_path=str(command_metadata_path),
            latest_summary_path=str(latest_summary_path),
            symbol_identity_validation={
                "command": "p linux_banner",
                "required": debug_profile.symbol_identity_required,
                "stdout_snippet": self._snippet(result.stdout),
            },
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
        self._append_jsonl(command_metadata_path, command_record)
        self._write_json(session_path, session.model_dump(mode="json"))
        summary_payload = {
            "run_id": run_id,
            "provider": self.name,
            "status": status,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "session_path": str(session_path),
            "session": session.model_dump(mode="json"),
            "build_metadata": build_metadata,
            "boot_metadata": boot_metadata,
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
            "command": command_record,
        }
        self._write_json(latest_summary_path, self.redactor.redact_value(summary_payload))
        return DebugProviderResult(
            status=status,
            summary="qemu gdbstub session started" if status == StepStatus.SUCCEEDED else "qemu gdbstub attach failed",
            session=session,
            artifacts=[artifact for artifact in artifacts if Path(artifact.path).is_file()],
            details={
                "session_path": str(session_path),
                "gdbstub_endpoint": endpoint,
                "exit_status": result.exit_status,
                "timed_out": result.timed_out,
            },
            error_category=runner_error_category
            or (ErrorCategory.DEBUG_ATTACH_FAILURE if status == StepStatus.FAILED else None),
            diagnostic=self._snippet(result.stderr or result.stdout) if status == StepStatus.FAILED else None,
        )

    def validate_symbol_name(self, symbol: str) -> str:
        if not SYMBOL_PATTERN.match(symbol):
            raise ProviderDebugError("invalid symbol name", category=ErrorCategory.CONFIGURATION_ERROR)
        return symbol

    def validate_register_name(self, register: str) -> str:
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
        host = endpoint.get("host")
        port = endpoint.get("port")
        if host not in {"127.0.0.1", "localhost"}:
            raise ProviderDebugError(
                "gdbstub endpoint must use localhost",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ProviderDebugError(
                "gdbstub endpoint port must be in 1..65535",
                category=ErrorCategory.CONFIGURATION_ERROR,
            )
        return {"host": "127.0.0.1" if host == "localhost" else host, "port": port}

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

    def _write_failure_transcript(
        self,
        *,
        transcript_path: Path,
        argv: list[str],
        commands: list[str],
        timeout: int,
        result: GdbCommandResult,
    ) -> None:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("w", encoding="utf-8") as transcript:
            transcript.write(f"$ {' '.join(argv)}\n")
            transcript.write("commands:\n")
            for command in commands:
                transcript.write(f"  {command}\n")
            transcript.write(f"timeout_seconds: {timeout}\n")
            transcript.write(f"stderr: {self._snippet(result.stderr)}\n")
            transcript.write(f"timed_out: {str(result.timed_out).lower()}\n")
            transcript.write(f"exit_status: {result.exit_status}\n")

    def _resolve_existing_path(self, path: Path, *, description: str) -> Path:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise ProviderDebugError(
                f"{description} does not exist",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"path": str(path)},
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
