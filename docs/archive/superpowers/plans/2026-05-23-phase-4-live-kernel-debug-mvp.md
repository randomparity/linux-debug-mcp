# Phase 4 Live Kernel Debug MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Phase 4 local QEMU gdbstub debug workflow, including QEMU gdbstub enablement, constrained `debug.*` tools, debug artifacts, and `workflow.build_boot_debug`.

**Architecture:** Keep MCP handlers in `server.py` responsible for manifest validation, idempotency, locks, and response shaping. Extend `LibvirtQemuProvider` only for debug-enabled boot planning and XML rendering, and put all gdb command planning, session files, transcript writing, parsing, and state transitions behind a new fakeable `QemuGdbstubProvider`.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, stdlib `subprocess`, `xml.etree.ElementTree`, existing `ArtifactStore`, `RunManifest`, `ToolResponse`, provider registry, and `Redactor`.

---

## Current-Code Constraints

- `TargetProfile` has `debug_gdbstub` but no `gdbstub_endpoint`; `DebugProfile.gdbstub_endpoint` exists but the Phase 4 design puts the endpoint on `TargetProfile`.
- `LibvirtQemuProvider._validate_profiles()` currently rejects `debug_gdbstub=True`.
- `BootPlan`, `target/boot-plan.json`, and `summaries/boot-summary.json` do not record debug boot state, gdbstub endpoint details, or whether `nokaslr` was provider-added.
- `ArtifactStore` has build, boot, target, tests, and collect locks, but no `debug_lock(run_id)`.
- `RunManifest` already has a `debug` step, but no code records debug step results.
- `server.py` currently registers every `debug.*` tool and `workflow.build_boot_debug` as stubs.
- `artifacts.collect` only treats build, boot, and run_tests artifact kinds as expected; debug artifacts are merely incidental if a step records them.
- `ProviderRegistry.with_defaults()` still lists Phase 4 operations under `stub-workflows`.

## Files

- Modify: `src/linux_debug_mcp/config.py` for `TargetProfile.gdbstub_endpoint`, stricter `DebugProfile` defaults, and endpoint/profile validation.
- Modify: `src/linux_debug_mcp/artifacts/store.py` for `debug_lock(run_id)`.
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` for debug gdbstub boot planning, endpoint parsing, port availability checks, `nokaslr`, XML rendering, summaries, and capability operations.
- Create: `src/linux_debug_mcp/providers/qemu_gdbstub.py` for the gdb controller boundary, command validators, session model, transcript artifacts, identity validation, read operations, stateful operations, and provider capability.
- Modify: `src/linux_debug_mcp/providers/registry.py` to register `local-qemu-gdbstub` and remove implemented Phase 4 operations from stubs.
- Modify: `src/linux_debug_mcp/server.py` for default debug profile data, debug helper functions, `debug.*` handlers, `workflow.build_boot_debug_handler()`, MCP tool wiring, and removal of Phase 4 stubs.
- Modify: `src/linux_debug_mcp/artifacts/manifest.py` only if debug step ordering needs a status default adjustment; the current `debug` step can be reused.
- Modify: `src/linux_debug_mcp/safety/redaction.py` only if transcript redaction needs a reusable helper beyond `Redactor.redact_text()` and `Redactor.redact_value()`.
- Create: `tests/test_qemu_gdbstub_provider.py` for provider command planning, validation, fake runner execution, session artifacts, parsing, identity checks, and lifecycle behavior.
- Modify: `tests/test_libvirt_qemu_provider.py` for debug boot endpoint XML, `nokaslr`, boot plan/summary fields, unsafe endpoint rejection, and occupied port handling.
- Create: `tests/test_debug_handlers.py` for `debug.*` handler validation, idempotency, locks, response redaction, manifest debug result, and error categories.
- Create: `tests/test_workflow_build_boot_debug_handler.py` for workflow success and create, build, boot, attach failure boundaries.
- Modify: `tests/test_artifacts_collect_handler.py` for debug artifact bundle contents and redaction.
- Modify: `tests/test_providers.py` and `tests/test_server.py` for provider capability registration and MCP tool registration.
- Modify: `tests/test_config.py` for new endpoint/profile defaults and validation.
- Modify: `README.md` and `docs/fedora-libvirt-user-guide.md` for the local live-debug pilot command flow and host prerequisites.

## Task 1: Add Debug Profile Defaults, Target Endpoint, And Debug Lock

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Modify: `src/linux_debug_mcp/artifacts/store.py`
- Modify: `tests/test_config.py`
- Modify: `tests/test_artifacts.py`

- [ ] **Step 1: Write failing config tests**

Add these tests to `tests/test_config.py`:

```python
from pydantic import ValidationError

from linux_debug_mcp.config import DebugProfile, TargetProfile


def test_target_profile_accepts_local_gdbstub_endpoint() -> None:
    profile = TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        target_ref="mcp-linux-debug-dev",
        managed_domain=True,
        libvirt_uri="qemu:///system",
        debug_gdbstub=True,
        gdbstub_endpoint="127.0.0.1:1234",
    )

    assert profile.debug_gdbstub is True
    assert profile.gdbstub_endpoint == "127.0.0.1:1234"


def test_default_debug_profile_matches_phase_4_policy() -> None:
    profile = DebugProfile(name="qemu-gdbstub-default")

    assert profile.kaslr_policy == "disabled"
    assert profile.symbol_identity_required is True
    assert profile.evaluation_mode == "predefined_inspectors"
    assert profile.enabled_operations == [
        "debug.start_session",
        "debug.interrupt",
        "debug.continue",
        "debug.set_breakpoint",
        "debug.clear_breakpoint",
        "debug.list_breakpoints",
        "debug.read_registers",
        "debug.read_symbol",
        "debug.read_memory",
        "debug.evaluate",
        "debug.end_session",
    ]


def test_debug_profile_rejects_unsupported_phase_4_policy() -> None:
    with pytest.raises(ValidationError):
        DebugProfile(name="bad", kaslr_policy="known")

    with pytest.raises(ValidationError):
        DebugProfile(name="bad", evaluation_mode="limited_expressions")
```

- [ ] **Step 2: Write failing debug lock test**

Add this test to `tests/test_artifacts.py`:

```python
def test_debug_lock_serializes_per_run(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    manifest = store.create_run(
        RunRequest(
            source_path=str(tmp_path),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            run_id="run-debug-lock",
        )
    )

    with store.debug_lock(manifest.run_id):
        with pytest.raises(ManifestStateError, match="debug is locked"):
            with store.debug_lock(manifest.run_id):
                pass
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
pytest tests/test_config.py tests/test_artifacts.py -q
```

Expected: FAIL because `TargetProfile.gdbstub_endpoint`, strict Phase 4 `DebugProfile` validation, and `ArtifactStore.debug_lock()` do not exist.

- [ ] **Step 4: Implement config and lock changes**

In `src/linux_debug_mcp/config.py`, define the operation list near the other module-level constants:

```python
PHASE_4_DEBUG_OPERATIONS = [
    "debug.start_session",
    "debug.interrupt",
    "debug.continue",
    "debug.set_breakpoint",
    "debug.clear_breakpoint",
    "debug.list_breakpoints",
    "debug.read_registers",
    "debug.read_symbol",
    "debug.read_memory",
    "debug.evaluate",
    "debug.end_session",
]
```

Add `gdbstub_endpoint` to `TargetProfile`:

```python
class TargetProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str = "local-libvirt-qemu"
    target_ref: str | None = None
    kernel_args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    cleanup_policy: Literal["preserve_on_failure", "stop_on_failure"] = "preserve_on_failure"
    debug_gdbstub: bool = False
    gdbstub_endpoint: str = "127.0.0.1:1234"
    libvirt_uri: str | None = None
    managed_domain: bool = False
    managed_domain_prefix: str | None = None
```

Change `DebugProfile` to Phase 4-only policies:

```python
class DebugProfile(ConfigModel):
    name: str
    enabled_operations: list[str] = Field(default_factory=lambda: list(PHASE_4_DEBUG_OPERATIONS))
    kaslr_policy: Literal["disabled"] = "disabled"
    symbol_identity_required: bool = True
    evaluation_mode: Literal["predefined_inspectors"] = "predefined_inspectors"
```

In `src/linux_debug_mcp/artifacts/store.py`, add:

```python
    @contextmanager
    def debug_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".debug.lock",
            locked_message="debug is locked",
            failure_prefix="failed to lock debug",
        ):
            yield
```

- [ ] **Step 5: Run tests and verify pass**

Run:

```bash
pytest tests/test_config.py tests/test_artifacts.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/config.py src/linux_debug_mcp/artifacts/store.py tests/test_config.py tests/test_artifacts.py
git commit -m "feat: add phase 4 debug profile state"
```

## Task 2: Enable Debug Gdbstub Boot In Libvirt Provider

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py`
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `tests/test_libvirt_qemu_provider.py`
- Modify: `tests/test_target_boot_handler.py`

- [ ] **Step 1: Write failing provider tests**

Add these tests to `tests/test_libvirt_qemu_provider.py`:

```python
class PortCheckingRunner:
    def __init__(self, *, port_available: bool = True) -> None:
        self.port_available = port_available

    def which(self, command: str) -> str | None:
        return "/usr/bin/virsh" if command == "virsh" else None

    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult:
        return CommandResult(argv=argv, exit_status=0, stdout="")

    def stream_console(
        self,
        domain: str,
        *,
        libvirt_uri: str,
        output_path: Path,
        timeout: int,
        readiness_marker: str,
    ) -> ConsoleResult:
        return ConsoleResult(
            status="ready",
            matched_marker=readiness_marker,
            snippet=readiness_marker,
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
        )

    def is_tcp_port_available(self, host: str, port: int) -> bool:
        return self.port_available


def test_debug_boot_adds_gdbstub_endpoint_and_nokaslr(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())

    plan = provider.plan_boot(
        run_id="run-debug",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234"),
        rootfs_profile=rootfs_profile(rootfs),
    )
    xml_text = provider.render_domain_xml(plan)
    root = ElementTree.fromstring(xml_text)

    assert plan.debug_gdbstub is True
    assert plan.gdbstub_endpoint == {"host": "127.0.0.1", "port": 1234}
    assert plan.nokaslr_source == "provider_added"
    assert "nokaslr" in plan.kernel_args
    qemu_args = root.findall(".//{http://libvirt.org/schemas/domain/qemu/1.0}arg")
    values = [item.attrib["value"] for item in qemu_args]
    assert "-gdb" in values
    assert "tcp:127.0.0.1:1234,server=on,wait=off" in values


@pytest.mark.parametrize(
    "endpoint",
    [
        "0.0.0.0:1234",
        "192.168.122.1:1234",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:1234/path",
        "127.0.0.1:1234?x=1",
        "127.0.0.1:12 34",
        "<bad>:1234",
    ],
)
def test_debug_boot_rejects_unsafe_gdbstub_endpoints(tmp_path: Path, endpoint: str) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())

    with pytest.raises(ProviderBootError) as exc_info:
        provider.plan_boot(
            run_id="run-debug",
            run_dir=run_dir,
            kernel_image_path=kernel,
            target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint=endpoint),
            rootfs_profile=rootfs_profile(rootfs),
        )

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


def test_debug_boot_rejects_occupied_gdbstub_port(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner(port_available=False))

    with pytest.raises(ProviderBootError, match="gdbstub endpoint is already in use") as exc_info:
        provider.plan_boot(
            run_id="run-debug",
            run_dir=run_dir,
            kernel_image_path=kernel,
            target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234"),
            rootfs_profile=rootfs_profile(rootfs),
        )

    assert exc_info.value.category == ErrorCategory.INFRASTRUCTURE_FAILURE
```

- [ ] **Step 2: Write failing handler test**

Add this test to `tests/test_target_boot_handler.py`:

```python
def test_target_boot_records_debug_endpoint_in_manifest(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    run_id = "run-abc123"
    record_build(artifact_root, run_id)
    provider = FakeBootProvider()
    response = target_boot_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        target_profiles={
            "local-qemu": TargetProfile(
                name="local-qemu",
                architecture="x86_64",
                target_ref="debug-vm",
                libvirt_uri="qemu:///system",
                managed_domain=True,
                debug_gdbstub=True,
                gdbstub_endpoint="127.0.0.1:1234",
            )
        },
        rootfs_profiles={"minimal": rootfs_profile(tmp_path)},
    )

    assert response.ok is True
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    boot = manifest.step_results["boot"]
    assert boot.details["debug_boot"] is True
    assert boot.details["gdbstub_endpoint"] == {"host": "127.0.0.1", "port": 1234}
    assert boot.details["nokaslr_source"] == "provider_added"
```

Update the `Plan` dataclass in `tests/test_target_boot_handler.py` so the fake provider can preserve debug fields:

```python
@dataclass
class Plan:
    run_id: str
    domain_name: str
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    debug_gdbstub: bool = False
    gdbstub_endpoint: dict[str, object] | None = None
    nokaslr_source: str = "not_applicable"
```

Update `FakeBootProvider.plan_boot()` to set those fields from `target_profile`, and update `FakeBootProvider.execute_boot()` details:

```python
        return Plan(
            run_id=run_id,
            domain_name=target_profile.target_ref or target_profile.name,
            boot_log_path=run_dir / "logs" / "boot.log",
            boot_plan_path=run_dir / "target" / "boot-plan.json",
            boot_summary_path=run_dir / "summaries" / "boot-summary.json",
            debug_gdbstub=target_profile.debug_gdbstub,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234} if target_profile.debug_gdbstub else None,
            nokaslr_source="provider_added" if target_profile.debug_gdbstub else "not_applicable",
        )
```

```python
            details={
                "domain": plan.domain_name,
                "provider_call": len(self.executions),
                "debug_boot": plan.debug_gdbstub,
                "gdbstub_endpoint": plan.gdbstub_endpoint,
                "nokaslr_source": plan.nokaslr_source,
            },
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
pytest tests/test_libvirt_qemu_provider.py tests/test_target_boot_handler.py -q
```

Expected: FAIL because debug gdbstub boot is still rejected and `BootPlan` lacks debug fields.

- [ ] **Step 4: Implement debug boot planning**

In `src/linux_debug_mcp/providers/libvirt_qemu.py`:

```python
QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
ElementTree.register_namespace("qemu", QEMU_NS)


@dataclass(frozen=True)
class GdbstubEndpoint:
    host: str
    port: int

    def as_dict(self) -> dict[str, object]:
        return {"host": self.host, "port": self.port}
```

Extend `BootPlan` with:

```python
    debug_gdbstub: bool
    gdbstub_endpoint: GdbstubEndpoint | None
    nokaslr_source: Literal["not_applicable", "profile_supplied", "provider_added"]
```

Extend `LibvirtRunner` with:

```python
    def is_tcp_port_available(self, host: str, port: int) -> bool:
        raise NotImplementedError
```

Implement it in `SubprocessLibvirtRunner` with a local bind probe:

```python
    def is_tcp_port_available(self, host: str, port: int) -> bool:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                return False
        return True
```

Add endpoint and kernel helpers:

```python
    def _parse_gdbstub_endpoint(self, endpoint: str) -> GdbstubEndpoint:
        if any(char.isspace() for char in endpoint) or any(char in endpoint for char in "<>$;&|?/#"):
            raise self._configuration_error("unsafe gdbstub endpoint syntax")
        host, separator, port_text = endpoint.rpartition(":")
        if separator == "" or host not in {"127.0.0.1", "localhost", "::1"}:
            raise self._configuration_error("gdbstub endpoint must bind to localhost")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise self._configuration_error("gdbstub endpoint port must be an integer") from exc
        if port < 1 or port > 65535:
            raise self._configuration_error("gdbstub endpoint port must be in 1..65535")
        normalized_host = "127.0.0.1" if host == "localhost" else host
        return GdbstubEndpoint(host=normalized_host, port=port)

    def _debug_kernel_args(self, configured_args: list[str], debug_enabled: bool) -> tuple[list[str], str]:
        args = self._kernel_args(configured_args)
        if not debug_enabled:
            return args, "not_applicable"
        if "nokaslr" in args:
            return args, "profile_supplied"
        return [*args, "nokaslr"], "provider_added"
```

Use those helpers in `plan_boot()`. When `target_profile.debug_gdbstub` is true, parse the endpoint, check `runner.is_tcp_port_available()`, include endpoint fields in the `BootPlan`, and raise `ProviderBootError("gdbstub endpoint is already in use", category=ErrorCategory.INFRASTRUCTURE_FAILURE)` if the port is occupied.

- [ ] **Step 5: Implement XML, plan, summary, and details fields**

In `render_domain_xml()`, add the qemu namespace and commandline args only when `plan.debug_gdbstub` is true:

```python
        if plan.debug_gdbstub and plan.gdbstub_endpoint is not None:
            domain.attrib[f"xmlns:qemu"] = QEMU_NS
            qemu_commandline = ElementTree.SubElement(domain, f"{{{QEMU_NS}}}commandline")
            ElementTree.SubElement(qemu_commandline, f"{{{QEMU_NS}}}arg", {"value": "-gdb"})
            ElementTree.SubElement(
                qemu_commandline,
                f"{{{QEMU_NS}}}arg",
                {"value": f"tcp:{plan.gdbstub_endpoint.host}:{plan.gdbstub_endpoint.port},server=on,wait=off"},
            )
```

Add these fields to `_write_boot_plan()` and successful boot `details`:

```python
"debug_boot": plan.debug_gdbstub,
"gdbstub_endpoint": plan.gdbstub_endpoint.as_dict() if plan.gdbstub_endpoint else None,
"nokaslr_source": plan.nokaslr_source,
```

Update `_validate_profiles()` so `debug_gdbstub=True` is accepted for local QEMU instead of rejected.

- [ ] **Step 6: Run tests and verify pass**

Run:

```bash
pytest tests/test_libvirt_qemu_provider.py tests/test_target_boot_handler.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py src/linux_debug_mcp/server.py tests/test_libvirt_qemu_provider.py tests/test_target_boot_handler.py
git commit -m "feat: enable qemu gdbstub boot"
```

## Task 3: Add QEMU Gdbstub Provider Session And Command Planning

**Files:**
- Create: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Create: `tests/test_qemu_gdbstub_provider.py`

- [ ] **Step 1: Write failing provider tests for planning and validation**

Create `tests/test_qemu_gdbstub_provider.py` with:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ErrorCategory, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import (
    GdbCommandResult,
    QemuGdbstubProvider,
    ProviderDebugError,
)


class FakeGdbRunner:
    def __init__(self, *, gdb_path: str | None = "/usr/bin/gdb") -> None:
        self.gdb_path = gdb_path
        self.batches: list[tuple[list[str], list[str]]] = []

    def which(self, command: str) -> str | None:
        return self.gdb_path if command == "gdb" else None

    def run_batch(
        self,
        argv: list[str],
        commands: list[str],
        *,
        timeout: int,
        transcript_path: Path,
    ) -> GdbCommandResult:
        self.batches.append((argv, commands))
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text("\n".join(commands), encoding="utf-8")
        return GdbCommandResult(exit_status=0, stdout="$1 = 0xffffffff81000000", stderr="")


def write_vmlinux(tmp_path: Path) -> Path:
    vmlinux = tmp_path / "build" / "vmlinux"
    vmlinux.parent.mkdir(parents=True)
    vmlinux.write_text("fake vmlinux", encoding="utf-8")
    return vmlinux


def test_start_session_records_files_and_uses_constrained_attach_batch(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    result = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default"),
        build_metadata={"kernel_release": "6.9.0-test"},
        boot_metadata={"debug_boot": True, "kernel_image_path": str(tmp_path / "bzImage")},
    )

    assert result.status == StepStatus.SUCCEEDED
    assert result.session.session_id.startswith("debug-")
    assert result.session.current_execution_state == "stopped"
    assert result.session.controller_mode == "batch"
    assert Path(result.session.transcript_path).is_file()
    assert Path(result.session.command_metadata_path).is_file()
    assert Path(result.session.latest_summary_path).is_file()
    assert result.artifacts_by_kind["debug-transcript"].is_file()


@pytest.mark.parametrize("symbol", ["", "bad-name", "bad;name", "bad name", "bad/name"])
def test_symbol_validation_rejects_unsafe_names(tmp_path: Path, symbol: str) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_symbol_name(symbol)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR


@pytest.mark.parametrize("byte_count", [-1, 0, 4097])
def test_memory_validation_rejects_invalid_byte_counts(tmp_path: Path, byte_count: int) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.validate_memory_read(address=0x1000, byte_count=byte_count)

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py -q
```

Expected: FAIL because `linux_debug_mcp.providers.qemu_gdbstub` does not exist.

- [ ] **Step 3: Implement provider skeleton and session model**

Create `src/linux_debug_mcp/providers/qemu_gdbstub.py`:

```python
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
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, OperationSemantics, ProviderCapability, StepStatus, TargetKind
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
```

Implement `SubprocessGdbRunner.run_batch()` with `subprocess.run(argv, check=False, shell=False, timeout=timeout, capture_output=True, text=True)` and append argv, commands, stdout, stderr, and timeout status to `transcript_path`.

- [ ] **Step 4: Implement start session planning and validators**

In `QemuGdbstubProvider`, implement:

```python
class QemuGdbstubProvider:
    name = "local-qemu-gdbstub"

    def __init__(self, *, runner: GdbRunner | None = None, redactor: Redactor | None = None) -> None:
        self.runner = runner or SubprocessGdbRunner()
        self.redactor = redactor or Redactor()

    def validate_symbol_name(self, symbol: str) -> str:
        if not SYMBOL_PATTERN.match(symbol):
            raise ProviderDebugError("invalid symbol name", category=ErrorCategory.CONFIGURATION_ERROR)
        return symbol

    def validate_register_name(self, register: str) -> str:
        if not REGISTER_PATTERN.match(register):
            raise ProviderDebugError("invalid register name", category=ErrorCategory.CONFIGURATION_ERROR)
        return register

    def validate_memory_read(self, *, address: int, byte_count: int) -> None:
        if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
            raise ProviderDebugError("address must fit in unsigned 64-bit range", category=ErrorCategory.CONFIGURATION_ERROR)
        if byte_count < 1 or byte_count > MAX_MEMORY_READ_BYTES:
            raise ProviderDebugError("byte_count must be between 1 and 4096", category=ErrorCategory.CONFIGURATION_ERROR)
```

`start_session()` must:
- require `runner.which("gdb")`;
- require existing `vmlinux_path`;
- require `boot_metadata["debug_boot"] is True`;
- create `debug/sessions/<session-id>.json`;
- create `debug/attempt-001/transcript.txt`, `debug/attempt-001/commands.jsonl`, and `debug/attempt-001/debug-summary.json`;
- run commands `set pagination off`, `set confirm off`, `file <vmlinux>`, `target remote <host>:<port>`, and `p linux_banner`;
- write JSONL metadata for the command batch;
- write a session file and summary file;
- return `DebugProviderResult`.

- [ ] **Step 5: Run tests and verify pass**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py -q
```

Expected: PASS for the planning, validation, and session-file tests.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/providers/qemu_gdbstub.py tests/test_qemu_gdbstub_provider.py
git commit -m "feat: add qemu gdbstub provider session planning"
```

## Task 4: Implement Strict Identity Validation And Start Session Handler

**Files:**
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_debug_handlers.py`
- Modify: `tests/test_qemu_gdbstub_provider.py`

- [ ] **Step 1: Add provider identity tests**

Append to `tests/test_qemu_gdbstub_provider.py`:

```python
def test_start_session_requires_same_run_linkage_and_live_banner(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    result = provider.start_session(
        run_id="run-debug",
        run_dir=tmp_path,
        vmlinux_path=vmlinux,
        gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
        debug_profile=DebugProfile(name="qemu-gdbstub-default"),
        build_metadata={
            "kernel_release": "6.9.0-test",
            "kernel_image_path": str(tmp_path / "build" / "bzImage"),
            "vmlinux_path": str(vmlinux),
        },
        boot_metadata={
            "debug_boot": True,
            "kernel_image_path": str(tmp_path / "build" / "bzImage"),
        },
    )

    assert result.session.symbol_identity_validation["same_run_artifact_linkage"] is True
    assert "live_banner_match" in result.session.symbol_identity_validation


def test_start_session_fails_when_same_run_linkage_is_missing(tmp_path: Path) -> None:
    vmlinux = write_vmlinux(tmp_path)
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.start_session(
            run_id="run-debug",
            run_dir=tmp_path,
            vmlinux_path=vmlinux,
            gdbstub_endpoint={"host": "127.0.0.1", "port": 1234},
            debug_profile=DebugProfile(name="qemu-gdbstub-default"),
            build_metadata={"kernel_release": "6.9.0-test", "kernel_image_path": str(tmp_path / "a")},
            boot_metadata={"debug_boot": True, "kernel_image_path": str(tmp_path / "b")},
        )

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR
```

- [ ] **Step 2: Add handler tests**

Create `tests/test_debug_handlers.py`:

```python
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import DebugProfile
from linux_debug_mcp.domain import ArtifactRef, ErrorCategory, RunRequest, StepResult, StepStatus
from linux_debug_mcp.providers.qemu_gdbstub import DebugProviderResult, DebugSession
from linux_debug_mcp.server import debug_start_session_handler


class FakeDebugProvider:
    name = "local-qemu-gdbstub"

    def __init__(self) -> None:
        self.calls = 0

    def start_session(self, **kwargs):
        self.calls += 1
        run_dir = kwargs["run_dir"]
        session_path = run_dir / "debug" / "sessions" / "debug-1.json"
        transcript_path = run_dir / "debug" / "attempt-001" / "transcript.txt"
        commands_path = run_dir / "debug" / "attempt-001" / "commands.jsonl"
        summary_path = run_dir / "debug" / "attempt-001" / "debug-summary.json"
        for path in [session_path, transcript_path, commands_path, summary_path]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
        session = DebugSession(
            session_id="debug-1",
            run_id=kwargs["run_id"],
            provider_name=self.name,
            gdbstub_endpoint=kwargs["gdbstub_endpoint"],
            vmlinux_path=str(kwargs["vmlinux_path"]),
            selected_debug_profile=kwargs["debug_profile"].name,
            attach_status="attached",
            started_at="2026-05-23T00:00:00+00:00",
            current_execution_state="stopped",
            transcript_path=str(transcript_path),
            command_metadata_path=str(commands_path),
            latest_summary_path=str(summary_path),
            symbol_identity_validation={"same_run_artifact_linkage": True, "live_banner_match": True},
        )
        return DebugProviderResult(
            status=StepStatus.SUCCEEDED,
            summary="debug session started",
            session=session,
            artifacts=[
                ArtifactRef(path=str(session_path), kind="debug-session"),
                ArtifactRef(path=str(transcript_path), kind="debug-transcript", sensitive=True),
                ArtifactRef(path=str(commands_path), kind="debug-commands", sensitive=True),
                ArtifactRef(path=str(summary_path), kind="debug-summary"),
            ],
            details={"debug_session_id": "debug-1"},
        )


def create_debug_ready_run(tmp_path: Path) -> tuple[Path, str]:
    artifact_root = tmp_path / "runs"
    source = tmp_path / "source"
    source.mkdir()
    store = ArtifactStore(artifact_root, source_paths=[source])
    manifest = store.create_run(
        RunRequest(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            debug_profile="qemu-gdbstub-default",
            run_id="run-debug",
        )
    )
    vmlinux = artifact_root / manifest.run_id / "build" / "vmlinux"
    kernel = artifact_root / manifest.run_id / "build" / "bzImage"
    vmlinux.write_text("vmlinux", encoding="utf-8")
    kernel.write_text("kernel", encoding="utf-8")
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="build",
            status=StepStatus.SUCCEEDED,
            summary="built",
            artifacts=[
                ArtifactRef(path=str(kernel), kind="kernel-image"),
                ArtifactRef(path=str(vmlinux), kind="vmlinux"),
            ],
            details={"kernel_release": "6.9.0-test", "kernel_image_path": str(kernel), "vmlinux_path": str(vmlinux)},
        ),
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="booted",
            details={
                "debug_boot": True,
                "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234},
                "kernel_image_path": str(kernel),
            },
        ),
    )
    return artifact_root, manifest.run_id


def test_debug_start_session_records_manifest_debug_step(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()

    response = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert response.ok is True
    assert response.data["debug_session_id"] == "debug-1"
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest(run_id)
    assert manifest.step_results["debug"].status == StepStatus.SUCCEEDED
    assert manifest.step_results["debug"].details["debug_session_id"] == "debug-1"


def test_debug_start_session_is_idempotent_for_active_session(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()

    first = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )
    second = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    assert first.ok is True
    assert second.ok is True
    assert provider.calls == 1
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py -q
```

Expected: FAIL because identity validation and `debug_start_session_handler()` are incomplete.

- [ ] **Step 4: Implement identity validation**

In `QemuGdbstubProvider.start_session()`, build this validation result:

```python
identity = {
    "same_run_artifact_linkage": build_metadata.get("kernel_image_path") == boot_metadata.get("kernel_image_path")
    and str(vmlinux_path) == str(build_metadata.get("vmlinux_path")),
    "live_banner_match": None,
    "build_kernel_release": build_metadata.get("kernel_release"),
}
```

After the attach batch, parse `linux_banner` output with a bounded substring check against `build_metadata["kernel_release"]`. If strict mode is enabled and `same_run_artifact_linkage` is false, raise `ProviderDebugError("strict symbol identity requires same-run artifact linkage", category=ErrorCategory.CONFIGURATION_ERROR)`. If the live banner read fails or mismatches, raise `ProviderDebugError("strict symbol identity live target check failed", category=ErrorCategory.DEBUG_ATTACH_FAILURE)`.

- [ ] **Step 5: Implement `debug_start_session_handler()`**

In `src/linux_debug_mcp/server.py`, add `DEFAULT_DEBUG_PROFILES` near existing defaults:

```python
DEFAULT_DEBUG_PROFILES = {
    "qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default"),
}
```

Add helpers:

```python
def _find_artifact(result: StepResult, kind: str) -> ArtifactRef | None:
    for artifact in result.artifacts:
        if artifact.kind == kind:
            return artifact
    return None


def _active_debug_session_from_result(result: StepResult) -> dict[str, Any] | None:
    if result.status != StepStatus.SUCCEEDED:
        return None
    if result.details.get("current_execution_state") == "ended":
        return None
    return result.details
```

Implement `debug_start_session_handler()` with this behavior:
- load manifest and require existing run;
- require succeeded `build` and `boot`;
- require `boot.details["debug_boot"] is True`;
- require a `vmlinux` artifact from build;
- resolve `debug_profile` from explicit argument, manifest request, or `"qemu-gdbstub-default"`;
- reject mismatched explicit profile when manifest has an immutable `debug_profile`;
- use `store.debug_lock(run_id)`;
- return recorded active session if present and `new_session` is false;
- call `provider.start_session(run_id=run_id, run_dir=store.run_dir(run_id), vmlinux_path=Path(vmlinux.path), gdbstub_endpoint=boot_result.details["gdbstub_endpoint"], debug_profile=resolved_debug_profile, build_metadata=build_result.details, boot_metadata=boot_result.details)`;
- record `StepResult(step_name="debug", status=result.status, summary=result.summary, artifacts=result.artifacts, details={"debug_session_id": result.session.session_id, "session_path": str(store.run_dir(run_id) / "debug" / "sessions" / f"{result.session.session_id}.json"), "current_execution_state": result.session.current_execution_state, "gdbstub_endpoint": result.session.gdbstub_endpoint, "transcript_path": result.session.transcript_path, "command_metadata_path": result.session.command_metadata_path, "latest_summary_path": result.session.latest_summary_path, "symbol_identity_validation": result.session.symbol_identity_validation})`;
- return redacted success or failure response.

- [ ] **Step 6: Run tests and verify pass**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/qemu_gdbstub.py src/linux_debug_mcp/server.py tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py
git commit -m "feat: start qemu gdbstub debug sessions"
```

## Task 5: Implement Read-Only Debug Operations

**Files:**
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `tests/test_qemu_gdbstub_provider.py`
- Modify: `tests/test_debug_handlers.py`

- [ ] **Step 1: Write failing provider tests**

Append to `tests/test_qemu_gdbstub_provider.py`:

```python
def test_read_registers_parses_fake_gdb_output(tmp_path: Path) -> None:
    runner = FakeGdbRunner()
    runner.run_batch = lambda argv, commands, timeout, transcript_path: GdbCommandResult(
        exit_status=0,
        stdout="rax            0x1\nrip            0xffffffff81000000\n",
        stderr="",
    )
    provider = QemuGdbstubProvider(runner=runner)
    session = provider.write_session_for_test(tmp_path, state="stopped")

    result = provider.read_registers(run_dir=tmp_path, session=session, registers=["rax", "rip"])

    assert result.details["registers"] == {"rax": "0x1", "rip": "0xffffffff81000000"}


def test_read_memory_enforces_4096_byte_limit(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())
    session = provider.write_session_for_test(tmp_path, state="stopped")

    with pytest.raises(ProviderDebugError):
        provider.read_memory(run_dir=tmp_path, session=session, address=0x1000, byte_count=4097)


def test_evaluate_rejects_unknown_inspector(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())
    session = provider.write_session_for_test(tmp_path, state="stopped")

    with pytest.raises(ProviderDebugError) as exc_info:
        provider.evaluate(run_dir=tmp_path, session=session, inspector="raw", arguments={})

    assert exc_info.value.category == ErrorCategory.CONFIGURATION_ERROR
```

`write_session_for_test()` is a test helper method on `QemuGdbstubProvider` that should create a valid `DebugSession` pointing at files under `tmp_path / "debug"`.

- [ ] **Step 2: Write failing handler tests**

Append to `tests/test_debug_handlers.py`:

```python
def test_debug_read_memory_requires_active_session(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)

    response = debug_read_memory_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        address=0x1000,
        byte_count=16,
        provider=FakeDebugProvider(),
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
```

Update the imports at the top of `tests/test_debug_handlers.py` when adding this test:

```python
from linux_debug_mcp.server import debug_read_memory_handler, debug_start_session_handler
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py -q
```

Expected: FAIL because read-only provider methods and handlers do not exist.

- [ ] **Step 4: Implement provider read operations**

Implement `DebugProviderResult`-returning methods:
- `read_registers(run_dir, session, registers)`;
- `read_symbol(run_dir, session, symbol)`;
- `read_memory(run_dir, session, address, byte_count)`;
- `evaluate(run_dir, session, inspector, arguments)`.

Use provider-owned command templates:

```python
commands = ["set pagination off", "set confirm off", f"file {session.vmlinux_path}", f"target remote {host}:{port}", "info registers rax rip"]
```

For memory reads, use:

```python
f"x/{byte_count}xb 0x{address:x}"
```

For predefined inspectors:
- `kernel_version`: run `p linux_banner` and return a bounded string;
- `symbol_address`: validate `arguments["symbol"]` and run `p &symbol`.

Every method must append command metadata to `commands.jsonl`, append transcript text to the current transcript, redact snippets, and return structured `details` with no raw unbounded output.

- [ ] **Step 5: Implement read-only handlers**

In `server.py`, implement:
- `_load_active_debug_session(store, run_id, debug_session_id)`;
- `debug_read_registers_handler()`;
- `debug_read_symbol_handler()`;
- `debug_read_memory_handler()`;
- `debug_evaluate_handler()`.

Each handler should:
- load the active session from the session file referenced in manifest debug details;
- use `store.debug_lock(run_id)`;
- call the provider method;
- return redacted `ToolResponse.success`;
- map `ProviderDebugError` categories directly to `ToolResponse.failure`.

- [ ] **Step 6: Run tests and verify pass**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/qemu_gdbstub.py src/linux_debug_mcp/server.py tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py
git commit -m "feat: add read-only debug operations"
```

## Task 6: Implement Stateful Debug Operations And Session Finalization

**Files:**
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `tests/test_qemu_gdbstub_provider.py`
- Modify: `tests/test_debug_handlers.py`

- [ ] **Step 1: Write failing provider lifecycle tests**

Append to `tests/test_qemu_gdbstub_provider.py`:

```python
def test_breakpoint_operations_require_attached_controller(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())
    session = provider.write_session_for_test(tmp_path, state="stopped", controller_mode="batch")

    with pytest.raises(ProviderDebugError, match="attached controller"):
        provider.set_breakpoint(run_dir=tmp_path, session=session, symbol="start_kernel")


def test_end_session_is_idempotent_when_controller_already_exited(tmp_path: Path) -> None:
    provider = QemuGdbstubProvider(runner=FakeGdbRunner())
    session = provider.write_session_for_test(tmp_path, state="stopped", controller_mode="attached", pid=999999)

    first = provider.end_session(run_dir=tmp_path, session=session)
    second = provider.end_session(run_dir=tmp_path, session=first.session)

    assert first.session.current_execution_state == "ended"
    assert second.session.current_execution_state == "ended"
```

- [ ] **Step 2: Write failing handler lifecycle tests**

Append to `tests/test_debug_handlers.py`:

```python
def test_debug_end_session_finalizes_manifest_state(tmp_path: Path) -> None:
    artifact_root, run_id = create_debug_ready_run(tmp_path)
    provider = FakeDebugProvider()
    start = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        provider=provider,
        debug_profiles={"qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default")},
    )

    response = debug_end_session_handler(
        artifact_root=artifact_root,
        run_id=run_id,
        debug_session_id=start.data["debug_session_id"],
        provider=provider,
    )

    assert response.ok is True
    assert response.data["current_execution_state"] == "ended"
```

Update the imports at the top of `tests/test_debug_handlers.py` when adding this test:

```python
from linux_debug_mcp.server import debug_end_session_handler, debug_read_memory_handler, debug_start_session_handler
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py -q
```

Expected: FAIL because stateful provider methods and handlers do not exist.

- [ ] **Step 4: Implement attached-controller contract**

In `QemuGdbstubProvider`, implement:
- `ensure_attached_controller(session)`;
- `set_breakpoint(run_dir, session, symbol)`;
- `clear_breakpoint(run_dir, session, breakpoint_id)`;
- `list_breakpoints(run_dir, session)`;
- `continue_execution(run_dir, session, timeout_seconds)`;
- `interrupt(run_dir, session, timeout_seconds)`;
- `end_session(run_dir, session)`.

Phase 4 may fail stateful operations with `configuration_error` unless the session is already `controller_mode="attached"`. When an attached controller is present, update session JSON and summary JSON for:
- breakpoint IDs and symbol metadata;
- `current_execution_state="running"` after continue;
- `current_execution_state="stopped"` after interrupt;
- `current_execution_state="ended"` and `ended_at` after end.

`end_session()` must terminate only `session.active_controller_pid` when present and alive. If the process is already gone, record `controller_last_observed_state="exited"` and still finalize.

- [ ] **Step 5: Implement stateful handlers**

In `server.py`, implement:
- `debug_set_breakpoint_handler()`;
- `debug_clear_breakpoint_handler()`;
- `debug_list_breakpoints_handler()`;
- `debug_continue_handler()`;
- `debug_interrupt_handler()`;
- `debug_end_session_handler()`.

Each handler uses `store.debug_lock(run_id)`, loads the active or requested session, calls the provider method, records updated manifest debug details, and returns redacted responses.

- [ ] **Step 6: Run tests and verify pass**

Run:

```bash
pytest tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/providers/qemu_gdbstub.py src/linux_debug_mcp/server.py tests/test_qemu_gdbstub_provider.py tests/test_debug_handlers.py
git commit -m "feat: add stateful debug session operations"
```

## Task 7: Add Build-Boot-Debug Workflow

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_workflow_build_boot_debug_handler.py`

- [ ] **Step 1: Write failing workflow tests**

Create `tests/test_workflow_build_boot_debug_handler.py`:

```python
from pathlib import Path

from linux_debug_mcp.domain import ErrorCategory, ToolResponse
from linux_debug_mcp.server import workflow_build_boot_debug_handler


def test_workflow_build_boot_debug_success(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_create(**kwargs):
        calls.append("create")
        return ToolResponse.success(summary="created", run_id="run-debug")

    def fake_build(**kwargs):
        calls.append("build")
        return ToolResponse.success(summary="built", run_id="run-debug")

    def fake_boot(**kwargs):
        calls.append("boot")
        return ToolResponse.success(summary="booted", run_id="run-debug", data={"debug_boot": True})

    def fake_debug(**kwargs):
        calls.append("debug")
        return ToolResponse.success(
            summary="debug session started",
            run_id="run-debug",
            data={"debug_session_id": "debug-1", "gdbstub_endpoint": {"host": "127.0.0.1", "port": 1234}},
        )

    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", fake_create)
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", fake_build)
    monkeypatch.setattr("linux_debug_mcp.server.target_boot_handler", fake_boot)
    monkeypatch.setattr("linux_debug_mcp.server.debug_start_session_handler", fake_debug)

    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path,
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is True
    assert calls == ["create", "build", "boot", "debug"]
    assert response.data["latest_successful_step"] == "debug"


def test_workflow_build_boot_debug_stops_before_debug_when_boot_fails(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    monkeypatch.setattr("linux_debug_mcp.server.create_run_handler", lambda **kwargs: ToolResponse.success(summary="created", run_id="run-debug"))
    monkeypatch.setattr("linux_debug_mcp.server.kernel_build_handler", lambda **kwargs: ToolResponse.success(summary="built", run_id="run-debug"))

    def fake_boot(**kwargs):
        calls.append("boot")
        return ToolResponse.failure(category=ErrorCategory.BOOT_TIMEOUT, message="boot timed out", run_id="run-debug")

    monkeypatch.setattr("linux_debug_mcp.server.target_boot_handler", fake_boot)

    response = workflow_build_boot_debug_handler(
        artifact_root=tmp_path,
        source_path=str(tmp_path),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
    )

    assert response.ok is False
    assert response.error.category == ErrorCategory.BOOT_TIMEOUT
    assert response.data["failing_step"] == "boot"
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_workflow_build_boot_debug_handler.py -q
```

Expected: FAIL because `workflow_build_boot_debug_handler()` does not exist.

- [ ] **Step 3: Implement workflow handler**

In `server.py`, implement `workflow_build_boot_debug_handler()` by mirroring `workflow_build_boot_test_handler()` with these differences:
- pass `debug_profile` into `create_run_handler()`;
- call `target_boot_handler()` with a debug-enabled target profile selected by the run request;
- call `debug_start_session_handler()` after boot;
- do not call `target_run_tests_handler()`;
- do not run smoke tests;
- return steps for `build`, `boot`, and `debug`;
- on failure, return `_workflow_failure_response()` with `collect_response=None`.

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
pytest tests/test_workflow_build_boot_debug_handler.py tests/test_workflow_build_boot_test_handler.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_workflow_build_boot_debug_handler.py
git commit -m "feat: add build boot debug workflow"
```

## Task 8: Wire MCP Tools, Provider Registry, And Artifact Collection

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `src/linux_debug_mcp/providers/qemu_gdbstub.py`
- Modify: `tests/test_server.py`
- Modify: `tests/test_providers.py`
- Modify: `tests/test_artifacts_collect_handler.py`

- [ ] **Step 1: Write failing registry and server tests**

Add to `tests/test_providers.py`:

```python
def test_registry_advertises_local_qemu_gdbstub_and_removes_phase_4_stubs() -> None:
    registry = ProviderRegistry.with_defaults()
    providers = {provider.provider_name: provider for provider in registry.list_capabilities()}

    debug_provider = providers["local-qemu-gdbstub"]
    assert "debug.start_session" in debug_provider.operations
    assert "workflow.build_boot_debug" in debug_provider.operations
    assert "stub-workflows" not in providers or "debug.start_session" not in providers["stub-workflows"].operations
```

Add to `tests/test_server.py`:

```python
def test_create_app_registers_phase_4_tools_as_real_handlers() -> None:
    app = create_app()
    tool_names = {tool.name for tool in app._tool_manager.list_tools()}

    assert "workflow.build_boot_debug" in tool_names
    assert "debug.start_session" in tool_names
    assert "debug.read_memory" in tool_names
    assert "debug.end_session" in tool_names
```

- [ ] **Step 2: Write failing artifact collection test**

Add to `tests/test_artifacts_collect_handler.py`:

```python
def test_artifacts_collect_includes_debug_artifacts(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    run_id = "run-abc123"
    store = ArtifactStore(artifact_root, create_root=False)
    debug_dir = artifact_root / run_id / "debug" / "attempt-001"
    debug_dir.mkdir(parents=True)
    transcript = debug_dir / "transcript.txt"
    commands = debug_dir / "commands.jsonl"
    summary = debug_dir / "debug-summary.json"
    session_file = artifact_root / run_id / "debug" / "sessions" / "debug-1.json"
    session_file.parent.mkdir(parents=True)
    for path in [transcript, commands, summary, session_file]:
        path.write_text("secret=redacted-by-test", encoding="utf-8")
    store.record_step_result(
        run_id,
        StepResult(
            step_name="debug",
            status=StepStatus.SUCCEEDED,
            summary="debug session started",
            artifacts=[
                ArtifactRef(path=str(session_file), kind="debug-session"),
                ArtifactRef(path=str(transcript), kind="debug-transcript", sensitive=True),
                ArtifactRef(path=str(commands), kind="debug-commands", sensitive=True),
                ArtifactRef(path=str(summary), kind="debug-summary"),
            ],
        ),
    )

    response = artifacts_collect_handler(artifact_root=artifact_root, run_id=run_id)

    assert response.ok is True
    kinds = {artifact.kind for artifact in response.artifacts}
    assert {"debug-session", "debug-transcript", "debug-commands", "debug-summary"}.issubset(kinds)
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
pytest tests/test_server.py tests/test_providers.py tests/test_artifacts_collect_handler.py -q
```

Expected: FAIL because provider capability, tool wiring, and debug artifact collection are incomplete.

- [ ] **Step 4: Implement provider capability and registry changes**

In `qemu_gdbstub.py`, add:

```python
def local_qemu_gdbstub_capability() -> ProviderCapability:
    return ProviderCapability(
        provider_name="local-qemu-gdbstub",
        provider_version="0.1.0",
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        operations=[
            "workflow.build_boot_debug",
            "debug.start_session",
            "debug.interrupt",
            "debug.continue",
            "debug.set_breakpoint",
            "debug.clear_breakpoint",
            "debug.list_breakpoints",
            "debug.read_registers",
            "debug.read_symbol",
            "debug.read_memory",
            "debug.evaluate",
            "debug.end_session",
        ],
        required_host_tools=["gdb"],
        destructive_permissions=["control MCP-owned QEMU execution through local gdbstub"],
        access_methods=["gdbstub", "filesystem", "subprocess"],
        semantics=OperationSemantics(
            idempotent=False,
            retryable=True,
            destructive=True,
            cancelable=True,
            concurrent_safe=False,
        ),
    )
```

In `registry.py`, import and register `local_qemu_gdbstub_capability()`, and remove Phase 4 operations from `stub-workflows`. If `stub-workflows` has no remaining operations, remove the stub provider registration.

- [ ] **Step 5: Wire MCP tools**

In `create_app()`, replace the Phase 4 stub loop with explicit tool functions for:
- `workflow.build_boot_debug`;
- `debug.start_session`;
- `debug.interrupt`;
- `debug.continue`;
- `debug.set_breakpoint`;
- `debug.clear_breakpoint`;
- `debug.list_breakpoints`;
- `debug.read_registers`;
- `debug.read_symbol`;
- `debug.read_memory`;
- `debug.evaluate`;
- `debug.end_session`.

Each function should call the corresponding handler and return `.model_dump(mode="json")`.

- [ ] **Step 6: Update artifact collection expected debug kinds**

In `_bundle_for_manifest()`, add:

```python
required_kinds_by_step = {
    "build": {"build-log", "kernel-config", "kernel-image"},
    "boot": {"domain-xml", "boot-plan", "console-log", "boot-log"},
    "run_tests": {"test-summary"},
    "debug": {"debug-session", "debug-transcript", "debug-commands", "debug-summary"},
}
optional_kinds_by_step = {"build": {"vmlinux"}, "boot": {"boot-summary"}}
```

Preserve the existing redaction path before writing `artifact-bundle.json`.

- [ ] **Step 7: Run tests and verify pass**

Run:

```bash
pytest tests/test_server.py tests/test_providers.py tests/test_artifacts_collect_handler.py -q
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/linux_debug_mcp/server.py src/linux_debug_mcp/providers/registry.py src/linux_debug_mcp/providers/qemu_gdbstub.py tests/test_server.py tests/test_providers.py tests/test_artifacts_collect_handler.py
git commit -m "feat: wire phase 4 debug tools"
```

## Task 9: Add Opt-In Live Coverage And Documentation

**Files:**
- Create: `tests/test_qemu_gdbstub_integration.py`
- Modify: `README.md`
- Modify: `docs/fedora-libvirt-user-guide.md`

- [ ] **Step 1: Write skipped-by-default integration test**

Create `tests/test_qemu_gdbstub_integration.py`:

```python
import os
from pathlib import Path

import pytest

from linux_debug_mcp.server import workflow_build_boot_debug_handler


pytestmark = pytest.mark.skipif(
    os.environ.get("LINUX_DEBUG_MCP_LIVE_GDBSTUB") != "1",
    reason="set LINUX_DEBUG_MCP_LIVE_GDBSTUB=1 to run live libvirt/gdbstub integration coverage",
)


def test_live_build_boot_debug_workflow() -> None:
    source_path = os.environ["LINUX_DEBUG_MCP_KERNEL_SOURCE"]
    rootfs_profile = os.environ.get("LINUX_DEBUG_MCP_ROOTFS_PROFILE", "minimal")
    artifact_root = Path(os.environ.get("LINUX_DEBUG_MCP_ARTIFACT_ROOT", ".linux-debug-mcp/runs"))

    response = workflow_build_boot_debug_handler(
        artifact_root=artifact_root,
        source_path=source_path,
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile=rootfs_profile,
        debug_profile="qemu-gdbstub-default",
    )

    assert response.ok is True
    assert response.data["steps"]["debug"]["ok"] is True
```

- [ ] **Step 2: Document local debug workflow**

In `README.md`, add a concise Phase 4 section with:
- host prerequisites: `virsh`, QEMU/libvirt, and `gdb`;
- rootfs readiness still comes from Phase 2;
- `workflow.build_boot_debug` runs create, build, debug-enabled boot, readiness wait, and debug attach;
- `target.run_tests` is not part of this workflow;
- `debug.read_memory` is capped at 4096 bytes;
- raw transcripts are artifact-only and response snippets are redacted.

In `docs/fedora-libvirt-user-guide.md`, add a matching operator note describing local-only `127.0.0.1:1234` gdbstub exposure and the fixed-port collision behavior.

- [ ] **Step 3: Run docs and integration collection tests**

Run:

```bash
pytest tests/test_qemu_gdbstub_integration.py -q
```

Expected without `LINUX_DEBUG_MCP_LIVE_GDBSTUB=1`: SKIPPED.

- [ ] **Step 4: Commit**

```bash
git add tests/test_qemu_gdbstub_integration.py README.md docs/fedora-libvirt-user-guide.md
git commit -m "docs: describe phase 4 live debug workflow"
```

## Task 10: Final Verification

**Files:**
- No new files beyond previous tasks.

- [ ] **Step 1: Run full unit suite**

Run:

```bash
pytest -q
```

Expected: PASS, with the live gdbstub integration test skipped unless `LINUX_DEBUG_MCP_LIVE_GDBSTUB=1`.

- [ ] **Step 2: Run formatting and hook checks**

Run:

```bash
pre-commit run --all-files
```

Expected: PASS.

- [ ] **Step 3: Inspect provider capabilities manually**

Run:

```bash
python - <<'PY'
from linux_debug_mcp.providers.registry import ProviderRegistry

providers = {provider.provider_name: provider for provider in ProviderRegistry.with_defaults().list_capabilities()}
print(providers["local-qemu-gdbstub"].operations)
print(providers.get("stub-workflows"))
PY
```

Expected: output includes `debug.start_session`, `debug.end_session`, and `workflow.build_boot_debug` under `local-qemu-gdbstub`; `stub-workflows` is either absent or contains no Phase 4 operations.

- [ ] **Step 4: Review final diff**

Run:

```bash
git diff --stat main..HEAD
git diff --check main..HEAD
```

Expected: `git diff --check` exits 0.

- [ ] **Step 5: Commit verification fixes if needed**

If any verification command fails, fix the failing behavior with the smallest scoped change, rerun the failing command, rerun `pytest -q`, and commit with a message that names the verified fix.
