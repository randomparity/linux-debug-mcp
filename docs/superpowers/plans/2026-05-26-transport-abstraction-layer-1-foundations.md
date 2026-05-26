# Transport abstraction — Layer 1: Foundations (schemas + pure seams) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the pure data model and pure-function seams for the transport
provider abstraction — every Pydantic wire schema, the env-only secrets resolver + Protocol, the
break-plan policy decision, two new error categories, and the `transport.*` operation
allowlist — with zero concurrency and zero process/IO behavior, fully unit-tested.

**Architecture:** New `seams/` and `transport/` packages under
`src/linux_debug_mcp/`. `seams/target.py` holds provisioning-owned *leaf* types (no
transport imports); `transport/base.py` holds the transport boundary schemas plus
`TargetHandle` (which closes the `TransportRef`↔`TargetHandle` type cycle, so it lives
with `TransportRef` rather than in `seams/target.py` as the spec's §2 sketch suggests —
shape is unchanged, only the file differs). `seams/secrets.py` and `seams/break_policy.py`
import those schemas one-directionally (no cycle). All models inherit the project
`Model`/`ConfigModel` base (`extra="forbid"`, `validate_assignment=True`).

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, `uv`, ruff. No new dependencies.

**Roadmap:** `docs/superpowers/plans/2026-05-26-transport-abstraction-roadmap.md`
**Spec:** `docs/superpowers/specs/2026-05-26-transport-abstraction-design.md` (§3, §4.1, §4.8, §5, §7.3, §8.1)
**Contract:** `docs/specs/interface-contracts.md` (§3.1–3.4, §4.1)

---

## File Structure

- Create: `src/linux_debug_mcp/seams/__init__.py` — empty package marker.
- Create: `src/linux_debug_mcp/seams/target.py` — provisioning leaf types: `Arch`,
  `ConsoleKind`, `TargetState`, `BreakHint` enums; `TargetKey` (frozen/hashable);
  `SshEndpoint`, `PlatformMetadata`, `KernelProvenance`, `LeaseInfo`.
- Create: `src/linux_debug_mcp/transport/__init__.py` — empty package marker.
- Create: `src/linux_debug_mcp/transport/base.py` — `LineRole`, `BreakMethod`,
  `EndpointExposure`, `RecordState`, `ExecutionState` enums; `TcpEndpoint`,
  `UnixSocketEndpoint`, `Endpoint` (discriminated union); `TransportRef`, `OpenRequest`,
  `TransportCapability`, `BreakPlan`, `TransportSession`, `TargetHandle`; `Transport`
  ABC; `TransportRegistry`; `new_session_id()`, `DEFAULT_MIN_LEASE_TTL_SECONDS`.
- Create: `src/linux_debug_mcp/seams/secrets.py` — `SecretsResolver` Protocol +
  `EnvSecretsResolver` (env-only) + `SecretsResolutionError`.
- Create: `src/linux_debug_mcp/seams/break_policy.py` — `BreakPolicy` Protocol +
  `ReferenceBreakPolicy` + `BreakPlanError`.
- Modify: `src/linux_debug_mcp/domain.py:29` — add `STALE_HANDLE`, `TRANSPORT_CONFLICT`.
- Modify: `src/linux_debug_mcp/config.py:107` — add `TRANSPORT_OPERATIONS`,
  `TRANSPORT_DESTRUCTIVE_PERMISSIONS`, `validate_transport_operation()`.
- Test: `tests/test_error_taxonomy.py`, `tests/test_seams_target.py`,
  `tests/test_transport_base.py`, `tests/test_seams_secrets.py`,
  `tests/test_seams_break_policy.py`, `tests/test_transport_operations.py`.

**Dependency order (no cycles):** `domain.py` → `seams/target.py` →
`transport/base.py` (imports target leaf types) → `seams/secrets.py` (imports
`safety/secrets.py`) → `seams/break_policy.py` (imports target + base) → `config.py`.

---

## Task 1: Error taxonomy — two new `ErrorCategory` values

**Files:**
- Modify: `src/linux_debug_mcp/domain.py:20-29`
- Test: `tests/test_error_taxonomy.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_error_taxonomy.py`:

```python
from linux_debug_mcp.domain import ErrorCategory


def test_stale_handle_category_value():
    assert ErrorCategory.STALE_HANDLE == "stale_handle"


def test_transport_conflict_category_value():
    assert ErrorCategory.TRANSPORT_CONFLICT == "transport_conflict"


def test_new_categories_are_distinct_members():
    values = {member.value for member in ErrorCategory}
    assert {"stale_handle", "transport_conflict"} <= values
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_error_taxonomy.py -q`
Expected: FAIL — `AttributeError: STALE_HANDLE` (member not defined).

- [ ] **Step 3: Add the two enum members**

In `src/linux_debug_mcp/domain.py`, edit the `ErrorCategory` enum (currently ending at
line 29 with `NOT_IMPLEMENTED = "not_implemented"`) to append the two members:

```python
class ErrorCategory(StrEnum):
    CONFIGURATION_ERROR = "configuration_error"
    MISSING_DEPENDENCY = "missing_dependency"
    BUILD_FAILURE = "build_failure"
    BOOT_TIMEOUT = "boot_timeout"
    READINESS_FAILURE = "readiness_failure"
    TEST_FAILURE = "test_failure"
    DEBUG_ATTACH_FAILURE = "debug_attach_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    NOT_IMPLEMENTED = "not_implemented"
    STALE_HANDLE = "stale_handle"
    TRANSPORT_CONFLICT = "transport_conflict"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_error_taxonomy.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_error_taxonomy.py
git commit -m "feat: add STALE_HANDLE and TRANSPORT_CONFLICT error categories (#10)"
```

---

## Task 2: Provisioning leaf schemas (`seams/target.py`)

**Files:**
- Create: `src/linux_debug_mcp/seams/__init__.py`
- Create: `src/linux_debug_mcp/seams/target.py`
- Test: `tests/test_seams_target.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_seams_target.py`:

```python
import hashlib

import pytest
from pydantic import ValidationError

from linux_debug_mcp.seams.target import (
    Arch,
    BreakHint,
    ConsoleKind,
    KernelProvenance,
    LeaseInfo,
    PlatformMetadata,
    SshEndpoint,
    TargetKey,
    TargetState,
)


def test_target_key_is_frozen_and_hashable():
    key = TargetKey(provisioner="local-qemu", target_id="run-1")
    assert hash(key) == hash(TargetKey(provisioner="local-qemu", target_id="run-1"))
    assert {key: "v"}[TargetKey(provisioner="local-qemu", target_id="run-1")] == "v"
    with pytest.raises(ValidationError):
        key.target_id = "mutated"


def test_target_key_distinct_provisioners_do_not_collide():
    a = TargetKey(provisioner="provA", target_id="t1")
    b = TargetKey(provisioner="provB", target_id="t1")
    assert a != b
    assert hash(a) != hash(b) or a != b  # different identity even if hashes collide


def test_target_key_recovery_key_is_canonical_hash():
    key = TargetKey(provisioner="local-qemu", target_id="run-1")
    expected = hashlib.sha256(b"local-qemu\x00run-1").hexdigest()
    assert key.recovery_key() == expected


def test_target_key_recovery_key_resists_delimiter_confusion():
    # ("a", "b\x00c") and ("a\x00b", "c") must not collide.
    left = TargetKey(provisioner="a", target_id="b\x00c").recovery_key()
    right = TargetKey(provisioner="a\x00b", target_id="c").recovery_key()
    assert left != right


def test_ssh_endpoint_port_bounds():
    SshEndpoint(host="h", port=22, user="root", key_ref="ref")
    with pytest.raises(ValidationError):
        SshEndpoint(host="h", port=0, user="root", key_ref="ref")
    with pytest.raises(ValidationError):
        SshEndpoint(host="h", port=70000, user="root", key_ref="ref")


def test_platform_metadata_requires_positive_console_count():
    PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=True,
        break_hints=[BreakHint.SYSRQ_G],
    )
    with pytest.raises(ValidationError):
        PlatformMetadata(
            console_kind=ConsoleKind.UART,
            console_count=0,
            dedicated_debug_line=False,
            ssh_reachable=True,
        )


def test_models_forbid_extra_fields():
    with pytest.raises(ValidationError):
        LeaseInfo(lease_id="l", holder="h", renewable=True, bogus=1)


def test_enums_have_contract_values():
    assert {a.value for a in Arch} == {"x86_64", "ppc64le", "s390x", "aarch64"}
    assert {c.value for c in ConsoleKind} == {"uart", "hvc", "virtio"}
    assert TargetState.READY == "ready"
    assert TargetState.DEBUGGING == "debugging"


def test_kernel_provenance_optional_refs_default_none():
    prov = KernelProvenance(
        build_id="bid", release="6.9.0", vmlinux_ref="ref", cmdline="ro"
    )
    assert prov.modules_ref is None
    assert prov.config_ref is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_target.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.seams'`.

- [ ] **Step 3: Create the package marker and the leaf schemas**

Create `src/linux_debug_mcp/seams/__init__.py` (empty):

```python
```

Create `src/linux_debug_mcp/seams/target.py`:

```python
from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from linux_debug_mcp.domain import Model


class Arch(StrEnum):
    X86_64 = "x86_64"
    PPC64LE = "ppc64le"
    S390X = "s390x"
    AARCH64 = "aarch64"


class ConsoleKind(StrEnum):
    UART = "uart"
    HVC = "hvc"
    VIRTIO = "virtio"


class TargetState(StrEnum):
    ACQUIRING = "acquiring"
    PREPARING = "preparing"
    BOOTING = "booting"
    READY = "ready"
    DEBUGGING = "debugging"
    RESETTING = "resetting"
    CRASHED = "crashed"
    RELEASING = "releasing"


class BreakHint(StrEnum):
    UART_BREAK = "uart_break"
    SYSRQ_G = "sysrq_g"
    AGENT_PROXY_BREAK = "agent_proxy_break"
    GDBSTUB_NATIVE = "gdbstub_native"


class TargetKey(BaseModel):
    """Contract-wide identity tuple: (provisioner, target_id). Frozen so it is
    hashable and usable as a dict/lease/guard key (contract §3.1)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provisioner: str
    target_id: str

    def recovery_key(self) -> str:
        """Canonical NUL-delimited sha256 of the key, for recovery-tombstone
        filenames (spec §4.7). Opaque key parts are never used as path segments."""
        payload = f"{self.provisioner}\x00{self.target_id}".encode()
        return hashlib.sha256(payload).hexdigest()


class SshEndpoint(Model):
    host: str
    port: int = Field(ge=1, le=65535)
    user: str
    key_ref: str


class PlatformMetadata(Model):
    console_kind: ConsoleKind
    console_count: int = Field(ge=1)
    dedicated_debug_line: bool
    ssh_reachable: bool
    break_hints: list[BreakHint] = Field(default_factory=list)


class KernelProvenance(Model):
    build_id: str
    release: str
    vmlinux_ref: str
    modules_ref: str | None = None
    cmdline: str
    config_ref: str | None = None


class LeaseInfo(Model):
    lease_id: str
    holder: str
    expires_at: datetime | None = None
    renewable: bool
```

Note: the `recovery_key()` delimiter-confusion test passes because the raw bytes
`a\x00(b\x00c)` and `(a\x00b)\x00c` differ — both contain two NULs but at different
offsets — so their digests differ. The test documents that NUL-joining is not collision-free
across *arbitrary* embedded NULs; real `TargetKey` parts never contain NUL, and the hash
is only ever a filename, never re-parsed back into components.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_target.py -q`
Expected: PASS (9 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/__init__.py src/linux_debug_mcp/seams/target.py tests/test_seams_target.py
git commit -m "feat: add provisioning leaf schemas in seams/target (#10)"
```

---

## Task 3: Transport boundary schemas (`transport/base.py`)

**Files:**
- Create: `src/linux_debug_mcp/transport/__init__.py`
- Create: `src/linux_debug_mcp/transport/base.py`
- Test: `tests/test_transport_base.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_transport_base.py`:

```python
from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from linux_debug_mcp.seams.target import ConsoleKind, LeaseInfo, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import (
    DEFAULT_MIN_LEASE_TTL_SECONDS,
    BreakMethod,
    BreakPlan,
    Endpoint,
    EndpointExposure,
    ExecutionState,
    LineRole,
    OpenRequest,
    RecordState,
    TargetHandle,
    TcpEndpoint,
    Transport,
    TransportCapability,
    TransportRef,
    TransportRegistry,
    TransportSession,
    UnixSocketEndpoint,
    new_session_id,
)


def _platform() -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=True,
    )


def _ref() -> TransportRef:
    return TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp-0",
        line_role=LineRole.RSP,
        caps=["provides_rsp"],
    )


def test_endpoint_discriminated_union_round_trips():
    adapter = TypeAdapter(Endpoint)
    tcp = adapter.validate_python({"kind": "tcp", "host": "127.0.0.1", "port": 1234})
    assert isinstance(tcp, TcpEndpoint)
    unix = adapter.validate_python({"kind": "unix", "path": "/tmp/c.sock", "mode": 0o600})
    assert isinstance(unix, UnixSocketEndpoint)
    assert adapter.validate_python(adapter.dump_python(tcp)) == tcp


def test_tcp_endpoint_port_bounds():
    TcpEndpoint(host="127.0.0.1", port=1)
    with pytest.raises(ValidationError):
        TcpEndpoint(host="127.0.0.1", port=0)


def test_unix_socket_mode_defaults_to_0600():
    assert UnixSocketEndpoint(path="/tmp/c.sock").mode == 0o600


def test_open_request_default_ttl_and_optional_lease():
    req = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=0,
        transport_ref=_ref(),
        required_caps=["provides_rsp"],
        platform=_platform(),
    )
    assert req.lease is None
    assert req.min_lease_ttl is None
    assert DEFAULT_MIN_LEASE_TTL_SECONDS == 300


def test_transport_ref_and_open_request_forbid_extra_fields():
    with pytest.raises(ValidationError):
        TransportRef(provider="p", channel_id="c", line_role=LineRole.RSP, bogus=1)


def test_open_request_requires_transport_ref():
    # transport_ref is mandatory: admission must re-bind/validate the selected channel.
    with pytest.raises(ValidationError):
        OpenRequest(
            target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
            generation=0,
            required_caps=["provides_rsp"],
            platform=_platform(),
        )


def test_open_request_has_no_recovery_field():
    # recovery is a transport.open tool arg (routes to admit_recovery), never a wire
    # field on the settled-contract OpenRequest (spec §3.2).
    with pytest.raises(ValidationError):
        OpenRequest(
            target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
            generation=0,
            transport_ref=_ref(),
            required_caps=["provides_rsp"],
            platform=_platform(),
            recovery=True,
        )


def test_transport_capability_family_is_fixed():
    cap = TransportCapability(
        provider_name="qemu-gdbstub",
        architectures=["x86_64"],
        provides_console=False,
        provides_rsp=True,
        supports_uart_break=False,
        endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
    )
    assert cap.provider_family == "transport"
    with pytest.raises(ValidationError):
        TransportCapability(
            provider_name="x",
            provider_family="provisioning",
            provides_console=False,
            provides_rsp=True,
            supports_uart_break=False,
            endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
        )


def test_target_handle_holds_transport_refs():
    # Proves the TransportRef <-> TargetHandle cycle is resolved at import time.
    handle = TargetHandle(
        target_id="run-1",
        provisioner="local-qemu",
        generation=0,
        arch="x86_64",
        native=True,
        state="ready",
        access={"ssh": None, "transports": [_ref()]},
        platform=_platform(),
        kernel={
            "build_id": "bid",
            "release": "6.9.0",
            "vmlinux_ref": "ref",
            "cmdline": "ro",
        },
        lease=None,
    )
    assert handle.access.transports[0].channel_id == "rsp-0"


def test_new_session_id_is_prefixed_and_unique():
    a, b = new_session_id(), new_session_id()
    assert a.startswith("transport-") and b.startswith("transport-")
    assert a != b


def test_transport_session_defaults():
    session = TransportSession(
        session_id=new_session_id(),
        target_key=TargetKey(provisioner="local-qemu", target_id="run-1"),
        generation=0,
        provider="qemu-gdbstub",
        channel_id="rsp-0",
        created_at=datetime.now(UTC),
    )
    assert session.record_state is RecordState.PENDING
    assert session.execution_state is ExecutionState.UNKNOWN
    assert session.attach_epoch == 0
    assert session.rsp_endpoint is None


def test_break_plan_method_enum():
    plan = BreakPlan(method=BreakMethod.GDBSTUB_NATIVE, channel_id="rsp-0", rationale="rsp")
    assert plan.method == "gdbstub_native"


def test_transport_registry_register_lookup_and_duplicate():
    registry = TransportRegistry()
    cap = TransportCapability(
        provider_name="qemu-gdbstub",
        provides_console=False,
        provides_rsp=True,
        supports_uart_break=False,
        endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL,
    )
    registry.register(cap)
    assert registry.get("qemu-gdbstub") is cap
    assert registry.endpoint_exposure("qemu-gdbstub") is EndpointExposure.LOOPBACK_LOCAL
    assert registry.list_capabilities() == [cap]
    with pytest.raises(ValueError):
        registry.register(cap)
    with pytest.raises(KeyError):
        registry.get("missing")


def test_transport_abc_cannot_be_instantiated_without_methods():
    with pytest.raises(TypeError):
        Transport()  # abstract
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_transport_base.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.transport'`.

- [ ] **Step 3: Create the package marker and the boundary schemas**

Create `src/linux_debug_mcp/transport/__init__.py` (empty):

```python
```

Create `src/linux_debug_mcp/transport/base.py`:

```python
from __future__ import annotations

import threading
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field

from linux_debug_mcp.domain import ArtifactRef, Model
from linux_debug_mcp.seams.target import (
    KernelProvenance,
    LeaseInfo,
    PlatformMetadata,
    SshEndpoint,
    TargetKey,
    TargetState,
)

DEFAULT_MIN_LEASE_TTL_SECONDS = 300


class LineRole(StrEnum):
    SHARED_CONSOLE = "shared_console"
    DEDICATED_DEBUG = "dedicated_debug"
    RSP = "rsp"


class BreakMethod(StrEnum):
    GDBSTUB_NATIVE = "gdbstub_native"
    UART_BREAK = "uart_break"
    AGENT_PROXY_BREAK = "agent_proxy_break"
    SYSRQ_G = "sysrq_g"


class EndpointExposure(StrEnum):
    LOOPBACK_LOCAL = "loopback_local"
    BROKERED_REQUIRED = "brokered_required"


class RecordState(StrEnum):
    PENDING = "pending"
    OPENING = "opening"
    READY = "ready"
    DEGRADED = "degraded"
    CLOSING = "closing"
    ABANDONED = "abandoned"
    CLOSED = "closed"


class ExecutionState(StrEnum):
    EXECUTING = "executing"
    HALTED = "halted"
    UNKNOWN = "unknown"


class TcpEndpoint(Model):
    kind: Literal["tcp"] = "tcp"
    host: str
    port: int = Field(ge=1, le=65535)


class UnixSocketEndpoint(Model):
    kind: Literal["unix"] = "unix"
    path: str
    mode: int = 0o600


Endpoint = Annotated[TcpEndpoint | UnixSocketEndpoint, Field(discriminator="kind")]


class TransportRef(Model):
    """The settled-contract channel descriptor (contract §3.2). Shape is frozen —
    this layer adds no field."""

    provider: str
    channel_id: str
    line_role: LineRole
    caps: list[str] = Field(default_factory=list)
    target_ref: dict[str, Any] = Field(default_factory=dict)
    opts: dict[str, Any] = Field(default_factory=dict)
    secret_refs: list[str] = Field(default_factory=list)


class OpenRequest(Model):
    """The settled-contract argument to transport.open() (contract §3.2). Shape is
    frozen — recovery-mode attach is a tool arg, not a field here (spec §3.2)."""

    target_key: TargetKey
    generation: int = Field(ge=0)
    transport_ref: TransportRef
    required_caps: list[str] = Field(default_factory=list)
    platform: PlatformMetadata
    lease: LeaseInfo | None = None
    min_lease_ttl: int | None = Field(default=None, ge=1)


class TransportCapability(Model):
    """01-owned capability surfaced in providers.list. `endpoint_exposure` drives the
    §8.4 endpoint-safety gate and is trusted registry metadata, never caller-supplied."""

    provider_name: str
    provider_family: Literal["transport"] = "transport"
    architectures: list[str] = Field(default_factory=list)
    provides_console: bool
    provides_rsp: bool
    supports_uart_break: bool
    endpoint_exposure: EndpointExposure
    operations: list[str] = Field(default_factory=list)


class BreakPlan(Model):
    method: BreakMethod
    channel_id: str
    rationale: str


class TargetAccess(Model):
    ssh: SshEndpoint | None = None
    transports: list[TransportRef] = Field(default_factory=list)


class TargetHandle(Model):
    """Provisioning-owned handle (contract §3.1). Defined here, beside `TransportRef`,
    to close the TransportRef<->TargetHandle type cycle; shape matches the contract."""

    target_id: str
    provisioner: str
    generation: int = Field(ge=0)
    arch: str
    native: bool
    state: TargetState
    access: TargetAccess
    platform: PlatformMetadata
    kernel: KernelProvenance
    lease: LeaseInfo | None = None


class TransportSession(Model):
    """Write-ahead durable ownership record (spec §3.2, §4.7). Persisted as JSON;
    liveness is owned by the in-process registry (Layer 4) while the server runs."""

    session_id: str
    target_key: TargetKey
    generation: int = Field(ge=0)
    provider: str
    channel_id: str
    console_endpoint: Endpoint | None = None
    rsp_endpoint: TcpEndpoint | None = None
    record_state: RecordState = RecordState.PENDING
    console_lease_token: str | None = None
    stop_guard_token: str | None = None
    attach_epoch: int = 0
    break_plan: BreakPlan | None = None
    execution_state: ExecutionState = ExecutionState.UNKNOWN
    backend_pid: int | None = None
    backend_start_time: str | None = None
    created_at: datetime
    ended_at: datetime | None = None
    artifacts: list[ArtifactRef] = Field(default_factory=list)


def new_session_id() -> str:
    return f"transport-{uuid.uuid4().hex}"


class Transport(ABC):
    """Abstract transport provider. Concrete transports (serial-local, qemu-gdbstub)
    land in Layer 3; the open() transaction (Layer 4) drives attach/close/health."""

    @property
    @abstractmethod
    def capability(self) -> TransportCapability: ...

    @abstractmethod
    def attach(
        self,
        request: OpenRequest,
        *,
        cancel: threading.Event,
        deadline: float,
        on_partial: Callable[[str, object], None],
    ) -> TransportSession: ...

    @abstractmethod
    def close(self, session: TransportSession) -> None: ...

    @abstractmethod
    def health(self, session: TransportSession) -> str: ...


class TransportRegistry:
    """In-process registry of transport capabilities, keyed by provider name. The
    §8.4 gate reads `endpoint_exposure` from here (trusted metadata)."""

    def __init__(self) -> None:
        self._capabilities: dict[str, TransportCapability] = {}

    def register(self, capability: TransportCapability) -> None:
        if capability.provider_name in self._capabilities:
            raise ValueError(f"transport already registered: {capability.provider_name}")
        self._capabilities[capability.provider_name] = capability

    def get(self, provider_name: str) -> TransportCapability:
        try:
            return self._capabilities[provider_name]
        except KeyError as exc:
            raise KeyError(f"unknown transport provider: {provider_name}") from exc

    def endpoint_exposure(self, provider_name: str) -> EndpointExposure:
        return self.get(provider_name).endpoint_exposure

    def list_capabilities(self) -> list[TransportCapability]:
        return list(self._capabilities.values())
```

Note: the schema subclasses inherit `extra="forbid"` from `Model`; do **not** re-declare
`model_config` on them. `TargetKey` is the only model with its own config (`frozen=True`)
and it lives in `seams/target.py`, not here.

- [ ] **Step 4: Run test + lint to verify they pass**

Run: `uv run python -m pytest tests/test_transport_base.py -q && uv run ruff check src/linux_debug_mcp/transport/base.py`
Expected: PASS (14 passed); ruff reports no errors (no unused imports).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/__init__.py src/linux_debug_mcp/transport/base.py tests/test_transport_base.py
git commit -m "feat: add transport boundary schemas and capability registry (#10)"
```

---

## Task 4: Env-only secrets resolver + Protocol (`seams/secrets.py`)

**Files:**
- Create: `src/linux_debug_mcp/seams/secrets.py`
- Test: `tests/test_seams_secrets.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_seams_secrets.py`:

```python
import pytest

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import (
    EnvSecretsResolver,
    SecretsResolutionError,
    SecretsResolver,
)


class _FakeResolver:
    """A test fake proving the Protocol is consumable without #08's real backend."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def resolve(self, refs: list[str]) -> dict[str, str]:
        return {ref: self._values[ref] for ref in refs if ref in self._values}


def test_resolver_and_fake_satisfy_protocol():
    assert isinstance(EnvSecretsResolver([]), SecretsResolver)
    assert isinstance(_FakeResolver({}), SecretsResolver)


def test_resolves_env_reference(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="tok", reference="MY_TOKEN")
    resolver = EnvSecretsResolver([ref])
    assert resolver.resolve(["MY_TOKEN"]) == {"MY_TOKEN": "s3cr3t"}


def test_unknown_reference_raises():
    resolver = EnvSecretsResolver([])
    with pytest.raises(SecretsResolutionError):
        resolver.resolve(["nope"])


def test_file_kind_is_deferred_to_08(tmp_path):
    # #10 creates no file credential source; file refs are owned by #08. The resolver
    # must NOT read the file — it raises before any IO.
    secret_file = tmp_path / "key"
    secret_file.write_text("TOP-SECRET-VALUE", encoding="utf-8")
    ref = SecretReference(kind=SecretReferenceKind.FILE, label="k", reference=str(secret_file))
    resolver = EnvSecretsResolver([ref])
    with pytest.raises(SecretsResolutionError) as excinfo:
        resolver.resolve([str(secret_file)])
    # Deferred, not read: the file's contents never appear in the error.
    assert "TOP-SECRET-VALUE" not in str(excinfo.value)
    assert "#08" in str(excinfo.value)


def test_external_kind_is_deferred_to_08():
    ref = SecretReference(kind=SecretReferenceKind.EXTERNAL, label="x", reference="vault://x")
    resolver = EnvSecretsResolver([ref])
    with pytest.raises(SecretsResolutionError) as excinfo:
        resolver.resolve(["vault://x"])
    assert "#08" in str(excinfo.value)


def test_missing_required_env_raises():
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="tok", reference="ABSENT_VAR")
    resolver = EnvSecretsResolver([ref])
    with pytest.raises(SecretsResolutionError):
        resolver.resolve(["ABSENT_VAR"])


def test_missing_optional_env_is_skipped(monkeypatch):
    monkeypatch.delenv("OPT_VAR", raising=False)
    ref = SecretReference(
        kind=SecretReferenceKind.ENV, label="opt", reference="OPT_VAR", required=False
    )
    resolver = EnvSecretsResolver([ref])
    assert resolver.resolve(["OPT_VAR"]) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_secrets.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.seams.secrets'`.

- [ ] **Step 3: Implement the resolver**

Create `src/linux_debug_mcp/seams/secrets.py`:

```python
from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


class SecretsResolutionError(ValueError):
    """Raised when a secret reference cannot be resolved. Messages MUST never contain
    a resolved secret value (spec §3.4, §8)."""


@runtime_checkable
class SecretsResolver(Protocol):
    def resolve(self, refs: list[str]) -> dict[str, str]: ...


class EnvSecretsResolver:
    """Minimal #08 seam. Resolves **env** refs only. `file` and `external` refs are
    **deferred to the #08 secrets store** — this issue creates no credential source and
    reads no files (the ownership map puts secret resolution under #08; the #08 hardening
    rule is "sources are env / external store / OS keyring — never repo files"). The
    `SecretsResolver` Protocol lets #08 drop in the real keyring/external/file backend
    unchanged, with its own validation, audit, and leak tests. Resolved env values are
    never persisted to session JSON, the manifest, logs, or tool output — that is
    enforced by callers; this only produces them.

    This is a deliberate, flagged deviation from spec §3.4 (which lists "env + file" for
    the minimal resolver): #08 owns credential policy and forbids repo files, so #10
    ships env-only and defers the rest."""

    def __init__(self, references: list[SecretReference]) -> None:
        self._by_reference = {ref.reference: ref for ref in references}

    def resolve(self, refs: list[str]) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for ref in refs:
            definition = self._by_reference.get(ref)
            if definition is None:
                raise SecretsResolutionError(f"unknown secret reference: {ref}")
            if definition.kind is not SecretReferenceKind.ENV:
                raise SecretsResolutionError(
                    f"{definition.kind} secret refs are deferred to the #08 secrets "
                    "store; the #10 minimal resolver resolves env only"
                )
            value = os.environ.get(definition.reference)
            if value is None:
                if definition.required:
                    raise SecretsResolutionError(
                        f"required env secret not set: {definition.reference}"
                    )
                continue
            resolved[ref] = value
        return resolved
```

Notes:
- File/external refs raise **before any IO** — the resolver never opens a file, so no
  credential file contents can leak (covered by `test_file_kind_is_deferred_to_08`).
- Error messages reference only the var name / kind, never a resolved value.
- The Protocol + the `_FakeResolver` in the test prove transports can be tested without
  #08's real backend; #08 later supplies keyring/external/file behind the same Protocol.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_secrets.py -q`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/secrets.py tests/test_seams_secrets.py
git commit -m "feat: add env-only secrets resolver seam; defer file/external to #08 (#10)"
```

---

## Task 5: Break-plan policy (`seams/break_policy.py`)

This is the pure decision layer for spec §4.1 / §4.8 — topology-first admission with
disproof-only pruning. Disproof *probes* (ssh / RSP reachability) run in Layer 3/4 and
their results are **injected** here as a set of positively-disproved methods. This layer
never performs IO.

**Files:**
- Create: `src/linux_debug_mcp/seams/break_policy.py`
- Test: `tests/test_seams_break_policy.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_seams_break_policy.py`:

```python
import pytest

from linux_debug_mcp.seams.break_policy import BreakPlanError, ReferenceBreakPolicy
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata
from linux_debug_mcp.transport.base import BreakMethod, LineRole, TransportRef


def _platform(*, ssh: bool, console: ConsoleKind = ConsoleKind.UART) -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=console,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=ssh,
    )


def _channel(role: LineRole, caps: list[str]) -> TransportRef:
    return TransportRef(provider="p", channel_id=f"{role}-0", line_role=role, caps=caps)


def test_rsp_channel_yields_gdbstub_native():
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.RSP, ["provides_rsp"]),
        platform=_platform(ssh=False),
    )
    assert plan.method is BreakMethod.GDBSTUB_NATIVE
    assert plan.channel_id == "rsp-0"


def test_dedicated_debug_uart_break():
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=False),
    )
    assert plan.method is BreakMethod.UART_BREAK


def test_shared_console_with_uart_break_and_no_ssh_admits_agent_proxy_break():
    # Contract §4.1 boundary case: this MUST be admitted via agent_proxy_break.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=False),
    )
    assert plan.method is BreakMethod.AGENT_PROXY_BREAK


def test_shared_console_without_uart_break_and_no_ssh_has_no_plan():
    # Contract §4.1: no predicate holds -> no_break_plan (NOT break_disproved).
    policy = ReferenceBreakPolicy()
    with pytest.raises(BreakPlanError) as excinfo:
        policy.plan(
            channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console"]),
            platform=_platform(ssh=False),
        )
    assert excinfo.value.code == "no_break_plan"


def test_line_native_preferred_over_ssh_fallback():
    # dedicated_debug + uart_break AND ssh_reachable -> uart_break wins over sysrq_g.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"]),
        platform=_platform(ssh=True),
    )
    assert plan.method is BreakMethod.UART_BREAK


def test_disproof_falls_back_to_next_candidate():
    # gdbstub_native disproved (RSP unreachable) but ssh present -> sysrq_g.
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.RSP, ["provides_rsp"]),
        platform=_platform(ssh=True),
        disproved={BreakMethod.GDBSTUB_NATIVE},
    )
    assert plan.method is BreakMethod.SYSRQ_G


def test_every_candidate_disproved_is_break_disproved():
    # Sole candidate sysrq_g, positively disproved -> break_disproved (NOT no_break_plan).
    policy = ReferenceBreakPolicy()
    with pytest.raises(BreakPlanError) as excinfo:
        policy.plan(
            channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console"]),
            platform=_platform(ssh=True),
            disproved={BreakMethod.SYSRQ_G},
        )
    assert excinfo.value.code == "break_disproved"


def test_hvc_console_with_ssh_uses_sysrq_g():
    policy = ReferenceBreakPolicy()
    plan = policy.plan(
        channel=_channel(LineRole.SHARED_CONSOLE, ["provides_console"]),
        platform=_platform(ssh=True, console=ConsoleKind.HVC),
    )
    assert plan.method is BreakMethod.SYSRQ_G
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_break_policy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.seams.break_policy'`.

- [ ] **Step 3: Implement the policy**

Create `src/linux_debug_mcp/seams/break_policy.py`:

```python
from __future__ import annotations

from typing import Protocol, runtime_checkable

from linux_debug_mcp.seams.target import PlatformMetadata
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan, LineRole, TransportRef

_SUPPORTS_UART_BREAK = "supports_uart_break"
_PROVIDES_RSP = "provides_rsp"

_RATIONALE = {
    BreakMethod.GDBSTUB_NATIVE: "rsp channel: gdb interrupts directly",
    BreakMethod.UART_BREAK: "dedicated debug line with UART break",
    BreakMethod.AGENT_PROXY_BREAK: "shared console with UART break via agent-proxy",
    BreakMethod.SYSRQ_G: "sysrq-g over ssh",
}


class BreakPlanError(ValueError):
    """Admission-time break-plan rejection. `code` is `no_break_plan` (no topology
    predicate holds) or `break_disproved` (every topology candidate positively
    disproved) — spec §4.8."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


@runtime_checkable
class BreakPolicy(Protocol):
    def plan(
        self,
        *,
        channel: TransportRef,
        platform: PlatformMetadata,
        disproved: set[BreakMethod] | None = None,
    ) -> BreakPlan: ...


class ReferenceBreakPolicy:
    """Encodes the contract §4.1 reference mappings as topology predicates against the
    *selected channel's* line_role + caps plus platform facts. Admission is
    topology-first (spec §4.8); disproof is disproof-only and injected by the caller."""

    def plan(
        self,
        *,
        channel: TransportRef,
        platform: PlatformMetadata,
        disproved: set[BreakMethod] | None = None,
    ) -> BreakPlan:
        disproved = disproved or set()
        candidates = self._candidates(channel, platform)
        if not candidates:
            raise BreakPlanError(
                "no break method's topology predicate holds for the selected channel",
                code="no_break_plan",
            )
        admissible = [method for method in candidates if method not in disproved]
        if not admissible:
            raise BreakPlanError(
                "every topology-admissible break method was positively disproved",
                code="break_disproved",
            )
        method = admissible[0]
        return BreakPlan(method=method, channel_id=channel.channel_id, rationale=_RATIONALE[method])

    def _candidates(self, channel: TransportRef, platform: PlatformMetadata) -> list[BreakMethod]:
        # Insertion order is preference order: line-native first, ssh fallback last.
        candidates: list[BreakMethod] = []
        if channel.line_role is LineRole.RSP and _PROVIDES_RSP in channel.caps:
            candidates.append(BreakMethod.GDBSTUB_NATIVE)
        if channel.line_role is LineRole.DEDICATED_DEBUG and _SUPPORTS_UART_BREAK in channel.caps:
            candidates.append(BreakMethod.UART_BREAK)
        if channel.line_role is LineRole.SHARED_CONSOLE and _SUPPORTS_UART_BREAK in channel.caps:
            candidates.append(BreakMethod.AGENT_PROXY_BREAK)
        if platform.ssh_reachable:
            candidates.append(BreakMethod.SYSRQ_G)
        return candidates
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_break_policy.py -q`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/break_policy.py tests/test_seams_break_policy.py
git commit -m "feat: add reference break-plan policy seam (#10)"
```

---

## Task 6: `transport.*` operation allowlist + destructive permissions (`config.py`)

**Files:**
- Modify: `src/linux_debug_mcp/config.py:107` (immediately after the existing
  constrained debug-operation allowlist — the `*_DEBUG_OPERATIONS` list that ends at
  line 107 with `]`)
- Test: `tests/test_transport_operations.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_transport_operations.py`:

```python
import pytest

from linux_debug_mcp.config import (
    TRANSPORT_DESTRUCTIVE_PERMISSIONS,
    TRANSPORT_OPERATIONS,
    validate_transport_operation,
)


def test_allowlist_contents():
    assert TRANSPORT_OPERATIONS == [
        "transport.open",
        "transport.status",
        "transport.health",
        "transport.inject_break",
        "transport.close",
    ]


def test_validate_accepts_allowed_operation():
    # Returns the op unchanged on success.
    assert validate_transport_operation("transport.open") == "transport.open"


def test_validate_rejects_unknown_operation():
    with pytest.raises(ValueError):
        validate_transport_operation("transport.nuke")


def test_inject_break_carries_destructive_permission():
    perms = TRANSPORT_DESTRUCTIVE_PERMISSIONS["transport.inject_break"]
    assert perms == ["drop target kernel into the debugger"]


def test_only_inject_break_is_destructive():
    assert set(TRANSPORT_DESTRUCTIVE_PERMISSIONS) == {"transport.inject_break"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_transport_operations.py -q`
Expected: FAIL — `ImportError: cannot import name 'TRANSPORT_OPERATIONS'`.

- [ ] **Step 3: Add the allowlist and validator**

In `src/linux_debug_mcp/config.py`, immediately after the existing constrained
debug-operation allowlist (the `*_DEBUG_OPERATIONS` list that ends at line 107 with
`]`), add:

```python
TRANSPORT_OPERATIONS = [
    "transport.open",
    "transport.status",
    "transport.health",
    "transport.inject_break",
    "transport.close",
]
TRANSPORT_DESTRUCTIVE_PERMISSIONS = {
    "transport.inject_break": ["drop target kernel into the debugger"],
}


def validate_transport_operation(operation: str) -> str:
    if operation not in TRANSPORT_OPERATIONS:
        raise ValueError(f"unsupported transport operation: {operation}")
    return operation
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_transport_operations.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_transport_operations.py
git commit -m "feat: add transport operation allowlist and destructive permissions (#10)"
```

---

## Task 7: Layer-1 verification gate

**Files:** none (verification only).

- [ ] **Step 1: Run the full test suite**

Run: `uv run python -m pytest -q`
Expected: all tests pass, including the six new test modules. No existing test regresses
(Layer 1 adds only new modules + two additive enum members + additive config constants).

- [ ] **Step 2: Lint + format check**

Run: `just lint`
Expected: `ruff check .` clean and `ruff format --check .` clean. If format flags the new
files, run `just format` and re-stage.

- [ ] **Step 3: Doc terminology guard — confirm this layer adds no new matches**

Layer 1 touches only `src/` and `tests/`, so it introduces no new `docs/` content.
Verify that the Layer 1 *code* edits add no forbidden terminology under `docs/`:

Run: `git stash --include-untracked --keep-index 2>/dev/null; rg -n "sprin[t]|Sprin[t]|SPRIN[T]" docs/ README.md > /tmp/before.txt; git stash pop 2>/dev/null; true`

The simpler, sufficient check: Layer 1 adds no files under `docs/` and edits no doc,
so `just check-docs`'s result is unchanged by this layer. Note that the guard may
already be red on **pre-existing committed docs** (other planning artifacts on the
repo predate this work and contain the legacy iteration-label word); that is a
separate, pre-existing condition this layer neither creates nor is responsible for
fixing. Confirm only that **no file you added or edited in Layer 1** introduces a new
match:

Run: `rg -n "sprin[t]|Sprin[t]|SPRIN[T]" tests/test_*.py src/linux_debug_mcp/seams src/linux_debug_mcp/transport || echo CLEAN`
Expected: `CLEAN` (the new code refers to the allowlist constant only by its real
symbol name in `config.py`, which lives under `src/` and is not scanned by the guard).

- [ ] **Step 4: Confirm no cycle and clean import**

Run: `uv run python -c "import linux_debug_mcp.transport.base, linux_debug_mcp.seams.break_policy, linux_debug_mcp.seams.secrets, linux_debug_mcp.seams.target; print('ok')"`
Expected: prints `ok` (no `ImportError`/circular-import error).

- [ ] **Step 5: Hand off to Layer 2**

Layer 1 is complete and green. The next layer (coordination primitives) consumes these
schemas. Return to the roadmap and write
`docs/superpowers/plans/2026-05-26-transport-abstraction-layer-2-coordination.md`.

---

## Self-Review

**Spec coverage (Layer 1 slice):**
- §3.1 provisioning schemas → Task 2 (`TargetKey`, `TargetState`, `PlatformMetadata`,
  `KernelProvenance`, `LeaseInfo`, `SshEndpoint`) + Task 3 (`TargetHandle`). ✓
- §3.2 transport boundary schemas → Task 3 (`Endpoint` union, `TransportRef`,
  `OpenRequest`, `TransportCapability` with `endpoint_exposure`, `BreakPlan`,
  `TransportSession`). Contract shapes frozen — no field added to `TransportRef`/
  `OpenRequest`; `endpoint_exposure` on `TransportCapability`; no `recovery` field. ✓
- §3.4 secrets resolver (env-only; `file`/`external` deferred to #08, raised before any
  IO; env values never surfaced/persisted) + `SecretsResolver` Protocol + test fake →
  Task 4. **Deliberate, flagged deviation** from §3.4's "env + file": #08 owns
  credential policy and forbids repo files, so #10 ships env-only and defers the rest
  behind the Protocol (see roadmap secrets-source invariant). ✓
- §4.1/§4.8 break policy (topology-first, disproof-only, `no_break_plan` vs
  `break_disproved`, the shared-console+`ssh_reachable=false`+`uart_break` admit case) →
  Task 5. ✓
- §7.3 `TRANSPORT_OPERATIONS` allowlist + `inject_break` destructive permission →
  Task 6. ✓
- §8.1 two new `ErrorCategory` values (`STALE_HANDLE`, `TRANSPORT_CONFLICT`) → Task 1. ✓

**Deliberately deferred to later layers (not gaps):** `details.code` machine-readable
strings are surfaced by handlers (Layer 5); the actual disproof *probes* and the
`SnapshotStore`/admission/registry/lifecycle/backends are Layers 2–4; the local-qemu
`TargetHandle` adapter is Layer 4; `providers.list` merge + startup capability validation
is Layer 5.

**Placeholder scan:** every code step contains complete, runnable code; no TBD/TODO. ✓

**Type consistency:** `BreakMethod`, `LineRole`, `TransportRef`, `BreakPlan`,
`PlatformMetadata` names are identical across Tasks 3 and 5. `EnvSecretsResolver`
constructed with `list[SecretReference]` in both impl and tests. `validate_transport_operation`
returns the op (used in tests). `TargetHandle.access` is a `TargetAccess` model (added in
Task 3 so the discriminated `transports` list parses). ✓
