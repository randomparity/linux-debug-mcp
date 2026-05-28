# Transport Abstraction — Layer 4 ("the heart") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make transport ownership durable and crash-recoverable, wire the `open()`/`close()` transaction + endpoint-safety + execution-state gates, migrate every public halt path onto that transaction, and ship the named `transport.*` MCP tools — so all of spec §10.2 is green together.

**Architecture:** Three staged phases on the existing `issue-10-transport-abstraction` branch. **Phase A** builds the internal authority (`coordination/registry.py` durable store + reaper + reconciliation + flock, the `coordination/transaction.py` open/close transaction, the endpoint-safety + execution-state gates, and the ADR-0006 cancel/epoch consolidation) returning **internal** `TransportSession` handles only — no MCP surface, tested against fakes. **Phase B** flips the public surface on: rewire `debug.start_session` and the gdbstub `debug.*` handlers onto the transaction, gate `target.run_tests` through `admit_ssh_tier` with a real kill-on-halt, add the `transport.open`/`close`/`inject_break` wrappers, the `create_app` capability-startup validation, and the legacy-`DebugSession` fence. **Phase C** asserts the §10.2 invariants together, adds the cancel-protocol property pass, and re-runs the gated integration end-to-end.

**Tech Stack:** Python 3.11+, Pydantic v2 (`extra="forbid"`), `pytest` (config in `pyproject.toml`, `pythonpath=src`), `hypothesis` (new dev dep for the stateful cancel-protocol test), `ruff` (line length 120, `E,F,I,UP,B,SIM`), `fcntl.flock`, `os.replace`/`os.fsync` for atomic durable writes. No new runtime dependency. `just test` / `just lint` / `just check-docs` are the per-task gates.

---

## Decisions & rejected alternatives (SETTLED — feed verbatim to every adversarial-review round)

These are decided. A review round may NOT reopen them; cite a contract section + a concrete interleaving to block, otherwise it is a non-blocking note (see `[[feedback-adversarial-review-convergence]]`).

- **Layered scope (roadmap):** ship `transport.open` **with** the full §10.2 invariant set — crash-recovery, execution-state, endpoint-safety — green together. No fallback split. The public endpoint-returning / halting / recovery paths ship in Layer 4; Layer 5 adds only the observational `transport.status`/`health` wrappers + `providers.list`.
- **Phase structure:** one plan, staged Phase A (internal, fakes, no MCP) → B (public wiring) → C (green-together conformance). All commits on `issue-10-transport-abstraction`. Review checkpoint between phases.
- **ADR 0005 — registry durability:** host-global `$XDG_RUNTIME_DIR/linux-debug-mcp/registry/`, one JSON record per `TargetKey` (filename via `TargetKey.recovery_key()`), atomic write-tmp→`fsync`→`os.replace`, labeled write-ahead stages, `instance.lock` flock single-instance, reconcile-before-admit. Rejected: artifact-root-scoped, SQLite, durable epoch counter. **Amended (2026-05-27 review):** `backend_pid`/`start_time` are write-ahead into the OPENING record on the `on_partial("backend_process")` callback so a death before READY is reapable (Finding #1); `recovery_required`'s single source of truth is the durable tombstone, with admission's `_recovery_required` a write-through cache and **one** dual-write helper for every mark/clear (Finding #5).
- **ADR 0006 — cancel/epoch model:** consolidate the stacked `note_execution_transition`/`cancel_ssh_tier`/`complete`-backstop/lifecycle-close fences into one `(generation, execution_epoch, execution_state)` transition table; adjudicate with a `hypothesis` stateful test. Authority stays the `StopCapableGuard` token (ADR 0002). Rejected: carry-forward + extend, more review rounds, TLA+/Alloy now. **Amended (2026-05-27 review):** cancel delivery to the in-flight ssh op is a **teardown-bounded** daemon watcher that polls `handle.wait_cancelled(0.1)` under a `watch_done` event and is `join`ed in a `finally` (never the fire-and-forget `if handle.wait_cancelled(): …` form, which parks forever on the success path and leaks the thread + handle — second-round Finding #1), setting the runner's cancel `Event` on a halt; an op spanning a halt terminalizes its RUNNING `StepResult` to FAILED, never SUCCEEDED (Finding #2).
- **ADR 0007 — local-qemu identity + snapshot producer:** `TargetKey(provisioner="local-qemu", target_id=run_id)`, `generation = BootAttempt.attempt` (reuse the boot-attempt counter, no new manifest field), documented `PlatformMetadata` defaults (UART console, `GDBSTUB_NATIVE` break hint, `ssh_reachable` from the rootfs profile). `target_boot_handler` publishes the authoritative `TargetSnapshot` via `publish_ready_snapshot` on boot-to-READY (Task B0) — the producer that unblocks every Phase B admission gate (Finding #3). Rejected: a dedicated manifest `generation` field (duplicates the boot-attempt counter, adds sync burden).
- **ADR 0003 — ownership split:** backends return `BackendAttachment`; Layer 4 mints `session_id`, owns/writes the `TransportSession` record, sets tokens/`record_state`/`break_plan`/`execution_state`. The record schema is **frozen** (spec §3.2): `stop_guard_token: str` is a bare string, so the `GuardToken` fence cannot be persisted.
- **ADR 0001/0002 — gate split + guard authority:** the execution-state gate's ssh-tier admission is Layer 2/4 split; the stop-controller's execution-event authority IS the guard token. gdbstub `debug.*` register/memory reads run while `HALTED` and are governed by the `StopCapableGuard`, **not** the ssh-`EXECUTING` gate. **ADR 0002 amended (2026-05-27 review):** the fenced `GuardToken` is held in an in-process `session_id → GuardToken` map (the frozen `stop_guard_token: str` cannot carry the fence — ADR 0003); `close()`/lifecycle release via the fenced `guard.release(target_key, token)`, and a post-restart `revoke()` is sound because the flock + reconcile-before-admit prove the prior holder dead (Finding #4).
- **Seam ownership:** #10 ships the `StopCapableGuard`/`SecretsResolver`/`LifecycleDispatcher`/`SnapshotStore` Protocols + minimal in-process impls; #08/provisioning later swap impls behind the same Protocol and must pass these tests.

Feed **ADRs 0001–0007** (including the 2026-05-27 amendments to 0002 / 0005 / 0006) as the SETTLED preamble to every review round.

---

## File structure

**Phase A — new/edited internal modules (no `server.py` edits):**

- `src/linux_debug_mcp/safety/runtime_locks.py` *(modify)* — add `private_runtime_registry_dir(*, base=None)` beside `private_runtime_lock_dir`, reusing `_ensure_private`.
- `src/linux_debug_mcp/coordination/registry.py` *(create)* — `SessionRegistry`: durable `TransportSession` JSON records + `recovery_required` tombstones (keyed by `TargetKey.recovery_key()`), atomic write-ahead stage writes, `instance.lock` flock, and `reconcile()` (orphan reap + tombstone/release). One responsibility: durable ownership + crash reconciliation.
- `src/linux_debug_mcp/coordination/endpoint_safety.py` *(create)* — `refuse_unsafe_exposure(capability, op)` (pre-attach `brokered_required` refusal) + `assert_loopback_endpoint(endpoint)` (return-path belt).
- `src/linux_debug_mcp/coordination/exec_probe.py` *(create)* — `probe_execution_state(*, registry, admission, target_key, generation) -> ExecutionProof`, the Layer-4 fresh liveness probe consuming the durable `execution_state`.
- `src/linux_debug_mcp/coordination/transaction.py` *(create)* — `TransportTransaction.open(request, *, recovery=False) -> TransportSession` and `.close(session_id, *, force=False)`: the write-ahead orchestrator over admission + registry + guard + lease + secrets + selection + backend, with full rollback. Subscribes to the `LifecycleDispatcher`.
- `src/linux_debug_mcp/coordination/admission.py` *(modify)* — ADR-0006 consolidation of the exec-epoch fences (behavior-preserving) + a transition-table docstring.
- `src/linux_debug_mcp/seams/target.py` *(modify)* — add the local-qemu `SnapshotStore`-publishing adapter (`publish_ready_snapshot(...)`) used to seed authoritative facts when a run boots READY.

**Phase B — `server.py` + provider edits (public surface):**

- `src/linux_debug_mcp/providers/local_ssh_tests.py` *(modify)* — add a cancellation hook (`cancel: threading.Event`) to `SubprocessSshRunner`/`LocalSshTestProvider.execute_tests`, killing the in-flight `Popen` on cancel.
- `src/linux_debug_mcp/server.py` *(modify)* — `target_boot_handler` publishes the authoritative `TargetSnapshot` on boot-to-READY (Task B0, ADR 0007); `target_run_tests_handler` ssh-tier gating + halt→runner cancel bridge; `debug_start_session_handler` + gdbstub `debug.*` migration onto the transaction; `transport.open`/`close`/`inject_break` handlers + `@app.tool` wrappers; `create_app` transport-registry construction + capability startup validation + reconcile-before-serve; legacy-`DebugSession` fence.

**Phase C — tests + docs:**

- `tests/test_layer4_conformance.py` *(create)* — the §10.2 green-together suite.
- `tests/test_exec_state_machine.py` *(create)* — the `hypothesis` cancel/epoch property pass.
- `tests/test_transport_open_close_integration.py` *(create, gated)* — end-to-end `inject_break` + unchanged qemu-gdbstub flow.

---

## Phase A — internal authority (no MCP surface; fakes)

### Task A0: shared Layer-4 test harness (`tests/_layer4_fakes.py`)

**Files:**
- Create: `tests/_layer4_fakes.py` (helper module only — no test file, no test collection at A0)

The load-bearing Phase A/B/C tests share one set of fakes instead of re-inlining them per module (the writing-plans anti-pattern the review flagged). This task lifts the inline fakes that A8's transaction test grew into an importable module: `FakeQemuTransport`/`FakeBrokeredTransport`, `FakeBreakPolicy`, `FakeReapProxy`, a cancellable `FakeSshRunner`, and the `build_txn`/`seed_snapshot`/`make_request` builders. Tests import by bare name (`from _layer4_fakes import …`) — the repo's `tests/` convention (`from conftest import …`), since `tests/` is on `sys.path`. **A0 ships only the module**: it imports `TransportTransaction` (born in Task A8), so nothing may import `_layer4_fakes` until A8 exists. Because it is a plain helper module (not `test_*.py`), pytest never collects or imports it on its own — so committing it at A0 leaves the full suite green across A1–A7 rather than reddening every run on a collection error. Its first consumer and verification is A8's rewritten `test_transport_transaction.py` (second-round Finding #4).

- [ ] **Step 1: Write the harness module**

```python
# tests/_layer4_fakes.py
"""Shared Layer-4 test harness (plan Task A0). One source of fakes for every load-bearing
open()/close()/gating/recovery test, so a contract change touches one file, not a dozen."""
from __future__ import annotations

import threading
from datetime import UTC, datetime

from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore, TargetSnapshot
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.coordination.transaction import TransportTransaction
from linux_debug_mcp.seams.guard import InProcessStopCapableGuard
from linux_debug_mcp.seams.secrets import EnvSecretsResolver
from linux_debug_mcp.seams.target import (
    BreakHint, ConsoleKind, PlatformMetadata, TargetKey, TargetState)
from linux_debug_mcp.transport.base import (
    BackendAttachment, BreakMethod, BreakPlan, EndpointExposure, LineRole, OpenRequest,
    TcpEndpoint, Transport, TransportCapability, TransportLocality, TransportRef)

KEY = TargetKey(provisioner="local-qemu", target_id="run-1")
PLATFORM = PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                            dedicated_debug_line=False, ssh_reachable=True,
                            break_hints=[BreakHint.GDBSTUB_NATIVE])
CHANNEL = TransportRef(provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))


class FakeQemuTransport(Transport):
    """Loopback-local qemu-gdbstub stand-in. `crash=True` raises in attach (rollback seam).
    `backend_pid` set ⇒ attach emits the `backend_process` partial BEFORE returning, so the
    write-ahead backend_pid path (Finding #1) is exercised."""

    def __init__(self, *, crash: bool = False, backend_pid: int | None = None,
                 backend_start_time: str | None = None) -> None:
        self._crash = crash
        self._backend_pid = backend_pid
        self._backend_start_time = backend_start_time
        self.closed: list[str] = []

    @property
    def capability(self) -> TransportCapability:
        return TransportCapability(
            provider_name="qemu-gdbstub", locality=TransportLocality.LOCAL,
            provides_console=False, provides_rsp=True, supports_uart_break=False,
            endpoint_exposure=EndpointExposure.LOOPBACK_LOCAL)

    def attach(self, request, *, cancel, deadline, on_partial) -> BackendAttachment:
        if self._backend_pid is not None:
            # emit pid+start_time as one partial (mirrors transport/proxy.py:184) so the
            # transaction can write it through into the OPENING record before we return.
            on_partial("backend_process",
                       {"pid": self._backend_pid, "start_time": self._backend_start_time})
        if self._crash:
            raise RuntimeError("attach blew up")
        return BackendAttachment(
            console_endpoint=None, rsp_endpoint=TcpEndpoint(host="127.0.0.1", port=5551),
            backend_pid=self._backend_pid, backend_start_time=self._backend_start_time)

    def close(self, session) -> None:
        self.closed.append(session.session_id)

    def health(self, session) -> str:
        return "ready"


class FakeBrokeredTransport(FakeQemuTransport):
    """brokered_required remote stand-in — its endpoint-returning open is refused pre-attach."""

    @property
    def capability(self) -> TransportCapability:
        return TransportCapability(
            provider_name="redfish-sol", locality=TransportLocality.REMOTE,
            provides_console=True, provides_rsp=True, supports_uart_break=False,
            endpoint_exposure=EndpointExposure.BROKERED_REQUIRED)


class FakeBreakPolicy:
    def plan(self, *, channel, platform, disproved):
        return BreakPlan(method=BreakMethod.GDBSTUB_NATIVE, channel_id=channel.channel_id, rationale="rsp")


class FakeReapProxy:
    """Records start-time-fenced reaps so reconcile-after-death tests assert reap-by-identity."""

    def __init__(self) -> None:
        self.reaped: list[tuple[int, str | None]] = []

    def stop_by_identity(self, pid: int, start_time: str | None) -> None:
        self.reaped.append((pid, start_time))


class FakeSshRunner:
    """Blocks in run() until its cancel event fires, so the async-halt cancel bridge (Fix 3)
    is exercised without a real subprocess. Consumed by Task B2 — depends on the
    `SshCommandResult.cancelled` field that Task B1 adds."""

    def __init__(self) -> None:
        self.cancel_observed = threading.Event()
        self.started = threading.Event()

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None):
        from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
        self.started.set()
        if cancel is not None:
            cancel.wait(timeout)
            if cancel.is_set():
                self.cancel_observed.set()
                return SshCommandResult(exit_status=-1, timed_out=False, cancelled=True)
        return SshCommandResult(exit_status=0, timed_out=False)


def seed_snapshot(store: SnapshotStore, *, key: TargetKey = KEY, generation: int = 1,
                  transports=(CHANNEL,), platform: PlatformMetadata = PLATFORM,
                  state: TargetState = TargetState.READY) -> None:
    """Publish an authoritative TargetSnapshot (mirrors the Task B0 producer, ADR 0007)."""
    store.put(key, TargetSnapshot(generation=generation, transports=tuple(transports),
                                  platform=platform, state=state))


def build_txn(transport: Transport, *, registry: SessionRegistry, guard=None, leases=None,
              generation: int = 1, state: TargetState = TargetState.READY):
    """Construct a TransportTransaction over a seeded snapshot. Returns (txn, admission)."""
    store = SnapshotStore()
    seed_snapshot(store, generation=generation, state=state)
    admission = AdmissionService(store)
    txn = TransportTransaction(
        admission=admission, registry=registry, guard=guard or InProcessStopCapableGuard(),
        leases=leases or ConsoleLeaseManager(), secrets=EnvSecretsResolver([]),
        break_policy=FakeBreakPolicy(),
        transports={transport.capability.provider_name: transport})
    return txn, admission


def make_request(provider: str = "qemu-gdbstub", *, generation: int = 1) -> OpenRequest:
    ref = CHANNEL if provider == "qemu-gdbstub" else TransportRef(
        provider=provider, channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))
    return OpenRequest(target_key=KEY, generation=generation, transport_ref=ref, platform=PLATFORM)
```

- [ ] **Step 2: Lint-gate the module (no test collection, no smoke test)**

There is **no** standalone `test_*` smoke module for the harness — writing one at A0 would error at collection (it imports the not-yet-existing `TransportTransaction`) and redden every full-suite run until A8. `_layer4_fakes.py` is verified by being imported and exercised by A8's `test_transport_transaction.py`, the harness's first consumer. A0's gate is lint only — `ruff` does not import or collect the module:

Run: `uv run ruff check tests/_layer4_fakes.py && uv run ruff format --check tests/_layer4_fakes.py`
Expected: PASS (clean import-sort + format). A full `uv run python -m pytest -q` here also stays green: pytest does not collect a non-`test_*` helper module, so the unresolved `TransportTransaction` import is never triggered until A8.

- [ ] **Step 3: Commit**

```bash
git add tests/_layer4_fakes.py
git commit -m "test: add the shared Layer-4 fakes harness (#10)"
```

---

### Task A1: `private_runtime_registry_dir()` helper

**Files:**
- Modify: `src/linux_debug_mcp/safety/runtime_locks.py`
- Test: `tests/test_runtime_locks.py` (exists — add cases)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_runtime_locks.py  (add)
import os
from pathlib import Path

import pytest

from linux_debug_mcp.safety.runtime_locks import (
    RuntimeLockError,
    private_runtime_registry_dir,
)


def test_registry_dir_prefers_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    result = private_runtime_registry_dir()
    assert result == tmp_path / "linux-debug-mcp" / "registry"
    assert result.is_dir()
    assert (result.stat().st_mode & 0o777) == 0o700


def test_registry_dir_fallback_when_no_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    result = private_runtime_registry_dir(base=tmp_path)
    assert result == tmp_path / f"linux-debug-mcp-{os.getuid()}" / "registry"
    assert result.is_dir()


def test_registry_dir_rejects_symlink(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    base = tmp_path / "linux-debug-mcp"
    base.mkdir(parents=True)
    (base / "registry").symlink_to(tmp_path)
    with pytest.raises(RuntimeLockError):
        private_runtime_registry_dir()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_runtime_locks.py -k registry -q`
Expected: FAIL — `ImportError: cannot import name 'private_runtime_registry_dir'`.

- [ ] **Step 3: Add the helper**

```python
# src/linux_debug_mcp/safety/runtime_locks.py  (add after private_runtime_lock_dir)
def private_runtime_registry_dir(*, base: Path | None = None) -> Path:
    """Resolve the host-global, uid-isolated durable-registry directory (ADR 0005).

    Sibling of the lock dir: ``$XDG_RUNTIME_DIR/linux-debug-mcp/registry`` (or the
    ``<base>/linux-debug-mcp-<uid>/registry`` fallback), with the same symlink/owner/0700
    validation. Holds one ``TransportSession`` JSON record per TargetKey, the recovery
    tombstones, and the single-instance ``instance.lock`` flock.
    """
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        base_dir = Path(runtime_dir) / "linux-debug-mcp"
    else:
        root = base if base is not None else Path(tempfile.gettempdir())
        base_dir = root / f"linux-debug-mcp-{os.getuid()}"
    _ensure_private(base_dir)
    registry_dir = base_dir / "registry"
    _ensure_private(registry_dir)
    return registry_dir
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_runtime_locks.py -k registry -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/safety/runtime_locks.py tests/test_runtime_locks.py
git commit -m "feat: add host-global runtime registry dir resolver (#10)"
```

---

### Task A2: durable record + tombstone read/write (atomic, write-ahead stages)

**Files:**
- Create: `src/linux_debug_mcp/coordination/registry.py`
- Test: `tests/test_session_registry.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_session_registry.py
from datetime import UTC, datetime

import pytest

from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import RecordState, TransportSession, new_session_id


def _key() -> TargetKey:
    return TargetKey(provisioner="local-qemu", target_id="run-abc")


def _session(key: TargetKey, **over) -> TransportSession:
    base = dict(
        session_id=new_session_id(),
        target_key=key,
        generation=1,
        provider="qemu-gdbstub",
        channel_id="rsp0",
        record_state=RecordState.PENDING,
        created_at=datetime.now(UTC),
    )
    base.update(over)
    return TransportSession(**base)


def test_record_round_trip(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    session = _session(key)
    reg.write_record(session)
    loaded = reg.read_record(key)
    assert loaded is not None
    assert loaded.session_id == session.session_id
    assert loaded.record_state is RecordState.PENDING


def test_record_filename_uses_recovery_key(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key))
    # opaque key parts never appear as path segments (spec §4.7)
    assert (tmp_path / f"owner-{key.recovery_key()}.json").exists()
    assert not any("run-abc" in p.name for p in tmp_path.iterdir())


def test_write_is_atomic_no_partial_files(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(_session(_key()))
    assert not list(tmp_path.glob("*.tmp"))  # tmp renamed away


def test_tombstone_round_trip_and_clear(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_tombstone(RecoveryTombstone(target_key=key, generation=4, reason="halted_on_close"))
    tomb = reg.read_tombstone(key)
    assert tomb is not None and tomb.generation == 4
    reg.clear_tombstone(key, expected_generation=4)
    assert reg.read_tombstone(key) is None


def test_clear_tombstone_is_generation_fenced(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_tombstone(RecoveryTombstone(target_key=key, generation=5, reason="halted"))
    reg.clear_tombstone(key, expected_generation=4)  # stale clear → no-op
    assert reg.read_tombstone(key) is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_session_registry.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.coordination.registry'`.

- [ ] **Step 3: Write the durable store**

```python
# src/linux_debug_mcp/coordination/registry.py
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import TransportSession


@dataclass(frozen=True)
class RecoveryTombstone:
    """Durable `recovery_required` marker (ADR 0005 / spec §4.7). Persisted beside the
    ownership record; survives a server restart so a crashed-while-halted target stays
    gated until an explicit clearance path runs."""

    target_key: TargetKey
    generation: int
    reason: str


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write-tmp → fsync → os.replace, so a crash mid-write never leaves a torn record
    (ADR 0005). The rename is atomic on the same filesystem; readers see old or new, never
    partial."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


class SessionRegistry:
    """Durable, host-global ownership store (ADR 0005). One JSON record + optional tombstone
    per TargetKey, filenames derived from `TargetKey.recovery_key()` so opaque key parts are
    never path segments. Atomic writes; the flock + reaper live in later tasks (A3/A4)."""

    def __init__(self, *, directory: Path) -> None:
        self._dir = directory

    def _record_path(self, target_key: TargetKey) -> Path:
        return self._dir / f"owner-{target_key.recovery_key()}.json"

    def _tomb_path(self, target_key: TargetKey) -> Path:
        return self._dir / f"tomb-{target_key.recovery_key()}.json"

    def write_record(self, session: TransportSession) -> None:
        _atomic_write_json(self._record_path(session.target_key), session.model_dump(mode="json"))

    def read_record(self, target_key: TargetKey) -> TransportSession | None:
        path = self._record_path(target_key)
        if not path.exists():
            return None
        return TransportSession.model_validate_json(path.read_text(encoding="utf-8"))

    def delete_record(self, target_key: TargetKey) -> None:
        self._record_path(target_key).unlink(missing_ok=True)

    def list_records(self) -> list[TransportSession]:
        records: list[TransportSession] = []
        for path in self._dir.glob("owner-*.json"):
            records.append(TransportSession.model_validate_json(path.read_text(encoding="utf-8")))
        return records

    def write_tombstone(self, tombstone: RecoveryTombstone) -> None:
        _atomic_write_json(
            self._tomb_path(tombstone.target_key),
            {
                "provisioner": tombstone.target_key.provisioner,
                "target_id": tombstone.target_key.target_id,
                "generation": tombstone.generation,
                "reason": tombstone.reason,
            },
        )

    def read_tombstone(self, target_key: TargetKey) -> RecoveryTombstone | None:
        path = self._tomb_path(target_key)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return RecoveryTombstone(
            target_key=TargetKey(provisioner=data["provisioner"], target_id=data["target_id"]),
            generation=data["generation"],
            reason=data["reason"],
        )

    def clear_tombstone(self, target_key: TargetKey, *, expected_generation: int) -> None:
        existing = self.read_tombstone(target_key)
        if existing is not None and existing.generation == expected_generation:
            self._tomb_path(target_key).unlink(missing_ok=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_session_registry.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/registry.py tests/test_session_registry.py
git commit -m "feat: add durable session-registry record + tombstone store (#10)"
```

---

### Task A3: single-instance flock ("second server fails loud")

**Files:**
- Modify: `src/linux_debug_mcp/coordination/registry.py`
- Test: `tests/test_session_registry.py` (add)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_session_registry.py  (add)
from linux_debug_mcp.coordination.registry import InstanceLockError


def test_second_instance_fails_loud(tmp_path):
    first = SessionRegistry(directory=tmp_path)
    first.acquire_instance_lock()
    second = SessionRegistry(directory=tmp_path)
    with pytest.raises(InstanceLockError):
        second.acquire_instance_lock()
    first.release_instance_lock()
    # once released, a new instance may acquire
    third = SessionRegistry(directory=tmp_path)
    third.acquire_instance_lock()
    third.release_instance_lock()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_session_registry.py -k instance -q`
Expected: FAIL — `ImportError: cannot import name 'InstanceLockError'`.

- [ ] **Step 3: Add the flock**

```python
# src/linux_debug_mcp/coordination/registry.py  (add imports + members)
import fcntl


class InstanceLockError(RuntimeError):
    """Raised when the host-global single-instance flock is already held — a second server
    process must fail loud, never admit alongside the first (ADR 0005, spec §10.2)."""


# inside SessionRegistry:
    def acquire_instance_lock(self) -> None:
        path = self._dir / "instance.lock"
        self._lock_fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._lock_fd)
            self._lock_fd = None
            raise InstanceLockError(
                "another linux-debug-mcp server already holds the registry instance lock"
            ) from exc

    def release_instance_lock(self) -> None:
        if getattr(self, "_lock_fd", None) is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None
```

Add `self._lock_fd: int | None = None` to `__init__`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_session_registry.py -k instance -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/registry.py tests/test_session_registry.py
git commit -m "feat: add single-instance flock to the session registry (#10)"
```

---

### Task A4: reconciliation + orphan reap (runs before admission opens)

**Files:**
- Modify: `src/linux_debug_mcp/coordination/registry.py`
- Test: `tests/test_session_registry.py` (add)

Reconciliation runs once at startup, after `acquire_instance_lock()` and **before** the `AdmissionService` accepts its first admit. For each durable record it: (a) if a backend pid is recorded and still live with the recorded start-time, force-reaps it via `proxy.stop_by_identity(pid, start_time)` — **never** signalling a foreign pid (start-time mismatch ⇒ skip); (b) if the record's `execution_state` is `HALTED`/`UNKNOWN`, writes a `recovery_required` tombstone and marks admission; (c) deletes the now-orphaned record. A foreign listener / mismatched start-time is left untouched (ADR 0004). Because the backend pid is **written through** into the OPENING record the instant the backend spawns (Task A8, Finding #1), a record persisted by a process that died between spawn and READY still carries a reapable pid — reconcile reaps it here rather than leaking the orphan.

The durable tombstone is the **single source of truth** for `recovery_required`; admission's in-memory `_recovery_required` is a write-through cache that `reconcile` rebuilds from the persisted tombstones (step 1 below). So a restart re-gates exactly the targets the tombstones name — and a clearance that went through the dual-write helper (Task A8 `_clear_recovery`) left no tombstone, so it stays cleared across the restart (Finding #5).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_session_registry.py  (add)
from linux_debug_mcp.transport.base import ExecutionState


class _FakeProxy:
    def __init__(self) -> None:
        self.reaped: list[tuple[int, str | None]] = []

    def stop_by_identity(self, pid: int, start_time: str | None) -> None:
        self.reaped.append((pid, start_time))


class _RecordingAdmission:
    def __init__(self) -> None:
        self.marked: list[tuple[TargetKey, int]] = []

    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None:
        self.marked.append((target_key, generation))


def test_reconcile_reaps_live_orphan_and_clears_record(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key, backend_pid=4321, backend_start_time="999",
                              execution_state=ExecutionState.EXECUTING))
    proxy, admission = _FakeProxy(), _RecordingAdmission()
    reg.reconcile(proxy=proxy, admission=admission)
    assert proxy.reaped == [(4321, "999")]
    assert reg.read_record(key) is None
    assert admission.marked == []  # EXECUTING/no-halt → no recovery tombstone


def test_reconcile_tombstones_halted_record(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key, generation=7, backend_pid=None,
                              execution_state=ExecutionState.HALTED))
    proxy, admission = _FakeProxy(), _RecordingAdmission()
    reg.reconcile(proxy=proxy, admission=admission)
    tomb = reg.read_tombstone(key)
    assert tomb is not None and tomb.generation == 7
    assert admission.marked == [(key, 7)]
    assert reg.read_record(key) is None


def test_reconcile_is_idempotent_across_two_restarts(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    key = _key()
    reg.write_record(_session(key, generation=7, execution_state=ExecutionState.HALTED))
    reg.reconcile(proxy=_FakeProxy(), admission=_RecordingAdmission())
    # second "restart": fresh registry, same dir; tombstone persists, no record to re-tombstone
    reg2 = SessionRegistry(directory=tmp_path)
    admission2 = _RecordingAdmission()
    reg2.reconcile(proxy=_FakeProxy(), admission=admission2)
    assert reg2.read_tombstone(key) is not None
    assert admission2.marked == [(key, 7)]  # re-marked from the durable tombstone, idempotent
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_session_registry.py -k reconcile -q`
Expected: FAIL — `AttributeError: 'SessionRegistry' object has no attribute 'reconcile'`.

- [ ] **Step 3: Implement `reconcile`**

```python
# src/linux_debug_mcp/coordination/registry.py  (add typing Protocols + method)
from typing import Protocol

from linux_debug_mcp.transport.base import ExecutionState


class _ReapProxy(Protocol):
    def stop_by_identity(self, pid: int, start_time: str | None) -> None: ...


class _RecoveryMarker(Protocol):
    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None: ...


# inside SessionRegistry:
    def reconcile(self, *, proxy: _ReapProxy, admission: _RecoveryMarker) -> None:
        """Crash reconciliation (ADR 0005, spec §4.7/§10.2). MUST run after
        acquire_instance_lock() and BEFORE admission accepts its first admit. Reaps live
        orphan backends (start-time fenced — never a foreign pid), re-asserts every durable
        tombstone into admission, and tombstones any record left HALTED/UNKNOWN."""
        # 1. re-assert persisted tombstones (durable across restarts)
        for path in self._dir.glob("tomb-*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            key = TargetKey(provisioner=data["provisioner"], target_id=data["target_id"])
            admission.mark_recovery_required(key, data["generation"])
        # 2. reap orphan records
        for record in self.list_records():
            if record.backend_pid is not None:
                # start-time fence lives inside stop_by_identity (ADR 0004): a pid whose live
                # start-time != record.backend_start_time is never signalled.
                proxy.stop_by_identity(record.backend_pid, record.backend_start_time)
            if record.execution_state in (ExecutionState.HALTED, ExecutionState.UNKNOWN):
                self.write_tombstone(
                    RecoveryTombstone(
                        target_key=record.target_key,
                        generation=record.generation,
                        reason=f"reconciled_{record.execution_state.value}",
                    )
                )
                admission.mark_recovery_required(record.target_key, record.generation)
            self.delete_record(record.target_key)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_session_registry.py -q`
Expected: PASS (all session-registry tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/registry.py tests/test_session_registry.py
git commit -m "feat: add startup reconciliation and orphan reap to the registry (#10)"
```

---

### Task A5: consolidate the cancel/epoch fences into one transition table (ADR 0006)

**Files:**
- Modify: `src/linux_debug_mcp/coordination/admission.py`
- Test: `tests/test_admission.py` (exists — keep all green), `tests/test_exec_state_machine.py` (the property pass is **Task C2**; this task only refactors + documents)

This is a **behavior-preserving refactor**. The exec-epoch fences are today spread across `note_execution_transition` (epoch bump), `cancel_ssh_tier` (generation + per-handle `admit_epoch <= halt_epoch`), `complete` (the `admit_epoch != current_epoch` backstop), and `close_admission`/`_is_stale_lifecycle_close`. Consolidate them behind two named, single-definition fences and a transition-table docstring, so future changes reason about the table, not six interacting guards. **No existing `test_admission.py` assertion may change.**

- [ ] **Step 1: Confirm the existing suite is green (baseline)**

Run: `uv run python -m pytest tests/test_admission.py -q`
Expected: PASS (record the count — it must be identical after the refactor).

- [ ] **Step 2: Add the transition-table docstring + named fences**

```python
# src/linux_debug_mcp/coordination/admission.py  (add near the top of AdmissionService)
    # --- ADR 0006: the (generation, execution_epoch) fence model -------------------------
    # The async-halt gate is ONE state machine. `generation` rejects prior-incarnation events;
    # `execution_epoch` (bumped by note_execution_transition on EVERY exec-state transition)
    # rejects any ssh-tier op whose admitted epoch is stale relative to a halt. Two fences,
    # applied uniformly:
    #
    #   transition            | generation fence            | epoch fence
    #   ----------------------|-----------------------------|-----------------------------
    #   note_execution_*      | bump only if gen == current | (defines the epoch)
    #   admit_ssh_tier (DBG)  | proof.generation == current | proof.epoch == current
    #   cancel_ssh_tier       | gen == current snapshot     | per-handle admit_epoch<=halt
    #   complete (ssh-tier)   | (n/a)                       | admit_epoch == current (backstop)
    #
    # Authority to drive note_*/cancel_* is the live StopCapableGuard token (ADR 0002), not
    # modelled here. The property pass (test_exec_state_machine.py) drives this table.
    def _generation_current(self, target_key: TargetKey, generation: int) -> bool:
        snapshot = self._store.get(target_key)
        return snapshot is not None and generation == snapshot.generation

    def _epoch_stale_for_op(self, handle: AdmissionHandle) -> bool:
        return handle.op is AdmissionOp.SSH_TIER and handle.admit_epoch != self._exec_epoch.get(
            handle.target_key, 0
        )
```

- [ ] **Step 3: Route the existing guards through the named fences**

In `note_execution_transition`, replace the inline `generation != snapshot.generation` check with `if not self._generation_current(target_key, generation): return self._exec_epoch.get(target_key, 0)`. In `cancel_ssh_tier`, replace the `snapshot is None or generation != snapshot.generation` early-return with `if not self._generation_current(target_key, generation): return []`. In `complete`, replace the inline epoch backstop condition with `if self._epoch_stale_for_op(handle): raise AdmissionError(...)` (keep the same message/code). Do not change any message, code, or control flow — only the predicate source.

- [ ] **Step 4: Run the full admission suite — count must match the baseline**

Run: `uv run python -m pytest tests/test_admission.py -q`
Expected: PASS, identical count to Step 1. If any assertion changed behavior, the refactor was not behavior-preserving — revert and redo.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/admission.py
git commit -m "refactor: express the cancel/epoch fences as one named model (ADR 0006) (#10)"
```

---

### Task A6: endpoint-safety gate (pre-attach refusal + return-path belt)

**Files:**
- Create: `src/linux_debug_mcp/coordination/endpoint_safety.py`
- Test: `tests/test_endpoint_safety.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_endpoint_safety.py
import pytest

from linux_debug_mcp.coordination.endpoint_safety import (
    EndpointSafetyError,
    assert_loopback_endpoint,
    refuse_unsafe_exposure,
)
from linux_debug_mcp.transport.base import (
    EndpointExposure,
    TcpEndpoint,
    TransportCapability,
    TransportLocality,
    UnixSocketEndpoint,
)


def _cap(exposure: EndpointExposure, locality: TransportLocality) -> TransportCapability:
    return TransportCapability(
        provider_name="x", locality=locality, provides_console=True, provides_rsp=True,
        supports_uart_break=False, endpoint_exposure=exposure,
    )


def test_loopback_local_rsp_open_is_allowed():
    refuse_unsafe_exposure(_cap(EndpointExposure.LOOPBACK_LOCAL, TransportLocality.LOCAL), op="transport.open")


def test_brokered_required_rsp_open_is_refused_before_attach():
    with pytest.raises(EndpointSafetyError) as exc:
        refuse_unsafe_exposure(_cap(EndpointExposure.BROKERED_REQUIRED, TransportLocality.REMOTE), op="transport.open")
    assert exc.value.code == "endpoint_unsafe"


def test_loopback_tcp_endpoint_passes_return_path_assert():
    assert_loopback_endpoint(TcpEndpoint(host="127.0.0.1", port=5551))


def test_unix_socket_endpoint_passes_return_path_assert():
    assert_loopback_endpoint(UnixSocketEndpoint(path="/run/x.sock", mode=0o600))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_endpoint_safety.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the gate**

```python
# src/linux_debug_mcp/coordination/endpoint_safety.py
from __future__ import annotations

import ipaddress

from linux_debug_mcp.transport.base import (
    Endpoint,
    EndpointExposure,
    TcpEndpoint,
    TransportCapability,
    UnixSocketEndpoint,
)

# Ops that return / depend on a live stop-capable endpoint. A brokered_required transport
# may not satisfy these with a raw endpoint (spec §8.4).
_ENDPOINT_RETURNING_OPS = frozenset({"transport.open", "transport.inject_break"})


class EndpointSafetyError(RuntimeError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def refuse_unsafe_exposure(capability: TransportCapability, *, op: str) -> None:
    """Pre-attach §8.4 gate: decided from TRUSTED registry metadata BEFORE any guard, lease,
    secret resolution, or provider attach. A `brokered_required` transport's endpoint-returning
    open is refused `endpoint_unsafe` — it never reaches attach (ADR 0005 / roadmap Layer 4)."""
    if op in _ENDPOINT_RETURNING_OPS and capability.endpoint_exposure is EndpointExposure.BROKERED_REQUIRED:
        raise EndpointSafetyError(
            f"transport {capability.provider_name!r} is brokered_required; a raw endpoint open is "
            "refused until the #08 broker exists",
            code="endpoint_unsafe",
        )


def assert_loopback_endpoint(endpoint: Endpoint) -> None:
    """Return-path belt: the bound address must be loopback (TcpEndpoint already enforces this
    at the schema boundary; this re-asserts at assembly so a future Endpoint variant can't slip
    a routable address through). UnixSocketEndpoint is local by construction."""
    if isinstance(endpoint, TcpEndpoint):
        if not ipaddress.ip_address(endpoint.host).is_loopback:
            raise EndpointSafetyError(f"bound RSP endpoint is not loopback: {endpoint.host}", code="endpoint_unsafe")
    elif not isinstance(endpoint, UnixSocketEndpoint):
        raise EndpointSafetyError(f"unrecognized endpoint type {type(endpoint).__name__}", code="endpoint_unsafe")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_endpoint_safety.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/endpoint_safety.py tests/test_endpoint_safety.py
git commit -m "feat: add the endpoint-safety pre-attach gate and loopback assertion (#10)"
```

---

### Task A7: execution-state probe (fresh `ExecutionProof` from the durable record)

**Files:**
- Create: `src/linux_debug_mcp/coordination/exec_probe.py`
- Test: `tests/test_exec_probe.py`

The ssh-tier gate needs a **fresh** `ExecutionProof(generation, epoch, state)`. For local-qemu the authoritative `execution_state` is what the stop-capable controller wrote into the durable record; the probe reads that record, stamps the current admission epoch + generation, and returns `UNKNOWN` if no consistent record exists (fail-closed).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_exec_probe.py
from datetime import UTC, datetime

from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore, TargetSnapshot
from linux_debug_mcp.coordination.exec_probe import probe_execution_state
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.target import (ConsoleKind, PlatformMetadata, TargetKey, TargetState)
from linux_debug_mcp.transport.base import (ExecutionState, RecordState, TransportSession, new_session_id)


def _platform() -> PlatformMetadata:
    return PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                            dedicated_debug_line=False, ssh_reachable=True)


def _seed(store, key, gen=3):
    store.put(key, TargetSnapshot(generation=gen, transports=(), platform=_platform(),
                                  state=TargetState.DEBUGGING))


def _rec(key, state, gen=3):
    return TransportSession(session_id=new_session_id(), target_key=key, generation=gen,
                            provider="qemu-gdbstub", channel_id="rsp0",
                            record_state=RecordState.READY, execution_state=state,
                            created_at=datetime.now(UTC))


def test_probe_reports_executing(tmp_path):
    key = TargetKey(provisioner="local-qemu", target_id="r1")
    store = SnapshotStore(); _seed(store, key)
    admission = AdmissionService(store)
    reg = SessionRegistry(directory=tmp_path); reg.write_record(_rec(key, ExecutionState.EXECUTING))
    proof = probe_execution_state(registry=reg, admission=admission, target_key=key, generation=3)
    assert proof.state is ExecutionState.EXECUTING
    assert proof.generation == 3 and proof.epoch == admission.current_execution_epoch(key)


def test_probe_reports_halted(tmp_path):
    key = TargetKey(provisioner="local-qemu", target_id="r2")
    store = SnapshotStore(); _seed(store, key)
    admission = AdmissionService(store)
    reg = SessionRegistry(directory=tmp_path); reg.write_record(_rec(key, ExecutionState.HALTED))
    proof = probe_execution_state(registry=reg, admission=admission, target_key=key, generation=3)
    assert proof.state is ExecutionState.HALTED


def test_probe_unknown_when_no_record(tmp_path):
    key = TargetKey(provisioner="local-qemu", target_id="r3")
    store = SnapshotStore(); _seed(store, key)
    admission = AdmissionService(store)
    reg = SessionRegistry(directory=tmp_path)
    proof = probe_execution_state(registry=reg, admission=admission, target_key=key, generation=3)
    assert proof.state is ExecutionState.UNKNOWN
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_exec_probe.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the probe**

```python
# src/linux_debug_mcp/coordination/exec_probe.py
from __future__ import annotations

from linux_debug_mcp.coordination.admission import AdmissionService, ExecutionProof
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.transport.base import ExecutionState


def probe_execution_state(
    *, registry: SessionRegistry, admission: AdmissionService, target_key: TargetKey, generation: int
) -> ExecutionProof:
    """Layer-4 fresh liveness probe (§4.6). Reads the authoritative `execution_state` the
    stop-capable controller persisted into the durable record and stamps the current
    generation + execution epoch so the ssh-tier gate can fence a stale proof. Fail-closed:
    no record (or no executing fact) ⇒ UNKNOWN — never an optimistic EXECUTING."""
    record = registry.read_record(target_key)
    state = record.execution_state if record is not None else ExecutionState.UNKNOWN
    return ExecutionProof(
        generation=generation,
        epoch=admission.current_execution_epoch(target_key),
        state=state,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_exec_probe.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/exec_probe.py tests/test_exec_probe.py
git commit -m "feat: add the Layer-4 execution-state probe (#10)"
```

---

### Task A8: the `open()`/`close()` transaction (write-ahead, full rollback)

**Files:**
- Create: `src/linux_debug_mcp/coordination/transaction.py`
- Test: `tests/test_transport_transaction.py`

The transaction orchestrates §4.3 in order: (1) endpoint-safety pre-attach refusal from trusted capability metadata; (2) `admit`/`admit_recovery`; (3) break-plan selection; (4) `StopCapableGuard` acquire; (5) `ConsoleLease` acquire (only if `provides_console`); (6) secret resolution; (7) mint `session_id` + write-ahead OPENING record; (8) `attach` (partials recorded for rollback; the `"backend_process"` partial is **written through** into the OPENING record); (9) assemble `TransportSession` + loopback assert + READY record; (10) `promote`. Any failure rolls back in reverse, leaking nothing. A `crash_after` set lets tests raise at each labeled write-ahead stage.

Two correctness invariants resolved from review live here:

- **Write-ahead `backend_pid` (Finding #1 / ADR 0005).** The `on_partial` callback is a closure that, the instant the backend reports `"backend_process" {"pid","start_time"}` (`transport/proxy.py:184`), updates the OPENING record via `registry.write_record(...)` carrying `backend_pid`/`backend_start_time` **before** `attach()` returns. So a death anywhere between child spawn and the READY write leaves a durable record reconcile can reap — never a `backend_pid=None` record that leaks the orphan. The local `partials` dict is retained only for in-process rollback.
- **In-process fenced guard token (Finding #4 / ADR 0002).** The durable record's `stop_guard_token: str` is a frozen bare string (spec §3.2 / ADR 0003) and cannot carry the `GuardToken` fence. The transaction therefore keeps an in-memory `dict[str, GuardToken]` keyed by `session_id`; `close()` and the lifecycle subscriber release via the **fenced** `self._guard.release(target_key, token)` (`seams/guard.py:55`), never the coarse `revoke()`. After a restart the in-memory token is gone, but the prior holder is provably dead (single-instance flock + reconcile-before-admit, ADR 0005), so reconciliation force-freeing via `revoke()` is correct — no competing live holder can exist.
- **Dual-write recovery tombstone (Finding #5 / ADR 0005).** A close-while-`HALTED`/`UNKNOWN` marks recovery through the single dual-write helper (`registry.write_tombstone(...)` + `admission.mark_recovery_required(...)`), never the tombstone alone — the durable tombstone is the source of truth and admission's gate is a write-through cache.

- [ ] **Step 1: Write the failing test (happy path + endpoint_unsafe + one rollback point + close)**

```python
# tests/test_transport_transaction.py
import pytest

from _layer4_fakes import (
    KEY, FakeBrokeredTransport, FakeQemuTransport, build_txn, make_request)
from linux_debug_mcp.coordination.endpoint_safety import EndpointSafetyError
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager, LeaseOwner
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.guard import InProcessStopCapableGuard
from linux_debug_mcp.transport.base import BackendAttachment, RecordState, TcpEndpoint


def test_open_happy_path_returns_loopback_session(tmp_path):
    txn, admission = build_txn(FakeQemuTransport(), registry=SessionRegistry(directory=tmp_path))
    session = txn.open(make_request())
    assert session.record_state is RecordState.READY
    assert isinstance(session.rsp_endpoint, TcpEndpoint) and session.rsp_endpoint.host == "127.0.0.1"
    assert session.stop_guard_token is not None
    # promoted: a second open on the same target is refused by the guard
    with pytest.raises(Exception):
        txn.open(make_request())


def test_brokered_required_refused_before_any_acquisition(tmp_path):
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    txn, _ = build_txn(FakeBrokeredTransport(), guard=guard, leases=leases,
                       registry=SessionRegistry(directory=tmp_path))
    with pytest.raises(EndpointSafetyError) as exc:
        txn.open(make_request(provider="redfish-sol"))
    assert exc.value.code == "endpoint_unsafe"
    # no guard acquired, no lease, no record written
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE
    assert SessionRegistry(directory=tmp_path).read_record(KEY) is None


def test_attach_failure_rolls_back_everything(tmp_path):
    guard, leases = InProcessStopCapableGuard(), ConsoleLeaseManager()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(crash=True), guard=guard, leases=leases, registry=reg)
    with pytest.raises(RuntimeError, match="attach blew up"):
        txn.open(make_request())
    assert reg.read_record(KEY) is None        # write-ahead record deleted
    assert leases.snapshot(KEY)[0] is LeaseOwner.FREE  # no lease leaked
    # guard freed via the FENCED release → a fresh open can now acquire
    txn_ok, _ = build_txn(FakeQemuTransport(), guard=guard, leases=leases, registry=reg)
    assert txn_ok.open(make_request()).record_state is RecordState.READY


def test_on_partial_writes_backend_pid_through_before_ready(tmp_path):
    # Finding #1: the backend pid must be in the durable OPENING record the instant the
    # backend_process partial fires — before attach() returns — so a death before READY is
    # reapable. A transport that reads its own record mid-attach proves the write-through ordering.
    reg = SessionRegistry(directory=tmp_path)

    class ReadsOwnRecordAtAttach(FakeQemuTransport):
        def attach(self, request, *, cancel, deadline, on_partial):
            attachment = super().attach(request, cancel=cancel, deadline=deadline, on_partial=on_partial)
            self.seen = reg.read_record(KEY)  # after the backend_process partial wrote through
            return attachment

    transport = ReadsOwnRecordAtAttach(backend_pid=4321, backend_start_time="999")
    txn, _ = build_txn(transport, registry=reg)
    txn.open(make_request())
    assert transport.seen is not None and transport.seen.backend_pid == 4321
    assert transport.seen.record_state is RecordState.OPENING


def test_close_reaps_and_clears(tmp_path):
    transport = FakeQemuTransport()
    reg = SessionRegistry(directory=tmp_path)
    txn, _ = build_txn(transport, registry=reg)
    session = txn.open(make_request())
    txn.close(session.session_id)
    assert transport.closed == [session.session_id]
    assert reg.read_record(KEY) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_transport_transaction.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the transaction**

```python
# src/linux_debug_mcp/coordination/transaction.py
from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from linux_debug_mcp.coordination.admission import AdmissionService, ExecutionProof
from linux_debug_mcp.coordination.endpoint_safety import assert_loopback_endpoint, refuse_unsafe_exposure
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager, LeaseOwner
from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.coordination.selection import select_stop_capable_channel
from linux_debug_mcp.seams.guard import GuardToken, StopCapableGuard
from linux_debug_mcp.seams.secrets import SecretsResolver
from linux_debug_mcp.transport.base import (
    ExecutionState, OpenRequest, RecordState, Transport, TransportSession, new_session_id)

_ATTACH_DEADLINE_SECONDS = 30.0


class TransportTransaction:
    """The §4.3 open()/close() write-ahead transaction (ADR 0003/0005). Owns TransportSession
    end-to-end; rolls back in reverse at every step, leaking no guard/lease/record/backend."""

    def __init__(self, *, admission: AdmissionService, registry: SessionRegistry,
                 guard: StopCapableGuard, leases: ConsoleLeaseManager, secrets: SecretsResolver,
                 break_policy, transports: dict[str, Transport]) -> None:
        self._admission = admission
        self._registry = registry
        self._guard = guard
        self._leases = leases
        self._secrets = secrets
        self._break_policy = break_policy
        self._transports = transports
        # Finding #4: the fenced GuardToken is held in-process (the frozen stop_guard_token: str
        # cannot carry the fence — ADR 0003); close()/lifecycle release by this token, not revoke().
        self._tokens: dict[str, GuardToken] = {}

    def open(self, request: OpenRequest, *, recovery: bool = False,
             crash_after: frozenset[str] = frozenset()) -> TransportSession:
        transport = self._transports[request.transport_ref.provider]
        capability = transport.capability
        # (1) pre-attach endpoint-safety refusal — trusted metadata, before any acquisition.
        refuse_unsafe_exposure(capability, op="transport.open")
        # (2) admission.
        handle = (self._admission.admit_recovery if recovery else self._admission.admit)(
            request.target_key, request)
        guard_token: GuardToken | None = None
        lease_token: str | None = None
        session_id: str | None = None
        backend_pid: int | None = None
        backend_start: str | None = None
        try:
            # (3) break-plan selection (authoritative channel from the handle).
            selection = select_stop_capable_channel(
                target_key=request.target_key, transports=(handle.channel,),
                required_caps=request.required_caps, platform=handle.platform,
                break_policy=self._break_policy)
            _crash(crash_after, "selected")
            # (4) stop-capable guard (target-wide single holder).
            guard_token = self._guard.acquire(request.target_key)
            _crash(crash_after, "guard")
            # (5) console lease (only providers that own a console).
            if capability.provides_console:
                lease_token = self._leases.acquire(request.target_key, LeaseOwner.TRANSPORT)
            _crash(crash_after, "lease")
            # (6) secrets (never persisted/logged).
            self._secrets.resolve(list(handle.channel.secret_refs))
            # (7) write-ahead OPENING record. The fenced token is held in-process keyed by
            # session_id (stop_guard_token persists only its secret as an audit marker — ADR 0003).
            session_id = new_session_id()
            self._tokens[session_id] = guard_token
            record = TransportSession(
                session_id=session_id, target_key=request.target_key, generation=request.generation,
                provider=capability.provider_name, channel_id=handle.channel.channel_id,
                record_state=RecordState.OPENING, console_lease_token=lease_token,
                stop_guard_token=guard_token.secret, attach_epoch=handle.admit_epoch,
                break_plan=selection.break_plan, execution_state=ExecutionState.EXECUTING,
                created_at=datetime.now(UTC))
            self._registry.write_record(record)
            _crash(crash_after, "record_written")
            # (8) attach. The on_partial closure WRITES THROUGH backend_pid/start-time into the
            # durable OPENING record the instant "backend_process" is reported — before attach()
            # returns — so a death before READY is reapable (Finding #1). `partials` stays for
            # in-process rollback.
            partials: dict[str, object] = {}

            def on_partial(label: str, resource: object) -> None:
                partials[label] = resource
                if label == "backend_process":
                    nonlocal backend_pid, backend_start
                    backend_pid, backend_start = resource["pid"], resource.get("start_time")
                    self._registry.write_record(record.model_copy(update=dict(
                        backend_pid=backend_pid, backend_start_time=backend_start)))

            attachment = transport.attach(
                request, cancel=threading.Event(), deadline=time.monotonic() + _ATTACH_DEADLINE_SECONDS,
                on_partial=on_partial)
            if attachment.backend_pid is not None:
                backend_pid, backend_start = attachment.backend_pid, attachment.backend_start_time
            # (9) assemble + loopback assert + READY record.
            for endpoint in (attachment.console_endpoint, attachment.rsp_endpoint):
                if endpoint is not None:
                    assert_loopback_endpoint(endpoint)
            session = record.model_copy(update=dict(
                record_state=RecordState.READY, console_endpoint=attachment.console_endpoint,
                rsp_endpoint=attachment.rsp_endpoint, backend_pid=backend_pid,
                backend_start_time=backend_start,
                artifacts=[attachment.console_artifact] if attachment.console_artifact else []))
            self._registry.write_record(session)
            _crash(crash_after, "ready")
            # (10) commit. A recovery attach clears the recovery gate through the DUAL-WRITE
            # helper (Finding #5) — durable tombstone + admission cache together, never one alone.
            self._admission.promote(handle)
            if recovery:
                self._clear_recovery(request.target_key, request.generation)
            return session
        except BaseException:
            self._rollback(request.target_key, handle, guard_token, lease_token, session_id,
                           backend_pid, backend_start, transport)
            raise

    def _rollback(self, target_key, handle, guard_token, lease_token, session_id,
                  backend_pid, backend_start, transport) -> None:
        # reverse order; each guarded so a partial rollback still completes.
        if backend_pid is not None:
            try:
                getattr(transport, "_proxy", None) and transport._proxy.stop_by_identity(backend_pid, backend_start)
            except Exception:
                pass
        if session_id is not None:
            self._tokens.pop(session_id, None)
            self._registry.delete_record(target_key)
        if lease_token is not None:
            self._leases.release(target_key, lease_token)
        if guard_token is not None:
            self._guard.release(target_key, guard_token)  # FENCED by-token release (ADR 0002)
        try:
            self._admission.rollback(handle)
        except Exception:
            pass

    def close(self, session_id: str, *, force: bool = False) -> None:
        # load the durable record by scanning (close is keyed by session_id; the record is by
        # TargetKey, so resolve via list_records — small set).
        record = next((r for r in self._registry.list_records() if r.session_id == session_id), None)
        if record is None:
            return
        transport = self._transports[record.provider]
        closing = record.model_copy(update=dict(record_state=RecordState.CLOSING))
        self._registry.write_record(closing)
        transport.close(closing)
        if record.console_lease_token is not None:
            self._leases.release(record.target_key, record.console_lease_token)
        # FENCED by-token release (Finding #4): the in-memory GuardToken, never revoke().
        token = self._tokens.pop(session_id, None)
        if token is not None:
            self._guard.release(record.target_key, token)
        # close-while-halted marks recovery via the DUAL-WRITE helper (Finding #5): durable
        # tombstone + admission cache together, never one alone. Otherwise delete cleanly.
        if record.execution_state in (ExecutionState.HALTED, ExecutionState.UNKNOWN) and not force:
            self._mark_recovery(record.target_key, record.generation, reason="closed_while_halted")
        self._registry.delete_record(record.target_key)

    def _mark_recovery(self, target_key, generation: int, *, reason: str) -> None:
        """Single source of truth is the durable tombstone; admission's `_recovery_required` is a
        write-through cache (Finding #5 / ADR 0005). Always write BOTH atomically."""
        self._registry.write_tombstone(RecoveryTombstone(
            target_key=target_key, generation=generation, reason=reason))
        self._admission.mark_recovery_required(target_key, generation)

    def _clear_recovery(self, target_key, generation: int) -> None:
        """Clearance counterpart of `_mark_recovery`: every clearance path (recovery attach, reset
        advancing generation, probe→EXECUTING) routes here so the tombstone and the cache clear
        together — never one without the other."""
        self._registry.clear_tombstone(target_key, expected_generation=generation)
        self._admission.clear_recovery_required(target_key, generation)


def _crash(crash_after: frozenset[str], label: str) -> None:
    """Write-ahead crash-point seam (ADR 0005): tests pass `crash_after={label}` to simulate a
    process death immediately after a labeled durable stage, exercising rollback/reconciliation."""
    if label in crash_after:
        raise _SimulatedCrash(label)


class _SimulatedCrash(RuntimeError):
    pass
```

> **Note for the implementer (Finding #4, resolved here):** `close()` releases the guard via the **fenced** `self._guard.release(target_key, token)` using the in-memory `session_id → GuardToken` map — not `revoke()`. The durable `stop_guard_token: str` is a frozen bare string (spec §3.2 / ADR 0003) and carries only the secret as an audit marker, so it cannot drive a fenced release; the in-process token is the authority within a server lifetime. Across a restart the map is empty, but the prior holder is provably dead (single-instance flock + reconcile-before-admit, ADR 0005), so reconciliation's force-free via `revoke()` is the correct path there — there is no competing live holder to fence against. Do not reintroduce `revoke()` on the `close()` path.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_transport_transaction.py -q`
Expected: PASS (5 passed). This module is the **first import** of the Task A0 `_layer4_fakes` harness (and its verification) — until now nothing imported it, so committing the harness at A0 left the suite green; this is where it first resolves `TransportTransaction`.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/transaction.py tests/test_transport_transaction.py
git commit -m "feat: add the open/close transaction with full rollback (#10)"
```

---

### Task A9: local-qemu snapshot adapter + lifecycle invalidation wiring

**Files:**
- Modify: `src/linux_debug_mcp/seams/target.py` (add `publish_ready_snapshot`)
- Modify: `src/linux_debug_mcp/coordination/transaction.py` (subscribe to lifecycle; `on_invalidate`)
- Test: `tests/test_transport_transaction.py` (add)

A live transport session subscribes to the `LifecycleDispatcher`. An invalidation-class event (reset/crash/release/lease-expired) is **terminal**: the transaction's subscriber revokes its guard/lease and force-reaps its backend out-of-band (the `force_drop` path), and admission is closed first (`invalidate_lifecycle`). The local-qemu adapter publishes the authoritative `TargetSnapshot` when a run boots READY.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_transport_transaction.py  (add)
from _layer4_fakes import KEY, FakeQemuTransport, build_txn, make_request
from linux_debug_mcp.coordination.lease import ConsoleLeaseManager
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.seams.guard import InProcessStopCapableGuard
from linux_debug_mcp.seams.lifecycle import InProcessLifecycleDispatcher, LifecycleEvent, LifecycleKind


def test_lifecycle_invalidation_revokes_guard_and_reaps(tmp_path):
    transport = FakeQemuTransport()
    guard, leases, reg = InProcessStopCapableGuard(), ConsoleLeaseManager(), SessionRegistry(directory=tmp_path)
    dispatcher = InProcessLifecycleDispatcher()
    txn, admission = build_txn(transport, guard=guard, leases=leases, registry=reg)
    txn.bind_lifecycle(dispatcher)
    session = txn.open(make_request())
    # an invalidation tears the session down: admission closed, guard freed (FENCED release), record gone
    admission.invalidate_lifecycle(
        LifecycleEvent(target_key=KEY, kind=LifecycleKind.CRASHED), dispatcher, generation=1)
    assert reg.read_record(KEY) is None
    # guard is free → a new incarnation (after a generation bump) could acquire
    assert guard.acquire(KEY) is not None
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_transport_transaction.py -k lifecycle -q`
Expected: FAIL — `AttributeError: 'TransportTransaction' object has no attribute 'bind_lifecycle'`.

- [ ] **Step 3: Implement the subscriber + adapter**

```python
# src/linux_debug_mcp/coordination/transaction.py  (add to TransportTransaction)
    def bind_lifecycle(self, dispatcher) -> None:
        self._dispatcher = dispatcher

    def _subscribe_session(self, session: TransportSession, guard_token, lease_token, backend_pid, backend_start):
        if getattr(self, "_dispatcher", None) is None:
            return
        transaction = self

        class _Sub:
            def invalidate(self, event, deadline) -> None:
                self.force_drop(event)

            def force_drop(self, event) -> None:
                # out-of-band release of recorded resources (lifecycle force_drop contract).
                if backend_pid is not None:
                    try:
                        getattr(transaction._transports[session.provider], "_proxy", None) and \
                            transaction._transports[session.provider]._proxy.stop_by_identity(backend_pid, backend_start)
                    except Exception:
                        pass
                if lease_token is not None:
                    transaction._leases.release(session.target_key, lease_token)
                if guard_token is not None:
                    transaction._guard.release(session.target_key, guard_token)
                transaction._registry.delete_record(session.target_key)

        self._dispatcher.subscribe(session.target_key, session.session_id, _Sub())
```

In `open()`, after `promote`, call `self._subscribe_session(session, guard_token, lease_token, backend_pid, backend_start)` before `return session`.

```python
# src/linux_debug_mcp/seams/target.py  (add)
def publish_ready_snapshot(admission, *, target_key, generation, transports, platform, lease=None) -> None:
    """Local-qemu adapter: publish the authoritative TargetSnapshot when a run boots READY,
    so admission can re-bind/validate transport.open requests against it (§4.1). Provisioning
    later owns this writer; the local-qemu path ships it now behind the same call."""
    from linux_debug_mcp.coordination.admission import TargetSnapshot
    from linux_debug_mcp.seams.target import TargetState
    admission.publish_snapshot(target_key, TargetSnapshot(
        generation=generation, transports=tuple(transports), platform=platform,
        state=TargetState.READY, lease=lease))
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_transport_transaction.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit + Phase A checkpoint**

```bash
git add src/linux_debug_mcp/coordination/transaction.py src/linux_debug_mcp/seams/target.py tests/test_transport_transaction.py
git commit -m "feat: wire lifecycle invalidation and the local-qemu snapshot adapter (#10)"
uv run python -m pytest -q && uv run ruff check . && uv run ruff format --check . && just check-docs
```

Expected: full suite + lint + docs guard green. **Phase A review checkpoint** — dispatch a whole-phase code review before starting Phase B.

---

## Phase B — public surface (server.py + provider edits)

> Phase B is the only phase that returns a live endpoint, halts a kernel, or exposes a `transport.*` tool. Per the roadmap, all of §10.2 must be green together (Phase C) before this work merges — but the code lands here.

### Task B-pre: lift the shared handler-test fakes into `tests/conftest.py`

**Files:**
- Modify: `tests/conftest.py`
- Modify: `tests/test_target_boot_handler.py`, `tests/test_target_run_tests_handler.py`

**Why this is first (second-round Finding #2).** B0 reuses the existing `target_boot_handler` harness and B2 reuses the `target_run_tests_handler` harness. The repo convention for shared test helpers is **`from conftest import …`** — that is where `make_source_tree`/`NoopBuildRunner` already live, and both handler-test modules already `import` from it. There are **no** test-module-to-test-module imports in the suite today; adding `from test_target_boot_handler import …` / `from test_target_run_tests_handler import …` in B0/B2 would introduce that anti-pattern. Separately, B2 makes `target_run_tests_handler` call `provider.execute_tests(plan, cancel=runner_cancel)` (`server.py:1327`), but the current `FakeTestProvider.execute_tests(self, plan)` (`tests/test_target_run_tests_handler.py:32`) takes no `cancel` → `TypeError` in the 16 existing run-tests tests. Lifting the shared builders into `conftest.py` once — and giving the relocated `FakeTestProvider.execute_tests` an optional `*, cancel=None` — fixes both: the new Phase B tests import `from conftest`, and the existing tests survive the handler change unchanged.

- [ ] **Step 1: Move the shared builders into `conftest.py`**

Move out of `tests/test_target_boot_handler.py`: `FakeBootProvider`, `target_profile`, `create_run`, `record_build`, `profiles`. Move out of `tests/test_target_run_tests_handler.py`: `FakeTestProvider`, `create_booted_run`, `rootfs`. Give the relocated `FakeTestProvider` the signature `def execute_tests(self, plan, *, cancel=None)` (the 16 existing callers pass no `cancel` and are unaffected; B2's handler passes `cancel=runner_cancel`). No behavior change to any builder — pure relocation.

- [ ] **Step 2: Update the two existing modules to import from `conftest`**

Both modules already do `from conftest import make_source_tree`; extend that import to pull the relocated builders (`from conftest import FakeBootProvider, create_run, make_source_tree, profiles, record_build, target_profile` in the boot module; `from conftest import FakeTestProvider, create_booted_run, make_source_tree, rootfs` in the run-tests module). Remove the now-moved definitions from each module.

- [ ] **Step 3: Re-run both modules green (the regression gate)**

Run: `uv run python -m pytest tests/test_target_boot_handler.py tests/test_target_run_tests_handler.py -q`
Expected: PASS, identical count to before the move — the relocation and the optional `cancel=None` are behavior-preserving for the existing tests.

- [ ] **Step 4: Commit**

```bash
git add tests/conftest.py tests/test_target_boot_handler.py tests/test_target_run_tests_handler.py
git commit -m "test: lift shared boot/run-tests fakes into conftest, add optional cancel kwarg (#10)"
```

---

### Task B0: publish the `TargetSnapshot` on boot-to-READY (the producer — unblocks every Phase B gate)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`target_boot_handler`, ~909)
- Test: `tests/test_server_boot_snapshot_producer.py`

**Why this is first.** `AdmissionService._bind_snapshot` admits a `transport.open` / ssh-tier op only against an authoritative `TargetSnapshot`. For the local-qemu-only path that ships in #10 there is no provisioner to publish one — so without this producer, every Phase B admission gate (`debug.start_session` B3, `target.run_tests` B2, `transport.*` B5) fails closed with `stale_handle`. ADR 0007 records the identity mapping; this task is the writer.

On boot-to-`StepStatus.SUCCEEDED`, `target_boot_handler` publishes the snapshot (ADR 0007):

- `TargetKey(provisioner="local-qemu", target_id=run_id)`;
- `generation = boot_attempt.attempt` — reuse `BootAttempt.attempt` (`artifacts/manifest.py:13`), no new manifest field;
- when the boot recorded a `gdbstub_endpoint` detail (`server.py:~1062`), an RSP channel `TransportRef(provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",), target_ref={"host": …, "port": …})`; otherwise an empty transport tuple;
- `PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, break_hints=[BreakHint.GDBSTUB_NATIVE], ssh_reachable=…)`, where `ssh_reachable` is whether the run's `RootfsProfile` carries `ssh_host`/`ssh_port` (`config.py:~248`);
- `publish_ready_snapshot(admission, target_key=…, generation=…, transports=[rsp_channel], platform=…)` (Task A9).

Inject the `AdmissionService` via a new optional `admission: AdmissionService | None = None` handler param (mirroring the existing `provider=`/`target_profiles=` injection), so the test passes a fake. B2/B3/B5 read this published snapshot rather than re-deriving the `TargetKey`/`generation`/`platform`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server_boot_snapshot_producer.py
import pytest

# the boot machinery (FakeBootProvider + create_run/record_build/profiles) is the shared
# handler harness relocated into conftest by Task B-pre; reuse it rather than re-inlining a boot fake.
from conftest import FakeBootProvider, create_run, profiles, record_build, target_profile

from linux_debug_mcp.coordination.admission import AdmissionError, AdmissionService, SnapshotStore
from linux_debug_mcp.config import TargetProfile
from linux_debug_mcp.seams.target import TargetKey
from linux_debug_mcp.server import target_boot_handler
from linux_debug_mcp.transport.base import LineRole, OpenRequest, TransportRef


def _debug_target() -> TargetProfile:
    return target_profile().model_copy(update={"debug_gdbstub": True})


def _rsp_request(generation: int) -> OpenRequest:
    key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    ref = TransportRef(provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))
    return OpenRequest(target_key=key, generation=generation, transport_ref=ref)


def _boot(artifact_root, tmp_path, admission, *, force_reboot=False):
    return target_boot_handler(
        artifact_root=artifact_root, run_id="run-abc123", provider=FakeBootProvider(),
        admission=admission, force_reboot=force_reboot,
        **profiles(tmp_path, target=_debug_target()))


def test_boot_publishes_ready_snapshot(tmp_path):
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    admission = AdmissionService(SnapshotStore())
    response = _boot(artifact_root, tmp_path, admission)
    assert response.ok is True
    # the snapshot was published, so admission can now bind the RSP channel (no stale_handle).
    handle = admission.admit(_rsp_request(generation=1).target_key, _rsp_request(generation=1))
    assert handle is not None


def test_reboot_bumps_generation_invalidates_old(tmp_path):
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    admission = AdmissionService(SnapshotStore())
    _boot(artifact_root, tmp_path, admission)                      # attempt 1 → generation 1
    stale = _rsp_request(generation=1)                              # minted against generation 1
    _boot(artifact_root, tmp_path, admission, force_reboot=True)    # attempt 2 → generation 2
    with pytest.raises(AdmissionError) as exc:
        admission.admit(stale.target_key, stale)
    assert exc.value.code == "stale_handle"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_server_boot_snapshot_producer.py -q`
Expected: FAIL — `target_boot_handler` has no `admission` param / publishes no snapshot, so `admit` raises `stale_handle` even on the first boot.

- [ ] **Step 3: Implement the producer**

Add the `admission: AdmissionService | None = None` param. On the terminal `SUCCEEDED` path (after the boot result is recorded, beside the `gdbstub_endpoint` detail at `server.py:~1062`), and only when `admission is not None`, build the `TargetKey`/`generation`/`transports`/`PlatformMetadata` as above and call `publish_ready_snapshot(...)`. Leave every existing boot assertion unchanged.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_server_boot_snapshot_producer.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_boot_snapshot_producer.py
git commit -m "feat: publish the local-qemu TargetSnapshot on boot-to-READY (ADR 0007) (#10)"
```

---

### Task B1: cancellable ssh runner (kill the in-flight subprocess on halt)

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_ssh_tests.py`
- Test: `tests/test_local_ssh_tests.py` (exists — add)

Today `SubprocessSshRunner.run` calls `subprocess.run(...)` with only a `timeout` — there is **no** cancellation. Replace with `Popen` + a wait loop honoring a `cancel: threading.Event`, killing the process group on cancel. Thread an optional `cancel` through `LocalSshTestProvider.execute_tests` → `runner.run`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_local_ssh_tests.py  (add)
import threading, time

from linux_debug_mcp.providers.local_ssh_tests import SubprocessSshRunner


def test_run_is_killed_on_cancel(tmp_path):
    runner = SubprocessSshRunner()
    cancel = threading.Event()
    out, err = tmp_path / "o", tmp_path / "e"
    t = threading.Timer(0.2, cancel.set)
    t.start()
    start = time.monotonic()
    result = runner.run(["sleep", "30"], timeout=30, stdout_path=out, stderr_path=err, cancel=cancel)
    t.cancel()
    assert time.monotonic() - start < 5          # killed, not waited 30s
    assert result.cancelled is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_local_ssh_tests.py -k cancel -q`
Expected: FAIL — `run()` has no `cancel` kwarg / `SshCommandResult` has no `cancelled`.

- [ ] **Step 3: Implement cancellable run**

```python
# src/linux_debug_mcp/providers/local_ssh_tests.py  (replace the subprocess.run body)
import os, signal, subprocess, threading

# add `cancelled: bool = False` to SshCommandResult; add `cancel: threading.Event | None = None`
# to the SshRunner.run Protocol and SubprocessSshRunner.run signature.

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None):
        with open(stdout_path, "w") as out, open(stderr_path, "w") as err:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, text=True,
                                    shell=False, start_new_session=True)
            deadline = None if timeout is None else (threading.TIMEOUT_MAX if timeout is None else timeout)
            waited = 0.0
            while True:
                try:
                    proc.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    waited += 0.1
                    if cancel is not None and cancel.is_set():
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                        return SshCommandResult(exit_status=-1, timed_out=False, cancelled=True)
                    if timeout is not None and waited >= timeout:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                        return SshCommandResult(exit_status=-1, timed_out=True)
        return SshCommandResult(exit_status=proc.returncode, timed_out=False)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_local_ssh_tests.py -q`
Expected: PASS (existing tests + new cancel test).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/local_ssh_tests.py tests/test_local_ssh_tests.py
git commit -m "feat: make the ssh runner cancellable (kill in-flight on halt) (#10)"
```

---

### Task B2: gate `target.run_tests` through `admit_ssh_tier` (with kill-on-halt)

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`target_run_tests_handler`, ~1218)
- Test: `tests/test_server_run_tests_gating.py`

The gate wraps **only the live-execution path**. A terminal cached `SUCCEEDED`/`FAILED` stays a pure manifest read (no gate). A cached `RUNNING` while the target is `HALTED` is terminalized. A fresh/forced run probes execution state; `HALTED` ⇒ `failure(READINESS_FAILURE, "target_halted")`; an admitted-then-halted run is cancelled (subprocess killed). The `TargetKey`/`generation`/`platform` come from the snapshot **published by Task B0** (ADR 0007) — `target_key = TargetKey("local-qemu", run_id)`, `generation = BootAttempt.attempt` — not re-derived here. Inject the `AdmissionService` + `SessionRegistry` via new optional handler params (mirroring the existing `provider=`/`test_suites=` injection) so tests pass fakes.

**The cancel bridge (Finding #2 / Finding #1 of the second review round).** A halt sets the `AdmissionHandle._cancel` fence on another thread (`cancel_ssh_tier`), but the ssh runner waits on a *different* object — its own `threading.Event`. Nothing connects them unless we build the edge. After `admit_ssh_tier` returns the handle, the handler spawns a **teardown-bounded daemon watcher** that polls `handle.wait_cancelled(0.1)` inside a loop guarded by a `watch_done` event, and the handler `join`s the watcher in a `finally` (see Step 3). This must NOT be the fire-and-forget `if handle.wait_cancelled(): runner_cancel.set()` form: `wait_cancelled(timeout=None)` parks until `_cancel` is set, but `complete()`/`_dispose_locked()` on the normal completion path never set `_cancel` (only the cancel paths do — `coordination/admission.py:191,671,774` vs. `:648,819`). An unbounded watcher therefore blocks forever on every non-halted run, leaking one daemon thread + the pinned completed `AdmissionHandle` + the `runner_cancel` closure per `target.run_tests` in a long-lived server. The bounded poll plus the `watch_done`/`join` teardown is what guarantees a normal completion tears the watcher down. `cancel_ssh_tier` already fences every live SSH_TIER binding for the target, so no separate cancel registry is needed; the watcher is just the per-op delivery edge from that fence to the subprocess.

- [ ] **Step 1: Write the failing tests** (the async-halt case is a full body; the two mechanical cases assert exact code/identity)

```python
# tests/test_server_run_tests_gating.py
import threading
import time
from datetime import UTC, datetime

from conftest import FakeTestProvider, create_booted_run, rootfs  # relocated in Task B-pre

from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore
from linux_debug_mcp.coordination.registry import SessionRegistry
from linux_debug_mcp.domain import ErrorCategory, StepResult, StepStatus
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult
from linux_debug_mcp.seams.target import (
    BreakHint, ConsoleKind, PlatformMetadata, TargetKey)
from linux_debug_mcp.server import target_run_tests_handler
from linux_debug_mcp.transport.base import (
    ExecutionState, LineRole, RecordState, TransportRef, TransportSession, new_session_id)

RUN_ID = "run-abc123"
KEY = TargetKey(provisioner="local-qemu", target_id=RUN_ID)
PLATFORM = PlatformMetadata(console_kind=ConsoleKind.UART, console_count=1,
                            dedicated_debug_line=False, ssh_reachable=True,
                            break_hints=[BreakHint.GDBSTUB_NATIVE])
CHANNEL = TransportRef(provider="qemu-gdbstub", channel_id="rsp0", line_role=LineRole.RSP, caps=("rsp",))


def _seed_admission(generation: int = 1) -> AdmissionService:
    from linux_debug_mcp.seams.target import publish_ready_snapshot
    admission = AdmissionService(SnapshotStore())
    publish_ready_snapshot(admission, target_key=KEY, generation=generation,
                           transports=[CHANNEL], platform=PLATFORM)
    return admission


def _record(reg: SessionRegistry, state: ExecutionState, generation: int = 1) -> None:
    reg.write_record(TransportSession(
        session_id=new_session_id(), target_key=KEY, generation=generation,
        provider="qemu-gdbstub", channel_id="rsp0", record_state=RecordState.READY,
        execution_state=state, created_at=datetime.now(UTC)))


def test_fresh_run_rejected_while_halted(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    reg = SessionRegistry(directory=tmp_path / "reg")
    _record(reg, ExecutionState.HALTED)
    response = target_run_tests_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=_seed_admission(), session_registry=reg)
    assert response.ok is False
    assert response.error.category == ErrorCategory.READINESS_FAILURE
    assert response.error.details["code"] == "target_halted"


def test_cached_succeeded_served_while_halted(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    # pre-record a terminal SUCCEEDED run_tests step; it is a pure read even while HALTED.
    from linux_debug_mcp.artifacts.store import ArtifactStore
    ArtifactStore(artifact_root, create_root=False).record_step_result(RUN_ID, StepResult(
        step_name="run_tests", status=StepStatus.SUCCEEDED, summary="cached pass"))
    reg = SessionRegistry(directory=tmp_path / "reg")
    _record(reg, ExecutionState.HALTED)

    class SpyAdmission(AdmissionService):
        ssh_tier_calls = 0
        def admit_ssh_tier(self, *a, **k):  # noqa: ANN001
            type(self).ssh_tier_calls += 1
            return super().admit_ssh_tier(*a, **k)

    admission = SpyAdmission(SnapshotStore())
    response = target_run_tests_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission, session_registry=reg)
    assert response.ok is True                       # served from the manifest
    assert SpyAdmission.ssh_tier_calls == 0          # never entered the gate


def test_admitted_then_halted_run_is_cancelled(tmp_path):
    artifact_root = create_booted_run(tmp_path)
    reg = SessionRegistry(directory=tmp_path / "reg")
    _record(reg, ExecutionState.EXECUTING)           # admittable; halt arrives mid-run
    admission = _seed_admission()

    class CancelAwareProvider(FakeTestProvider):
        def __init__(self):
            super().__init__()
            self.cancel_observed = threading.Event()
        def execute_tests(self, plan, *, cancel=None):
            self.executions += 1
            if cancel is not None and cancel.wait(5) and cancel.is_set():
                self.cancel_observed.set()
                return TestExecutionResult(status=StepStatus.FAILED, summary="cancelled",
                                           artifacts=[], details={"cancelled": True})
            return self.result

    provider = CancelAwareProvider()

    # fire the async halt shortly after the handler admits and the runner starts blocking.
    def _halt():
        time.sleep(0.2)
        halt_epoch = admission.note_execution_transition(KEY, 1)
        admission.cancel_ssh_tier(KEY, 1, halt_epoch=halt_epoch)

    live_before = set(threading.enumerate())
    timer = threading.Thread(target=_halt, daemon=True)
    timer.start()
    start = time.monotonic()
    response = target_run_tests_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission, session_registry=reg)
    elapsed = time.monotonic() - start
    timer.join(timeout=2)
    assert provider.cancel_observed.is_set()         # the bridge delivered the halt to the runner
    assert response.ok is False                      # op spanned a halt → failure, never SUCCEEDED
    assert elapsed < 5                               # cancelled, not hung on the 30s timeout
    # the cancel-bridge watcher was torn down in finally — even on the halt path it does not leak.
    leftover = [t for t in threading.enumerate()
                if t.is_alive() and t not in live_before and t is not timer]
    assert leftover == []
    # the RUNNING manifest step was terminalized to FAILED, not left RUNNING.
    from linux_debug_mcp.artifacts.store import ArtifactStore
    step = ArtifactStore(artifact_root, create_root=False).load_manifest(RUN_ID).step_results.get("run_tests")
    assert step is not None and step.status == StepStatus.FAILED


def test_clean_run_leaves_no_watcher_thread(tmp_path):
    # the regression for Finding #1 (round 2): a normal, non-halted run must tear the
    # cancel-bridge watcher down. complete()/_dispose_locked() never set the handle's _cancel,
    # so a fire-and-forget watcher would park on wait_cancelled() forever and leak. The bounded
    # poll + watch_done + join-in-finally must leave no live thread and a disposed handle.
    artifact_root = create_booted_run(tmp_path)
    reg = SessionRegistry(directory=tmp_path / "reg")
    _record(reg, ExecutionState.EXECUTING)           # admittable; no halt ever arrives
    admission = _seed_admission()
    live_before = set(threading.enumerate())
    response = target_run_tests_handler(
        artifact_root=artifact_root, run_id=RUN_ID, provider=FakeTestProvider(),
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        admission=admission, session_registry=reg)
    assert response.ok is True                        # ran to completion (SUCCEEDED)
    leftover = [t for t in threading.enumerate() if t.is_alive() and t not in live_before]
    assert leftover == []                             # watcher joined in finally — no parked thread
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_server_run_tests_gating.py -q`
Expected: FAIL — handler does not accept `admission=`/`session_registry=`, does not gate, and `execute_tests` takes no `cancel`.

- [ ] **Step 3: Implement the gate in `target_run_tests_handler`**

After the cached short-circuit (which stays unchanged for terminal `SUCCEEDED`; add the same early-return for terminal `FAILED` as a pure read), before the live `provider.execute_tests(plan)` call (`server.py:1327`, which this task changes to pass `cancel=runner_cancel`): read `target_key`/`generation`/`platform` from the published snapshot (Task B0); probe via `probe_execution_state(...)` and build an `ExecutionProof`; call `admission.admit_ssh_tier(target_key, generation, platform, execution_proof=proof)`. On `AdmissionError`, return `ToolResponse.failure(category=exc.category, message=str(exc), details={"code": exc.code})` (a `HALTED` proof yields `READINESS_FAILURE`/`target_halted`).

Then run the op under a **teardown-bounded** cancel-bridge watcher — never the fire-and-forget `if handle.wait_cancelled(): runner_cancel.set()` form, which parks forever on the success path (Finding #1, round 2):

```python
runner_cancel = threading.Event()
watch_done = threading.Event()

def _watch() -> None:
    # bounded poll, NOT an unbounded park: complete()/_dispose_locked() never set the handle's
    # _cancel (admission.py:671,774), so wait_cancelled(None) would block forever on a clean run
    # and leak the thread + the pinned completed handle + this closure.
    while not watch_done.is_set():
        if handle.wait_cancelled(0.1):
            runner_cancel.set()
            return

watcher = threading.Thread(target=_watch, daemon=True)
watcher.start()
try:
    result = provider.execute_tests(plan, cancel=runner_cancel)
    admission.complete(handle)            # may raise AdmissionError(execution_state_changed)
finally:
    watch_done.set()                      # stop the poll loop on EVERY exit path
    watcher.join(timeout=2)               # …and reap it before returning — no parked thread
```

If `complete()` raises `execution_state_changed` (the op spanned a halt), **terminalize the RUNNING manifest `StepResult` to FAILED** and return failure — never record SUCCEEDED, never leave a stale RUNNING step. A cached `RUNNING` while `HALTED` is force-failed via the existing stale-`RUNNING` path (server.py:~1325), extended to also terminalize when a halt is observed. The `finally` runs on the success, cancel, and `execution_state_changed` paths alike, so the watcher is always joined: a normal completion leaves no parked thread and no pinned handle (asserted by `test_clean_run_leaves_no_watcher_thread`).

- [ ] **Step 4: Run to verify they pass — and the existing run-tests suite stays green**

Run: `uv run python -m pytest tests/test_server_run_tests_gating.py tests/test_target_run_tests_handler.py -q`
Expected: PASS. `test_target_run_tests_handler.py` must stay at its prior count: the relocated `FakeTestProvider.execute_tests` now accepts `*, cancel=None` (Task B-pre), so the handler's new `cancel=runner_cancel` call site (`server.py:1327`) no longer raises `TypeError` in those 16 tests.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_run_tests_gating.py
git commit -m "feat: gate target.run_tests on execution state with kill-on-halt (#10)"
```

---

### Task B3: migrate `debug.start_session` onto the `open()` transaction

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`debug_start_session_handler`, ~1389)
- Test: `tests/test_server_debug_session_migration.py`

`debug.start_session` already halts the kernel via the qemu gdbstub provider but holds **no** guard and writes **no** durable execution state. Route it through `TransportTransaction.open(...)` for the `qemu-gdbstub` channel so it acquires the `StopCapableGuard`, writes a durable `TransportSession` record, and — **before** the gdb attach halts the kernel — persists `execution_state=HALTED`. The `TargetKey`/`generation` come from the snapshot **published by Task B0** (ADR 0007), not re-derived. The guard's fenced by-token release on detach is already owned by the transaction's in-memory token map (Task A8 / ADR 0002) — `close()` is by-token, so B3 does **not** reopen the guard-release question; it just calls `transaction.close(session_id)`. Add `recovery: bool = False` → routes to `open(recovery=True)`, the agent clearance path, which clears the tombstone through the dual-write helper (`_clear_recovery`, Task A8 / Finding #5). The existing `DebugSession` manifest record continues for backward compatibility but is now bound to the transport-ownership record (its `session_id`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server_debug_session_migration.py
# Tests (handler-level, fakes injected):
#  - test_start_session_acquires_guard_and_writes_durable_record: after start_session, the
#    SessionRegistry has a record for the target with stop_guard_token set and
#    execution_state=HALTED written BEFORE the provider's attach/halt ran (assert ordering
#    via a provider spy that reads the registry at attach time).
#  - test_halt_via_start_session_makes_run_tests_reject: start_session, then
#    target_run_tests_handler returns READINESS_FAILURE/target_halted.
#  - test_second_stop_capable_session_refused: a second start_session on the same target
#    raises/returns DEBUG_ATTACH_FAILURE (guard conflict → mapped category).
#  - test_recovery_attach_clears_tombstone: with a recovery_required tombstone present,
#    start_session(recovery=True) is admitted and clears it.
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_server_debug_session_migration.py -q`
Expected: FAIL.

- [ ] **Step 3: Implement the migration**

In `debug_start_session_handler`: build the `OpenRequest` for the recorded `gdbstub_endpoint` (qemu-gdbstub channel), call `transaction.open(request, recovery=recovery)`; map `GuardConflict`/`EndpointSafetyError`/`AdmissionError` to `ToolResponse.failure` with `DEBUG_ATTACH_FAILURE`/`READINESS_FAILURE`. **Write `execution_state=HALTED` to the durable record before invoking `provider.start_session(...)`** (the gdb attach halts). Bind the returned `session.session_id` into the persisted `DebugSession` details. On clean detach/end, `transaction.close(session_id)`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_server_debug_session_migration.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_debug_session_migration.py
git commit -m "feat: migrate debug.start_session onto the open() transaction (#10)"
```

---

### Task B4: keep gdbstub `debug.*` reads under the guard, NOT the ssh gate

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (the `_debug_operation_response` path, ~1599)
- Test: `tests/test_server_debug_reads_while_halted.py`

ADR 0001/0002: gdb register/memory reads execute precisely while `HALTED` and are governed by the `StopCapableGuard`/stop-capable session, **not** the ssh-`EXECUTING` gate. This task adds a regression test proving the reads still work while `HALTED` and a guard-bound check that they require the owning session's token — it must **not** introduce ssh gating on these handlers.

- [ ] **Step 1: Write the regression tests**

```python
# tests/test_server_debug_reads_while_halted.py
#  - test_read_registers_works_while_halted: with execution_state=HALTED, debug_read_registers_handler
#    returns SUCCEEDED (the read is valid precisely because the kernel is stopped).
#  - test_debug_read_not_ssh_gated: assert the read handler path never calls admit_ssh_tier
#    (inject a spy admission; assert zero ssh-tier calls).
```

- [ ] **Step 2-4: Run / implement / verify**

The reads should already pass while `HALTED` (they are RSP/gdbstub). The only change is ensuring the migration in B3 did not accidentally route them through the ssh gate. Run the tests; if green with no code change, that is the correct outcome — the test is the guardrail. If B3 over-gated, remove the ssh gate from the read path.

Run: `uv run python -m pytest tests/test_server_debug_reads_while_halted.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_server_debug_reads_while_halted.py src/linux_debug_mcp/server.py
git commit -m "test: pin gdbstub debug.* reads under the guard, not ssh gating (#10)"
```

---

### Task B5: public `transport.open` / `transport.close` / `transport.inject_break` tools

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (handlers + `@app.tool` wrappers in `create_app`)
- Test: `tests/test_server_transport_tools.py`

`transport.inject_break` is destructive: it carries the `TRANSPORT_DESTRUCTIVE_PERMISSIONS` gate, and it MUST write `execution_state=HALTED` (or `UNKNOWN` for an unconfirmable break) to the durable record **before** issuing the break, recovering a mid-break timeout to `UNKNOWN` (never stale `EXECUTING`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server_transport_tools.py
#  - test_transport_open_returns_session_and_records_endpoint
#  - test_transport_open_recovery_clears_tombstone
#  - test_transport_close_reaps_and_clears
#  - test_inject_break_writes_halted_before_break: a spy break-mechanism reads the durable
#    record at break time and sees execution_state=HALTED already persisted.
#  - test_inject_break_timeout_records_unknown_not_executing
#  - test_inject_break_requires_destructive_permission (per config.TRANSPORT_DESTRUCTIVE_PERMISSIONS)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_server_transport_tools.py -q`
Expected: FAIL — handlers/tools don't exist.

- [ ] **Step 3: Implement handlers + wrappers**

Add `transport_open_handler`, `transport_close_handler`, `transport_inject_break_handler` (calling `validate_transport_operation` + the transaction + `break_inject.inject_break`), each returning a `ToolResponse`, and register `@app.tool(name="transport.open"|"transport.close"|"transport.inject_break")` wrappers in `create_app` that `.model_dump(mode="json")`. `transport.open` with `recovery=true` admits via `open(recovery=True)` and clears the recovery gate through the **dual-write helper** `_clear_recovery` (Task A8 / Finding #5) — tombstone and admission cache together, never one alone. `inject_break` writes `HALTED` to the record (via `registry.write_record`) before calling the break mechanism; on a break-mechanism timeout, write `UNKNOWN`. Populate `suggested_next_actions` (`"debug.start_session"`, `"transport.status"`).

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_server_transport_tools.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_transport_tools.py
git commit -m "feat: add transport.open/close/inject_break MCP tools (#10)"
```

---

### Task B6: `create_app` transport-registry construction + capability startup validation + reconcile-before-serve

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`create_app`, ~2502)
- Test: `tests/test_server_startup_validation.py`

Construct the `TransportRegistry` (capabilities), the `SessionRegistry` (durable, via `private_runtime_registry_dir()`), the `AdmissionService`, guard/lease managers, and the `TransportTransaction`. Acquire the instance flock, run `registry.reconcile(...)` **before** any tool can admit, and validate every registered transport capability (the schema-level `_remote_must_be_brokered` already fires at construction; add a `create_app` belt that re-checks and fails loud on a misconfigured registry).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server_startup_validation.py
#  - test_create_app_runs_reconcile_before_serving: inject a SessionRegistry with a HALTED
#    record; after create_app, a recovery_required tombstone exists (reconcile ran).
#  - test_create_app_rejects_remote_loopback_local_capability: a registry containing a REMOTE
#    capability that (somehow) advertises loopback_local makes create_app raise at startup.
#  - test_second_app_instance_fails_loud: two create_app against the same registry dir → the
#    second raises InstanceLockError.
```

- [ ] **Step 2-4: Run / implement / verify**

Wire the construction + reconcile + validation into `create_app` (after the `sensitive_paths` line, ~2507). Use an injectable `transport_registry=None` / `session_registry=None` param mirroring the existing `registry=None` pattern so tests pass fakes.

Run: `uv run python -m pytest tests/test_server_startup_validation.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_startup_validation.py
git commit -m "feat: wire transport registry, reconcile, and startup validation into create_app (#10)"
```

---

### Task B7: legacy-`DebugSession` version-skew fence

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (the debug-session load path, `_load_active_debug_session` / `_debug_operation_response`)
- Test: `tests/test_server_legacy_session_fence.py`

A pre-Layer-4 persisted `DebugSession` (raw `gdbstub_endpoint`, no transport-ownership record / generation / guard token) must **not** be silently resumed after upgrade. The migrated `debug.*` handler refuses it: force-end only after proving `EXECUTING`, else convert it to a `recovery_required` tombstone — so an old session can never bypass the durable model or leave `target.run_tests` blind to a kernel it already halted.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server_legacy_session_fence.py
#  - test_legacy_session_without_ownership_record_is_refused: a manifest DebugSession with no
#    matching SessionRegistry record → the debug.* handler returns DEBUG_ATTACH_FAILURE with a
#    "legacy_session_no_ownership" code, NOT a silent resume.
#  - test_legacy_session_converted_to_tombstone_when_not_executing: refusal also writes a
#    recovery_required tombstone for the target.
```

- [ ] **Step 2-4: Run / implement / verify**

In the debug-session load path, after loading a persisted `DebugSession`, look up the `SessionRegistry` record by target; if absent, refuse + tombstone (unless a fresh `EXECUTING` probe proves the kernel is running, in which case force-end is permitted).

Run: `uv run python -m pytest tests/test_server_legacy_session_fence.py -q`
Expected: PASS.

- [ ] **Step 5: Commit + Phase B checkpoint**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_legacy_session_fence.py
git commit -m "feat: fence legacy gdbstub debug sessions on load (#10)"
uv run python -m pytest -q && uv run ruff check . && uv run ruff format --check . && just check-docs
```

Expected: green. **Phase B review checkpoint** before Phase C.

---

## Phase C — green-together §10.2 conformance + property pass + gated integration

### Task C1: the §10.2 green-together conformance suite

**Files:**
- Create: `tests/test_layer4_conformance.py`
- Test: itself

One module that asserts the §10.2 invariant set **together**, against the real Phase A/B wiring with injected fakes (fake `Transport`, the real `AdmissionService`/`SessionRegistry`/guard/lease). Each invariant is a named test mapping to a §9.1 case. This is the merge bar.

- [ ] **Step 1: Write the conformance tests** (one `def test_*` per bullet, real assertions)

```python
# tests/test_layer4_conformance.py — required cases (each a concrete test):
#  open() transaction
#  - test_open_rollback_at_each_crash_point: parametrize crash_after over
#    {"selected","guard","lease","record_written","ready"}; after each, assert NO leak
#    (guard free, lease FREE, no record, admission has no binding).
#  endpoint-safety
#  - test_brokered_required_open_refused_endpoint_unsafe_pre_attach (no guard/lease/secret/attach)
#  - test_loopback_local_returns_tcp_endpoint
#  crash recovery — ROLLBACK path (in-process: the crash_after seam, transaction unwinds itself)
#  - test_open_rollback_at_each_crash_point covers this (above): the process is alive, so
#    rollback runs in reverse and leaks nothing.
#  crash recovery — RECONCILE-AFTER-DEATH path (record persisted, process gone; next startup reaps)
#  - test_orphan_reaped_after_death_between_spawn_and_ready (FULL body below): an OPENING record
#    with a live fake pid was written through (Finding #1); rollback never ran; reconcile reaps
#    by identity and deletes the record. This is a DIFFERENT path from rollback — both covered.
#  - test_writeahead_record_found_and_released_on_restart
#  - test_second_server_instance_fails_loud_on_flock
#  - test_halted_target_recovery_required_gate
#  - test_recovery_clearance_recovery_true_attach (FULL body below — the ONE clearance #10 wires)
#  - test_stale_generation_tombstone_is_no_op_after_reboot (FULL body below — fail-closed: #10
#    has NO probe-clear / reset-clear; those are spec §4.7 paths 1–2 owned by later layers)
#  - test_recovery_cleared_then_restart_admittable (FULL body below, Finding #5): a cleared
#    recovery stays cleared across a restart — no stale tombstone re-gates the target.
#  - test_two_restart_durability_of_tombstone
#  - test_tombstone_generation_idempotency_fail_closed_at_bare_startup
#  - test_abandoned_attach_epoch_fence
#  lifecycle
#  - test_invalidation_cancels_pending_and_promoted_bindings
#  - test_invalidation_awaited_blocks_until_teardown
#  execution-state gate
#  - test_run_tests_rejected_while_halted
#  - test_run_tests_admitted_while_executing
#  - test_async_halt_cancels_in_flight_run_tests (subprocess killed, not hung)
#  - test_cancel_bridge_watcher_torn_down_no_leak (clean AND halted runs join the watcher in
#    finally — no parked daemon thread, no pinned completed handle; Finding #1, round 2)
#  - test_stale_executing_proof_probe_timeout
#  - test_failed_inject_break_records_unknown
#  - test_out_of_band_halt_recorded_unknown_not_executing
#  - test_cached_succeeded_served_while_halted (pure read, not gated)
#  - test_cached_running_terminalized_while_halted
#  - test_gdbstub_reads_exempt_from_ssh_gate
#  close / legacy
#  - test_close_while_halted_tombstones_then_revokes_never_false_executing
#  - test_legacy_debug_session_refused_on_load
#  redaction / secrets
#  - test_secret_refs_never_surfaced_in_response_or_record
#  - test_console_and_gdb_transcript_redacted_into_durable_record
```

The load-bearing reconcile-after-death and recovery-clearance cases get full bodies (the rest are mechanical and assert the exact `ErrorCategory`/`code`/`StepResult` identity named above):

```python
# tests/test_layer4_conformance.py  (load-bearing bodies)
from datetime import UTC, datetime

from _layer4_fakes import KEY, FakeQemuTransport, FakeReapProxy, build_txn, make_request, seed_snapshot
from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore
from linux_debug_mcp.coordination.registry import RecoveryTombstone, SessionRegistry
from linux_debug_mcp.transport.base import (
    ExecutionState, RecordState, TransportSession, new_session_id)


def _mark_recovery(reg, admission, *, generation=1):
    # dual-write: durable tombstone (source of truth) + admission cache (write-through).
    reg.write_tombstone(RecoveryTombstone(target_key=KEY, generation=generation, reason="halted"))
    admission.mark_recovery_required(KEY, generation)


def test_orphan_reaped_after_death_between_spawn_and_ready(tmp_path):
    # a process died after the OPENING record was written through with a live backend pid, but
    # before READY. Rollback never ran (the process is gone); the next startup's reconcile must
    # reap the orphan by identity and delete the record.
    reg = SessionRegistry(directory=tmp_path)
    reg.write_record(TransportSession(
        session_id=new_session_id(), target_key=KEY, generation=1, provider="qemu-gdbstub",
        channel_id="rsp0", record_state=RecordState.OPENING, backend_pid=4321,
        backend_start_time="999", execution_state=ExecutionState.EXECUTING,
        created_at=datetime.now(UTC)))
    proxy, admission = FakeReapProxy(), AdmissionService(SnapshotStore())
    fresh = SessionRegistry(directory=tmp_path)            # "restart": fresh registry, same dir
    fresh.reconcile(proxy=proxy, admission=admission)
    assert proxy.reaped == [(4321, "999")]                 # reaped by identity (ADR 0004)
    assert fresh.read_record(KEY) is None                  # orphan record cleared


def test_recovery_clearance_recovery_true_attach(tmp_path):
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    _mark_recovery(reg, admission)
    session = txn.open(make_request(), recovery=True)      # admit_recovery → _clear_recovery
    assert session.record_state is RecordState.READY
    assert reg.read_tombstone(KEY) is None                 # tombstone cleared
    assert admission._recovery_required.get(KEY) is None   # AND the cache — single source of truth
    txn.close(session.session_id)


def test_stale_generation_tombstone_is_no_op_after_reboot(tmp_path):
    # Honest fail-closed case (second-round Finding #3). #10 implements exactly ONE recovery
    # clearance trigger — recovery-attach (open(recovery=True) → _clear_recovery). It has NO
    # probe-clear and NO reset-clear path (those are spec §4.7 paths 1–2, owned by later layers:
    # provisioning #38 and a future liveness-probe handler). So a tombstone naming generation N is
    # NOT auto-cleared by a reboot advancing the snapshot to N+1 — it keeps gating, fail-closed,
    # until the recovery-attach trigger runs.
    reg = SessionRegistry(directory=tmp_path)
    _, admission = build_txn(FakeQemuTransport(), registry=reg, generation=1)
    _mark_recovery(reg, admission, generation=1)
    # "reboot": a fresh server over the same dir; the snapshot is now generation 2 (BootAttempt.attempt).
    reg2 = SessionRegistry(directory=tmp_path)
    admission2 = AdmissionService(SnapshotStore())
    seed_snapshot(admission2._store, generation=2)
    reg2.reconcile(proxy=FakeReapProxy(), admission=admission2)
    assert reg2.read_tombstone(KEY) is not None            # the gen-1 tombstone survives the gen bump
    assert admission2._recovery_required.get(KEY) == 1     # re-marked from the durable tombstone — still gated


def test_recovery_cleared_then_restart_admittable(tmp_path):
    # Finding #5: a cleared recovery must STAY cleared across a restart — the durable tombstone
    # is the single source of truth, so reconcile finds nothing to re-gate.
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(FakeQemuTransport(), registry=reg)
    _mark_recovery(reg, admission)
    txn.open(make_request(), recovery=True)                # clears via _clear_recovery
    reg2 = SessionRegistry(directory=tmp_path)             # "restart": fresh registry + admission
    admission2 = AdmissionService(SnapshotStore())
    reg2.reconcile(proxy=FakeReapProxy(), admission=admission2)
    assert reg2.read_tombstone(KEY) is None                # no stale tombstone re-gates the target
    assert admission2._recovery_required.get(KEY) is None
```

Implement the remaining mechanical cases with the same fakes + the real transaction. For the crash-point (rollback) cases, use `txn.open(request, crash_after=frozenset({...}))` and assert the registry/guard/lease/admission state afterward. For "restart", construct a fresh `SessionRegistry(directory=same)` + fresh `AdmissionService` and call `reconcile(...)`. `test_async_halt_cancels_in_flight_run_tests` reuses the full body from Task B2.

- [ ] **Step 2: Run — all must pass together**

Run: `uv run python -m pytest tests/test_layer4_conformance.py -q`
Expected: PASS (the full §10.2 set green together — the merge bar).

- [ ] **Step 3: Commit**

```bash
git add tests/test_layer4_conformance.py
git commit -m "test: assert the §10.2 invariant set green together (#10)"
```

---

### Task C2: cancel/epoch property pass (`hypothesis` stateful)

**Files:**
- Modify: `pyproject.toml` (add `hypothesis` to the `dev`/`test` extra)
- Create: `tests/test_exec_state_machine.py`
- Test: itself

ADR 0006: adjudicate the consolidated cancel/epoch model with a `hypothesis` `RuleBasedStateMachine` driving `admit_ssh_tier`/`note_execution_transition`/`cancel_ssh_tier`/`complete`/`close_admission`/`reopen`/`invalidate_lifecycle` in adversarial orders, asserting the invariants. If the state space proves too irregular for a clean machine, fall back to a hand-written interleaving matrix over the transition table (still in this file).

- [ ] **Step 1: Add the dev dependency**

```bash
uv add --dev hypothesis
```
Confirm it lands in the `dev`/`test` extra in `pyproject.toml` and `uv.lock` updates.

- [ ] **Step 2: Write the stateful test**

```python
# tests/test_exec_state_machine.py
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, precondition
# Model the (generation, execution_epoch, execution_state) machine over a single TargetKey.
# rules: admit_ssh_tier (with a freshly-probed proof), note_execution_transition(halt/resume),
#        cancel_ssh_tier(halt_epoch), complete(handle), close_admission/reopen, invalidate.
# invariants the machine must hold (each an @invariant or post-rule assert):
#  - no handle reports COMPLETED success if it spanned a halt (epoch advanced since admit)
#  - no stale EXECUTING proof admits after a halt (epoch fence)
#  - a delayed cancel still cancels its pre-halt op, never a post-resume op
#  - a prior-generation event (note/cancel/close) is a no-op
#  - at most one stop-capable guard holder per target at any time
class ExecStateMachine(RuleBasedStateMachine):
    ...
TestExecState = ExecStateMachine.TestCase
TestExecState.settings = settings(max_examples=300, stateful_step_count=40)
```

- [ ] **Step 3: Run**

Run: `uv run python -m pytest tests/test_exec_state_machine.py -q`
Expected: PASS. A failing counterexample here is a **real** protocol defect in the ADR-0006 model — fix the mechanism in `admission.py` (not the test), then re-run.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock tests/test_exec_state_machine.py
git commit -m "test: property-test the cancel/epoch state machine (ADR 0006) (#10)"
```

---

### Task C3: gated end-to-end integration (real inject_break + unchanged qemu-gdbstub flow)

**Files:**
- Create: `tests/test_transport_open_close_integration.py` (gated, skipped without `agent-proxy`/`gdb`/`virsh`)
- Test: itself

- [ ] **Step 1: Write the gated integration tests**

```python
# tests/test_transport_open_close_integration.py
#  - test_inject_break_drops_kgdb_target_into_debugger: PTY + real agent-proxy + a kgdb-enabled
#    guest (or the serial-local PTY fixture from test_serial_local_transport_integration.py);
#    transaction.open → transport.inject_break → assert the target halts (gdb 'target remote'
#    on the rsp_endpoint observes a stop). Skipped unless LDM_REQUIRE_AGENT_PROXY=1.
#  - test_qemu_gdbstub_flow_unchanged: the existing debug.start_session → debug.read_* flow over
#    the migrated transaction produces the SAME results as before (gated on
#    LINUX_DEBUG_MCP_LIVE_GDBSTUB=1) — proving the migration is behavior-preserving.
```

Reuse the PTY + agent-proxy fixtures from `tests/test_serial_local_transport_integration.py` and the virsh/gdb harness from `tests/test_qemu_gdbstub_integration.py`. Keep the tool-gating (`@pytest.mark.skipif`) intact.

- [ ] **Step 2: Run (skips cleanly without tools)**

Run: `uv run python -m pytest tests/test_transport_open_close_integration.py -q`
Expected: SKIPPED on the dev host (no agent-proxy/gdb/virsh); PASS in the gated CI job.

- [ ] **Step 3: Wire the gated CI job**

Extend `.github/workflows/transport-integration.yml` (added in Layer 3) to also run this module with `LDM_REQUIRE_AGENT_PROXY=1` so a skip is impossible there. Validate: `actionlint .github/workflows/transport-integration.yml && zizmor .github/workflows/transport-integration.yml`.

- [ ] **Step 4: Commit**

```bash
git add tests/test_transport_open_close_integration.py .github/workflows/transport-integration.yml
git commit -m "test: gated end-to-end inject_break + unchanged gdbstub flow (#10)"
```

---

## Final verification

- [ ] **Full suite + lint + docs guard green**

Run: `uv run python -m pytest -q && uv run ruff check . && uv run ruff format --check . && just check-docs`
Expected: all pass; integration tests skip cleanly without tools; the §10.2 conformance module is green.

- [ ] **Confirm the gated CI job is green and did not skip.** The end-to-end halt and the unchanged-gdbstub claim are only proven in the `LDM_REQUIRE_AGENT_PROXY=1` / `LINUX_DEBUG_MCP_LIVE_GDBSTUB=1` job. "Green on the dev host" (where they skip) is **not** the merge bar.

- [ ] **Dispatch a final whole-layer code review** (subagent-driven-development final reviewer), then run the `/codex:adversarial-review --base main` loop, feeding the "Decisions & rejected alternatives" section above (ADRs 0001–0007, including the 2026-05-27 amendments to 0002/0005/0006) as the SETTLED preamble each round. Per `[[feedback-adversarial-review-convergence]]`: this is a concurrency-heavy surface — judge on **finding quality + the green property pass (C2)**, not on reaching `approve`; the property/interleaving pass is the durable adjudicator, not more review rounds. Push back on a round that contradicts a settled ADR; record rationale, do not flip.

---

## Self-review notes

- **Spec coverage (§10.2 → task):** **authoritative snapshot producer (the Phase-B unblocker, ADR 0007) → B0 `test_boot_publishes_ready_snapshot`/`test_reboot_bumps_generation_invalidates_old`**; console-lease/guard exclusivity → A8/B5 + C1; admission freshness + snapshot re-binding + rollback-at-every-step → A8 + C1 `test_open_rollback_at_each_crash_point`; crash recovery (write-ahead found+released; **orphan reaped after death between spawn and READY → A8 on_partial write-through + C1 `test_orphan_reaped_after_death_between_spawn_and_ready`**, a distinct path from in-process rollback; recovery_required + the single recovery-attach clearance #10 implements (`admit_recovery` → C1 `test_recovery_clearance_recovery_true_attach`; the probe-clear and reset-clear paths are spec §4.7 paths 1–2, owned by a future liveness-probe handler / provisioning #38 — **out of scope here**, with the fail-closed boundary asserted by C1 `test_stale_generation_tombstone_is_no_op_after_reboot`) + **restart durability of a cleared gate → C1 `test_recovery_cleared_then_restart_admittable`**; abandoned-attach epoch fence) → A4 + A8 + C1; cancellable attach incl. pre-`on_partial` hang → A8 (cancel event + deadline) + Layer-3 `test_transport_proxy.py` (already green); execution-state gate (HALTED reject, probe_timeout, unknown-on-failed-break) → A7 + B2 + B5 + C1; **async halt → in-flight ssh cancel: the `handle.wait_cancelled()` watcher bridge (ADR 0006) → B2 `test_admitted_then_halted_run_is_cancelled` + C1 `test_async_halt_cancels_in_flight_run_tests`**; break-plan executable preflight fail-closed → A8 (select before guard); endpoint-safety gate + permissioned console refusal → A6 + C1; port identity verification → Layer-3 (`test_transport_proxy.py`); `secret_refs` never surfaced + redaction → C1 `test_secret_refs_never_surfaced`/`test_*_transcript_redacted`. §10.1 functional (providers.list flags, unchanged gdbstub flow) → C3 + Layer 5.
- **Placeholder scan:** Phase A steps carry complete code. The shared `tests/_layer4_fakes.py` harness (Task A0) holds the fakes once; the load-bearing Phase B/C tests carry **full bodies** importing from it — the boot snapshot producer (B0), the async-halt cancel bridge (B2), the orphan reconcile-after-death case and the recovery clearances + restart (C1). Remaining mechanical cases are enumerated named cases each stating the exact asserted `ErrorCategory`/`code`/`StepResult` identity. No "TBD"/"handle edge cases"/"similar to Task N"/"full bodies follow the pattern" disclaimer remains.
- **Type consistency:** `TransportSession`, `BackendAttachment`, `ExecutionProof(generation, epoch, state)`, `AdmissionHandle.admit_epoch`/`wait_cancelled`, `GuardToken(target_key, fence, secret)` + the in-process `session_id → GuardToken` map, `RecoveryTombstone(target_key, generation, reason)`, the dual-write helpers `_mark_recovery`/`_clear_recovery`, `publish_ready_snapshot(admission, *, target_key, generation, transports, platform)`, `TargetKey("local-qemu", run_id)` + `generation = BootAttempt.attempt`, `SessionRegistry` method names (`write_record`/`read_record`/`delete_record`/`list_records`/`write_tombstone`/`read_tombstone`/`clear_tombstone`/`acquire_instance_lock`/`reconcile`), `TransportTransaction(admission, registry, guard, leases, secrets, break_policy, transports)`, and `probe_execution_state(*, registry, admission, target_key, generation)` are used identically across B0, A8, B2, B3, B5, and C1.
- **Layering:** Phase A imports only Layer 1–3 + existing code; `server.py` is untouched until Phase B (B0 is the first `server.py` edit). The endpoint-safety gate decides from trusted `TransportCapability` metadata (the schema-level `_remote_must_be_brokered` is the first line; A6 is the runtime gate; B6 is the startup belt). The guard release is **fenced by-token** via the in-process `session_id → GuardToken` map, resolved in A8 (not carried as a coarse `close()`→`revoke()` edge); `revoke()` survives only on the reconcile path, where the prior holder is provably dead (ADR 0002 amendment).
- **Deviations recorded:** `debug.step` does not exist (single-step unimplemented) — no task assumes it. `ExecutionState.EXECUTING` is written on a clean `transport.open`; the `HALTED` transition is owned by `debug.start_session` (B3) and `transport.inject_break` (B5), each writing it **before** the halt. The `complete()` epoch backstop maps `execution_state_changed` to a failure on the run_tests path (B2) and terminalizes the RUNNING `StepResult` to FAILED, never a recorded SUCCEEDED. The local-qemu `generation` reuses `BootAttempt.attempt` rather than a new manifest field (ADR 0007); the frozen `stop_guard_token: str` stays an audit marker, with the fence held in-process (ADR 0002 amendment).
