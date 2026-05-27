# Transport abstraction — Layer 2: Coordination primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the pure concurrency + admission primitives the `open()` transaction will
orchestrate — console lease, stop-capable guard, lifecycle dispatcher, snapshot store +
admission service, and break-plan-aware channel selection — entirely in-memory
(threading only), with zero process/socket/filesystem IO, fully unit-tested.

**Architecture:** New `coordination/` package (`lease.py`, `admission.py`, `selection.py`)
holds 01-owned cross-cutting state; `seams/guard.py` and `seams/lifecycle.py` add the
`StopCapableGuard`/`LifecycleDispatcher` **Protocols plus minimal in-process impls** that
#08/provisioning later swap (the Protocol is frozen; only the impl changes — see the
roadmap seam-ownership invariant). Everything keys on the full `TargetKey`
`(provisioner, target_id)` tuple. All blocking work is bounded by an explicit
`teardown_deadline`; nothing is left to hang.

**Tech Stack:** Python 3.11+, Pydantic v2 (only for reused Layer-1 schemas), `threading`,
pytest, `uv`, ruff. No new dependencies.

**Roadmap:** `docs/superpowers/plans/2026-05-26-transport-abstraction-roadmap.md`
**Spec:** `docs/superpowers/specs/2026-05-26-transport-abstraction-design.md` (§3.3, §4.1, §4.2, §4.4, §4.5, §4.8, §5, §9.1)
**Contract:** `docs/specs/interface-contracts.md` (§3.3, §4.1, §8)
**Depends on:** Layer 1 (merged) — `seams/target.py`, `transport/base.py`, `seams/break_policy.py`, `domain.py`.

---

## Scope boundary (what is NOT in Layer 2)

These are **Layer 4** and must not be built here — building them now would pull in
process/filesystem IO this layer forbids:

- The `open()`/`close()` **transaction orchestration** (the 8-step sequence that *uses*
  these primitives), `coordination/registry.py`, the reaper, durable JSON ownership
  records, `flock` single-instance/per-device locks, startup reconciliation.
- The **durable recovery-required tombstone** store (persisted JSON, the hashed filename) and
  the three clearance paths' *mechanisms*. Layer 2 ships the in-memory recovery gate
  (`admit_recovery()`, `mark`/`clear_recovery_required` — ordinary `admit()` rejects while
  marked, `admit_recovery()` is the one allowed path) so the Protocol is settled and testable;
  Layer 4 *drives* it from durable tombstones written by startup reconciliation and clears it
  via the three clearance paths.
- The **bounded liveness probe** itself (`EXECUTING`↔`HALTED` ground truth, its `probe_timeout`)
  and the stop-capable controller's `EXECUTING`↔`HALTED` writes. The probe is Layer 4 — Layer 2
  never manufactures execution state and never trusts a cached flag (spec §4.6: "do not trust a
  possibly-stale `EXECUTING`"; a crash can land between observing a halt and the write-ahead
  landing). **But ssh-tier admission and cancellation stay in Layer 2's one admission service**
  (contract §5.3/§5.6): `admit_ssh_tier` admits `READY` with no proof, and admits a `DEBUGGING`
  target ONLY when Layer 4 passes a fresh `ExecutionProof` reporting `EXECUTING` that is fenced on
  BOTH the snapshot `generation` AND a per-target **execution epoch** (`current_execution_epoch` /
  `note_execution_transition`) — the epoch bumps on every `EXECUTING`↔`HALTED`/`UNKNOWN`
  transition, so a proof taken before a same-generation halt can NOT be replayed afterwards (HALTED
  → `target_halted`; missing/stale/UNKNOWN → `execution_state_unknown`, fail-closed).
  `cancel_ssh_tier(target_key, generation)` cancels in-flight ssh ops on async `HALTED` without
  closing the target (and bumps the epoch), **generation-fenced** so a late HALTED from a prior
  incarnation cannot cancel ssh work admitted after a reset/reopen. So Layer 4 owns the *probe*;
  Layer 2 owns the *binding, fences, and lifecycle invalidation* — an EXECUTING ssh op is a
  first-class admission binding, not a bypass.
- Real backends/processes. The lifecycle dispatcher tears down **subscriber callbacks**,
  not real agent-proxy children.

Layer 2 produces working, unit-tested primitives that Layer 4 wires to real resources.

---

## Decisions & rejected alternatives

These are settled; do not relitigate them in implementation or in a re-review round
without new evidence (see `CLAUDE.md` → "Design decisions (ADRs)").

- **Execution-state gate ownership — [ADR 0001](../../adr/0001-layer2-layer4-execution-state-gate-split.md).**
  Layer 4 owns the bounded liveness *probe*; Layer 2 owns ssh-tier admission
  binding/fence/lifecycle and admits a `DEBUGGING` target only on a fresh, **generation-
  and epoch-fenced** `ExecutionProof`. *Rejected:* a Layer-2 `ExecutionStateStore` cached
  flag (stale-`EXECUTING` hazard), full Layer-2 fail-closed (loses the shared
  binding/cancel/lifecycle for `DEBUGGING` ssh ops), and an `ExecutionStateGate` callback
  under the admission lock (could wedge `close_admission`).
- **§4.5 close-before-teardown ordering.** Enforced by
  `AdmissionService.invalidate_lifecycle` (run `close_admission` to completion, *then*
  `dispatcher.emit`); the dispatcher is step-2 (teardown) only. *Rejected:* admission close
  as a `LifecycleSubscriber`/pre-close hook inside `emit` — concurrent with teardown
  (owner-free window), and a best-effort/bounded hook can fail open.
- **Break disproof scope is method-aware.** Line-bound methods
  (`gdbstub_native`/`uart_break`/`agent_proxy_break`) are per-channel; `SYSRQ_G` is
  target-wide (ssh-issued, kernel-scoped preconditions). *Rejected:* a single
  channel-scoped key for all methods — lets a sibling channel rescue a target-wide SysRq
  disproof.
- **Snapshot publication shares the admission key-lock** (`publish_snapshot`); guard
  `release(target_key, token)` is TargetKey-fenced; `abandon` requires reaper
  `confirm_reaped`; overdue subscribers are reported per instance. *Rejected:* raw
  `SnapshotStore.put` on the live path (generation bump can split an admit), `release(token)`
  (a misrouted token frees the wrong target), and disposing a cancelled binding before
  teardown is proven.

---

## File Structure

- Create: `src/linux_debug_mcp/coordination/__init__.py` — empty package marker.
- Create: `src/linux_debug_mcp/coordination/lease.py` — `LeaseOwner` enum, `LeaseConflict`,
  `ConsoleLease` (thread-safe CAS acquire / idempotent by-token release / revoke), and
  `ConsoleLeaseManager` (the single authority keyed by `TargetKey`, so all paths share one
  lease per target — contract §3.3).
- Create: `src/linux_debug_mcp/seams/guard.py` — `GuardConflict`, `GuardToken`,
  `StopCapableGuard` Protocol, `InProcessStopCapableGuard` (fenced single-holder per `TargetKey`;
  `release(target_key, token)` is TargetKey-fenced per contract §5.6 so a misrouted token can't
  free another target's guard).
- Create: `src/linux_debug_mcp/seams/lifecycle.py` — `LifecycleKind` enum, `LifecycleEvent`,
  `LifecycleSubscriber` Protocol, `InvalidationResult`, `LifecycleDispatcher` Protocol,
  `InProcessLifecycleDispatcher` (§4.5 **step 2** — teardown only; admission is closed in step 1
  before `emit` runs, see `AdmissionService.invalidate_lifecycle`): two bounded phases under
  shared deadlines: supervised `invalidate` workers, then `force_drop` for overdue subscribers to
  release out-of-band resources independent of the wedged invalidate; `emit` always returns
  bounded; **single-flight** by `(TargetKey, name)` so a permanently-stuck subscriber never
  accumulates workers across events; observable `outstanding_overdue()`/`overdue_subscribers()`;
  errors aggregated; late effects token/generation fenced), the subscriber Protocol
  (`invalidate(event, deadline)` + `force_drop(event)`), `DEFAULT_TEARDOWN_DEADLINE_SECONDS`.
- Create: `src/linux_debug_mcp/coordination/admission.py` — `AdmissionOp`, `AdmissionState`
  (incl. `COMPLETED`), `AdmissionError`, `ExecutionProof`, `TargetSnapshot`,
  `AdmissionHandle`, `SnapshotStore`, `AdmissionService` (single-phase admit: freshness /
  snapshot-rebind / caps / platform-drift / lease-identity / lease-near-expiry / state gate /
  ssh-tier `DEBUGGING` admitted only on a fresh `ExecutionProof` fenced on generation AND
  execution epoch (`current_execution_epoch`/`note_execution_transition`; the probe is Layer 4)
  else fail-closed, plus generation-fenced `cancel_ssh_tier(target_key, generation)` (bumps the
  epoch) for async-halt cancellation, and `publish_snapshot` (key-locked authoritative-facts publication) / target_key
  check; separate `admit` (transport.open) and `admit_ssh_tier` (no transport_ref) entries /
  `admit_recovery` (requires current tombstone) / `promote` / `complete` / `rollback` /
  `confirm_reaped` (reaper proof-of-teardown) / `abandon` (closed-target + cancelled + reaped
  only) with handle finality / idempotent `close_admission` (lifecycle gate) / generation-fenced
  `mark`/`clear_recovery_required` (tombstone gate) / `reopen` validated against snapshot
  generation + no outstanding bindings; `invalidate_lifecycle(event, dispatcher)` enforces §4.5
  ordering — close_admission (step 1) BEFORE `dispatcher.emit` (step 2)). `SnapshotStore`
  rejects generation regressions (monotonic freshness fence).
- Create: `src/linux_debug_mcp/coordination/selection.py` — `SelectionError`, `BreakDisproof`
  (method-aware disproof scope: line-bound methods are per-channel, SYSRQ_G is target-wide),
  `Selection`, `select_stop_capable_channel` (break-plan-aware, `transports[]`-order authoritative).
- Test: `tests/test_coordination_lease.py`, `tests/test_seams_guard.py`,
  `tests/test_seams_lifecycle.py`, `tests/test_coordination_admission.py`,
  `tests/test_coordination_selection.py`.

**Dependency order (no cycles):** Layer-1 modules → `coordination/lease.py` →
`seams/guard.py` → `seams/lifecycle.py` → `coordination/admission.py` (imports
`seams/lifecycle`, `seams/target`, `transport/base`, `domain`) → `coordination/selection.py`
(imports `seams/break_policy`, `seams/target`, `transport/base`).

---

## Task 1: ConsoleLease (`coordination/lease.py`)

**Files:**
- Create: `src/linux_debug_mcp/coordination/__init__.py`
- Create: `src/linux_debug_mcp/coordination/lease.py`
- Test: `tests/test_coordination_lease.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_coordination_lease.py`:

```python
import threading

import pytest

from linux_debug_mcp.coordination.lease import (
    ConsoleLease,
    ConsoleLeaseManager,
    LeaseConflict,
    LeaseOwner,
)
from linux_debug_mcp.seams.target import TargetKey


def _lease() -> ConsoleLease:
    return ConsoleLease(TargetKey(provisioner="local-qemu", target_id="run-1"))


def test_acquire_on_free_returns_token_and_marks_owner():
    lease = _lease()
    token = lease.acquire(LeaseOwner.TRANSPORT)
    owner, held, _ = lease.snapshot()
    assert owner is LeaseOwner.TRANSPORT
    assert held == token


def test_acquire_for_free_owner_is_rejected():
    with pytest.raises(ValueError):
        _lease().acquire(LeaseOwner.FREE)


def test_concurrent_acquire_yields_exactly_one_conflict():
    lease = _lease()
    winners: list[str] = []
    conflicts: list[LeaseConflict] = []
    barrier = threading.Barrier(2)

    def contend() -> None:
        barrier.wait()
        try:
            winners.append(lease.acquire(LeaseOwner.TRANSPORT))
        except LeaseConflict as exc:
            conflicts.append(exc)

    threads = [threading.Thread(target=contend) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(winners) == 1
    assert len(conflicts) == 1


def test_release_is_idempotent_by_token():
    lease = _lease()
    token = lease.acquire(LeaseOwner.TRANSPORT)
    assert lease.release(token) is True
    assert lease.release(token) is False  # second release is a no-op
    assert lease.snapshot()[0] is LeaseOwner.FREE


def test_stale_token_release_is_noop_after_revoke():
    lease = _lease()
    token = lease.acquire(LeaseOwner.TRANSPORT)
    lease.revoke()
    # post-revoke the lease is free and the old token is invalid
    assert lease.snapshot()[0] is LeaseOwner.FREE
    assert lease.release(token) is False
    # a new owner can acquire after revoke
    new_token = lease.acquire(LeaseOwner.PROVISIONER)
    assert new_token != token


def test_acquire_bumps_generation():
    # Contract §3.3: generation increments on every acquire (distinct ownership epoch).
    lease = _lease()
    _, _, before = lease.snapshot()
    lease.acquire(LeaseOwner.TRANSPORT)
    _, _, after = lease.snapshot()
    assert after == before + 1


def test_revoke_bumps_generation():
    lease = _lease()
    lease.acquire(LeaseOwner.TRANSPORT)
    _, _, gen_before_revoke = lease.snapshot()
    lease.revoke()
    _, _, gen_after = lease.snapshot()
    assert gen_after == gen_before_revoke + 1


def test_acquire_then_revoke_advances_generation_twice():
    # acquire (+1) and revoke (+1) each advance the epoch.
    lease = _lease()
    _, _, before = lease.snapshot()
    lease.acquire(LeaseOwner.TRANSPORT)
    lease.revoke()
    _, _, after = lease.snapshot()
    assert after == before + 2


def test_reacquire_after_release_is_a_new_epoch():
    # release does NOT bump generation; the next acquire does, so each grant is distinct.
    lease = _lease()
    first = lease.acquire(LeaseOwner.TRANSPORT)
    _, _, gen_after_first = lease.snapshot()
    assert lease.release(first) is True
    second = lease.acquire(LeaseOwner.PROVISIONER)
    _, _, gen_after_second = lease.snapshot()
    assert second != first
    assert gen_after_second == gen_after_first + 1


def test_manager_shares_one_lease_per_target_key():
    # The manager is the single authority: two acquire paths for the SAME TargetKey contend on
    # one shared lease, so a second caller conflicts rather than minting a fresh FREE lease.
    manager = ConsoleLeaseManager()
    key = TargetKey(provisioner="local-qemu", target_id="run-1")
    token = manager.acquire(key, LeaseOwner.TRANSPORT)
    with pytest.raises(LeaseConflict):
        manager.acquire(key, LeaseOwner.TRANSPORT)
    assert manager.release(key, token) is True
    manager.acquire(key, LeaseOwner.PROVISIONER)  # free again after release


def test_manager_distinct_target_keys_are_independent():
    manager = ConsoleLeaseManager()
    a = TargetKey(provisioner="local-qemu", target_id="a")
    b = TargetKey(provisioner="local-qemu", target_id="b")
    manager.acquire(a, LeaseOwner.TRANSPORT)
    manager.acquire(b, LeaseOwner.TRANSPORT)  # different TargetKey -> no conflict
    assert manager.snapshot(a)[0] is LeaseOwner.TRANSPORT
    assert manager.snapshot(b)[0] is LeaseOwner.TRANSPORT
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_coordination_lease.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.coordination'`.

- [ ] **Step 3: Create the package marker and the lease**

Create `src/linux_debug_mcp/coordination/__init__.py` (empty):

```python
```

Create `src/linux_debug_mcp/coordination/lease.py`:

```python
from __future__ import annotations

import threading
import uuid
from enum import StrEnum

from linux_debug_mcp.seams.target import TargetKey


class LeaseOwner(StrEnum):
    FREE = "free"
    PROVISIONER = "provisioner"
    TRANSPORT = "transport"


class LeaseConflict(RuntimeError):
    """Raised when acquire() loses the CAS against an already-held lease (spec §4.4)."""


class ConsoleLease:
    """Single-owner console lease for one TargetKey (contract §3.3, spec §4.4). Thread-safe;
    state is mutated only via acquire/release/revoke. `generation` is the ownership-epoch
    fence the contract increments on **every acquire and revoke** (interface-contracts.md
    §3.3): each grant is a distinct epoch, and release succeeds only for the current
    generation's token. qemu-gdbstub leaves it trivially FREE so the protocol is a no-op."""

    def __init__(self, target: TargetKey) -> None:
        self._target = target
        self._lock = threading.Lock()
        self._owner = LeaseOwner.FREE
        self._token: str | None = None
        self._generation = 0

    @property
    def target(self) -> TargetKey:
        return self._target

    def snapshot(self) -> tuple[LeaseOwner, str | None, int]:
        with self._lock:
            return self._owner, self._token, self._generation

    def acquire(self, owner: LeaseOwner) -> str:
        if owner is LeaseOwner.FREE:
            raise ValueError("cannot acquire a console lease for owner FREE")
        with self._lock:
            if self._owner is not LeaseOwner.FREE:
                raise LeaseConflict(f"console lease for {self._target} held by {self._owner}")
            self._owner = owner
            self._generation += 1  # contract §3.3: generation increments on every acquire
            self._token = uuid.uuid4().hex
            return self._token

    def release(self, token: str) -> bool:
        """Idempotent by-token release. Returns True iff this token currently held the lease
        and it was freed; a stale/unknown token (e.g. post-revoke) is a no-op returning False."""
        with self._lock:
            if self._token is None or token != self._token:
                return False
            self._owner = LeaseOwner.FREE
            self._token = None
            return True

    def revoke(self) -> None:
        """Force the lease FREE, bump generation, and invalidate the outstanding token. Only
        the §4.5 lifecycle-invalidation path calls this."""
        with self._lock:
            self._owner = LeaseOwner.FREE
            self._token = None
            self._generation += 1


class ConsoleLeaseManager:
    """The single in-process console-lease authority, **keyed by TargetKey** (contract §3.3).
    All acquire/release/revoke for a target go through the one ConsoleLease this manager owns
    for that key, so two unrelated Layer-4 code paths cannot each mint a fresh FREE lease for
    the same target and double-drive its console. Distinct TargetKeys are independent."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._leases: dict[TargetKey, ConsoleLease] = {}

    def _lease_for(self, target: TargetKey) -> ConsoleLease:
        with self._lock:
            lease = self._leases.get(target)
            if lease is None:
                lease = ConsoleLease(target)
                self._leases[target] = lease
            return lease

    def acquire(self, target: TargetKey, owner: LeaseOwner) -> str:
        return self._lease_for(target).acquire(owner)

    def release(self, target: TargetKey, token: str) -> bool:
        return self._lease_for(target).release(token)

    def revoke(self, target: TargetKey) -> None:
        self._lease_for(target).revoke()

    def snapshot(self, target: TargetKey) -> tuple[LeaseOwner, str | None, int]:
        return self._lease_for(target).snapshot()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_coordination_lease.py -q`
Expected: PASS (11 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/__init__.py src/linux_debug_mcp/coordination/lease.py tests/test_coordination_lease.py
git commit -m "feat: add ConsoleLease CAS primitive (#10)"
```

---

## Task 2: StopCapableGuard (`seams/guard.py`)

**Files:**
- Create: `src/linux_debug_mcp/seams/guard.py`
- Test: `tests/test_seams_guard.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_seams_guard.py`:

```python
import threading

import pytest

from linux_debug_mcp.seams.guard import (
    GuardConflict,
    InProcessStopCapableGuard,
    StopCapableGuard,
)
from linux_debug_mcp.seams.target import TargetKey


def _key(target_id: str = "run-1", provisioner: str = "local-qemu") -> TargetKey:
    return TargetKey(provisioner=provisioner, target_id=target_id)


def test_impl_satisfies_protocol():
    assert isinstance(InProcessStopCapableGuard(), StopCapableGuard)


def test_single_holder_target_wide():
    # gdb-on-RSP and kdb-on-console both acquire the SAME target's guard -> second refused.
    guard = InProcessStopCapableGuard()
    guard.acquire(_key())
    with pytest.raises(GuardConflict):
        guard.acquire(_key())


def test_distinct_targets_do_not_conflict():
    guard = InProcessStopCapableGuard()
    guard.acquire(_key(target_id="a"))
    guard.acquire(_key(target_id="b"))  # different TargetKey, no conflict


def test_cross_provisioner_same_target_id_isolated():
    guard = InProcessStopCapableGuard()
    guard.acquire(_key(provisioner="provA"))
    guard.acquire(_key(provisioner="provB"))  # same target_id, different key, no conflict


def test_release_by_token_then_reacquire():
    guard = InProcessStopCapableGuard()
    token = guard.acquire(_key())
    assert guard.release(_key(), token) is True
    guard.acquire(_key())  # free again


def test_release_is_idempotent_and_fenced():
    guard = InProcessStopCapableGuard()
    token = guard.acquire(_key())
    assert guard.release(_key(), token) is True
    assert guard.release(_key(), token) is False  # stale token no-op


def test_revoke_invalidates_outstanding_token():
    guard = InProcessStopCapableGuard()
    token = guard.acquire(_key())
    guard.revoke(_key())
    assert guard.release(_key(), token) is False  # token fenced by revoke
    guard.acquire(_key())  # free after revoke


def test_release_with_mismatched_target_key_does_not_free_the_token_target():
    # Contract §5.6 release(target_key, token): a token misrouted to another target's cleanup
    # must NOT release its real target. Hand target A's live token to a release keyed on target B:
    # B is untouched and — crucially — A stays held, so a second stop-capable session on A is
    # still refused.
    guard = InProcessStopCapableGuard()
    token_a = guard.acquire(_key(provisioner="provA"))
    assert guard.release(_key(provisioner="provB"), token_a) is False  # wrong target -> no-op
    with pytest.raises(GuardConflict):
        guard.acquire(_key(provisioner="provA"))  # A is still held — not freed by the misroute
    assert guard.release(_key(provisioner="provA"), token_a) is True  # correct target frees it


def test_reacquire_after_revoke_has_a_higher_fence():
    guard = InProcessStopCapableGuard()
    first = guard.acquire(_key())
    guard.revoke(_key())
    second = guard.acquire(_key())
    assert second.fence > first.fence


def test_concurrent_acquire_yields_exactly_one_holder():
    guard = InProcessStopCapableGuard()
    held = []
    conflicts = []
    barrier = threading.Barrier(2)

    def contend() -> None:
        barrier.wait()
        try:
            held.append(guard.acquire(_key()))
        except GuardConflict as exc:
            conflicts.append(exc)

    threads = [threading.Thread(target=contend) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(held) == 1
    assert len(conflicts) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_guard.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.seams.guard'` (10 tests once implemented).

- [ ] **Step 3: Implement the guard**

Create `src/linux_debug_mcp/seams/guard.py`:

```python
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from linux_debug_mcp.seams.target import TargetKey


class GuardConflict(RuntimeError):
    """Raised when acquire() fails because the target already has a stop-capable holder
    (spec §4.4/§4.6: one stop-capable session per TargetKey, target-wide)."""


@dataclass(frozen=True)
class GuardToken:
    """Fenced single-holder token. `fence` is monotonic across the guard so a token from a
    revoked/superseded holder can never release or act on a later holder."""

    target_key: TargetKey
    fence: int
    secret: str


@runtime_checkable
class StopCapableGuard(Protocol):
    def acquire(self, target_key: TargetKey) -> GuardToken: ...

    def release(self, target_key: TargetKey, token: GuardToken) -> bool: ...

    def revoke(self, target_key: TargetKey) -> None: ...


class InProcessStopCapableGuard:
    """Minimal in-process impl of the #08-owned `StopCapableGuard` interface. One holder per
    TargetKey, target-wide — both `debug.gdb` (RSP) and `debug.kdb` (console) acquire it, so
    a single stop-capable session is enforced even with no console lease. #08 later swaps this
    impl behind the same Protocol and must pass these same tests (roadmap seam-ownership rule)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._holders: dict[TargetKey, GuardToken] = {}
        self._fence = 0

    def acquire(self, target_key: TargetKey) -> GuardToken:
        with self._lock:
            if target_key in self._holders:
                raise GuardConflict(f"stop-capable session already held for {target_key}")
            self._fence += 1
            token = GuardToken(target_key=target_key, fence=self._fence, secret=uuid.uuid4().hex)
            self._holders[target_key] = token
            return token

    def release(self, target_key: TargetKey, token: GuardToken) -> bool:
        """Idempotent, **TargetKey-fenced** by-token release (contract §5.6: `release(target_key,
        token)`). Returns True iff `token` is the current holder of `target_key`. A token whose
        `target_key` does not match the argument (a misrouted token from another target), or a
        stale/fenced token (post-revoke or post-release), is a no-op returning False — so cleanup
        keyed on the wrong target can never release another target's live stop-capable guard."""
        with self._lock:
            if token.target_key != target_key:
                return False
            current = self._holders.get(target_key)
            if current is None or current != token:
                return False
            del self._holders[target_key]
            return True

    def revoke(self, target_key: TargetKey) -> None:
        """Force-free the holder (only from §4.5 invalidation). The outstanding token is
        fenced: a subsequent release(old_token) is a no-op."""
        with self._lock:
            self._holders.pop(target_key, None)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_guard.py -q`
Expected: PASS (10 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/guard.py tests/test_seams_guard.py
git commit -m "feat: add in-process StopCapableGuard seam (#10)"
```

---

## Task 3: LifecycleDispatcher (`seams/lifecycle.py`)

**Files:**
- Create: `src/linux_debug_mcp/seams/lifecycle.py`
- Test: `tests/test_seams_lifecycle.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_seams_lifecycle.py`:

```python
import threading
import time

from linux_debug_mcp.seams.lifecycle import (
    InProcessLifecycleDispatcher,
    LifecycleDispatcher,
    LifecycleEvent,
    LifecycleKind,
    LifecycleSubscriber,
    OverdueSubscriber,
)
from linux_debug_mcp.seams.target import TargetKey


def _key(target_id: str = "run-1", provisioner: str = "local-qemu") -> TargetKey:
    return TargetKey(provisioner=provisioner, target_id=target_id)


class _RecordingSubscriber:
    def __init__(self) -> None:
        self.events: list[LifecycleEvent] = []
        self.deadlines: list[float] = []

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        self.events.append(event)
        self.deadlines.append(deadline)

    def force_drop(self, event: LifecycleEvent) -> None:
        pass


class _RaisingSubscriber:
    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        raise RuntimeError("teardown boom")

    def force_drop(self, event: LifecycleEvent) -> None:
        pass


class _StuckSubscriber:
    def __init__(self) -> None:
        self.force_dropped = threading.Event()

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        time.sleep(60)  # never returns within the deadline (contract violation)

    def force_drop(self, event: LifecycleEvent) -> None:
        self.force_dropped.set()  # release recorded resources, independently of invalidate


class _SlowButFinishingSubscriber:
    def __init__(self, sleep_for: float) -> None:
        self._sleep_for = sleep_for

    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        time.sleep(self._sleep_for)  # overruns the deadline but eventually finishes

    def force_drop(self, event: LifecycleEvent) -> None:
        pass


def test_impls_satisfy_protocols():
    assert isinstance(InProcessLifecycleDispatcher(), LifecycleDispatcher)
    assert isinstance(_RecordingSubscriber(), LifecycleSubscriber)


def test_emit_delivers_to_subscribers_for_the_key_only():
    dispatcher = InProcessLifecycleDispatcher()
    here, elsewhere = _RecordingSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(target_id="a"), "here", here)
    dispatcher.subscribe(_key(target_id="b"), "elsewhere", elsewhere)
    event = LifecycleEvent(target_key=_key(target_id="a"), kind=LifecycleKind.RESETTING)
    result = dispatcher.emit(event)
    assert here.events == [event]
    assert elsewhere.events == []
    assert result.errors == {}


def test_cross_provisioner_same_target_id_isolated():
    dispatcher = InProcessLifecycleDispatcher()
    a, b = _RecordingSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(provisioner="provA"), "a", a)
    dispatcher.subscribe(_key(provisioner="provB"), "b", b)
    dispatcher.emit(LifecycleEvent(target_key=_key(provisioner="provA"), kind=LifecycleKind.CRASHED))
    assert len(a.events) == 1
    assert b.events == []


def test_invalidate_receives_the_teardown_deadline_budget():
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=2.5)
    sub = _RecordingSubscriber()
    dispatcher.subscribe(_key(), "s", sub)
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.RELEASING))
    assert sub.deadlines == [2.5]  # the subscriber is told its self-bounding budget


def test_subscriber_error_is_aggregated_not_propagated():
    dispatcher = InProcessLifecycleDispatcher()
    boom, good = _RaisingSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(), "boom", boom)
    dispatcher.subscribe(_key(), "good", good)
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.RELEASING))
    assert "boom" in result.errors  # the raised error is captured, not propagated
    assert good.events  # the healthy subscriber still ran; the transition completed


def test_stuck_subscriber_is_abandoned_and_emit_returns_within_deadline():
    # A subscriber that overruns the deadline must NOT block the transition: emit() returns
    # within ~the deadline, records it overdue + errors, and the healthy subscriber still ran.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    stuck, good = _StuckSubscriber(), _RecordingSubscriber()
    dispatcher.subscribe(_key(), "stuck", stuck)
    dispatcher.subscribe(_key(), "good", good)
    start = time.monotonic()
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    elapsed = time.monotonic() - start
    assert elapsed < 2.0  # bounded by the deadline, not the 60s sleep
    assert "stuck" in result.overdue
    assert stuck.force_dropped.is_set()  # force_drop was invoked on the overdue subscriber
    assert "stuck" in result.force_dropped
    assert good.events  # the transition completed for the healthy subscriber


def test_force_drop_releases_externally_held_resources_when_invalidate_wedges():
    # The contract requirement (§4.5): a subscriber whose invalidate() is stuck must still
    # have its line dropped. force_drop releases the lease the subscriber recorded out-of-band
    # (in shared state), independently of the wedged invalidate() frame, before emit returns.
    from linux_debug_mcp.coordination.lease import ConsoleLease, LeaseOwner

    lease = ConsoleLease(_key())
    lease.acquire(LeaseOwner.TRANSPORT)

    class _WedgedOwner:
        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            time.sleep(60)  # wedges before it can release the lease itself

        def force_drop(self, event: LifecycleEvent) -> None:
            lease.revoke()  # releases the out-of-band resource the subscriber owned

    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    dispatcher.subscribe(_key(), "owner", _WedgedOwner())
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert "owner" in result.overdue
    assert "owner" in result.force_dropped
    assert lease.snapshot()[0] is LeaseOwner.FREE  # the line was dropped despite the wedge


def test_overdue_worker_is_observable_then_pruned_when_it_finishes():
    # CPython cannot kill the abandoned worker, so it is tracked as observable overdue state;
    # once a (slow-but-finishing) subscriber completes, the count prunes back to 0.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.2)
    dispatcher.subscribe(_key(), "slow", _SlowButFinishingSubscriber(sleep_for=0.6))
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert "slow" in result.overdue
    assert dispatcher.outstanding_overdue() >= 1  # abandoned worker still running
    time.sleep(0.7)  # let it finish
    assert dispatcher.outstanding_overdue() == 0  # pruned -> no permanent accumulation


def test_self_bounded_subscriber_leaves_no_overdue_across_repeated_emits():
    # A correctly self-bounded (fast) subscriber finishes within the deadline every time, so
    # repeated lifecycle events never accumulate overdue workers.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=1.0)
    dispatcher.subscribe(_key(), "s", _RecordingSubscriber())
    for _ in range(20):
        result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
        assert result.overdue == ()
    assert dispatcher.outstanding_overdue() == 0


def test_single_flight_caps_workers_for_a_permanently_stuck_subscriber():
    # Repeated lifecycle events against a permanently-wedged subscriber must NOT spawn a new
    # stuck thread each time: it is tracked single-flight by (TargetKey, name) and not
    # re-invoked while still overdue, so worker count stays bounded at one.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.1)
    dispatcher.subscribe(_key(), "stuck", _StuckSubscriber())
    for _ in range(5):
        result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
        assert "stuck" in result.overdue
    assert dispatcher.outstanding_overdue() == 1  # not 5
    overdue = dispatcher.overdue_subscribers()
    assert overdue == {OverdueSubscriber(target_key=_key(), name="stuck", instance_id=next(iter(overdue)).instance_id)}


def test_new_subscriber_under_a_reused_overdue_name_is_still_torn_down():
    # Single-flight keys on the subscriber instance: a fresh subscriber registered under a name
    # whose predecessor is still wedged is NOT skipped — it is invalidated and force-dropped.
    dispatcher = InProcessLifecycleDispatcher(teardown_deadline=0.1)
    first = _StuckSubscriber()
    dispatcher.subscribe(_key(), "s", first)
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))  # "s" now overdue
    fresh = _StuckSubscriber()
    dispatcher.subscribe(_key(), "s", fresh)  # reuse the name with a NEW instance
    result = dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert fresh.force_dropped.is_set()  # the new binding was torn down, not skipped
    assert "s" in result.overdue
    # BOTH wedged instances stay observable as DISTINCT records (the reaper can act on each);
    # the new entry never overwrote/hid the old one, and identity is not collapsed by name.
    assert dispatcher.outstanding_overdue() == 2
    overdue = dispatcher.overdue_subscribers()
    assert len(overdue) == 2
    assert {o.name for o in overdue} == {"s"}
    assert {o.instance_id for o in overdue} == {id(first), id(fresh)}  # distinct per-instance ids


def test_subscriber_teardown_side_effect_is_token_fenced():
    # A subscriber forcibly releases its resource (revoke) inside its bounded invalidate; a
    # later stale-token release by any actor is a no-op, so resource state cannot be corrupted
    # after the transition (§4.4/§4.5 fencing, defense-in-depth over the supervised contract).
    from linux_debug_mcp.coordination.lease import ConsoleLease, LeaseOwner

    lease = ConsoleLease(_key())
    stale_token = lease.acquire(LeaseOwner.TRANSPORT)

    class _RevokingSubscriber:
        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            lease.revoke()  # the bounded, forced release this subscriber owns

        def force_drop(self, event: LifecycleEvent) -> None:
            pass

    dispatcher = InProcessLifecycleDispatcher()
    dispatcher.subscribe(_key(), "revoke", _RevokingSubscriber())
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED))
    assert lease.snapshot()[0] is LeaseOwner.FREE  # revoke took effect
    assert lease.release(stale_token) is False  # stale token fenced -> no-op


def test_unsubscribe_stops_delivery():
    dispatcher = InProcessLifecycleDispatcher()
    sub = _RecordingSubscriber()
    dispatcher.subscribe(_key(), "s", sub)
    dispatcher.unsubscribe(_key(), "s")
    dispatcher.emit(LifecycleEvent(target_key=_key(), kind=LifecycleKind.BOOTING))
    assert sub.events == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_seams_lifecycle.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.seams.lifecycle'`.

- [ ] **Step 3: Implement the dispatcher**

Create `src/linux_debug_mcp/seams/lifecycle.py`:

```python
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from linux_debug_mcp.seams.target import TargetKey

DEFAULT_TEARDOWN_DEADLINE_SECONDS = 5.0


class LifecycleKind(StrEnum):
    RESETTING = "resetting"
    CRASHED = "crashed"
    BOOTING = "booting"
    RELEASING = "releasing"
    LEASE_EXPIRED = "lease_expired"


@dataclass(frozen=True)
class LifecycleEvent:
    target_key: TargetKey
    kind: LifecycleKind


@runtime_checkable
class LifecycleSubscriber(Protocol):
    def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
        """Best-effort bounded teardown (e.g. `proc.wait(min(remaining, ...))`→`SIGKILL`).
        Idempotent. Run on a supervised worker joined under the deadline."""
        ...

    def force_drop(self, event: LifecycleEvent) -> None:
        """Invoked by the dispatcher when invalidate() exceeds the deadline. It releases the
        resources the subscriber recorded **out-of-band** — the registry's lease/guard tokens
        and recorded child pid — so release happens **independently of the wedged invalidate()
        frame** (those resources live in shared state, not the stuck stack). MUST be
        non-blocking and idempotent. This is how a transition completes without a leaked owner
        even when invalidate() is stuck; CPython cannot kill the wedged thread, but force_drop
        drops what it owned, and the still-running thread's late effects are token/gen fenced."""
        ...


@dataclass
class InvalidationResult:
    """Outcome of one emit(). `errors` maps subscriber-name → message. `overdue` lists
    subscribers whose invalidate() exceeded the deadline (their worker may still be running —
    see `outstanding_overdue()`); `force_dropped` lists those whose force_drop() then released
    their resources cleanly. The transition always completes."""

    target_key: TargetKey
    kind: LifecycleKind
    errors: dict[str, str] = field(default_factory=dict)
    overdue: tuple[str, ...] = ()
    force_dropped: tuple[str, ...] = ()


@dataclass(frozen=True)
class OverdueSubscriber:
    """Stable per-binding identity of a still-wedged teardown worker, so the Layer-4 reaper can
    act on *each* distinct wedged instance — not a name collapsed across instances. `instance_id`
    is `id()` of the wedged subscriber (stable while its worker keeps the object alive); two
    instances registered under a reused name are two distinct records, reapable independently."""

    target_key: TargetKey
    name: str
    instance_id: int


@runtime_checkable
class LifecycleDispatcher(Protocol):
    def subscribe(self, target_key: TargetKey, name: str, subscriber: LifecycleSubscriber) -> None: ...

    def unsubscribe(self, target_key: TargetKey, name: str) -> None: ...

    def emit(self, event: LifecycleEvent) -> InvalidationResult:
        """Run **step 2** of §4.5 — teardown only. The caller MUST have already closed admission
        (step 1, `AdmissionService.close_admission`) for this `target_key`; the safe ordering is
        enforced by `AdmissionService.invalidate_lifecycle`, which closes admission before calling
        this. emit() does not touch admission state (that would invert the layer dependency)."""
        ...


class InProcessLifecycleDispatcher:
    """TargetKey-keyed invalidation — **step 2** of §4.5 (teardown only; admission is closed in
    step 1 before this runs, see `AdmissionService.invalidate_lifecycle`). Two bounded phases,
    each joined **concurrently under one shared `teardown_deadline`**, so emit() always returns
    within ~2×deadline regardless of subscriber count and the transition never blocks on a stuck
    subscriber:

    1. invalidate() — best-effort teardown on a supervised worker.
    2. for any subscriber whose invalidate() overran, **force_drop()** — releases the
       resources that subscriber recorded out-of-band (lease/guard tokens, child pid),
       independently of the wedged invalidate() frame, so the line is dropped before emit
       returns even though the invalidate() thread is still stuck.

    CPython can't kill the wedged invalidate() thread, so it is tracked **single-flight** by
    `(TargetKey, subscriber)` in observable `outstanding_overdue()`/`overdue_subscribers()`
    state: a subscriber already overdue from a prior event is **not re-invoked**, so repeated
    reset/crash/release events against a permanently-wedged subscriber add **no** new threads
    (bounded at one stuck worker per subscriber). Its late effects are token/generation fenced.
    Per-subscriber errors are aggregated, never propagated."""

    def __init__(self, *, teardown_deadline: float = DEFAULT_TEARDOWN_DEADLINE_SECONDS) -> None:
        self._teardown_deadline = teardown_deadline
        self._lock = threading.Lock()
        self._subscribers: dict[TargetKey, dict[str, LifecycleSubscriber]] = {}
        # wedged workers keyed by (TargetKey, name, subscriber-instance id): keying on the
        # instance keeps each distinct wedged subscriber visible (a fresh instance reusing a
        # name never overwrites/hides its still-stuck predecessor) and is single-flight per
        # instance. id() is stable while the worker is alive (it references the subscriber).
        self._overdue: dict[tuple[TargetKey, str, int], threading.Thread] = {}

    def subscribe(self, target_key: TargetKey, name: str, subscriber: LifecycleSubscriber) -> None:
        with self._lock:
            self._subscribers.setdefault(target_key, {})[name] = subscriber

    def unsubscribe(self, target_key: TargetKey, name: str) -> None:
        with self._lock:
            subscribers = self._subscribers.get(target_key)
            if subscribers is not None:
                subscribers.pop(name, None)

    def _prune_overdue(self) -> None:  # caller holds self._lock
        self._overdue = {key: worker for key, worker in self._overdue.items() if worker.is_alive()}

    def overdue_subscribers(self) -> set[OverdueSubscriber]:
        """Every still-wedged teardown worker as an `OverdueSubscriber(target_key, name,
        instance_id)`, so the Layer-4 reaper can act on each distinct wedged instance — not a
        count, and not a name that collapses multiple wedged instances into one. A fresh
        subscriber registered under a reused name (its predecessor still stuck) is a SEPARATE
        record (distinct `instance_id`), so both are enumerated and reaped independently."""
        with self._lock:
            self._prune_overdue()
            return {
                OverdueSubscriber(target_key=target_key, name=name, instance_id=instance_id)
                for (target_key, name, instance_id) in self._overdue
            }

    def outstanding_overdue(self) -> int:
        with self._lock:
            self._prune_overdue()
            return len(self._overdue)

    def _run_bounded(
        self, names_to_fns: dict[str, Callable[[], None]]
    ) -> tuple[dict[str, dict[str, str]], list[str], dict[str, threading.Thread]]:
        """Run each named callable on a daemon worker, join all under ONE shared deadline.
        Returns (per-name error boxes, names still alive at the deadline, the worker map)."""
        boxes: dict[str, dict[str, str]] = {name: {} for name in names_to_fns}
        workers: dict[str, threading.Thread] = {}
        for name, fn in names_to_fns.items():

            def run(fn: Callable[[], None] = fn, box: dict[str, str] = boxes[name]) -> None:
                try:
                    fn()
                except Exception as exc:  # aggregate, never propagate
                    box["error"] = repr(exc)

            worker = threading.Thread(target=run, name=f"lifecycle-{name}", daemon=True)
            workers[name] = worker
            worker.start()
        deadline = time.monotonic() + self._teardown_deadline
        for worker in workers.values():
            worker.join(max(0.0, deadline - time.monotonic()))
        alive = [name for name, worker in workers.items() if worker.is_alive()]
        return boxes, alive, workers

    def emit(self, event: LifecycleEvent) -> InvalidationResult:
        # §4.5 step 2 (teardown). The caller (AdmissionService.invalidate_lifecycle) has already
        # run step 1 — admission is closed for this target_key, so no new admit can enter the
        # owner-free window while subscribers release leases/guards below.
        with self._lock:
            targeted = dict(self._subscribers.get(event.target_key, {}))
            self._prune_overdue()
            # Single-flight is keyed on the *subscriber instance*: a name is skipped only if the
            # currently-registered subscriber instance for it is the one still wedged. A new
            # subscriber registered under a reused name (its predecessor still overdue) has a
            # different id, so it is NOT skipped — its new live binding is still torn down, and
            # the predecessor's worker stays separately tracked/observable.
            already_overdue = {
                name for name, sub in targeted.items() if (event.target_key, name, id(sub)) in self._overdue
            }
        errors: dict[str, str] = {}
        overdue: list[str] = list(already_overdue)
        for name in already_overdue:
            errors[name] = "subscriber still overdue from a prior event; not re-invoked (single-flight)"
        runnable = {name: sub for name, sub in targeted.items() if name not in already_overdue}
        # Phase 1: invalidate() the runnable subscribers, concurrently under one shared deadline.
        inv_boxes, inv_alive, inv_workers = self._run_bounded(
            {name: (lambda s=sub: s.invalidate(event, self._teardown_deadline)) for name, sub in runnable.items()}
        )
        with self._lock:
            for name in inv_alive:
                self._overdue[(event.target_key, name, id(runnable[name]))] = inv_workers[name]  # per-instance
        for name in runnable:
            if name not in inv_alive and "error" in inv_boxes[name]:
                errors[name] = inv_boxes[name]["error"]
        # Phase 2: force_drop() the newly-overdue ones, concurrently under one shared deadline.
        force_dropped: list[str] = []
        if inv_alive:
            for name in inv_alive:
                overdue.append(name)
                errors[name] = f"invalidate exceeded {self._teardown_deadline}s; force_drop invoked"
            fd_boxes, fd_alive, _ = self._run_bounded({name: (lambda s=runnable[name]: s.force_drop(event)) for name in inv_alive})
            for name in inv_alive:
                if name in fd_alive:
                    errors[name] = "invalidate and force_drop both exceeded the deadline; registry reaper is the backstop"
                elif "error" in fd_boxes[name]:
                    errors[name] = f"force_drop error: {fd_boxes[name]['error']}"
                else:
                    force_dropped.append(name)
        return InvalidationResult(
            target_key=event.target_key,
            kind=event.kind,
            errors=errors,
            overdue=tuple(overdue),
            force_dropped=tuple(force_dropped),
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_seams_lifecycle.py -q`
Expected: PASS (13 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/lifecycle.py tests/test_seams_lifecycle.py
git commit -m "feat: add bounded in-process LifecycleDispatcher seam (#10)"
```

---

## Task 4: SnapshotStore + AdmissionService (`coordination/admission.py`)

This is the admission gate: freshness, snapshot re-binding, lease near-expiry, and the
**static** `TargetState` gate. It registers pending bindings carrying a `threading.Event`
cancel fence, and exposes `close_admission` (the §4.5 step-1 primitive). `invalidate_lifecycle`
enforces the §4.5 ordering in one place — it closes admission (step 1) BEFORE calling
`dispatcher.emit` (step 2 teardown), so no subscriber can release a lease/guard while admission
is still open. Positive ssh-tier admission against a `DEBUGGING` target (needs a fresh probe)
and the recovery-tombstone *mechanism* are Layer 4.

**Files:**
- Create: `src/linux_debug_mcp/coordination/admission.py`
- Test: `tests/test_coordination_admission.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_coordination_admission.py`:

```python
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from linux_debug_mcp.coordination.admission import (
    AdmissionError,
    AdmissionOp,
    AdmissionService,
    AdmissionState,
    ExecutionProof,
    SnapshotStore,
    TargetSnapshot,
)
from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.lifecycle import InProcessLifecycleDispatcher, LifecycleEvent, LifecycleKind
from linux_debug_mcp.seams.target import (
    ConsoleKind,
    LeaseInfo,
    PlatformMetadata,
    TargetKey,
    TargetState,
)
from linux_debug_mcp.transport.base import ExecutionState, LineRole, OpenRequest, TransportRef


def _key() -> TargetKey:
    return TargetKey(provisioner="local-qemu", target_id="run-1")


def _platform() -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=True
    )


def _channel() -> TransportRef:
    return TransportRef(
        provider="qemu-gdbstub", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp"]
    )


def _snapshot(*, generation: int = 0, state: TargetState = TargetState.READY, lease=None) -> TargetSnapshot:
    return TargetSnapshot(
        generation=generation,
        transports=(_channel(),),
        platform=_platform(),
        state=state,
        lease=lease,
    )


def _request(
    *, generation: int = 0, channel: TransportRef | None = None, min_lease_ttl=None, lease: LeaseInfo | None = None
) -> OpenRequest:
    return OpenRequest(
        target_key=_key(),
        generation=generation,
        transport_ref=channel or _channel(),
        required_caps=["provides_rsp"],
        platform=_platform(),
        min_lease_ttl=min_lease_ttl,
        lease=lease,
    )


def _service(snapshot: TargetSnapshot) -> AdmissionService:
    store = SnapshotStore()
    store.put(_key(), snapshot)
    return AdmissionService(store)


def test_admit_success_registers_pending_handle():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    assert handle.state is AdmissionState.PENDING
    assert handle.cancelled is False
    assert handle.channel.channel_id == "rsp-0"


def test_missing_snapshot_is_stale_handle():
    service = AdmissionService(SnapshotStore())
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request())
    assert excinfo.value.category is ErrorCategory.STALE_HANDLE


def test_generation_mismatch_is_stale_handle():
    service = _service(_snapshot(generation=5))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=4))
    assert excinfo.value.category is ErrorCategory.STALE_HANDLE


def test_foreign_channel_id_is_rejected():
    service = _service(_snapshot())
    foreign = TransportRef(provider="qemu-gdbstub", channel_id="ghost", line_role=LineRole.RSP, caps=["provides_rsp"])
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(channel=foreign))
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_edited_caps_on_known_channel_is_rejected():
    service = _service(_snapshot())
    edited = TransportRef(
        provider="qemu-gdbstub", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp", "supports_uart_break"]
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(channel=edited))
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_rebind_uses_snapshot_channel_object_not_caller_copy():
    snapshot = _snapshot()
    service = _service(snapshot)
    handle = service.admit(_key(), _request())
    # the bound channel is the snapshot's offered (frozen, shared) object, not the request copy
    assert handle.channel is snapshot.transports[0]


def test_admit_rejects_insufficient_required_caps():
    # The snapshot channel offers only provides_rsp; a tier requiring more is refused even
    # though the (provider, channel_id) rebind matches.
    service = _service(_snapshot())
    request = OpenRequest(
        target_key=_key(),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp", "supports_uart_break"],
        platform=_platform(),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), request)
    assert excinfo.value.code == "insufficient_caps"


def test_admit_rejects_platform_drift():
    # platform is a cached OpenRequest fact: if it has drifted from the authoritative snapshot
    # (here ssh_reachable True vs the request's False) admission rejects before any acquisition.
    snap_platform = PlatformMetadata(
        console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=True
    )
    store = SnapshotStore()
    store.put(
        _key(),
        TargetSnapshot(generation=0, transports=(_channel(),), platform=snap_platform, state=TargetState.READY),
    )
    service = AdmissionService(store)
    request = OpenRequest(
        target_key=_key(),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp"],
        platform=PlatformMetadata(
            console_kind=ConsoleKind.UART, console_count=1, dedicated_debug_line=False, ssh_reachable=False
        ),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), request)
    assert excinfo.value.code == "stale_platform"


def test_handle_binds_authoritative_platform_when_request_matches():
    # When the request platform matches the snapshot, it passes the drift check and the handle
    # carries the snapshot's authoritative platform object.
    service = _service(_snapshot())  # snapshot + _request both use _platform()
    handle = service.admit(_key(), _request())
    assert handle.platform == _platform()


def test_handle_platform_is_defensively_copied():
    # Mutating the platform returned from the handle must not change the bound authoritative
    # facts (the property hands out a fresh deep copy each access).
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    leaked = handle.platform
    leaked.ssh_reachable = not leaked.ssh_reachable  # mutate the returned copy
    assert handle.platform.ssh_reachable == _platform().ssh_reachable  # bound facts unchanged


def test_stale_lease_identity_rejected():
    later = datetime.now(UTC) + timedelta(hours=1)
    snap_lease = LeaseInfo(lease_id="snap-lease", holder="h", renewable=True, expires_at=later)
    service = _service(_snapshot(lease=snap_lease))
    request = OpenRequest(
        target_key=_key(),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp"],
        platform=_platform(),
        lease=LeaseInfo(lease_id="FOREIGN", holder="h", renewable=True, expires_at=later),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), request)
    assert excinfo.value.code == "stale_lease"


def test_snapshot_store_isolates_mutable_facts():
    later = datetime.now(UTC) + timedelta(hours=1)
    original = _snapshot(lease=LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=later))
    store = SnapshotStore()
    store.put(_key(), original)
    # mutating the caller's original after put() must not change the published facts
    original.lease.expires_at = datetime.now(UTC) + timedelta(seconds=1)
    assert store.get(_key()).lease.expires_at == later
    # mutating a returned copy must not change the store either
    returned = store.get(_key())
    returned.lease.expires_at = datetime.now(UTC) + timedelta(seconds=1)
    assert store.get(_key()).lease.expires_at == later


@pytest.mark.parametrize(
    "state",
    [
        TargetState.ACQUIRING,
        TargetState.PREPARING,
        TargetState.BOOTING,
        TargetState.RESETTING,
        TargetState.RELEASING,
        TargetState.CRASHED,
    ],
)
def test_non_live_state_rejected(state):
    service = _service(_snapshot(state=state))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.category is ErrorCategory.READINESS_FAILURE


def test_transport_open_requires_ready_state():
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError):
        service.admit(_key(), _request())


def test_ssh_tier_admits_on_ready():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    assert handle.state is AdmissionState.PENDING


def test_ssh_tier_on_debugging_without_proof_is_failclosed():
    # §5.6: a DEBUGGING target needs a FRESH EXECUTING probe (Layer 4) to admit ssh-tier; with no
    # proof (incl. probe_timeout) Layer 2 fails closed rather than admit on a possibly-stale flag.
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.code == "execution_state_unknown"


def test_ssh_tier_on_debugging_admits_with_fresh_executing_proof():
    # §5.3/§5.6: Layer 4 probes, then registers the EXECUTING ssh op in the SAME admission service
    # so it shares the cancel fence and lifecycle invalidation. A generation- AND epoch-current
    # EXECUTING proof admits.
    service = _service(_snapshot(generation=3, state=TargetState.DEBUGGING))
    epoch = service.current_execution_epoch(_key())
    handle = service.admit_ssh_tier(
        _key(), 3, _platform(), execution_proof=ExecutionProof(generation=3, epoch=epoch, state=ExecutionState.EXECUTING)
    )
    assert handle.state is AdmissionState.PENDING
    assert handle.op is AdmissionOp.SSH_TIER


def test_ssh_tier_on_debugging_rejected_when_proof_is_halted():
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    epoch = service.current_execution_epoch(_key())
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(
            _key(), 0, _platform(), execution_proof=ExecutionProof(generation=0, epoch=epoch, state=ExecutionState.HALTED)
        )
    assert excinfo.value.code == "target_halted"


def test_ssh_tier_on_debugging_rejected_when_proof_is_stale_generation():
    # A proof probed at a prior incarnation must not admit against the current snapshot — the
    # generation fence stops a stale EXECUTING from a pre-reset generation leaking ssh work in.
    service = _service(_snapshot(generation=4, state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(
            _key(), 4, _platform(), execution_proof=ExecutionProof(generation=3, epoch=0, state=ExecutionState.EXECUTING)
        )
    assert excinfo.value.code == "stale_handle"


def test_ssh_tier_executing_proof_is_rejected_after_a_same_generation_halt():
    # §4.6/§5.6 replay defense: an EXECUTING proof taken before an EXECUTING->HALTED transition
    # MUST NOT be replayable afterwards. A halt does not bump generation, so the epoch fence is
    # what catches it: cancel_ssh_tier (the halt) bumps the execution epoch, so the pre-halt proof
    # no longer matches and a new admit must re-probe rather than attach to a halted kernel.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    proof = ExecutionProof(generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING)
    op = service.admit_ssh_tier(_key(), 1, _platform(), execution_proof=proof)
    service.cancel_ssh_tier(_key(), 1)  # the kernel halted: cancel in-flight ops AND bump the epoch
    service.rollback(op)
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 1, _platform(), execution_proof=proof)  # SAME pre-halt proof
    assert excinfo.value.code == "execution_state_unknown"
    # a fresh re-probe (current epoch) admits again once the kernel is EXECUTING
    fresh = ExecutionProof(generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING)
    assert service.admit_ssh_tier(_key(), 1, _platform(), execution_proof=fresh).state is AdmissionState.PENDING


def test_cancel_ssh_tier_cancels_in_flight_without_closing_admission():
    # §5.6 async halt: in-flight ssh ops are cancelled when the kernel halts, but the target is
    # NOT torn down — once it resumes, a fresh EXECUTING proof admits ssh work again.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    ssh = service.admit_ssh_tier(
        _key(), 1, _platform(),
        execution_proof=ExecutionProof(generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING),
    )
    cancelled = service.cancel_ssh_tier(_key(), 1)
    assert ssh.cancelled and [h.handle_id for h in cancelled] == [ssh.handle_id]
    service.rollback(ssh)  # the op owner unwinds its cancelled handle
    # admission was NOT closed: a fresh EXECUTING proof (current epoch) admits after the resume
    resumed = service.admit_ssh_tier(
        _key(), 1, _platform(),
        execution_proof=ExecutionProof(generation=1, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING),
    )
    assert resumed.state is AdmissionState.PENDING


def test_stale_generation_cancel_leaves_newer_generation_ssh_handle_untouched():
    # A late HALTED from a prior incarnation must not cancel ssh work admitted after a reopen.
    # The handle carries the generation it was admitted at; cancel_ssh_tier fences on it, so a
    # cancel for the OLD generation is a no-op against a NEW-generation handle.
    service = _service(_snapshot(generation=5, state=TargetState.DEBUGGING))
    fresh = service.admit_ssh_tier(
        _key(), 5, _platform(),
        execution_proof=ExecutionProof(generation=5, epoch=service.current_execution_epoch(_key()), state=ExecutionState.EXECUTING),
    )
    cancelled = service.cancel_ssh_tier(_key(), 4)  # stale controller, prior generation
    assert cancelled == []
    assert fresh.cancelled is False  # the newer-generation ssh op is untouched
    assert service.cancel_ssh_tier(_key(), 5) == [fresh]  # the matching-generation cancel does fire


def test_ssh_only_target_with_no_transports_admits_ssh_tier():
    # An ssh-only target may have transports == (); admit_ssh_tier carries no transport_ref.
    store = SnapshotStore()
    store.put(_key(), TargetSnapshot(generation=0, transports=(), platform=_platform(), state=TargetState.READY))
    service = AdmissionService(store)
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    assert handle.op is AdmissionOp.SSH_TIER
    assert handle.channel is None


def test_ssh_only_target_rejects_resetting_state():
    store = SnapshotStore()
    store.put(_key(), TargetSnapshot(generation=0, transports=(), platform=_platform(), state=TargetState.RESETTING))
    service = AdmissionService(store)
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.code == "target_not_ready"


def test_near_expiry_lease_rejected_using_snapshot_copy():
    soon = datetime.now(UTC) + timedelta(seconds=10)
    lease = LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=soon)
    service = _service(_snapshot(lease=lease))
    # caller holds the matching lease but asks for a 300s minimum; snapshot expires in 10s -> reject
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(min_lease_ttl=300, lease=lease))
    assert excinfo.value.code == "lease_near_expiry"


def test_healthy_lease_admits():
    later = datetime.now(UTC) + timedelta(hours=1)
    lease = LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=later)
    service = _service(_snapshot(lease=lease))
    handle = service.admit(_key(), _request(min_lease_ttl=300, lease=lease))
    assert handle.state is AdmissionState.PENDING


def test_leased_target_rejects_request_with_no_lease():
    # Scarce-target fence: a leased snapshot requires the request to carry the matching lease;
    # omitting it must not bypass lease-holder identity even if generation/channel/platform match.
    later = datetime.now(UTC) + timedelta(hours=1)
    service = _service(_snapshot(lease=LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=later)))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request())  # no lease in the request
    assert excinfo.value.code == "stale_lease"


def test_promote_then_rollback_state_transitions():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    service.promote(handle)
    assert handle.state is AdmissionState.PROMOTED
    service.rollback(handle)  # a promoted-but-failed open rolls back
    assert handle.state is AdmissionState.ROLLED_BACK


def test_complete_on_pending_transport_open_is_rejected():
    # A pending transport.open must promote or rollback — never complete straight from PENDING,
    # which would drop an in-flight open without rolling back its partial resources.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    with pytest.raises(AdmissionError) as excinfo:
        service.complete(handle)
    assert excinfo.value.code == "invalid_terminal_transition"
    # promoting first, then completing, is allowed
    service.promote(handle)
    service.complete(handle)
    assert handle.state is AdmissionState.COMPLETED


def test_ssh_tier_complete_deregisters_handle():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    service.complete(handle)
    assert handle.state is AdmissionState.COMPLETED
    # a completed handle is deregistered: a later invalidation does not re-touch it
    assert service.close_admission(_key()) == []


def test_promote_after_rollback_is_rejected():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    service.rollback(handle)
    with pytest.raises(AdmissionError) as excinfo:
        service.promote(handle)
    assert excinfo.value.code == "handle_not_pending"


def test_double_completion_is_rejected():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    service.complete(handle)
    with pytest.raises(AdmissionError) as excinfo:
        service.complete(handle)
    assert excinfo.value.code == "handle_already_disposed"


def test_rollback_after_completion_is_rejected():
    service = _service(_snapshot(state=TargetState.READY))
    handle = service.admit_ssh_tier(_key(), 0, _platform())
    service.complete(handle)
    with pytest.raises(AdmissionError) as excinfo:
        service.rollback(handle)
    assert excinfo.value.code == "handle_already_disposed"


def test_admission_handle_cancellation_is_read_only_and_monotonic():
    # The cancel fence is private: callers cannot clear or reassign it, and there is no public
    # Event. Only the service signals cancellation (monotonically), via close_admission.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    assert handle.cancelled is False
    assert not hasattr(handle, "cancel")  # no public Event to clear/reassign
    with pytest.raises(AttributeError):
        handle.cancelled = False  # read-only property
    with pytest.raises(AttributeError):
        handle.state = AdmissionState.PROMOTED  # read-only property
    service.close_admission(_key())
    assert handle.cancelled is True
    with pytest.raises(AdmissionError):
        service.promote(handle)  # a cancelled handle cannot be promoted


def test_close_admission_cancels_pending_and_promoted_and_blocks_new():
    service = _service(_snapshot())
    pending = service.admit_ssh_tier(_key(), 0, _platform())
    promoted = service.admit_ssh_tier(_key(), 0, _platform())
    service.promote(promoted)
    cancelled = service.close_admission(_key())
    assert pending.cancelled and promoted.cancelled
    assert {pending.handle_id, promoted.handle_id} == {h.handle_id for h in cancelled}
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert excinfo.value.code == "admission_closed"


def test_promote_after_cancel_is_rejected():
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    service.close_admission(_key())
    with pytest.raises(AdmissionError):
        service.promote(handle)


def test_invalidate_lifecycle_closes_admission_before_any_teardown():
    # §4.5 ordering, enforced in one place: invalidate_lifecycle runs step 1 (close_admission)
    # to completion BEFORE step 2 (dispatcher.emit teardown). A teardown subscriber that probes
    # admission at the moment it runs must find it already CLOSED — so no subscriber can release
    # a lease/guard while a concurrent admit could still slip in against the stale generation.
    store = SnapshotStore()
    store.put(_key(), _snapshot())
    service = AdmissionService(store)
    dispatcher = InProcessLifecycleDispatcher()
    observed_closed: list[bool] = []

    class _ProbingSubscriber:
        def invalidate(self, event: LifecycleEvent, deadline: float) -> None:
            try:
                service.admit(_key(), _request())
                observed_closed.append(False)  # admission was still open during teardown — BUG
            except AdmissionError as exc:
                observed_closed.append(exc.code == "admission_closed")

        def force_drop(self, event: LifecycleEvent) -> None:
            pass

    dispatcher.subscribe(_key(), "transport", _ProbingSubscriber())
    pending = service.admit_ssh_tier(_key(), 0, _platform())
    service.invalidate_lifecycle(LifecycleEvent(target_key=_key(), kind=LifecycleKind.CRASHED), dispatcher)
    assert pending.cancelled  # step 1 cancelled the in-flight handle
    assert observed_closed == [True]  # admission was already closed when teardown ran


def test_reopen_after_generation_bump_allows_admission():
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    service.close_admission(_key())  # records closed-at generation 0
    # provisioning publishes the new-incarnation snapshot, THEN admission reopens
    store.put(_key(), _snapshot(generation=1))
    service.reopen(_key())
    handle = service.admit(_key(), _request(generation=1))
    assert handle.state is AdmissionState.PENDING


def test_early_reopen_before_new_snapshot_stays_closed():
    # The race the fence prevents: reopen is called before the generation-1 snapshot is
    # published. reopen reads the authoritative store (still generation 0) and refuses, so a
    # stale generation-0 OpenRequest cannot replay during reset/release.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    service.close_admission(_key())
    with pytest.raises(AdmissionError) as excinfo:
        service.reopen(_key())  # store still has generation 0
    assert excinfo.value.code == "generation_not_advanced"
    with pytest.raises(AdmissionError) as still_closed:
        service.admit(_key(), _request(generation=0))
    assert still_closed.value.code == "admission_closed"


def test_reopen_blocked_while_prior_bindings_outstanding():
    # reopen must not admit new work while a prior-generation handle is still unwinding, or
    # stale work could return/mutate alongside the new incarnation.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    handle = service.admit(_key(), _request())
    service.close_admission(_key())  # handle cancelled but still a registered PENDING binding
    store.put(_key(), _snapshot(generation=1))
    with pytest.raises(AdmissionError) as excinfo:
        service.reopen(_key())
    assert excinfo.value.code == "bindings_outstanding"
    service.rollback(handle)  # the open transaction disposes the stale handle
    service.reopen(_key())  # now there are no outstanding bindings -> reopen succeeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_abandon_force_drops_overdue_handle_so_reopen_can_proceed():
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    handle = service.admit(_key(), _request())
    service.close_admission(_key())
    service.confirm_reaped(handle)  # the Layer-4 reaper reclaimed its resources
    service.abandon(handle)  # owner could not roll it back -> explicit force-drop
    assert handle.state is AdmissionState.ABANDONED
    store.put(_key(), _snapshot(generation=1))
    service.reopen(_key())  # the abandoned handle was deregistered, so reopen proceeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_abandon_requires_reaper_confirmation_before_reopen():
    # A cancelled PROMOTED handle on a closed target must not be deregistered (and so must not
    # unblock reopen) until the reaper proves its external resources were reclaimed. Otherwise a
    # new incarnation could be admitted alongside a still-live backend/lease/guard.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    handle = service.admit(_key(), _request())
    service.promote(handle)
    service.close_admission(_key())  # cancelled, but resources not yet reaped
    with pytest.raises(AdmissionError) as not_reaped:
        service.abandon(handle)
    assert not_reaped.value.code == "reaper_confirmation_required"
    store.put(_key(), _snapshot(generation=1))
    with pytest.raises(AdmissionError) as still_outstanding:
        service.reopen(_key())  # the live binding still blocks reopen
    assert still_outstanding.value.code == "bindings_outstanding"
    service.confirm_reaped(handle)
    service.abandon(handle)
    service.reopen(_key())
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_confirm_reaped_requires_closed_target_and_cancelled_handle():
    # confirm_reaped is the reaper's hook: it is rejected on a live (not-closed) target so it can
    # never falsely mark a live binding as reaped.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    with pytest.raises(AdmissionError) as excinfo:
        service.confirm_reaped(handle)
    assert excinfo.value.code == "reap_not_permitted"
    assert handle.reaped is False


def test_snapshot_store_rejects_generation_regression():
    # generation is the monotonic freshness fence: a stale/out-of-order writer storing an older
    # generation after a newer one must be refused, or _bind_snapshot would treat the stale
    # generation as current and admit a pre-reset OpenRequest.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=2))
    store.put(_key(), _snapshot(generation=2))  # idempotent re-publish at the same gen is allowed
    with pytest.raises(AdmissionError) as excinfo:
        store.put(_key(), _snapshot(generation=1))
    assert excinfo.value.code == "snapshot_generation_regression"
    assert store.get(_key()).generation == 2  # the authoritative generation did not regress


def test_tombstone_ahead_of_snapshot_fails_closed():
    # A recovery_required tombstone parked AHEAD of the published snapshot (e.g. the snapshot has
    # not yet caught up) must gate ordinary admit closed, not be treated as a superseded stale
    # tombstone. Only a tombstone strictly older than the snapshot is superseded.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=1))
    service = AdmissionService(store)
    service.mark_recovery_required(_key(), 2)  # parked ahead of the gen-1 snapshot
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=1))
    assert excinfo.value.code == "recovery_required"


def test_stale_recovery_clear_does_not_free_a_newer_tombstone():
    # A stale actor clearing generation N must NOT free a newer N+1 recovery_required mark.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 1)
    service.clear_recovery_required(_key(), 0)  # stale clear for the old generation -> no-op
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=1))
    assert excinfo.value.code == "recovery_required"
    service.clear_recovery_required(_key(), 1)  # generation-current clear succeeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_stale_recovery_mark_does_not_regress_a_current_tombstone():
    # A stale mark for generation N must not overwrite a current N+1 mark.
    service = _service(_snapshot(generation=1, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 1)
    service.mark_recovery_required(_key(), 0)  # stale -> ignored, the N=1 tombstone stands
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request(generation=1))
    assert excinfo.value.code == "recovery_required"


def test_request_target_key_mismatch_is_rejected():
    # The OpenRequest's own target_key must match the admission target; a foreign request
    # whose generation/channel happen to match must not be admitted cross-target.
    service = _service(_snapshot())
    foreign = OpenRequest(
        target_key=TargetKey(provisioner="local-qemu", target_id="OTHER"),
        generation=0,
        transport_ref=_channel(),
        required_caps=["provides_rsp"],
        platform=_platform(),
    )
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), foreign)
    assert excinfo.value.code == "target_mismatch"


def test_admit_recovery_requires_a_generation_current_tombstone():
    service = _service(_snapshot(generation=0, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 0)
    handle = service.admit_recovery(_key(), _request())
    assert handle.op is AdmissionOp.TRANSPORT_OPEN
    assert handle.state is AdmissionState.PENDING


def test_admit_recovery_without_tombstone_is_rejected():
    # admit_recovery is not a general bypass: with no current recovery_required tombstone it
    # must be rejected, not silently admitted against a DEBUGGING target.
    service = _service(_snapshot(generation=0, state=TargetState.DEBUGGING))
    with pytest.raises(AdmissionError) as excinfo:
        service.admit_recovery(_key(), _request())
    assert excinfo.value.code == "not_recovery_required"


def test_ordinary_lifecycle_close_blocks_even_admit_recovery():
    # During an ordinary reset/release teardown, NO new work registers — not even recovery —
    # before leases/guards are revoked. (close_admission is the lifecycle gate.)
    service = _service(_snapshot(state=TargetState.DEBUGGING))
    service.close_admission(_key())
    with pytest.raises(AdmissionError) as ordinary:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert ordinary.value.code == "admission_closed"
    with pytest.raises(AdmissionError) as recovery:
        service.admit_recovery(_key(), _request())
    assert recovery.value.code == "admission_closed"


def test_recovery_required_blocks_ordinary_admit_but_allows_recovery():
    # The recovery_required tombstone gate (distinct from lifecycle close): ordinary admit is
    # rejected, but admit_recovery is the one path allowed to resume/detach the parked kernel.
    service = _service(_snapshot(generation=0, state=TargetState.DEBUGGING))
    service.mark_recovery_required(_key(), 0)  # parked at the current generation
    with pytest.raises(AdmissionError) as ordinary:
        service.admit_ssh_tier(_key(), 0, _platform())
    assert ordinary.value.code == "recovery_required"
    handle = service.admit_recovery(_key(), _request())
    assert handle.state is AdmissionState.PENDING


def test_stale_recovery_tombstone_is_superseded_after_generation_bump():
    # A reset advanced the incarnation past the parked generation: the N=0 tombstone is stale
    # and must NOT strand the freshly-booted N=1 kernel (§4.7 generation idempotency).
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0, state=TargetState.READY))
    service = AdmissionService(store)
    service.mark_recovery_required(_key(), 0)
    store.put(_key(), _snapshot(generation=1, state=TargetState.READY))
    handle = service.admit(_key(), _request(generation=1))
    assert handle.state is AdmissionState.PENDING


def test_recovery_tombstone_fails_closed_without_authoritative_snapshot():
    # Bare startup: a tombstone exists but no authoritative snapshot/generation yet -> the gate
    # FAILS CLOSED with recovery_required (not stale_handle), so a parked key can't be admitted.
    service = AdmissionService(SnapshotStore())
    service.mark_recovery_required(_key(), 0)
    with pytest.raises(AdmissionError) as excinfo:
        service.admit(_key(), _request())
    assert excinfo.value.code == "recovery_required"


def test_abandon_requires_closed_target_and_cancelled_handle():
    # abandon is not a way to drop a live binding: it is rejected before close, and rejected
    # for a promoted live session that was never cancelled.
    service = _service(_snapshot())
    handle = service.admit(_key(), _request())
    with pytest.raises(AdmissionError) as before_close:
        service.abandon(handle)  # target not closed, handle not cancelled
    assert before_close.value.code == "abandon_not_permitted"
    service.promote(handle)
    with pytest.raises(AdmissionError) as promoted_live:
        service.abandon(handle)  # still not closed/cancelled
    assert promoted_live.value.code == "abandon_not_permitted"


def test_close_admission_is_idempotent_across_generation_publication():
    # A duplicate close after generation N+1 is published must NOT push the reopen bar to N+2:
    # the first closed-at generation (N) is preserved, so reopen at N+1 still succeeds.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    service.close_admission(_key())  # closed at generation 0
    store.put(_key(), _snapshot(generation=1))
    service.close_admission(_key())  # duplicate close after N+1 published -> still closed-at 0
    service.reopen(_key())  # 1 > 0 -> succeeds
    assert service.admit(_key(), _request(generation=1)).state is AdmissionState.PENDING


def test_publish_snapshot_serializes_with_the_admission_key_lock():
    # F3: a generation bump must not interleave between an admit's snapshot read and its handle
    # registration. publish_snapshot takes the SAME per-TargetKey lock as admit, so while that
    # lock is held (standing in for an in-flight admit critical section) a concurrent publication
    # blocks until the section completes — it cannot split an admit.
    store = SnapshotStore()
    store.put(_key(), _snapshot(generation=0))
    service = AdmissionService(store)
    published = threading.Event()

    def publisher() -> None:
        service.publish_snapshot(_key(), _snapshot(generation=1))
        published.set()

    with service._key_lock(_key()):  # hold the key lock as an in-flight admit would
        worker = threading.Thread(target=publisher)
        worker.start()
        time.sleep(0.05)
        assert not published.is_set()  # blocked on the shared per-TargetKey lock
    worker.join(2.0)
    assert published.is_set()  # released once the critical section ended
    assert store.get(_key()).generation == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_coordination_admission.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.coordination.admission'`.

- [ ] **Step 3: Implement the snapshot store + admission service**

Create `src/linux_debug_mcp/coordination/admission.py`:

```python
from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.seams.lifecycle import InvalidationResult, LifecycleDispatcher, LifecycleEvent
from linux_debug_mcp.seams.target import LeaseInfo, PlatformMetadata, TargetKey, TargetState
from linux_debug_mcp.transport.base import (
    DEFAULT_MIN_LEASE_TTL_SECONDS,
    ExecutionState,
    OpenRequest,
    TransportRef,
)

# States from which no live op may attach (the target is mid-transition or dead).
_NON_LIVE_STATES = frozenset(
    {
        TargetState.ACQUIRING,
        TargetState.PREPARING,
        TargetState.BOOTING,
        TargetState.RESETTING,
        TargetState.RELEASING,
        TargetState.CRASHED,
    }
)


class AdmissionOp(StrEnum):
    TRANSPORT_OPEN = "transport.open"  # stop-capable attach (requires READY)
    SSH_TIER = "ssh_tier"  # smoke tests / ssh debug reads (READY or DEBUGGING)


class AdmissionState(StrEnum):
    PENDING = "pending"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"
    COMPLETED = "completed"
    ABANDONED = "abandoned"  # force-dropped overdue handle whose owner could not roll it back


@dataclass(frozen=True)
class ExecutionProof:
    """A FRESH execution-state observation, produced ONLY by the Layer-4 bounded liveness probe
    (§4.6/§5.6). Layer 2 never manufactures it — so a positive ssh-tier admission against a
    DEBUGGING target always rests on a fresh probe, never a cached/stale flag (spec §4.6: "do not
    trust a possibly-stale EXECUTING"). Two freshness fences: `generation` is the snapshot
    generation the probe observed at (rejects a proof from a prior incarnation), and `epoch` is
    the per-target **execution epoch** the probe read at (`current_execution_epoch`). Because a
    bare halt/continue does NOT bump `generation`, `epoch` is what stops an `EXECUTING` proof
    taken before an `EXECUTING→HALTED` transition from being replayed afterwards: every transition
    bumps the epoch, so a stale proof no longer matches and admission re-probes instead of hanging
    on a frozen network stack. `state` is the probed `ExecutionState`. The probe (and its
    `probe_timeout`) is Layer 4; admission only consumes the value — no callback/IO under the lock."""

    generation: int
    epoch: int
    state: ExecutionState


class AdmissionError(RuntimeError):
    """Admission refusal. `category` is the agent-facing ErrorCategory; `code` is the precise
    machine-readable reason (spec §4.2/§8.1)."""

    def __init__(self, message: str, *, category: ErrorCategory, code: str) -> None:
        super().__init__(message)
        self.category = category
        self.code = code


@dataclass(frozen=True)
class TargetSnapshot:
    """Authoritative per-target facts admission re-binds against (spec §4.1). The local-qemu
    adapter (Layer 4) writes this when a run boots to READY; provisioning later owns it."""

    generation: int
    transports: tuple[TransportRef, ...]
    platform: PlatformMetadata
    state: TargetState
    lease: LeaseInfo | None = None


class AdmissionHandle:
    """Opaque scoped binding (spec §3.3). Cancellation is **private and monotonic** — only the
    AdmissionService signals it (and never clears it); callers get a read-only `cancelled`
    property and an interruptible `wait_cancelled(timeout)`, with no public Event to clear or
    reassign. Identity/authority fields (`channel`, `platform`) are read-only and bound from
    the authoritative snapshot at admit() time, so downstream code never re-reads caller copies."""

    __slots__ = ("_handle_id", "_target_key", "_generation", "_op", "_channel", "_platform", "_recovery", "_state", "_cancel", "_reaped")

    def __init__(
        self,
        *,
        handle_id: str,
        target_key: TargetKey,
        generation: int,
        op: AdmissionOp,
        channel: TransportRef | None,
        platform: PlatformMetadata,
        recovery: bool,
    ) -> None:
        self._handle_id = handle_id
        self._target_key = target_key
        # The authoritative snapshot generation this handle was admitted against. Bound at
        # registration so targeted async operations (cancel_ssh_tier) can fence on it: a late
        # cancel from a prior incarnation must never touch a handle admitted after a reset/reopen.
        self._generation = generation
        self._op = op
        self._channel = channel
        self._platform = platform
        self._recovery = recovery
        self._state = AdmissionState.PENDING
        self._cancel = threading.Event()
        # Set by AdmissionService.confirm_reaped() once the Layer-4 reaper has reclaimed every
        # external resource this binding held (backend child, lease, guard). Private and
        # monotonic, like _cancel: only the service signals it, and abandon() requires it so a
        # cancelled binding can never be deregistered (unblocking reopen) before teardown is proven.
        self._reaped = threading.Event()

    @property
    def handle_id(self) -> str:
        return self._handle_id

    @property
    def target_key(self) -> TargetKey:
        return self._target_key

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def op(self) -> AdmissionOp:
        return self._op

    @property
    def channel(self) -> TransportRef | None:
        return self._channel

    @property
    def platform(self) -> PlatformMetadata:
        # PlatformMetadata is a mutable pydantic model; return a defensive deep copy each access
        # so a consumer cannot mutate the handle's bound authoritative facts (ssh_reachable,
        # console_kind, break_hints) between admission and break-plan selection.
        return self._platform.model_copy(deep=True)

    @property
    def recovery(self) -> bool:
        return self._recovery

    @property
    def state(self) -> AdmissionState:
        return self._state

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    @property
    def reaped(self) -> bool:
        return self._reaped.is_set()

    def wait_cancelled(self, timeout: float | None = None) -> bool:
        return self._cancel.wait(timeout)


def _isolate_snapshot(snapshot: TargetSnapshot) -> TargetSnapshot:
    """Return a copy whose mutable Layer-1 models (LeaseInfo/PlatformMetadata have
    validate_assignment, so they are mutable) are deep-copied, so neither a caller retaining
    the original nor a consumer of get() can mutate the published authoritative facts.
    `transports` are frozen, deeply-immutable TransportRefs, so the tuple is shared safely."""
    return TargetSnapshot(
        generation=snapshot.generation,
        transports=tuple(snapshot.transports),
        platform=snapshot.platform.model_copy(deep=True),
        state=snapshot.state,
        lease=snapshot.lease.model_copy(deep=True) if snapshot.lease is not None else None,
    )


class SnapshotStore:
    """In-memory TargetKey → TargetSnapshot map (spec §4.1). Thread-safe, and isolates the
    authoritative facts on both put() and get() so a retained reference cannot mutate
    `lease.expires_at` / `platform.ssh_reachable` after publication without a generation bump.
    `generation` is the **monotonic freshness fence**, so put() rejects any regression for a
    key: a stale/out-of-order publisher storing generation N after N+1 cannot make a pre-reset
    OpenRequest admissible again (it would defeat stale_handle before any lease/guard acquire)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshots: dict[TargetKey, TargetSnapshot] = {}

    def put(self, target_key: TargetKey, snapshot: TargetSnapshot) -> None:
        with self._lock:
            current = self._snapshots.get(target_key)
            if current is not None and snapshot.generation < current.generation:
                raise AdmissionError(
                    f"snapshot generation regression for target: {snapshot.generation} < {current.generation}",
                    category=ErrorCategory.CONFIGURATION_ERROR,
                    code="snapshot_generation_regression",
                )
            self._snapshots[target_key] = _isolate_snapshot(snapshot)

    def get(self, target_key: TargetKey) -> TargetSnapshot | None:
        with self._lock:
            stored = self._snapshots.get(target_key)
            return _isolate_snapshot(stored) if stored is not None else None


class AdmissionService:
    """The short-critical-section admission gate (spec §4.2). One RLock per TargetKey guards
    freshness + snapshot re-binding + lease near-expiry + the static state gate, then
    registers a pending binding with a cancel fence. The open() transaction (Layer 4) drives
    promote/rollback. `invalidate_lifecycle` enforces the §4.5 ordering — close_admission (step 1)
    runs to completion before `dispatcher.emit` (step 2 teardown), so admission is provably closed
    before any subscriber can release a lease/guard."""

    def __init__(
        self,
        snapshot_store: SnapshotStore,
        *,
        default_min_lease_ttl: int = DEFAULT_MIN_LEASE_TTL_SECONDS,
    ) -> None:
        self._store = snapshot_store
        self._default_min_lease_ttl = default_min_lease_ttl
        self._table_lock = threading.Lock()
        self._key_locks: dict[TargetKey, threading.RLock] = {}
        self._bindings: dict[TargetKey, list[AdmissionHandle]] = defaultdict(list)
        self._closed_at: dict[TargetKey, int] = {}  # lifecycle closure: target_key -> gen closed at
        self._recovery_required: dict[TargetKey, int] = {}  # tombstone gate: target_key -> parked gen (§4.7)
        self._exec_epoch: dict[TargetKey, int] = {}  # §4.6 execution epoch: bumps on EVERY exec-state transition

    def _key_lock(self, target_key: TargetKey) -> threading.RLock:
        with self._table_lock:
            lock = self._key_locks.get(target_key)
            if lock is None:
                lock = threading.RLock()
                self._key_locks[target_key] = lock
            return lock

    def current_execution_epoch(self, target_key: TargetKey) -> int:
        """The per-target execution epoch Layer 4 stamps onto an `ExecutionProof` right after it
        probes `EXECUTING` (§4.6). admit_ssh_tier admits only if the proof's epoch still matches,
        so a transition between probe and admit invalidates the proof."""
        with self._key_lock(target_key):
            return self._exec_epoch.get(target_key, 0)

    def note_execution_transition(self, target_key: TargetKey) -> int:
        """Layer 4 calls this on EVERY execution-state transition the stop-capable controller
        causes (`EXECUTING→HALTED`, `HALTED→EXECUTING`, `→UNKNOWN`). It bumps the execution epoch so
        any `ExecutionProof` stamped before the transition no longer matches — a stale `EXECUTING`
        can never be replayed across a halt. Returns the new epoch."""
        with self._key_lock(target_key):
            epoch = self._exec_epoch.get(target_key, 0) + 1
            self._exec_epoch[target_key] = epoch
            return epoch

    def publish_snapshot(self, target_key: TargetKey, snapshot: TargetSnapshot) -> None:
        """The authoritative-facts publication entry Layer 4 MUST use for a live target. It holds
        the SAME per-TargetKey lock as admit/reopen/close, so a generation bump can never
        interleave between an admit's snapshot read and its handle registration — admit sees one
        consistent snapshot for the whole critical section, and a publication either fully precedes
        or fully follows it. (`SnapshotStore.put` keeps its own monotonic-generation guard as
        defense in depth; calling it directly is only for single-threaded test seeding before
        admission is active.)"""
        with self._key_lock(target_key):
            self._store.put(target_key, snapshot)

    def admit(self, target_key: TargetKey, request: OpenRequest, *, now: datetime | None = None) -> AdmissionHandle:
        """transport.open admission: requires a `transport_ref`, the target must be READY."""
        with self._key_lock(target_key):
            snapshot, channel = self._validate_open(target_key, request, now or datetime.now(UTC), recovery=False)
            if snapshot.state is not TargetState.READY:
                raise AdmissionError("stop-capable open requires READY", category=ErrorCategory.READINESS_FAILURE, code="target_not_ready")
            return self._register(target_key, AdmissionOp.TRANSPORT_OPEN, channel, snapshot, recovery=False)

    def admit_recovery(self, target_key: TargetKey, request: OpenRequest, *, now: datetime | None = None) -> AdmissionHandle:
        """The one admission entry permitted while a target is `recovery_required` (§4.7): it
        bypasses the recovery_required gate (NOT the lifecycle close gate), requires a
        generation-current tombstone (never a general bypass), and may attach to DEBUGGING."""
        with self._key_lock(target_key):
            snapshot, channel = self._validate_open(target_key, request, now or datetime.now(UTC), recovery=True)
            self._require_recovery_tombstone(target_key, snapshot)
            return self._register(target_key, AdmissionOp.TRANSPORT_OPEN, channel, snapshot, recovery=True)

    def admit_ssh_tier(
        self,
        target_key: TargetKey,
        generation: int,
        platform: PlatformMetadata,
        *,
        lease: LeaseInfo | None = None,
        min_lease_ttl: int | None = None,
        execution_proof: ExecutionProof | None = None,
        now: datetime | None = None,
    ) -> AdmissionHandle:
        """ssh-backed live-tier admission (smoke tests / ssh debug reads), registered in the SAME
        per-TargetKey service as transport.open so it shares the cancel fence, binding table, and
        lifecycle invalidation (contract §5.3). An ssh-only target may have `transports == ()`, so
        this carries **no transport_ref** and binds no channel. **READY** admits with no execution
        proof. **DEBUGGING** admits ONLY when the caller supplies a fresh, generation-current
        `ExecutionProof` reporting `EXECUTING` (§5.6) — the probe is Layer 4; Layer 2 fences it by
        generation and never trusts a cached flag. `HALTED` → `target_halted`; a missing, stale, or
        `UNKNOWN` proof → `execution_state_unknown` (fail-closed, never left to hang)."""
        now = now or datetime.now(UTC)
        with self._key_lock(target_key):
            snapshot = self._bind_snapshot(target_key, generation, recovery=False)
            self._check_platform_drift(snapshot, platform)
            self._check_lease_identity(snapshot, lease)
            self._check_lease_ttl(snapshot, lease, min_lease_ttl, now)
            self._reject_non_live(snapshot.state)
            if snapshot.state is not TargetState.READY:  # the only other live state is DEBUGGING
                self._require_executing_proof(target_key, snapshot, execution_proof)
            return self._register(target_key, AdmissionOp.SSH_TIER, None, snapshot, recovery=False)

    def _validate_open(self, target_key: TargetKey, request: OpenRequest, now: datetime, *, recovery: bool) -> tuple[TargetSnapshot, TransportRef]:
        """All authoritative checks for a transport_ref-carrying (open/recovery) request."""
        if request.target_key != target_key:
            raise AdmissionError(
                "request.target_key does not match the admission target",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="target_mismatch",
            )
        snapshot = self._bind_snapshot(target_key, request.generation, recovery=recovery)
        channel = self._rebind(request.transport_ref, snapshot)
        self._check_caps(request.required_caps, channel)
        self._check_platform_drift(snapshot, request.platform)
        self._check_lease_identity(snapshot, request.lease)
        self._check_lease_ttl(snapshot, request.lease, request.min_lease_ttl, now)
        self._reject_non_live(snapshot.state)
        return snapshot, channel

    def _require_recovery_tombstone(self, target_key: TargetKey, snapshot: TargetSnapshot) -> None:
        tombstone_generation = self._recovery_required.get(target_key)
        if tombstone_generation is None or tombstone_generation != snapshot.generation:
            raise AdmissionError(
                "recovery-mode attach requires a generation-current recovery_required tombstone",
                category=ErrorCategory.READINESS_FAILURE,
                code="not_recovery_required",
            )

    def _check_platform_drift(self, snapshot: TargetSnapshot, platform: PlatformMetadata) -> None:
        # platform is a cached request fact (contract §3.3): reject if it has drifted from the
        # authoritative snapshot, so a stale/foreign handle fails before any acquisition.
        if platform != snapshot.platform:
            raise AdmissionError(
                "request.platform does not match the authoritative snapshot (stale/foreign facts)",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="stale_platform",
            )

    def _bind_snapshot(self, target_key: TargetKey, generation: int, *, recovery: bool) -> TargetSnapshot:
        # Ordinary lifecycle closure (reset/release/crash teardown) blocks ALL new work —
        # including admit_recovery() — so no live op registers before leases/guards are
        # revoked. This is distinct from the recovery_required tombstone gate below.
        if target_key in self._closed_at:
            raise AdmissionError("admission closed for target", category=ErrorCategory.READINESS_FAILURE, code="admission_closed")
        snapshot = self._store.get(target_key)
        tombstone_generation = self._recovery_required.get(target_key)
        if not recovery and tombstone_generation is not None:
            # Generation-aware tombstone (§4.7): gate ordinary admit while the tombstone is
            # current OR ahead of the authoritative snapshot. At bare startup (no snapshot / no
            # authoritative generation) FAIL CLOSED. Only a tombstone strictly OLDER than the
            # current snapshot is stale (a reset advanced past the parked generation) and is
            # superseded — admission is allowed (Layer 4 clears it via the reset path). A
            # tombstone AHEAD of the snapshot (snapshot regressed below it, or it was parked at a
            # not-yet-published generation) must fail closed, never admit against the stale facts.
            if snapshot is None or tombstone_generation >= snapshot.generation:
                raise AdmissionError(
                    "target is recovery_required; only transport.open(recovery=true) may attach",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="recovery_required",
                )
        if snapshot is None:
            raise AdmissionError("no authoritative snapshot for target", category=ErrorCategory.STALE_HANDLE, code="stale_handle")
        if generation != snapshot.generation:
            raise AdmissionError(
                f"stale generation {generation} != {snapshot.generation}",
                category=ErrorCategory.STALE_HANDLE,
                code="stale_handle",
            )
        return snapshot

    def _check_caps(self, required_caps: Iterable[str], channel: TransportRef) -> None:
        if not set(required_caps) <= set(channel.caps):
            raise AdmissionError(
                "selected channel does not satisfy the tier's required_caps",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="insufficient_caps",
            )

    def _register(self, target_key: TargetKey, op: AdmissionOp, channel: TransportRef | None, snapshot: TargetSnapshot, recovery: bool) -> AdmissionHandle:
        handle = AdmissionHandle(
            handle_id=uuid.uuid4().hex,
            target_key=target_key,
            generation=snapshot.generation,  # bind the admitted generation for async fencing
            op=op,
            channel=channel,
            platform=snapshot.platform,  # authoritative facts bound from the snapshot copy
            recovery=recovery,
        )
        self._bindings[target_key].append(handle)
        return handle

    def _rebind(self, ref: TransportRef, snapshot: TargetSnapshot) -> TransportRef:
        for offered in snapshot.transports:
            if offered.provider == ref.provider and offered.channel_id == ref.channel_id:
                if offered.target_ref == ref.target_ref and offered.line_role == ref.line_role and offered.caps == ref.caps:
                    return offered  # re-bind to the snapshot's object, never the caller copy
                raise AdmissionError("transport_ref does not match snapshot", category=ErrorCategory.CONFIGURATION_ERROR, code="foreign_ref")
        raise AdmissionError("no such channel in snapshot", category=ErrorCategory.CONFIGURATION_ERROR, code="foreign_ref")

    def _check_lease_identity(self, snapshot: TargetSnapshot, lease: LeaseInfo | None) -> None:
        # Scarce-target lease fence (contract §3.1/§5.3): when the authoritative snapshot holds
        # a lease, the request MUST carry the matching lease_id — a prior holder (or a
        # hand-crafted request that omits the lease) cannot replay a handle. An unleased target
        # (e.g. local qemu, snapshot.lease is None) has no lease requirement.
        if snapshot.lease is None:
            return
        if lease is None or lease.lease_id != snapshot.lease.lease_id:
            raise AdmissionError(
                "request lease is missing or does not match the authoritative snapshot lease",
                category=ErrorCategory.CONFIGURATION_ERROR,
                code="stale_lease",
            )

    def _check_lease_ttl(self, snapshot: TargetSnapshot, lease: LeaseInfo | None, min_lease_ttl: int | None, now: datetime) -> None:
        if snapshot.lease is None or snapshot.lease.expires_at is None:
            return  # no lease constraint (e.g. local qemu)
        min_ttl = min_lease_ttl if min_lease_ttl is not None else self._default_min_lease_ttl
        if snapshot.lease.expires_at <= now + timedelta(seconds=min_ttl):
            raise AdmissionError(
                "snapshot lease too close to expiry for min_lease_ttl",
                category=ErrorCategory.READINESS_FAILURE,
                code="lease_near_expiry",
            )

    def _reject_non_live(self, state: TargetState) -> None:
        if state in _NON_LIVE_STATES:
            raise AdmissionError(f"target not in a live state: {state}", category=ErrorCategory.READINESS_FAILURE, code="target_not_ready")

    def _require_executing_proof(self, target_key: TargetKey, snapshot: TargetSnapshot, proof: ExecutionProof | None) -> None:
        # §4.6/§5.6: ssh-tier against a DEBUGGING target is admitted ONLY on a fresh, generation-
        # AND epoch-current EXECUTING proof from the Layer-4 probe. No proof (incl. probe_timeout) or
        # an UNKNOWN proof fails closed; a proof from a prior incarnation (generation) or from before
        # an execution-state transition (epoch) is stale and refused — re-probe rather than admit
        # against a possibly-HALTED kernel; a current HALTED proof is rejected immediately.
        if proof is None or proof.state is ExecutionState.UNKNOWN:
            raise AdmissionError(
                "ssh-tier op against a DEBUGGING target requires a fresh EXECUTING probe (Layer 4)",
                category=ErrorCategory.READINESS_FAILURE,
                code="execution_state_unknown",
            )
        if proof.generation != snapshot.generation:
            raise AdmissionError(
                f"stale execution proof: probed at generation {proof.generation} != {snapshot.generation}",
                category=ErrorCategory.STALE_HANDLE,
                code="stale_handle",
            )
        if proof.epoch != self._exec_epoch.get(target_key, 0):
            raise AdmissionError(
                "stale execution proof: an execution-state transition occurred since the probe; re-probe",
                category=ErrorCategory.READINESS_FAILURE,
                code="execution_state_unknown",
            )
        if proof.state is ExecutionState.HALTED:
            raise AdmissionError(
                "target halted in debugger; resume or detach first",
                category=ErrorCategory.READINESS_FAILURE,
                code="target_halted",
            )
        # proof.state is EXECUTING, generation-current, epoch-current -> admit.

    def cancel_ssh_tier(self, target_key: TargetKey, generation: int) -> list[AdmissionHandle]:
        """§5.6 async-halt cancellation: when the kernel halts under the stop-capable controller,
        in-flight ssh-tier ops would hang on a dead network stack. Cancel the fence on every live
        SSH_TIER binding **of the given generation** (their owners then roll back) WITHOUT closing
        admission — the target is still DEBUGGING, not torn down, so once it resumes a fresh
        EXECUTING proof can admit ssh work again. **Generation-fenced:** a late HALTED from a prior
        incarnation (an old controller/stale worker) carries that incarnation's generation and so
        cannot cancel ssh work admitted after a reset/reopen on a newer generation. transport.open
        (stop-capable) bindings are untouched. The halt that triggers this IS an execution-state
        transition, so it **bumps the execution epoch** — an `EXECUTING` proof stamped before the
        halt can never be replayed to admit a new ssh op afterwards. Returns the cancelled handles."""
        with self._key_lock(target_key):
            self._exec_epoch[target_key] = self._exec_epoch.get(target_key, 0) + 1  # the halt is a transition
            cancelled = [
                h
                for h in self._bindings.get(target_key, ())
                if h.op is AdmissionOp.SSH_TIER and h.generation == generation
            ]
            for handle in cancelled:
                handle._cancel.set()  # monotonic private fence; only the service signals it
            return cancelled

    def promote(self, handle: AdmissionHandle) -> AdmissionHandle:
        """Promote a PENDING binding to a live session/op binding. Rejects a non-registered,
        non-PENDING (double-promote), or cancelled handle so a rolled-back/completed handle
        can never escape lifecycle cancellation."""
        with self._key_lock(handle.target_key):
            if handle not in self._bindings.get(handle.target_key, ()) or handle.state is not AdmissionState.PENDING:
                raise AdmissionError("handle is not a registered PENDING binding", category=ErrorCategory.READINESS_FAILURE, code="handle_not_pending")
            if handle.cancelled:
                raise AdmissionError("admission cancelled before promotion", category=ErrorCategory.READINESS_FAILURE, code="admission_cancelled")
            handle._state = AdmissionState.PROMOTED
            return handle

    def complete(self, handle: AdmissionHandle) -> None:
        """Normal terminal disposal: a finished ssh-tier op or a cleanly-closed (already
        PROMOTED) session. A **PENDING transport.open may NOT be completed** — it must promote
        on success or rollback on failure; completing it straight from PENDING would deregister
        an in-flight open without rolling back its partial guard/lease/backend resources."""
        with self._key_lock(handle.target_key):
            if handle.state is AdmissionState.PENDING and handle.op is AdmissionOp.TRANSPORT_OPEN:
                raise AdmissionError(
                    "a pending transport.open must promote or roll back, not complete",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="invalid_terminal_transition",
                )
            self._dispose_locked(handle, AdmissionState.COMPLETED)

    def rollback(self, handle: AdmissionHandle) -> None:
        """Failure/cancel terminal disposal (open transaction rollback)."""
        with self._key_lock(handle.target_key):
            self._dispose_locked(handle, AdmissionState.ROLLED_BACK)

    def confirm_reaped(self, handle: AdmissionHandle) -> None:
        """The Layer-4 reaper calls this once it has reclaimed **every** external resource the
        binding held (force-killed the backend child, released the lease and guard) for a
        cancelled handle on a closed target. Private and monotonic, like the cancel fence: it is
        the proof-of-teardown that abandon() requires, so a still-live promoted session can never
        be deregistered (unblocking reopen) before its resources are gone."""
        with self._key_lock(handle.target_key):
            if handle.target_key not in self._closed_at or not handle.cancelled:
                raise AdmissionError(
                    "confirm_reaped requires a closed target and a cancelled handle",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="reap_not_permitted",
                )
            if handle not in self._bindings.get(handle.target_key, ()):
                raise AdmissionError(
                    "handle already disposed or not registered",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="handle_already_disposed",
                )
            handle._reaped.set()

    def abandon(self, handle: AdmissionHandle) -> None:
        """Explicit, audited terminal disposal of an **overdue, cancelled** handle whose owner
        could not roll it back (e.g. a wedged open worker), only on a **closed** target whose
        resources the Layer-4 reaper has already reclaimed (`confirm_reaped`) — never a way to
        drop a live promoted session out from under lifecycle cancellation, and never before
        teardown is proven. Deregisters it so reopen() can proceed. Late effects are token/gen
        fenced."""
        with self._key_lock(handle.target_key):
            if handle.target_key not in self._closed_at or not handle.cancelled:
                raise AdmissionError(
                    "abandon requires a closed target and a cancelled handle",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="abandon_not_permitted",
                )
            if not handle.reaped:
                raise AdmissionError(
                    "abandon requires the reaper to confirm the binding's resources were reclaimed",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="reaper_confirmation_required",
                )
            self._dispose_locked(handle, AdmissionState.ABANDONED)

    def _dispose_locked(self, handle: AdmissionHandle, terminal: AdmissionState) -> None:
        # caller holds the key lock
        bindings = self._bindings.get(handle.target_key)
        if bindings is None or handle not in bindings or handle.state not in (AdmissionState.PENDING, AdmissionState.PROMOTED):
            raise AdmissionError("handle already disposed or not registered", category=ErrorCategory.READINESS_FAILURE, code="handle_already_disposed")
        handle._state = terminal
        bindings.remove(handle)

    def close_admission(self, target_key: TargetKey) -> list[AdmissionHandle]:
        """§4.5 step 1: reject new admit() for the key and set the cancel fence on every live
        binding. Records the generation being torn down so admission cannot be reopened until a
        strictly-newer incarnation appears. **Idempotent**: a duplicate close while already
        closed preserves the FIRST closed-at generation (a later close at N+1 must not push the
        reopen bar to N+2 and strand a recovered target). Returns the cancelled handles."""
        with self._key_lock(target_key):
            if target_key not in self._closed_at:
                snapshot = self._store.get(target_key)
                self._closed_at[target_key] = snapshot.generation if snapshot is not None else -1
            handles = list(self._bindings.get(target_key, ()))
            for handle in handles:
                handle._cancel.set()  # monotonic private fence; only the service signals it
            return handles

    def reopen(self, target_key: TargetKey) -> None:
        """Reopen admission for the key only after the §4.5 generation bump (step 5) has been
        published to the SnapshotStore. The decision is read from the **authoritative
        snapshot under the lock**, not a caller-supplied number: it rejects unless a snapshot
        exists AND its generation is strictly greater than the generation closed at. So an
        early reopen before the new snapshot is published — or a racing reopen during
        reset/release — leaves admission closed and a stale-generation OpenRequest still
        rejected (the replay the gate prevents)."""
        with self._key_lock(target_key):
            closed_generation = self._closed_at.get(target_key)
            if closed_generation is None:
                return  # not closed
            snapshot = self._store.get(target_key)
            if snapshot is None or snapshot.generation <= closed_generation:
                raise AdmissionError(
                    "admission stays closed: authoritative snapshot has not advanced past the closed generation",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="generation_not_advanced",
                )
            # A terminal handle is removed from _bindings by _dispose, so a non-empty list means
            # pending/promoted work from the prior generation is still unwinding. Refuse to
            # reopen until every old handle is rolled back / completed / abandoned, so new work
            # is never admitted alongside stale work that could still return or mutate.
            if self._bindings.get(target_key):
                raise AdmissionError(
                    "cannot reopen: prior-generation bindings still outstanding; roll back or abandon them first",
                    category=ErrorCategory.READINESS_FAILURE,
                    code="bindings_outstanding",
                )
            del self._closed_at[target_key]

    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None:
        """Layer-4 reconciliation marks a parked-kernel TargetKey at the generation it was
        parked at (§4.7). Generation-fenced: it never **regresses** a current tombstone with an
        older generation (a stale mark for N can't overwrite a newer N+1 mark). While marked,
        ordinary admit() is rejected `recovery_required` (fail-closed at bare startup) until the
        snapshot advances past it or it is cleared; only admit_recovery() may attach meanwhile."""
        with self._key_lock(target_key):
            existing = self._recovery_required.get(target_key)
            if existing is not None and generation < existing:
                return
            self._recovery_required[target_key] = generation

    def clear_recovery_required(self, target_key: TargetKey, expected_generation: int) -> None:
        """Cleared by Layer-4's three clearance paths (probe→EXECUTING, reset advancing
        generation, or a completed recovery-mode attach). Generation-fenced: a stale clear for
        generation N is a no-op if a newer N+1 tombstone now stands, so a stale actor cannot
        free a still-parked newer incarnation."""
        with self._key_lock(target_key):
            if self._recovery_required.get(target_key) == expected_generation:
                del self._recovery_required[target_key]

    def invalidate_lifecycle(self, event: LifecycleEvent, dispatcher: LifecycleDispatcher) -> InvalidationResult:
        """§4.5 steps 1→2 in the **mandatory** order, enforced in one place so teardown can never
        run while admission is still open. Step 1: `close_admission(event.target_key)` — set the
        cancel fence on every live binding and reject new admit() for the key. This is a confirmed,
        synchronous, non-blocking primitive (lock-guarded flag flips only, no IO, no callbacks), so
        it always completes here before step 2 begins — there is no best-effort hook that could
        leave admission open. Step 2: `dispatcher.emit(event)` — the bounded teardown. Because the
        fence is provably set before any subscriber runs, no concurrent admit() can enter the
        owner-free window and seize a freed lease against the not-yet-bumped generation. The
        Layer-4 lifecycle transaction wraps this with §4.5 steps 3–5 (revoke lease/guard via the
        subscribers, bump generation)."""
        self.close_admission(event.target_key)  # step 1: mandatory, confirmed, before any teardown
        return dispatcher.emit(event)  # step 2: teardown only — admission already closed
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_coordination_admission.py -q`
Expected: PASS (57 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/admission.py tests/test_coordination_admission.py
git commit -m "feat: add SnapshotStore and admission service (#10)"
```

---

## Task 5: Break-plan-aware selection (`coordination/selection.py`)

**Files:**
- Create: `src/linux_debug_mcp/coordination/selection.py`
- Test: `tests/test_coordination_selection.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_coordination_selection.py`:

```python
import pytest

from linux_debug_mcp.coordination.selection import (
    BreakDisproof,
    Selection,
    SelectionError,
    select_stop_capable_channel,
)
from linux_debug_mcp.seams.break_policy import ReferenceBreakPolicy
from linux_debug_mcp.seams.target import ConsoleKind, PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import BreakMethod, LineRole, TransportRef


_TK = TargetKey(provisioner="local-qemu", target_id="run-1")


def _platform(*, ssh: bool, console: ConsoleKind = ConsoleKind.UART) -> PlatformMetadata:
    return PlatformMetadata(
        console_kind=console, console_count=1, dedicated_debug_line=False, ssh_reachable=ssh
    )


def _channel(channel_id: str, role: LineRole, caps: list[str]) -> TransportRef:
    return TransportRef(provider="p", channel_id=channel_id, line_role=role, caps=caps)


def test_picks_rsp_channel_with_gdbstub_native():
    policy = ReferenceBreakPolicy()
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(_channel("rsp-0", LineRole.RSP, ["provides_rsp"]),),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
    )
    assert isinstance(selection, Selection)
    assert selection.channel.channel_id == "rsp-0"
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_skips_caps_sufficient_but_unbreakable_channel():
    # First channel satisfies caps (provides_console) but is a shared console with no
    # uart_break and no ssh -> no_break_plan; selection must skip to the breakable one.
    policy = ReferenceBreakPolicy()
    unbreakable = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    breakable = _channel("dbg-0", LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(unbreakable, breakable),
        required_caps=["provides_console"],
        platform=_platform(ssh=False),
        break_policy=policy,
    )
    assert selection.channel.channel_id == "dbg-0"
    assert selection.break_plan.method is BreakMethod.UART_BREAK


def test_transports_order_is_authoritative():
    # Two breakable channels; the first in transports[] order wins.
    policy = ReferenceBreakPolicy()
    first = _channel("dbg-0", LineRole.DEDICATED_DEBUG, ["provides_console", "supports_uart_break"])
    second = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(first, second),
        required_caps=[],
        platform=_platform(ssh=False),
        break_policy=policy,
    )
    assert selection.channel.channel_id == "dbg-0"


def test_no_channel_satisfies_caps():
    policy = ReferenceBreakPolicy()
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(_channel("rsp-0", LineRole.RSP, ["provides_rsp"]),),
            required_caps=["provides_console"],
            platform=_platform(ssh=False),
            break_policy=policy,
        )
    assert excinfo.value.code == "no_capable_channel"


def test_capable_but_no_breakable_surfaces_break_policy_code():
    # Only channel satisfies caps but has no executable break (shared console, no uart, no ssh).
    policy = ReferenceBreakPolicy()
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(_channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"]),),
            required_caps=["provides_console"],
            platform=_platform(ssh=False),
            break_policy=policy,
        )
    assert excinfo.value.code == "no_break_plan"


def test_disproved_method_falls_through_to_break_disproved():
    # Sole candidate is sysrq_g (shared console, ssh) but it is positively disproved.
    policy = ReferenceBreakPolicy()
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(_channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"]),),
            required_caps=["provides_console"],
            platform=_platform(ssh=True),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.SYSRQ_G)},  # target-wide, no channel scope
        )
    assert excinfo.value.code == "break_disproved"


def test_break_disproved_not_downgraded_by_a_later_topology_less_channel():
    # capable channel A's only candidate is positively disproved (break_disproved); capable
    # channel B has no topology candidate (no_break_plan). The aggregate must stay
    # break_disproved, not be downgraded to no_break_plan (contract §4.8 taxonomy).
    policy = ReferenceBreakPolicy()
    rsp = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    console = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(rsp, console),
            required_caps=[],
            platform=_platform(ssh=False),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},
        )
    assert excinfo.value.code == "break_disproved"


def test_break_disproved_detected_regardless_of_channel_order():
    # Same two channels, opposite order: the disproof signal must survive even when the
    # topology-less channel is evaluated last.
    policy = ReferenceBreakPolicy()
    rsp = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    console = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(console, rsp),
            required_caps=[],
            platform=_platform(ssh=False),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},
        )
    assert excinfo.value.code == "break_disproved"


def test_channel_scoped_disproof_does_not_poison_other_channels():
    # Two RSP channels both offer gdbstub_native; disproving it on rsp-0 (its endpoint
    # unreachable) must NOT disqualify rsp-1, which is selected instead (§4.8 channel-scoped).
    policy = ReferenceBreakPolicy()
    rsp0 = _channel("rsp-0", LineRole.RSP, ["provides_rsp"])
    rsp1 = _channel("rsp-1", LineRole.RSP, ["provides_rsp"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(rsp0, rsp1),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
        disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},
    )
    assert selection.channel.channel_id == "rsp-1"
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_target_wide_sysrq_disproof_applies_to_every_channel():
    # §4.8: SYSRQ_G is issued over ssh and its preconditions are target-wide. Two shared consoles
    # both have only sysrq_g as their candidate (ssh present, no uart_break). A target-wide SysRq
    # disproof recorded while evaluating con-0 MUST also prune sysrq_g on con-1, so selection
    # returns break_disproved rather than "rescuing" the target via the sibling channel.
    policy = ReferenceBreakPolicy()
    con0 = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    con1 = _channel("con-1", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(con0, con1),
            required_caps=["provides_console"],
            platform=_platform(ssh=True),
            break_policy=policy,
            disproved={BreakDisproof(_TK, BreakMethod.SYSRQ_G)},  # target-wide -> prunes both channels
        )
    assert excinfo.value.code == "break_disproved"


def test_target_wide_disproof_rejects_channel_scoping():
    # A SYSRQ_G disproof must not be constructed with a channel scope — its preconditions are
    # target-wide, so accidentally scoping it would silently let a sibling channel bypass it.
    with pytest.raises(ValueError):
        BreakDisproof(_TK, BreakMethod.SYSRQ_G, provider="p", channel_id="con-0")
    # and a line-bound method must name a channel
    with pytest.raises(ValueError):
        BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE)


def test_disproof_is_isolated_per_full_channel_identity_across_providers():
    # Two transports share channel_id "rsp-0" under different providers; disproving provider A's
    # gdbstub_native must NOT poison provider B's identically-named channel (§3.2 identity is
    # (provider, channel_id)).
    policy = ReferenceBreakPolicy()
    chan_a = TransportRef(provider="provA", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp"])
    chan_b = TransportRef(provider="provB", channel_id="rsp-0", line_role=LineRole.RSP, caps=["provides_rsp"])
    selection = select_stop_capable_channel(
        target_key=_TK,
        transports=(chan_a, chan_b),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
        disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="provA", channel_id="rsp-0")},
    )
    assert selection.channel.provider == "provB"
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_disproof_for_one_targetkey_does_not_poison_another():
    # channel_id is unique only within a target; a disproof recorded against _TK must NOT apply
    # to a different TargetKey that happens to reuse the same provider/channel_id (§3.2).
    policy = ReferenceBreakPolicy()
    other = TargetKey(provisioner="local-qemu", target_id="other")
    selection = select_stop_capable_channel(
        target_key=other,
        transports=(_channel("rsp-0", LineRole.RSP, ["provides_rsp"]),),
        required_caps=["provides_rsp"],
        platform=_platform(ssh=False),
        break_policy=policy,
        disproved={BreakDisproof(_TK, BreakMethod.GDBSTUB_NATIVE, provider="p", channel_id="rsp-0")},  # keyed to _TK, not `other`
    )
    assert selection.break_plan.method is BreakMethod.GDBSTUB_NATIVE


def test_all_topology_less_channels_yield_no_break_plan():
    # No channel has any topology candidate -> no_break_plan (nothing was disproved).
    policy = ReferenceBreakPolicy()
    a = _channel("con-0", LineRole.SHARED_CONSOLE, ["provides_console"])
    b = _channel("con-1", LineRole.SHARED_CONSOLE, ["provides_console"])
    with pytest.raises(SelectionError) as excinfo:
        select_stop_capable_channel(
            target_key=_TK,
            transports=(a, b),
            required_caps=[],
            platform=_platform(ssh=False),
            break_policy=policy,
        )
    assert excinfo.value.code == "no_break_plan"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_coordination_selection.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_debug_mcp.coordination.selection'`.

- [ ] **Step 3: Implement selection**

Create `src/linux_debug_mcp/coordination/selection.py`:

```python
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from linux_debug_mcp.seams.break_policy import BreakPolicy, BreakPlanError
from linux_debug_mcp.seams.target import PlatformMetadata, TargetKey
from linux_debug_mcp.transport.base import BreakMethod, BreakPlan, TransportRef


class SelectionError(RuntimeError):
    """No channel could be selected. `code` is `no_capable_channel` (no channel satisfies the
    required caps) or the break policy's `no_break_plan`/`break_disproved` (a capable channel
    exists but none has an executable break plan) — spec §4.1/§4.8."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


# §4.8: SYSRQ_G is issued over ssh and its preconditions (/proc/sys/kernel/sysrq,
# /proc/sysrq-trigger) are a property of the running KERNEL, not of any one console/RSP line — so
# a SYSRQ_G disproof is TARGET-WIDE and must prune the method on every channel of the target. The
# line-bound methods (gdbstub_native/uart_break/agent_proxy_break) are disproved per channel.
_TARGET_WIDE_BREAK_METHODS = frozenset({BreakMethod.SYSRQ_G})


@dataclass(frozen=True)
class BreakDisproof:
    """A §4.8 probe result proving a `BreakMethod` cannot execute. Its identity SCOPE is
    method-dependent: line-bound methods name a specific channel (`provider` + `channel_id`
    required); a TARGET-WIDE method (SYSRQ_G) carries no channel (both None) and applies to every
    channel of the target. Channel identity is keyed within a target (`channel_id` is unique only
    inside one target's `transports[]`, §3.2) and targets are isolated by `TargetKey`, so a
    line-bound disproof never poisons another target reusing the same provider/channel_id."""

    target_key: TargetKey
    method: BreakMethod
    provider: str | None = None
    channel_id: str | None = None

    def __post_init__(self) -> None:
        target_wide = self.method in _TARGET_WIDE_BREAK_METHODS
        if target_wide and (self.provider is not None or self.channel_id is not None):
            raise ValueError(f"{self.method} disproof is target-wide; it must not be scoped to a channel")
        if not target_wide and (self.provider is None or self.channel_id is None):
            raise ValueError(f"{self.method} disproof is line-bound; it must name a provider and channel_id")

    def applies_to(self, target_key: TargetKey, channel: TransportRef) -> bool:
        if self.target_key != target_key:
            return False
        if self.method in _TARGET_WIDE_BREAK_METHODS:
            return True  # target-wide: prunes the method on every channel of the target
        return self.provider == channel.provider and self.channel_id == channel.channel_id


@dataclass(frozen=True)
class Selection:
    channel: TransportRef
    break_plan: BreakPlan


def select_stop_capable_channel(
    *,
    target_key: TargetKey,
    transports: Sequence[TransportRef],
    required_caps: Iterable[str],
    platform: PlatformMetadata,
    break_policy: BreakPolicy,
    disproved: set[BreakDisproof] | None = None,
) -> Selection:
    """Pick the first `transports[]` channel for `target_key` (order is authoritative, contract
    §4.1) that satisfies `required_caps` AND has an executable break plan; a caps-sufficient but
    unbreakable channel is skipped, not selected. `disproved` is a set of `BreakDisproof` whose
    scope is method-aware (§4.8): a line-bound disproof prunes its method only on its own channel,
    while a target-wide disproof (SYSRQ_G) prunes that method on EVERY channel of the target — so
    an ssh-issued SysRq disproof recorded while evaluating one channel is not silently ignored for
    a sibling channel. Raises SelectionError(no_capable_channel) if no channel satisfies the caps;
    otherwise surfaces the aggregated no_break_plan/break_disproved code when capable channels
    exist but none is breakable."""
    required = set(required_caps)
    capable = [channel for channel in transports if required <= set(channel.caps)]
    if not capable:
        raise SelectionError("no channel satisfies the required caps", code="no_capable_channel")
    disproved = disproved or set()
    saw_disproved = False
    for channel in capable:
        channel_disproved = {d.method for d in disproved if d.applies_to(target_key, channel)}
        try:
            plan = break_policy.plan(channel=channel, platform=platform, disproved=channel_disproved)
        except BreakPlanError as exc:
            # Aggregate the contract's error taxonomy across ALL capable channels rather than
            # keeping only the last one: a positive disproof on any channel must not be
            # downgraded to no_break_plan by a later topology-less channel (§4.8).
            if exc.code == "break_disproved":
                saw_disproved = True
            continue
        return Selection(channel=channel, break_plan=plan)
    code = "break_disproved" if saw_disproved else "no_break_plan"
    raise SelectionError("no capable channel has an executable break plan", code=code)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_coordination_selection.py -q`
Expected: PASS (14 passed).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/selection.py tests/test_coordination_selection.py
git commit -m "feat: add break-plan-aware channel selection (#10)"
```

---

## Task 6: Layer-2 verification gate

**Files:** none (verification only).

- [ ] **Step 1: Run the full test suite**

Run: `uv run python -m pytest -q`
Expected: all new Layer-2 modules pass alongside the Layer-1 suite. Note: two
`tests/test_qemu_gdbstub_provider.py` PID-verification tests fail on macOS (pre-existing,
environment-dependent — `alive_unverified` vs `alive_not_controller`); they are unrelated to
this layer. Confirm no *other* regression and that every Layer-2 test passes.

- [ ] **Step 2: Lint + format check**

Run: `just lint`
Expected: `ruff check .` clean and `ruff format --check .` clean. If format flags the new
files, run `just format` and re-stage.

- [ ] **Step 3: Confirm no import cycle and clean import**

Run: `uv run python -c "import linux_debug_mcp.coordination.lease, linux_debug_mcp.coordination.admission, linux_debug_mcp.coordination.selection, linux_debug_mcp.seams.guard, linux_debug_mcp.seams.lifecycle, linux_debug_mcp.server; print('ok')"`
Expected: prints `ok` (Layer 2 imports only Layer-1 + stdlib; `server.py` still loads).

- [ ] **Step 4: Doc terminology guard**

Run: `just check-docs`
Expected: passes. Layer 2 adds only `src/` + `tests/` code plus this plan doc (already clear
of the forbidden term), so the guard result is unchanged.

- [ ] **Step 5: Hand off to Layer 3**

Layer 2 is complete and green. Layer 3 (backends & transports) builds `ProxyBackend`/
`AgentProxyBackend`, `serial-local`, the qemu-gdbstub adapter, and the `send_break`
mechanism against fakes/PTY — it does **not** consume the admission/lease/guard wiring
(that is Layer 4's `open()` transaction). Return to the roadmap and write
`docs/superpowers/plans/2026-05-26-transport-abstraction-layer-3-backends.md`.

---

## Self-Review

**Spec coverage (Layer 2 slice, against the roadmap's Layer-2 conformance list + §9.1):**
- Console-lease CAS race → exactly one `lease_conflict`; idempotent by-token release;
  stale-token release no-op post-revoke; `generation` increments on **every acquire and
  revoke** (contract §3.3 — each grant is a distinct ownership epoch); a `ConsoleLeaseManager`
  is the single `TargetKey`-keyed authority so independent paths share one lease per target → Task 1. ✓
- `StopCapableGuard` target-wide single-holder (gdb-on-RSP + kdb-on-console refused); fenced
  `release(target_key, token)` is **TargetKey-fenced** (contract §5.6) so a token misrouted to
  another target's cleanup can never free the wrong target's live guard → Task 2. ✓
- `LifecycleDispatcher` is §4.5 **step 2** (teardown only). The §4.5 ordering is enforced by
  `AdmissionService.invalidate_lifecycle`, which runs step 1 (`close_admission`, a confirmed,
  synchronous, non-blocking primitive) to completion BEFORE calling `dispatcher.emit` — so
  admission is provably closed before any subscriber can release a lease/guard, closing the
  owner-free window in which a concurrent `admit()` could seize a freed lease against a stale
  generation. There is no best-effort pre-close hook that could leave admission open. emit() runs
  **two bounded phases** under shared deadlines: `invalidate(event,
  deadline)` on supervised workers, then **`force_drop(event)`** for any overdue subscriber —
  force_drop releases the resources the subscriber recorded **out-of-band** (lease/guard
  tokens, child pid) **independently of the wedged invalidate frame**, so the line is dropped
  before `emit()` returns even when invalidate is stuck. `emit()` always returns within
  ~2×deadline; the wedged invalidate thread (CPython can't kill it) is **single-flight per
  subscriber instance** — keyed by `(TargetKey, name, instance-id)`, not re-invoked while
  overdue (so repeated events add no workers), and a fresh instance reusing a name never
  overwrites/hides its still-stuck predecessor — observable via `outstanding_overdue()` (count)
  and `overdue_subscribers()`, which returns a distinct `OverdueSubscriber(target_key, name,
  instance_id)` per wedged worker (identity is NOT collapsed by name, so the Layer-4 reaper can
  act on each binding; prunes when finished; persistent non-zero signals a contract violation);
  late effects token/generation fenced; errors aggregated → Task 3. ✓
- `SnapshotStore` (deep-copy isolation on put/get so published `lease`/`platform` facts can't
  be mutated post-publication; **`put()` rejects generation regressions** so a stale/out-of-order
  writer cannot make a pre-reset OpenRequest admissible by storing N after N+1 — `generation` is
  the monotonic freshness fence) — and live publication goes through
  **`AdmissionService.publish_snapshot`, which holds the same per-`TargetKey` lock as admit**, so
  a generation bump can never interleave between an admit's snapshot read and its handle
  registration. Admission: freshness reject / snapshot re-binding
  (foreign/edited ref reject) / `required_caps <= channel.caps` revalidation / authoritative
  `platform` + lease-identity binding (caller copies never trusted) / stale-`expires_at`
  (near-expiry) reject before acquisition / static `TargetState` gate / `request.target_key`
  consistency / ssh-tier `DEBUGGING` admitted only on a fresh `ExecutionProof` fenced on **both
  generation and a per-target execution epoch** reporting `EXECUTING` (HALTED→`target_halted`;
  missing/stale/UNKNOWN→`execution_state_unknown`, fail-closed) — the epoch bumps on every
  execution-state transition (and on `cancel_ssh_tier`), so a proof taken before a same-generation
  halt can't be replayed to attach to a halted kernel; the probe is Layer 4 but the EXECUTING ssh
  op is a first-class binding in the SAME service (contract §5.3), and `cancel_ssh_tier(target_key,
  generation)` cancels in-flight ssh ops on async `HALTED` without closing the target —
  **generation-fenced** (each handle records its admitted generation) so a late HALTED from a
  prior incarnation cannot cancel newer-generation ssh work (§5.6); **transport.open** (`admit`) and **ssh-tier** (`admit_ssh_tier`, which
  carries **no transport_ref** so an ssh-only `transports == ()` target admits) are separate
  entries; **platform-drift** is rejected (`request.platform` ≠ snapshot); **opaque,
  monotonic** `AdmissionHandle` (private cancel fence, read-only props, `channel: …|None`);
  the scarce-target **lease fence** (a leased snapshot requires the request to carry the
  matching `lease_id`; a missing lease is rejected, contract §3.1/§5.3); `handle.platform` is
  handed out as a **defensive deep copy** so bound facts can't be mutated post-admission;
  **op/state-specific** handle finality (a PENDING `transport.open` may only promote or
  rollback — never `complete`; `promote`/`complete`/`rollback`/`abandon` reject
  non-PENDING/non-registered/double-disposal, and `abandon` additionally requires a **closed
  target + cancelled handle + reaper proof-of-teardown** (`confirm_reaped`, so a cancelled
  promoted session can never be deregistered — unblocking `reopen` — before its backend/lease/
  guard are reclaimed));
  invalidation cancels pending + promoted bindings; cross-provisioner isolation by `TargetKey`;
  `reopen` requires the authoritative snapshot advanced past the closed generation **and no
  outstanding prior-generation bindings**; `close_admission` is **idempotent** (preserves the
  first closed-at generation); **two distinct closure gates** — ordinary lifecycle
  `close_admission` blocks ALL new work (incl. `admit_recovery`) during reset/release teardown,
  while a **generation-fenced** `recovery_required` tombstone gate (`mark`(key, gen) no-regress
  / `clear`(key, gen) no stale-clear; fail-closed at bare startup, stale-after-generation-bump)
  rejects ordinary `admit()` while `admit_recovery()` **requires a generation-current
  tombstone** (never a general bypass) as the one parked-kernel attach path (§4.7) → Task 4. ✓
- Break-plan-aware selection: skip caps-sufficient-but-unbreakable channel, pick breakable;
  `transports[]` order authoritative; disproof scope is **method-aware** (`BreakDisproof`, §4.8):
  line-bound methods (`gdbstub_native`/`uart_break`/`agent_proxy_break`) are keyed by **target +
  full channel identity** (`provider` + `channel_id`, §3.2) so disproving one channel never poisons
  another (different provider under the same `channel_id`, or a different `TargetKey` reusing the
  same provider/channel_id), while **`SYSRQ_G` is target-wide** (ssh-issued, kernel-scoped
  preconditions) so its disproof prunes the method on EVERY channel — a sibling channel can't
  rescue a target-wide-disproved SysRq; the `no_break_plan` vs `break_disproved` taxonomy is
  **aggregated across all capable channels** (a disproof on any channel is never downgraded);
  `line_role` determines `uart_break` vs `agent_proxy_break` (delegated to the Layer-1
  `BreakPolicy`) → Task 5. ✓

**Deliberately deferred to Layer 4 (not gaps — see Scope boundary):** the `open()`/`close()`
transaction orchestration, `coordination/registry.py`, durable write-ahead ownership records,
`flock` single-instance/per-device locks, startup reconciliation, recovery-required tombstones
+ the three clearance paths, the execution-state (`EXECUTING`/`HALTED`) dynamics + in-flight
ssh cancel + bounded liveness probe, and the endpoint-safety runtime gate. Layer 2 ships the
`admit_recovery` entry point and the `close_admission`/cancel-fence primitive that Layer 4
orchestrates.

**Placeholder scan:** every code step contains complete, runnable code; no TBD/TODO. ✓

**Type consistency:** `TargetKey`, `LeaseInfo`, `PlatformMetadata`, `TargetState`,
`ConsoleKind` come from `seams/target.py`; `TransportRef`, `OpenRequest`, `BreakPlan`,
`BreakMethod`, `LineRole`, `ExecutionState`, `DEFAULT_MIN_LEASE_TTL_SECONDS` from
`transport/base.py`; `BreakPolicy`/`ReferenceBreakPolicy`/`BreakPlanError` (with `.code`) from
`seams/break_policy.py`; `ErrorCategory` (`STALE_HANDLE`, `CONFIGURATION_ERROR`,
`READINESS_FAILURE`) from `domain.py`. `GuardToken.fence`; `StopCapableGuard.release(target_key,
token)` (TargetKey-fenced); the opaque
`AdmissionHandle` exposes read-only `.cancelled`/`.reaped`/`.state`/`.generation`/`.channel`/`.platform`/`.handle_id`
(no public `cancel`/`reaped` Event; `channel` may be `None` for ssh-tier);
`ExecutionProof.generation`/`.epoch`/`.state`, `AdmissionService.admit_ssh_tier(..., execution_proof=…)`,
`AdmissionService.current_execution_epoch(target_key)`/`.note_execution_transition(target_key)`,
`AdmissionService.cancel_ssh_tier(target_key, generation)`, `AdmissionService.publish_snapshot(target_key, snapshot)`,
`AdmissionService.invalidate_lifecycle(event, dispatcher)` (close_admission → dispatcher.emit),
`TargetSnapshot.transports`/`.lease`/`.state`/`.generation`/`.platform`,
`BreakDisproof.target_key`/`.method`/`.provider`/`.channel_id` (method-aware scope),
`Selection.channel`/`.break_plan`, `LifecycleEvent.target_key`/`.kind`,
`OverdueSubscriber.target_key`/`.name`/`.instance_id` (returned by `overdue_subscribers()`),
`LifecycleSubscriber.invalidate(event, deadline)` + `force_drop(event)`, and
`InvalidationResult.errors`/`.overdue`/`.force_dropped` are referenced consistently across
tasks and tests. `select_stop_capable_channel` is keyword-only
and matches its test call sites. ✓
