from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from kdive.seams.target import TargetKey

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
        # Per-TargetKey emit serialization: the single-flight check ("is this instance already
        # overdue?") and the overdue-recording happen in two separate self._lock critical sections
        # with worker starts in between, so two CONCURRENT emits for the same target could both
        # pass the check and each start an invalidate() for the same wedged instance, clobbering
        # one _overdue record and hiding a stuck worker from the reaper. Serializing emit() per
        # target closes that window; different targets still emit concurrently.
        self._emit_locks: dict[TargetKey, threading.Lock] = {}

    def subscribe(self, target_key: TargetKey, name: str, subscriber: LifecycleSubscriber) -> None:
        with self._lock:
            self._subscribers.setdefault(target_key, {})[name] = subscriber

    def unsubscribe(self, target_key: TargetKey, name: str) -> None:
        with self._lock:
            subscribers = self._subscribers.get(target_key)
            if subscribers is not None:
                subscribers.pop(name, None)

    def _emit_lock(self, target_key: TargetKey) -> threading.Lock:
        with self._lock:
            lock = self._emit_locks.get(target_key)
            if lock is None:
                lock = threading.Lock()
                self._emit_locks[target_key] = lock
            return lock

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
        # owner-free window while subscribers release leases/guards below. Serialized per
        # target_key so the single-flight check below cannot race a concurrent emit for the same
        # target (which would start two invalidate workers for one instance); other targets are
        # unaffected. Holding this across the deadline keeps each emit bounded at ~2×deadline.
        with self._emit_lock(event.target_key):
            with self._lock:
                targeted = dict(self._subscribers.get(event.target_key, {}))
                self._prune_overdue()
                # Single-flight is keyed on the *subscriber instance*: a name is skipped only if
                # the currently-registered subscriber instance for it is the one still wedged. A
                # new subscriber registered under a reused name (its predecessor still overdue)
                # has a different id, so it is NOT skipped — its new live binding is still torn
                # down, and the predecessor's worker stays separately tracked/observable.
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
                fd_boxes, fd_alive, _ = self._run_bounded(
                    {name: (lambda s=runnable[name]: s.force_drop(event)) for name in inv_alive}
                )
                for name in inv_alive:
                    if name in fd_alive:
                        errors[name] = (
                            "invalidate and force_drop both exceeded the deadline; registry reaper is the backstop"
                        )
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
