from __future__ import annotations

import threading
import uuid
from enum import StrEnum

from kdive.seams.target import TargetKey


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
