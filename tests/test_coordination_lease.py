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
