import contextlib
import threading

import pytest

from kdive.seams.guard import (
    GuardConflict,
    InProcessStopCapableGuard,
    StopCapableGuard,
)
from kdive.seams.target import TargetKey


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


def test_stale_token_cannot_clear_a_newer_holder_after_revoke_reacquire():
    # TD-36: the "stale clears newer" hazard the revoke() docstring warns about. After
    # revoke -> reacquire, a release keyed with the PRE-revoke token must be a fenced no-op and must
    # NOT free the newer holder. This is what makes revoke safe even if a tokenless invalidator
    # races a re-acquire: the old token can never act on the new session.
    guard = InProcessStopCapableGuard()
    stale = guard.acquire(_key())
    guard.revoke(_key())
    fresh = guard.acquire(_key())
    assert guard.release(_key(), stale) is False  # stale token does not free the new holder
    with pytest.raises(GuardConflict):
        guard.acquire(_key())  # the newer holder is intact — not cleared by the stale release
    assert guard.release(_key(), fresh) is True  # only the new holder's own token frees it


def _revoke_at(guard: InProcessStopCapableGuard, barrier: threading.Barrier) -> None:
    barrier.wait()
    guard.revoke(_key())


def _reacquire_at(guard: InProcessStopCapableGuard, barrier: threading.Barrier) -> None:
    barrier.wait()
    with contextlib.suppress(GuardConflict):
        guard.acquire(_key())


def test_concurrent_revoke_and_reacquire_never_leaves_stale_holder():
    # Run revoke and a re-acquire concurrently many times; whatever wins, the lock serializes them so
    # the pre-revoke token is always fenced out and can never free the post-race holder. Proves the
    # race cannot produce a "stale clears newer" violation.
    guard = InProcessStopCapableGuard()
    for _ in range(200):
        old = guard.acquire(_key())
        barrier = threading.Barrier(2)
        threads = [
            threading.Thread(target=_revoke_at, args=(guard, barrier)),
            threading.Thread(target=_reacquire_at, args=(guard, barrier)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # The old token can never free whatever holds now (it is fenced, or nothing holds).
        assert guard.release(_key(), old) is False
        # Normalize back to a free guard for the next iteration without relying on token identity.
        guard.revoke(_key())
        assert guard.acquire(_key()) is not None
        guard.revoke(_key())


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
