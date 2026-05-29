# ADR 0015 — `StopCapableGuard.revoke()` retained as a contract primitive; §5.4 invalidation frees the guard by fenced release

**Status:** Accepted (2026-05-29) · **Issue:** #68 (epic #9, split from #17) · **Affects:** `seams/guard.py` (`StopCapableGuard.revoke` docstring), `docs/specs/interface-contracts.md` §5.4 step 4 / §5.6 rule 1 / acceptance checklist. Builds on [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) (does not re-decide it).

## Context

Issue #68 closes out the `StopCapableGuard`: a `TargetKey`-keyed single-holder fenced token enforcing one stop-capable session per target (§5.6 rule 1). The token primitive (`StopCapableGuard` Protocol + `InProcessStopCapableGuard`), its acquisition as step 4 of `transport.open()`'s admission transaction (§5.3), and its release on detach/close/rollback/§5.4 invalidation all shipped earlier under #10 (transport Layer 4) and #66 (SessionGuard).

While verifying the acceptance criteria two wording/code discrepancies surfaced:

1. **Contract §5.4 step 4 and §5.6 rule 1 said §5.4 invalidation/force-reap `revoke(target_key)`s the guard.** The Layer-4 implementation does **not** call `revoke()` there. Per [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) Finding #4, `TransportTransaction` holds the `GuardToken` in an in-process `session_id → GuardToken` map and frees the guard on every path — `close()`, rollback, `force_release()`, and the §5.4 lifecycle subscriber's `force_drop()` — via the **fenced** `release(target_key, token)`, never the coarse `revoke()`. Fenced release is strictly safer: it cannot clear a newer holder if a stale subscriber fires, whereas `revoke()` force-frees regardless of who holds the slot.

2. **`StopCapableGuard.revoke()` therefore has no production caller.** It is exercised only by `seams/guard.py` unit tests. Its docstring claimed it was "used only from §4.5 invalidation", which is no longer accurate.

The open question: does the codebase **delete** the now-unused `revoke()` (per the no-dead-code rule), or **retain** it — and how should the contract wording be corrected so the spec matches the shipped behavior?

## Decision

- **Retain `revoke()` as a `StopCapableGuard` Protocol contract primitive.** §5.6 rule 1 names the guard's lifecycle as `acquire`/`release`/`revoke`, and the ownership map (§6) assigns the guard to issue 08's SessionGuard, which "later swaps this impl behind the same Protocol." `revoke()` is the contract's coarse **tokenless** force-free: the operation an invalidator that does *not* hold the session's token would use. Removing it would narrow the Protocol the future #08 impl must satisfy and drop a primitive the contract names. It is kept and unit-tested for its fence semantics (a post-`revoke` token is a no-op; a re-`acquire` mints a higher fence).
- **`revoke()` carries a safe-use precondition** that any caller MUST satisfy: because it clears the *current* holder unconditionally, it can wrongly clear a **newer** holder that acquired after a §5.4 revoke→re-acquire — the exact "stale clears newer" violation fenced `release` prevents. It is therefore sound only when the caller can prove no live holder it would wrongly clear exists. [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) establishes the one such condition in this codebase: the **post-restart reconcile** path, where the `instance.lock` flock plus reconcile-before-admit prove the prior holder is dead and the fresh in-process guard has no holder at all. Within a single server lifetime every token-holding path MUST use fenced `release(target_key, token)`, never `revoke()`.
- **The §5.4 invalidation path frees the guard by fenced `release(target_key, token)`, not `revoke()`** — confirming and not re-opening [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) Finding #4. Every in-process holder has its token in `TransportTransaction._tokens`, so the fenced release always applies.
- **Correct the contract wording** so §5.4 step 4, §5.6 rule 1, and the acceptance checklist describe the operation as *freeing the slot* — by the fenced by-token `release` where the invalidator holds the token (the in-process Layer-4 path), with `revoke(target_key)` retained as the coarse tokenless force-free for a holder that does not. This removes the false implication that the live code calls `revoke()` on §5.4.
- **Update the `revoke()` docstring** in `seams/guard.py` to state it is the tokenless contract primitive with no in-process caller today, citing ADR 0002 and this ADR.

## Consequences

- The spec no longer contradicts the implementation: a reader tracing §5.4 → the lifecycle subscriber finds a fenced `release`, exactly as the contract now describes.
- `revoke()` is intentionally retained despite having no production caller; this ADR is the record that prevents it being flagged as dead code and removed in a later sweep. A future #08 impl swap (or a tokenless force-reap path) may use it.
- No production behavior changes — this issue is test + documentation closure over substrate shipped by #10/#66. The new behavioral assurance is a test (the mixed RSP+console refusal below), not new code.
- The headline AC — a second stop-capable session refused target-wide on a target exposing **both** an RSP path and a console, with the guard independent of the console lease — is pinned by a transaction-level test that opens via a loopback-local RSP channel, then proves a second open via a distinct loopback-local console channel is refused by the guard **while the console lease is still free**. This is the §5.6 rule 1 "console lease necessary but not sufficient" property; prior tests proved single-holder only at the guard unit level or by reusing the same transport.

## Considered & rejected

1. **Delete `revoke()` from the Protocol, impl, and tests** (per the no-dead-code rule, since no production path calls it). **Rejected:** §5.6 rule 1 names `revoke` as part of the guard's lifecycle and §6 hands the guard to a future #08 impl behind the same Protocol; deleting it narrows that contract and removes the coarse force-free a tokenless invalidator (or a swapped impl) would need. The retention is a deliberate, recorded decision, not an oversight — which is precisely what an ADR is for.
2. **Change the implementation to call `revoke()` on §5.4** so the original contract wording becomes true. **Rejected:** this re-opens [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) Finding #4. Fenced by-token release is strictly safer than `revoke()` — it cannot clear a newer holder if a stale subscriber fires after a §5.4 revoke→re-acquire — and the transaction already holds the token, so there is no reason to use the coarser primitive. ADR 0002 settled this; #68 must not relitigate it.
3. **Leave the contract wording as-is** and treat the discrepancy as harmless. **Rejected:** a spec that says the code `revoke()`s when it actually fenced-`release`s misleads both future maintainers and the next reviewer, and would be re-flagged on every read of §5.4/§5.6.
4. **Prove the headline AC only at the guard unit level** (two `acquire()` calls on one `TargetKey`). **Rejected:** the distinctive claim of §5.6 rule 1 is that the guard is independent of the *console lease* across *distinct physical paths*. A unit test that calls `acquire()` twice does not exercise two channels or show the console lease is free at the point of refusal; the transaction-level test does.

## References

interface-contracts §5.4 (step 4 — free the guard), §5.6 rule 1 (one stop-capable session per target; console lease necessary but not sufficient), §9.4; [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) (guard token is the stop-controller authority; in-process fenced release, Finding #4); [ADR 0013](0013-session-guard-precondition-teardown-seam.md) (SessionGuard composition seam).
