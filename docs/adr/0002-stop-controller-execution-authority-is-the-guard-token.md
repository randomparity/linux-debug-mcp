# ADR 0002 — Stop-controller execution-event authority is the guard token (a Layer-4 precondition), not a Layer-2 binding fence

**Status:** Accepted (2026-05-27) · **Issue:** #10 · **Affects:** Layer 2 (`AdmissionService.cancel_ssh_tier` / `note_execution_transition`), Layer 4 (stop-capable controller, guard wiring), issue 08 (`StopCapableGuard`)

## Context

`AdmissionService.cancel_ssh_tier(target_key, generation)` cancels in-flight `SSH_TIER` ops on an async `HALTED`, and `note_execution_transition(target_key, generation)` bumps the execution epoch on every execution-state transition (§4.6). [ADR 0001](0001-layer2-layer4-execution-state-gate-split.md) already fences both on the **generation** (cross-incarnation) and places "the `EXECUTING→HALTED` in-flight cancel" *driving* in Layer 4.

Adversarial review raised a concrete **same-generation** interleaving the generation fence cannot catch: a `debug.*` session attaches/detaches **without bumping the `TargetKey` generation** (contract §3.1/§5.1 — only reset/kexec/reimage/release bumps it). So within one generation: (1) stop session **A** halts/continues, then detaches; (2) a new ssh-tier op (or stop session **B** + an ssh-tier op) is admitted while `EXECUTING`; (3) a delayed/stale event worker from **A** reports `HALTED` and calls `cancel_ssh_tier(target, gen)`. A generation-only fence admits this call and cancels the current ssh work, even though the *current* controller did not halt the kernel — violating §5.6 rule 2 (ssh-tier is permitted while `EXECUTING`).

The open question: **does Layer 2 model stop-controller authority (a stop-session / attach-epoch fence in `AdmissionService`) to reject stale same-generation events, or is that authority owned elsewhere?**

## Decision

- The **single authority** for "who is the current stop-capable controller" is the **`StopCapableGuard` token** (contract §5.6 rule 1; ownership map §6 — owned by issue 08's SessionGuard, wired by Layer 4's `open()`/lifecycle transaction). The guard is a single-holder fenced token whose `acquire` mints a new fence, whose `release`/`revoke` invalidates the outstanding token, and for which **"a stale token is a no-op"** and the guard "never outlives the session that holds it."
- `cancel_ssh_tier` and `note_execution_transition` are Layer-2 **execution-event primitives** with an explicit **precondition**: the caller is the current stop-capable controller acting under its **live guard token**. Layer 4 enforces this — an event worker MUST verify its guard token is still current (not released/revoked) before driving an execution event. A detached session A released its token on detach, so its stale `HALTED` worker is already non-authoritative and MUST NOT call these primitives.
- Layer 2 keeps the **generation fence** it already has (rejects cross-incarnation events) and the **execution-epoch** fence on `ExecutionProof` (rejects pre-transition proofs). It does **not** additionally model stop-session identity.

## Consequences

- The reviewer's interleaving is prevented at the guard layer: step (3) requires session A to drive a cancellation after detach, i.e. without a live guard token — a **Layer-4 contract violation**, not a Layer-2 defect. Correct Layer-4 event workers re-check token currency and no-op.
- `cancel_ssh_tier` / `note_execution_transition` docstrings state the guard-token precondition and cite this ADR, so the obligation is visible at the call site Layer 4 implements.
- Layer-4 conformance tests (issue 08 / the open() transaction) must cover: a stale same-generation controller whose token was released/revoked does not drive `cancel_ssh_tier` against newly-admitted ssh work.

## Considered & rejected

1. **A stop-session / attach-epoch fence inside `AdmissionService`** (the reviewer's suggestion: thread a stop-session id/attach-epoch through `note_execution_transition`/`cancel_ssh_tier` and reject non-current holders). **Rejected:** it duplicates the guard, creating **two sources of truth** for stop-session liveness (the guard token vs. an admission-side epoch) that can disagree under §5.4 revoke→re-acquire; and the contract (§5.6 rule 1, ownership map §6) assigns that authority to issue 08's guard, not the admission service. ADR 0001 likewise placed the cancel *driving* in Layer 4.
2. **Fence the cancel on the current promoted stop-capable `TRANSPORT_OPEN` binding** (use the admission binding as the authority). **Rejected:** the `AdmissionService` does not model the stop controller as a live binding for the async-halt path — `cancel_ssh_tier` is legitimately called against a `DEBUGGING` target with only ssh-tier bindings registered (see `test_cancel_ssh_tier_cancels_in_flight_without_closing_admission`). Requiring a promoted stop binding would both break that model and re-introduce a parallel authority (same defect as option 1).
3. **An optional authority parameter validated only when supplied.** **Rejected:** an optional fence is not a fence — a caller can omit it — so it provides no guarantee while implying one.

## References

contract §5.6 (rule 1 guard authority + "stale token no-op"; rule 2 ssh-tier gated on EXECUTING), §3.1/§5.1 (generation bumps only on reset/kexec/reimage/release, not debug detach), ownership map §6 (StopCapableGuard owned by 08); [ADR 0001](0001-layer2-layer4-execution-state-gate-split.md) (Layer-4 owns the probe + cancel driving; Layer-2 owns binding/fence/lifecycle).
