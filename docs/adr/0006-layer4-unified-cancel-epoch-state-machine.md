# ADR 0006 — Layer-4 unifies the async-halt cancel/epoch protocol into one modelled state machine

**Status:** Accepted (2026-05-27) · **Issue:** #10 · **Affects:** Layer 2/4 (`coordination/admission.py` — `note_execution_transition`, `cancel_ssh_tier`, `complete`, `close_admission`, `_is_stale_lifecycle_close`), Layer 4 (`server.py` `target.run_tests` rewire, the stop-capable controller)

## Context

The execution-state gate's async-halt cancellation accreted across the Layer-1+2 adversarial-review loop as a **cluster of stacked timing-edge fixes**, each exposing the next (review rounds r2→r5→r7→r8→r9→r10):

- r2 — generation-fence the epoch bump (`note_execution_transition`).
- r5 — fence the cancel by halt-epoch.
- r7 — don't drop the whole cancel; filter **per handle** by admitted epoch (`admit_epoch <= halt_epoch`).
- r8 — generation-fence the lifecycle close.
- r9 — also skip the teardown emit on a stale lifecycle retry.
- r10 — fence `complete()` by epoch as a backstop for the cancel-delivery gap.

Today the invariant is spread across `note_execution_transition` (the sole epoch bumper, generation-fenced), `cancel_ssh_tier` (generation fence **plus** a per-handle `admit_epoch <= halt_epoch` filter), `complete` (an `admit_epoch != current_epoch` backstop for the record-vs-deliver window), and `close_admission`/`_is_stale_lifecycle_close`. Each is individually defensible and all held through 10 rounds without reverting — but they are *refinements of prior fixes*, which is the documented signal of fixing symptoms rather than the mechanism. Layer 4 is the first layer that drives this gate against the **real** `target.run_tests` path (killing an in-flight ssh `subprocess` on halt rather than letting it block under the tests lock), so it is the right and necessary point to consolidate before adding a second consumer (the future `debug.introspect` tier) on top of the patch stack.

Adversarial review cannot settle this: a concurrency protocol's interleavings are combinatorial and a fresh reviewer re-litigates each round. Tests — specifically an interleaving/property pass — are what falsify a concurrency design cheaply.

## Decision

- **One authoritative model.** Define the per-`TargetKey` execution-gating state as a single `(generation, execution_epoch, execution_state)` machine with an explicit, enumerated transition table. `generation` is the incarnation (bumped by provisioning lifecycle), `execution_epoch` bumps on **every** stop-capable execution-state transition, `execution_state ∈ {EXECUTING, HALTED, UNKNOWN}`. The table is written into the plan as transitions × fences, not prose.
- **Replace the patch stack with the model.** `note_execution_transition`, `cancel_ssh_tier`, `complete`'s epoch backstop, and the lifecycle-close fences are re-expressed as the transition function and a small set of named **fences** (`generation_fence`, `epoch_fence`, `guard_token_authority`) applied uniformly, rather than as six independently-reasoned guards. Where the unified model proves an existing guard redundant, the guard is removed (not left as defensive duplication); where it proves one necessary, it is the same fence applied at that transition.
- **Authority stays the guard token (ADR 0002).** The model does not introduce a parallel stop-session authority. The `generation` fence rejects prior-incarnation events; the **live `StopCapableGuard` token** remains the sole authority distinguishing a stale *same-generation* controller (a detached session's late worker), exactly as today. This ADR reorganizes the fences; it does not move authority.
- **Tests adjudicate, not review rounds.** The protocol ships with a **hypothesis stateful test** (or, if the state space proves too irregular for a clean `RuleBasedStateMachine`, a hand-written interleaving matrix) that drives the transition table — admit/halt/resume/cancel/complete/close/invalidate in adversarial orders — and asserts the invariants: no stale `EXECUTING` survives a halt; an ssh op spanning a halt rolls back, never completes; a delayed cancel still cancels its pre-halt op without touching post-resume work; a prior-incarnation event is a no-op. Merge bar for the gate is **finding quality + a green property pass**, not reaching `approve` in the review loop.

## Consequences

- The async-halt edge cluster becomes one reviewable artifact with one rationale, so a future change reasons about the transition table rather than re-deriving six interacting guards. The next consumer (`debug.introspect`) reuses the model instead of re-discovering its edges.
- There is real risk of **behavioral regression** while replacing guards that currently pass. Mitigation: the existing Layer-2 conformance tests for each edge (the r2/r5/r7/r8/r9/r10 cases) are kept and must stay green under the unified implementation — the model must *subsume* them, proven by re-running them, before any are deleted as redundant.
- The property/interleaving pass is new test infrastructure (a `hypothesis` dev-dependency if not already present). That cost is the point: per the project's own retro, running tests is the only thing that falsified a self-contradictory concurrency design that ~17 review rounds missed.
- If the unified model reveals that one of the stacked fixes was compensating for a different latent bug, that surfaces as a property-test counterexample during Layer 4 rather than in production — the intended outcome.

## Considered & rejected

1. **Carry the Layer-2 protocol forward unchanged; only extend for the real `run_tests` kill-on-halt.** Lowest churn; the stack held 10 rounds. **Rejected:** it adds a second live consumer (and later a third, `debug.introspect`) on top of a mechanism whose own retro flags it as symptom-patching; the r5→r7 and r8→r9 pairs are refinements-of-fixes, the documented signal that the mechanism — not just its edges — needs one coherent statement. Deferring the consolidation only raises the cost of doing it.
2. **More adversarial-review rounds on the protocol design before coding.** **Rejected:** a concurrency protocol is unfalsifiable in prose review — combinatorial interleavings, fresh-reviewer re-litigation, oscillation. The project's recorded experience is that review consumed the full round cap on this exact surface without converging, and that a one-token test fixture exposed a contradiction the rounds never did. Adjudication moves to tests.
3. **Model-check the state machine (TLA+/Alloy) instead of property tests.** Strongest interleaving coverage. **Rejected for now:** introduces a toolchain and modelling language outside the repo's Python/pytest idiom for a state space small enough that `hypothesis` stateful testing covers it; revisit only if the property pass proves inadequate. Recorded so it is not relitigated.

## References

design §4.6 (execution state, epoch, raw-endpoint `unknown` caveat), §5.4 (delayed cancel), §5.6 (async-halt rules 1–2: stale token no-op, op spanning a halt rolls back); roadmap Layer 4 row (real `target.run_tests` through `admit()` + in-flight cancel; "the async-halt ssh cancellation … is the fragile spot to revisit holistically in Layer 4"); `coordination/admission.py` (`note_execution_transition`, `cancel_ssh_tier`, `complete`, `close_admission`, `_is_stale_lifecycle_close`); [ADR 0001](0001-layer2-layer4-execution-state-gate-split.md) (the L2/L4 gate split), [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) (guard token is the single execution-event authority).
