# ADR 0001 — Layer-2/Layer-4 split for the execution-state gate (ssh-tier admission)

**Status:** Accepted (2026-05-26) · **Issue:** #10 · **Affects:** Layer 2 (admission), Layer 4 (probe/controller)

## Context

Contract §5.6 / design §4.6: ssh-tier ops (smoke-test reads, ssh debug reads) against a `DEBUGGING` target are permitted only while the kernel is `EXECUTING`; while `HALTED` the network stack is frozen, so such an op must be **rejected immediately** (never left to hang) and in-flight ops must be **cancelled** on an async halt.

The authoritative execution state is owned solely by the stop-capable controller (single writer) and must be established by a **bounded liveness probe** — a cached `EXECUTING` can be stale, because a crash can land between observing a halt and the write-ahead landing ("do not trust a possibly-stale `EXECUTING`").

The roadmap places the bounded probe, the controller, and the `open()` transaction in **Layer 4**; Layer 2 ships the admission service (binding, cancel fence, lifecycle invalidation) and the Protocols/seams. **The spec does not dictate which layer makes the positive `EXECUTING` admission decision** — and that gap was relitigated repeatedly during adversarial review of the Layer-2 plan.

## Decision

- **Layer 4 owns the probe**; **Layer 2 owns the binding/fence/lifecycle** for ssh-tier ops, in the *same* per-`TargetKey` `AdmissionService` as `transport.open` (contract §5.3).
- `admit_ssh_tier`: `READY` admits with no proof. `DEBUGGING` admits **only** when Layer 4 passes a fresh `ExecutionProof(generation, epoch, state=EXECUTING)`, fenced on **both** the snapshot generation **and** a per-target **execution epoch** that bumps on every execution-state transition. `HALTED` → `target_halted`; missing/stale/`UNKNOWN` → `execution_state_unknown` (fail-closed).
- `cancel_ssh_tier(target_key, generation)` cancels in-flight `SSH_TIER` bindings on async `HALTED` **without** closing the target; it is generation-fenced and bumps the epoch.
- Layer 2 holds no execution state of its own beyond the epoch counter, and never reads a cached `EXECUTING` flag.

### Two distinct probes, two purposes (amendment 2026-05-27, Finding F2/F5)

The single name "probe" in §4.6 covered two operationally different reads. They are kept separate so neither degenerates into the other:

| Probe | Caller | What it reads | When it fires |
|---|---|---|---|
| `probe_execution_state` (cached fact) | ssh-tier admit gate (`admit_ssh_tier` against `DEBUGGING`) | `TransportSession.execution_state` from the durable record | Before admitting an ssh op into a `DEBUGGING` target |
| `probe_rsp_halted` (live RSP `?`) | `transport.inject_break` post-break confirmation | A bounded RSP `?`/stop-reply exchange against the session's `rsp_endpoint` | Immediately after the break mechanism returns success |

The cached-fact read is authoritative for the ssh-tier admit gate **because the stop-capable controller is the single writer** to that flag, **and** Finding F8 closes the legacy out-of-band halt bypass (the `debug.read_*` path that could halt the kernel as a side-effect of `target remote` without a durable record). The combination — single writer + no legacy bypass — is what makes the cached fact a sound admit decision; it is *not* a re-relitigation of rejected alternative 1 below, because that alternative was specifically about an unwritten/stale cache, not an authoritatively-written one.

The post-break confirmation **must not** read the cached flag: the inject_break handler's own `_halt_debug_transport` writes `HALTED` to the very flag the probe would read, so a kernel that silently kept running would still report HALTED and `break_unconfirmed` was unreachable on the success path. A real RSP `?` is the only non-circular check there — it catches a silent-no-op break mechanism or a misconfigured `break_plan`.

## Consequences

- Layer 4 must call `note_execution_transition` on every transition and stamp proofs from `current_execution_epoch`; the probe, its `probe_timeout`, and the `EXECUTING→HALTED` in-flight cancel live in Layer 4.
- A pre-halt `EXECUTING` proof cannot be replayed (epoch fence); a prior-incarnation proof cannot leak across a reset (generation fence).
- The `EXECUTING` ssh op is a first-class admission binding sharing the cancel fence and lifecycle invalidation — no bypass or duplication of the coordination invariants.

## Considered & rejected

1. **`ExecutionStateStore` — a Layer-2 in-memory `TargetKey→ExecutionState`, published by Layer 4, read under the admission lock.** Rejected: a cached `EXECUTING` can be stale (§4.6), so admitting on it can attach an ssh op to a halted kernel and hang; it also pulls Layer-4-owned dynamics into Layer 2 with no freshness fence. *(Tried in plan review cycle-2 round 3; removed round 4.)*
2. **Fully fail-closed in Layer 2 — reject all `DEBUGGING` ssh-tier; do positive `EXECUTING` admission entirely in Layer 4 via its own path.** Rejected: Layer 4 then has no way to register/cancel a `DEBUGGING` ssh op in the *same* admission service, so it would bypass or duplicate the binding/cancel/lifecycle invariants the contract (§5.3/§5.6) requires. *(Tried round 4; replaced round 5.)*
3. **`ExecutionStateGate` Protocol — an arbitrary callback invoked under the per-`TargetKey` admission lock.** Rejected: a callback that blocks or performs IO could wedge `close_admission` for the same key. *(Tried round 3; removed round 4.)*
4. **Cached `execution_state` read as the `transport.inject_break` post-probe.** Rejected (Finding F2/F5, 2026-05-27): the inject_break handler's `_halt_debug_transport` writes `HALTED` to that flag *before* the break mechanism runs, so reading it back as the confirmation makes `break_unconfirmed` unreachable on the success path — a silent-no-op break mechanism would report success against a still-EXECUTING kernel. The bounded RSP `?` exchange (`probe_rsp_halted`) is the only non-circular check. This rejection does NOT reopen alternative 1 above: the ssh-tier admit gate still reads the cached fact, defended by the single-writer property and Finding F8's closure of the legacy out-of-band halt bypass.

## References

design §4.6/§5.6; contract §5.3/§5.6; the Layer-2 plan's "Decisions & rejected alternatives"; roadmap layer map (probe = Layer 4).
