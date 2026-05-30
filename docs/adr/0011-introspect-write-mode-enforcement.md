# ADR 0011 — `debug.introspect` write mode: policy-gate enforcement + cooperative wrapper write-guard

**Status:** Accepted (2026-05-29) · **Issue:** #56 · **Epic:** #9 · **Supersedes (in part):** #11 · **Depends on:** #51 · **Affects:** `src/kdive/config.py` (`ALLOWED_DEBUG_OPERATIONS`, new `INTROSPECT_DESTRUCTIVE_PERMISSIONS` + generalised `missing_destructive_permissions`), `src/kdive/domain.py` (`DebugIntrospectRunRequest.acknowledged_permissions`), `src/kdive/providers/local_drgn_introspect.py` (`render_wrapper` `allow_write` seam, write-guard snippet), `src/kdive/server.py` (`_execute_introspect_call` gate, `_finalize_introspect_call` audit + `write_mode_disabled` outcome, vmcore not-applicable, MCP tool param)

## Context

#51 shipped `debug.introspect.run` (live drgn-over-SSH) and `debug.introspect.from_vmcore` (#55, offline). Both **hard-reject** `allow_write=true` with `CONFIGURATION_ERROR` / `allow_write_not_supported`. #56 replaces that stub with a real opt-in so power users can run scripts that mutate kernel state.

The #51 design (`docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md` §3.5, risk #0) is the load-bearing prior decision: **`allow_write` is not a sandbox.** The user script runs via `exec()` with full Python builtins; with `allow_write=false` it can already `import os`, `import ctypes`, open `/dev/mem`, etc. The blast radius equals `ssh <user>@<host> sudo python3 -c <script>`. The established trust boundary is *"an agent already authorised to call `debug.introspect.run` against this target."* #51 explicitly rejected AST write-detection and restricted-builtins as security theater against a fully-trusted, Turing-complete script and deferred the *capability* to #56.

The spec leaves these open, decided here:

1. What is the actual enforcement mechanism, given the script is fully trusted?
2. Where does write mode apply — live only, or vmcore/helpers too?
3. How is the `DebugProfile`-level gate modelled?
4. How does the per-call acknowledgement reuse the `transport.inject_break` pattern?
5. What does the wrapper write-guard do, and how is it kept transparent to read-only scripts (AC#1)?
6. What is the audit trail and the failure contract?

## Decision

### 1. Enforcement is a policy gate; the wrapper write-guard is a cooperative guardrail, not a sandbox

The **security boundary** is the policy gate (decisions 3–4): `allow_write=true` is admitted only when the `DebugProfile` enables the write capability **and** the per-call destructive-permission ack is present. This is a real, non-bypassable control because it runs host-side, before any script executes.

The wrapper **write-guard** (decision 5) is a *cooperative guardrail*: when `allow_write=false` it makes drgn's documented write API (`prog.write`) raise, surfacing a clean `write_mode_disabled` outcome instead of an opaque drgn error. It prevents *accidental* mutation by a read-only-intent script and satisfies AC#2's "rejected" requirement at runtime. It is **not** an adversarial sandbox: a script with full builtins can still reach `/dev/mem`/`ctypes` regardless, exactly as §3.5 documents. We do not claim otherwise anywhere in code, docs, or response text.

### 2. Write mode applies to the live path only; vmcore is "not applicable", helpers stay read-only

- **`debug.introspect.run` (live):** full write-mode opt-in lands here.
- **`debug.introspect.from_vmcore`:** a vmcore is an immutable core-dump file; drgn cannot write to it and there is no `DebugProfile` in the request to gate against (ADR 0010 / §5.6 rule 3). `allow_write=true` stays **rejected**, reclassified from `allow_write_not_supported` to `CONFIGURATION_ERROR` / `write_mode_not_applicable` with a message naming the offline reason. The hard-reject is *kept*, not removed.
- **`debug.introspect.helper` / `from_vmcore_helper`:** curated helpers are read-only by construction and pin `allow_write=False` internally (out of scope: "no new write-style helpers"). Unchanged.

### 3. The `DebugProfile` gate is a distinct pseudo-operation `debug.introspect.write`

A new operation string `debug.introspect.write` is added to `ALLOWED_DEBUG_OPERATIONS`. It is **not** a tool name — it is the capability token the write gate checks via the existing `_ensure_debug_operation_enabled(profile, "debug.introspect.write")`, exactly as Finding F14 gated `transport.inject_break`. The base `debug.introspect.run` op gate still runs first; the write op gate runs *additionally*, only when `allow_write=true`. Like every other entry, it is in the default `enabled_operations`, so a default profile permits write mode *capability*; the per-call ack is the second, always-required factor (mirrors inject_break, which is also default-enabled but always needs its ack). A read-only profile narrows `enabled_operations` to exclude `debug.introspect.write` and refuses write mode outright.

### 4. The per-call ack reuses the destructive-permission mechanism, generalised

`config.missing_destructive_permissions(operation, acknowledged)` is generalised to take the registry it reads (default still `TRANSPORT_DESTRUCTIVE_PERMISSIONS`) so introspect can reuse the same set-difference logic without duplicating it. A new constant:

```python
INTROSPECT_DESTRUCTIVE_PERMISSIONS = {
    "debug.introspect.run": ["mutate live kernel state via drgn write APIs"],
}
```

`DebugIntrospectRunRequest` gains `acknowledged_permissions: list[str] = []`. When `allow_write=true`, the handler computes the missing set; non-empty → `CONFIGURATION_ERROR` / `permission_required` with `required_permissions`. When `allow_write=false`, the field is ignored (no ack needed, no behavioural change).

Gate order in `_execute_introspect_call` (all before any SSH/admission work): base op gate → **if `allow_write`: write op gate, then ack gate** → timeout/script invariants → … A read-only call skips both new gates entirely.

### 5. The wrapper write-guard is a `drgn.Program` *subclass*, not a proxy

`render_wrapper(...)` gains `allow_write: bool = False`, parameterising an `${ALLOW_WRITE_SETUP}` block in the **live** prologue. When `allow_write=false` the prologue binds `_li_program_class` to a `drgn.Program` subclass whose `write()` raises a sentinel `_li_WriteModeDisabled`; when `true` it binds `_li_program_class = drgn.Program` (writes flow to drgn, which itself fails on today's read-only targets — that is drgn's call, not ours). The prologue's `prog = drgn.Program()` becomes `prog = _li_program_class()`.

A **subclass, not a proxy**, is the whole point (alternative 4, rejected): a subclass instance *is* a real `Program` — `isinstance(prog, drgn.Program)` is true, drgn's C constructors (`drgn.Object(prog, …)`) accept it, every read is native, and only `write` is overridden. AC#1 (read-only script identical false-vs-true) therefore holds *by construction*, not by exhaustively re-forwarding a protocol. A proxy fails this: drgn's C-level `PyObject_TypeCheck` rejects a non-`Program` object, so a proxy would break read-only scripts that pass `prog` to a C constructor.

The guarded-subclass *factory* (`_guarded_program_class(base)`) and the sentinel are factored so a unit test passes a **fake base class** (no drgn installed) and asserts `write()` raises while everything else is inherited. The sentinel `_li_WriteModeDisabled` is defined unconditionally in the shared `_WRAPPER_BODY` so the body stays shared with the vmcore path (which never raises it); the body's user-script `exec` gains an `except _li_WriteModeDisabled` arm before the generic handler, emitting `outcome.status="write_mode_disabled"`.

**Named assumption (pinned by the env-gated integration test, ADR 0010 precedent):** `drgn.Program` is subclassable and a Python `write` override is invoked for a user-level `prog.write(...)` call. If drgn ever makes `Program` final, the live integration test fails loud.

### 6. Audit trail: manifest detail (both outcome paths) + a dedicated host log line

**Invariant:** *audit log line ⟺ `allow_write` recorded in the manifest step ⟺ the call minted a call_id (actually executed).* `allow_write` is threaded into **both** `_finalize_introspect_call` (success-path `step_details`) **and** `_record_introspect_failure` (failure-path `details`) — the latter builds its own details dict, so updating only the success path would silently drop `allow_write` from every failed call, including `write_mode_disabled` itself and any errored write-mode script. `StepResult.details["allow_write"]` is recorded on every live call regardless of outcome.

When `allow_write=true`, `details["acknowledged_permissions"]` records the **satisfied required permissions** (caller ack ∩ the server allowlist), not the raw caller list. One WARNING `logging` line — `audit: debug.introspect.run write-mode invocation run_id=… call_id=… permissions=…` — is emitted in `_execute_introspect_call` immediately after the call_id is minted, so it fires exactly once for every call that also gets a manifest step. A call rejected at the gate (no call_id) is visible via its failure response, not the audit log.

## Consequences

- The boundary is honest and host-side: it cannot be defeated by script cleverness because it runs before `exec`. The guard adds defence-in-depth + a clean error, and the docs never over-claim it.
- Write mode is opt-in twice (profile capability + per-call ack), so neither a forgotten profile setting nor a copy-pasted ack alone enables mutation — both are required, matching inject_break's posture.
- A read-only call's code path is byte-for-byte unchanged except for two skipped gate checks; AC#1 holds by construction on the host side and by the transparency tests on the wrapper side.
- vmcore and helper paths are untouched behaviourally beyond the reclassified vmcore rejection message, so #55/#54 contracts are preserved.
- Adding `debug.introspect.write` to `ALLOWED_DEBUG_OPERATIONS` extends the default `enabled_operations`; the committed default-profile snapshot test is updated in the same change.
- Auditability is grep-able and durable: every mutation-capable call leaves both a manifest flag and a log line, satisfying AC#3.

## Considered & rejected

1. **AST analysis of the user script for drgn write APIs.** Rejected: unsound against a fully-trusted, Turing-complete script with full builtins — `getattr(prog, "wr"+"ite")`, `exec`, ctypes, or `/dev/mem` all bypass it. #51 §3.5 already rejected this; re-affirmed. It would be security theater that implies a guarantee we cannot keep.

2. **Restricted-builtins / stripped-namespace sandbox (remove write helpers / builtins when `allow_write=false`).** Rejected: same unsoundness (the script can re-import, reach `__builtins__` via object graphs), *and* it risks breaking read-only scripts (AC#1) by removing names they legitimately use. The cooperative `prog.write` guard is the bounded, transparent subset of this idea that is honest about its scope.

3. **Pure policy gate with no runtime guard at all.** Rejected against AC#2's literal "a script that calls a known drgn write API … otherwise it is rejected": with no guard a write call under `allow_write=false` would simply run and fail with an opaque drgn error (today) or silently succeed (on a future writable target) — neither is a clean, intent-respecting rejection. The cooperative guard gives a structured `write_mode_disabled` and enforces intent even if a writable target later appears, at small cost.

4. **Wrapping read-only `Program` proxy (delegation object) instead of a subclass.** Rejected: a proxy is not a `Program`, so drgn's C-level `PyObject_TypeCheck` rejects it wherever the program is passed by argument to a C constructor (`drgn.Object(prog, …)`, `drgn.cast(...)`) — idioms read-only scripts use — a direct AC#1 violation. A proxy also can't be *both* the thing that intercepts `.write` and the real program handed to those constructors (a single `prog` binding can't be two objects). The `drgn.Program` **subclass** (decision 5) sidesteps this entirely: it *is* a `Program` (isinstance true, C constructors accept it), reads are native, only `write` is overridden. The remaining bypass — a script reaching the base-class `write` via `drgn.Program.write(prog, …)` — is irrelevant because the *policy gate*, not the guard, is the security boundary; the guard only stops accidental writes and gives a clean error.

5. **A boolean `DebugProfile.allow_write` field instead of an `enabled_operations` entry.** Rejected: it forks the gating model. Every other halting/mutating op (including `transport.inject_break`) is gated through `enabled_operations` + `_ensure_debug_operation_enabled`; a one-off boolean would need its own validator, its own snapshot handling, and a parallel "is this disabled by profile?" code path. A pseudo-op reuses the single existing gate and the `unsupported debug operation` / `disabled by selected profile` error contract verbatim.

6. **Enable write mode for `debug.introspect.from_vmcore` too.** Rejected: a vmcore is an immutable file, drgn cannot write to it, and the offline path carries no `DebugProfile` to gate against (ADR 0010). Offering a "write mode" there would be a phantom feature. The path keeps its hard-reject, only reclassified to `write_mode_not_applicable` so the agent gets an accurate reason.

7. **A per-call `allow_write` boolean carried in the request but ack passed as a separate handler kwarg (as `transport.inject_break` does with `acknowledged_permissions`).** Rejected for introspect: `inject_break`'s ack is a handler kwarg because it has no request model. `debug.introspect.run` already has `DebugIntrospectRunRequest`; putting `acknowledged_permissions` on the model keeps the agent-facing contract in one validated place and lets the MCP wrapper expose it as a normal tool parameter, consistent with the other introspect fields.

8. **Persist the caller's raw `acknowledged_permissions` list verbatim (redacted or not).** Rejected: the request field is an arbitrary unbounded `list[str]`, and the gate accepts supersets, so echoing it into the durable manifest and the audit log line would persist unvalidated, attacker-influenced strings (including newlines → forged audit lines) — a manifest-pollution / log-injection vector. Instead we record only the **satisfied required permissions** (caller ack ∩ the server allowlist `INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"]`). Those are fixed, server-defined, human-readable capability descriptions with no secrets and no caller-controlled content, so they are recorded *without* `Redactor` (redacting them would obscure the audit trail AC#3 needs) while everything that *does* carry guest output — stdout/stderr/tracebacks — stays redacted as before.

## References

spec `docs/superpowers/specs/2026-05-29-debug-introspect-write-mode-design.md`;
#51 spec `docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md` §3.5 + risk #0 (the "not a sandbox" decision this builds on);
ADR 0009 (shared executor), ADR 0010 (vmcore execution model, §5.6 rule 3);
`config.py` `TRANSPORT_DESTRUCTIVE_PERMISSIONS` / `missing_destructive_permissions` (the ack pattern mirrored);
`server.py` `transport_inject_break_handler` (Finding F14 profile-op gate), `_execute_introspect_call`, `_finalize_introspect_call`;
`providers/local_drgn_introspect.py` `render_wrapper` / `WRAPPER_TEMPLATE`.
