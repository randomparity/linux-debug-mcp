# `debug.introspect` write mode — `allow_write=true` opt-in (design)

**Issue:** #56 · **Epic:** #9 · **Supersedes (in part):** #11 · **Depends on:** #51 (live runner), #55 (vmcore) · **ADR:** [0011](../../adr/0011-introspect-write-mode-enforcement.md)

## 1. Background and scope

#51 ships `debug.introspect.run` with `allow_write` hard-rejected (`CONFIGURATION_ERROR` / `allow_write_not_supported`). #56 turns the flag into a real, audited opt-in for scripts that mutate kernel state.

The governing prior decision is #51 design §3.5 / risk #0: **`allow_write` is not a sandbox.** A script runs via `exec()` with full builtins; with `allow_write=false` it can already `import os`, `ctypes`, open `/dev/mem`. The trust boundary is *"an agent already authorised to call `debug.introspect.run` against this target."* This spec does not change that boundary; it adds a host-side **policy gate** as the real control plus a **cooperative wrapper guard** for clean, intent-respecting rejection.

### In scope

- `debug.introspect.run(allow_write, acknowledged_permissions)` opt-in: a `DebugProfile` write-capability gate **and** a per-call destructive-permission ack, mirroring `transport.inject_break`.
- A wrapper write-guard that makes `prog.write` raise `write_mode_disabled` when `allow_write=false`, transparent to read-only scripts.
- Audit trail: a manifest `details.allow_write` flag (+ `acknowledged_permissions`) and one dedicated host log line per write-mode invocation.

### Out of scope

- New write-style helpers in the curated `HELPER_REGISTRY` (this lands the capability, not new usage).
- Sandboxing the target-side `exec` against an adversarial script (unchanged from §3.5; the guard is explicitly *not* a sandbox).
- Write mode for `debug.introspect.from_vmcore` (immutable core file — see §4) or the helper tools (read-only by construction).

## 2. Enforcement model

Two independent factors, both required for a write to be admitted, mirroring `transport.inject_break`:

| Factor | Mechanism | Failure when missing (allow_write=true) |
|---|---|---|
| Profile capability | `debug.introspect.write` ∈ `DebugProfile.enabled_operations`, checked via `_ensure_debug_operation_enabled` | `CONFIGURATION_ERROR` / `operation_disabled` |
| Per-call ack | `acknowledged_permissions` ⊇ `INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"]` | `CONFIGURATION_ERROR` / `permission_required` (with `required_permissions`) |

The **policy gate is the security boundary** (host-side, pre-`exec`). The **wrapper guard is a cooperative guardrail**: it blocks the documented `prog.write` path and yields a clean error; it is not, and is never described as, an adversarial sandbox (full-builtins bypass remains per §3.5). See ADR 0011 §1.

`allow_write=false` (default) is unchanged from #51: no ack consulted, both new gates skipped, and the guard installed (so an accidental `prog.write` is rejected cleanly rather than failing opaquely).

## 3. Tool surface (`debug.introspect.run`)

### 3.1 Request

`DebugIntrospectRunRequest` gains one field:

```python
acknowledged_permissions: list[str] = Field(default_factory=list)
```

`allow_write: bool = False` already exists. No other field changes. The field is part of the validated request model (not a bare handler kwarg) so the MCP tool exposes it as a normal parameter; rationale in ADR 0011 §7.

### 3.2 Failure contract (additions)

| Condition | Category | `details.code` |
|---|---|---|
| `allow_write=true`, profile lacks `debug.introspect.write` | `CONFIGURATION_ERROR` | `operation_disabled` |
| `allow_write=true`, ack missing/insufficient | `CONFIGURATION_ERROR` | `permission_required` (+ `required_permissions`) |
| `allow_write=false`, script calls `prog.write` | `CONFIGURATION_ERROR` | `write_mode_disabled` |
| `from_vmcore` with `allow_write=true` | `CONFIGURATION_ERROR` | `write_mode_not_applicable` |

The first two are host-side, pre-SSH (no admission acquired, no call_id minted). `write_mode_disabled` is a wrapper outcome surfaced by `_finalize_introspect_call` like the other `outcome.status` branches (a call_id and forensic StepResult exist). `acknowledged_permissions` ⊋ required (acking *more* than required) is accepted — the set-difference only checks the required subset is covered.

### 3.3 Gate ordering in `_execute_introspect_call`

Replacing the current `if request.allow_write: return failure(...)` block, before any sudo/admission/SSH work:

1. base op gate: `_ensure_debug_operation_enabled(profile, "debug.introspect.run")` (already present).
2. **if `request.allow_write`:** write op gate `_ensure_debug_operation_enabled(profile, "debug.introspect.write")`, then ack gate `missing_destructive_permissions("debug.introspect.run", request.acknowledged_permissions)`.
3. timeout band, script non-empty / ≤ cap invariants (already present).

A read-only call (`allow_write=false`) never enters step 2.

## 4. `from_vmcore`: write mode not applicable

A vmcore is an immutable core-dump file; drgn cannot write to it and the offline request carries no `DebugProfile` (ADR 0010 / §5.6 rule 3). The existing reject in `_execute_vmcore_introspect_call` is **kept**, reclassified:

- code `allow_write_not_supported` → `write_mode_not_applicable`
- message names the offline reason ("write mode is not applicable to offline vmcore analysis; the core file is immutable").

Still `CONFIGURATION_ERROR`. Helpers (`debug.introspect.helper`, `from_vmcore_helper`) continue to pin `allow_write=False` internally; unchanged.

## 5. Config additions

```python
# config.py
ALLOWED_DEBUG_OPERATIONS = [ ..., "debug.introspect.write", ... ]   # appended

INTROSPECT_DESTRUCTIVE_PERMISSIONS = {
    "debug.introspect.run": ["mutate live kernel state via drgn write APIs"],
}
```

`missing_destructive_permissions(operation, acknowledged, *, registry=TRANSPORT_DESTRUCTIVE_PERMISSIONS)` is generalised to take the registry it reads (default preserves the transport call site verbatim), so introspect reuses the same set-difference. `debug.introspect.write` is a **capability token, not a tool name** — it is only ever passed to `_ensure_debug_operation_enabled`, never registered as an MCP tool.

Adding the op extends the default `enabled_operations`; the committed default-profile snapshot in `tests/test_config.py` is updated in the same change.

## 6. Wrapper write-guard

`render_wrapper(..., allow_write: bool = False)` substitutes a `${ALLOW_WRITE_GUARD}` block into the live template:

- `allow_write=true` → empty block (writes flow to drgn; on today's read-only targets drgn itself fails — that is drgn's call).
- `allow_write=false` → install a guard that intercepts `prog.write` and raises a sentinel `_li_WriteModeDisabled`; the user-script `exec` wrapper catches it and sets `outcome.status="write_mode_disabled"`.

The guard snippet is a **module-level string constant** in `local_drgn_introspect.py`, `exec`-able against a fake program object in a unit test (drgn not required). It forwards the drgn `Program` read protocol — `__getattr__`, `__getitem__`, `__contains__`, `__call__`, `__iter__`, `__len__` — so a read-only script behaves identically with the guard present (AC#1). It intercepts the `prog.write` attribute path only; argument-position uses of the real program (e.g. `drgn.Object(prog, …)`) keep the unwrapped program (ADR 0011 §5 known limitation — the policy gate, not the guard, is the boundary).

`render_wrapper_skeleton` and `render_vmcore_wrapper*` are unchanged (skeleton mirrors the live caps; vmcore has no write mode). The `${ALLOW_WRITE_GUARD}` placeholder is `""` for the skeleton so the agent-visible skeleton matches a default read-only render.

## 7. Audit trail

In `_finalize_introspect_call` (live path), threaded an `allow_write: bool` parameter:

- `StepResult.details["allow_write"]` recorded on every introspect call.
- `StepResult.details["acknowledged_permissions"]` recorded (verbatim — fixed capability strings, not secrets; ADR 0011 §8) when `allow_write=true`.
- On an admitted write-mode call, one `logging.getLogger(...).warning("audit: debug.introspect.run write-mode invocation run_id=%s call_id=%s acknowledged=%s", ...)` line. Fires after the gate passes and the call_id is minted, independent of whether the script actually wrote.

The vmcore finalizer call passes `allow_write=False` (vmcore never reaches finalize with write mode — it is rejected upstream).

## 8. Test plan (TDD)

Handler-level (FakeRunner, no drgn):

- `test_allow_write_requires_profile_op` — `allow_write=true` + profile without `debug.introspect.write` → `operation_disabled`.
- `test_allow_write_requires_ack` — `allow_write=true`, op enabled, empty/partial ack → `permission_required` with `required_permissions`.
- `test_allow_write_admitted_with_op_and_ack` — both present → reaches the runner (FakeRunner returns ok); `details.allow_write is True`, `details.acknowledged_permissions` recorded.
- `test_allow_write_extra_ack_accepted` — acking a superset is accepted.
- `test_read_only_call_ignores_ack_and_skips_gates` — `allow_write=false` with a profile lacking `debug.introspect.write` still succeeds; no ack consulted.
- `test_write_mode_audit_log_line` — caplog asserts the WARNING audit line on a write-mode call and its absence on a read-only call.
- `test_vmcore_allow_write_not_applicable` — replaces `test_allow_write_rejected`; asserts code `write_mode_not_applicable`.
- `test_run_allow_write_no_longer_unsupported` — updates the existing `test_allow_write_rejected` for the live path to the new gated behaviour.

Render-level (string assertions):

- `test_render_wrapper_threads_allow_write_guard` — guard block present when `allow_write=false`, absent when `true`; live template recomposition byte-identical test still passes (guard placeholder default `""`).
- `test_write_guard_blocks_write_forwards_reads` — `exec` the guard snippet against a fake program; `prog.write(...)` raises the sentinel; `prog.attr`, `prog["x"]`, `prog(...)`, `x in prog`, `iter(prog)`, `len(prog)` all forward.

Config:

- update `test_qemu_gdbstub_default_profile_*` default-profile `enabled_operations` snapshot to include `debug.introspect.write`.
- `test_missing_destructive_permissions_introspect` — set-difference against `INTROSPECT_DESTRUCTIVE_PERMISSIONS`.

Env-gated integration (drgn present, kept gated):

- a live `allow_write=true` round trip that calls `prog.write` (asserting it reaches drgn, which fails on the read-only target — proving the guard is *not* installed under write mode) and an `allow_write=false` round trip asserting `write_mode_disabled`. Gated behind the existing drgn/target markers; never un-gated.

## 9. Risks

1. **Guard transparency (AC#1).** A subtle proxy gap could break a read-only script under `allow_write=false`. Mitigation: the guard intercepts only `prog.write` and forwards the full documented protocol; `test_write_guard_blocks_write_forwards_reads` plus the env-gated live test verify transparency. The known C-constructor limitation is documented, not silently shipped.
2. **Guard is not a sandbox.** A determined script bypasses it (full builtins). This is by design and stated in §2 and ADR 0011 §1; the policy gate is the boundary. Not over-claiming is the mitigation.
3. **Default profiles enable the write capability.** Like `transport.inject_break`, `debug.introspect.write` is default-enabled, so the per-call ack is the always-required second factor. Operators wanting a hard read-only posture narrow `enabled_operations`. Documented in §2 / ADR 0011 §3.
