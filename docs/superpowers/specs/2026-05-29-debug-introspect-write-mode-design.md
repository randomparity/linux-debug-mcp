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

The first two are host-side, pre-SSH (no admission acquired, no call_id minted). `write_mode_disabled` is a wrapper outcome surfaced by `_finalize_introspect_call` like the other `outcome.status` branches (a call_id and forensic StepResult exist). Acking *more* than required is accepted (the set-difference only checks the required subset is covered), but **only the satisfied required permissions** are persisted/logged — never the raw caller list (§7).

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

The guard is a **`drgn.Program` subclass whose `write()` raises**, not a wrapping proxy. A proxy is unsound: drgn's C constructors (`drgn.Object(prog, …)`) use `PyObject_TypeCheck`, which a Python proxy cannot satisfy — so a proxy would break read-only scripts that pass `prog` to a C constructor, a direct AC#1 violation (ADR 0011 §4, rejected). A subclass instance *is* a real `Program`: `isinstance(prog, drgn.Program)` is true, every read is native, and only the `write` attribute is overridden in Python. AC#1 holds for the entire read / `isinstance` surface by construction; the *only* observable difference between the modes is `type(prog)` / `prog.__class__` / `repr(prog)` (the subclass vs the plain `Program`), which read-only drgn scripts do not depend on (§9 risk 1).

`render_wrapper(..., allow_write: bool = False)` parameterises the **live** prologue's program construction via an `${ALLOW_WRITE_SETUP}` block:

- `allow_write=false` → emit `class _li_GuardedProgram(drgn.Program): def write(self, *a, **k): raise _li_WriteModeDisabled(...)` and bind `_li_program_class = _li_GuardedProgram`.
- `allow_write=true` → bind `_li_program_class = drgn.Program` (no override; writes flow to drgn, which itself fails on today's read-only targets — that is drgn's call, see §9 risk 4).

The live prologue's `prog = drgn.Program()` becomes `prog = _li_program_class()`. **Ordering constraint:** `${ALLOW_WRITE_SETUP}` must be emitted *after* the `_li_drgn_helper_names = set(globals().keys()) - _li_pre_helpers` snapshot and immediately before `prog = _li_program_class()`; otherwise `_li_GuardedProgram`/`_li_program_class` are captured as "drgn helpers" and leaked into the user namespace by the body's `for name in _li_drgn_helper_names` copy loop (harmless but surprising). The `_li_` prefix already protects them from the `from drgn.helpers.linux import *` wildcard (#51 R2-F8).

The sentinel `class _li_WriteModeDisabled(Exception): pass` is defined unconditionally in the shared `_WRAPPER_BODY` (before the user-script `exec`), and the `exec` wrapper gains an `except _li_WriteModeDisabled` arm *before* the generic `except BaseException`, setting `outcome.status="write_mode_disabled"`. Defining the sentinel unconditionally keeps the body shared with the vmcore path (which never raises it — vmcore has no write mode and uses the plain `drgn.Program()` in its own prologue).

**The wrapper outcome alone is not enough — `_finalize_introspect_call` must discriminate it.** Outcome statuses are matched by an explicit if-chain (`server.py:3142-3196`); anything unmatched falls through to `status = "script_error" if outcome_status == "error" else "ok"` (`server.py:3245`) → `ToolResponse.success`. So a `write_mode_disabled` outcome **with no added branch would be reported as a successful introspect call** — inverting AC#2. The implementation MUST add a branch alongside the existing outcome-status branches (before the build_id verify at `server.py:3198`) returning `_fail(category=CONFIGURATION_ERROR, code="write_mode_disabled", outcome_status_for_forensics="write_mode_disabled", include_stdout_json=True, redacted_payload=rp)`. The §8 test `test_write_mode_disabled_outcome_rejected` guards against the silent-success default.

The guarded subclass is **inlined** into the rendered wrapper by the `${ALLOW_WRITE_SETUP}` substitution (two small module-constant blocks: the guarded-subclass block for `allow_write=false`, `_li_program_class = drgn.Program` for `true`). It is verified drgn-free by `exec`-ing the *real rendered wrapper* in-process against a class-based stub `drgn.Program` (the existing wrapper test harness, extended so `drgn.Program` is a subclassable class rather than the current factory function) — this tests the shipped artifact directly rather than a parallel helper, avoiding a second copy of the guard logic.

**Named assumption (pinned by the env-gated integration test, ADR 0010 precedent):** `drgn.Program` is subclassable and a Python `write` override is invoked for `prog.write(...)` from user code. The live integration test fails loud if this ceases to hold.

`render_wrapper_skeleton` and `render_vmcore_wrapper*` are unchanged behaviourally; the skeleton renders with `allow_write=false`'s `${ALLOW_WRITE_SETUP}` so the agent-visible skeleton matches a default read-only render. The byte-identical-template / golden-wrapper snapshot test is regenerated for the new placeholder.

## 7. Audit trail

**Invariant:** for a live call, *audit log line ⟺ manifest step records `allow_write` ⟺ the call minted a call_id (i.e. actually executed)*. A call rejected at the gate (`operation_disabled` / `permission_required`) mints no call_id, runs nothing, and is visible only via its failure response — not the audit log; a call that passes the gate but fails admission/sudo likewise mints no call_id and is recorded nowhere because it never ran.

This requires recording `allow_write` on **both** the success and failure manifest paths (finding: `_record_introspect_failure` builds its own `details` dict, so the success-path `step_details` change alone would drop `allow_write` from every failed call — including `write_mode_disabled` itself and any errored write-mode script):

- Thread an `allow_write: bool` parameter into **both** `_finalize_introspect_call` (success-path `step_details`) **and** `_record_introspect_failure` (failure-path `details`). `StepResult.details["allow_write"]` is recorded on every live introspect call regardless of outcome.
- When `allow_write=true`, also record `StepResult.details["acknowledged_permissions"]` = the **satisfied required permissions** (the intersection of the caller's ack with `INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"]`), **not** the raw caller list. The required strings are a fixed, server-defined allowlist (no secrets, no caller-controlled content, no newlines), so recording them verbatim is safe and is the audit signal AC#3 needs; echoing the raw `acknowledged_permissions` would persist unbounded, unvalidated, unredacted caller input into durable records and the log line (log-injection / manifest-pollution vector) — rejected, ADR 0011 §8.
- One audit log line per executed write-mode call, emitted in `_execute_introspect_call` immediately after the call_id is minted (so it fires exactly once for every call that also gets a manifest step, independent of the later runner outcome): `logging.getLogger(...).warning("audit: debug.introspect.run write-mode invocation run_id=%s call_id=%s permissions=%s", run_id, call_id, satisfied_required)`.

The vmcore finalizer call passes `allow_write=False` (vmcore never reaches finalize with write mode — it is rejected upstream), so the audit additions are inert there.

## 8. Test plan (TDD)

Handler-level (FakeRunner, no drgn):

- `test_allow_write_requires_profile_op` — `allow_write=true` + profile without `debug.introspect.write` → `operation_disabled`.
- `test_allow_write_requires_ack` — `allow_write=true`, op enabled, empty/partial ack → `permission_required` with `required_permissions`.
- `test_allow_write_admitted_with_op_and_ack` — both present → reaches the runner (FakeRunner returns ok); `details.allow_write is True`, `details.acknowledged_permissions` == the satisfied required list. **Fixtures:** the live path proceeds past the gate to admission, so this reuses the existing `test_debug_introspect_run.py` live harness (injected `admission` + `session_registry`, a published READY snapshot, and a boot step with recorded `KernelProvenance`) — not the vmcore harness. The current pre-SSH `test_allow_write_rejected` needs none of these; the new test does.
- `test_allow_write_extra_ack_accepted` — acking a superset is accepted, and only the satisfied required subset is recorded in `details.acknowledged_permissions` (not the extra strings).
- `test_allow_write_failure_records_allow_write` — a write-mode call whose runner result triages to a FAILED step (e.g. a script-error outcome) still records `details.allow_write is True` via `_record_introspect_failure` (guards finding: failure path must not drop the flag).
- `test_read_only_call_ignores_ack_and_skips_gates` — `allow_write=false` with a profile lacking `debug.introspect.write` still succeeds; no ack consulted.
- `test_write_mode_audit_log_line` — caplog asserts exactly one WARNING audit line (with the satisfied required permissions, not raw caller input) on a write-mode call, and its absence on a read-only call.
- `test_vmcore_allow_write_not_applicable` — replaces `test_allow_write_rejected` in `test_debug_introspect_from_vmcore.py`; asserts code `write_mode_not_applicable`.
- `test_run_allow_write_no_longer_unsupported` — updates the existing live-path `test_allow_write_rejected` (`test_debug_introspect_run.py`) to the new gated behaviour (gate rejection, not `allow_write_not_supported`).

Render-level (string assertions):

- `test_render_wrapper_threads_allow_write_setup` — `${ALLOW_WRITE_SETUP}` renders the guarded-subclass binding when `allow_write=false` and the plain `_li_program_class = drgn.Program` binding when `true`; the regenerated golden live-template snapshot matches.
- `test_wrapper_write_guard_blocks_write_when_allow_write_false` / `test_wrapper_write_allowed_when_allow_write_true` — `exec` the real rendered wrapper in-process against a class-based stub `drgn.Program`; a `prog.write(...)` script yields `outcome.status="write_mode_disabled"` under `allow_write=false` and runs (no guard) under `allow_write=true`. A read-only script under both modes proves AC#1 transparency (the subclass is a real `Program`).
- `test_write_mode_disabled_outcome_rejected` — feed `_finalize_introspect_call` (via the handler + a FakeRunner returning a `{"outcome": {"status": "write_mode_disabled"}, ...}` document) and assert the response is `CONFIGURATION_ERROR` / `write_mode_disabled` with a FAILED manifest step — guarding the silent-success fall-through (`server.py:3245`).

Config:

- update `test_qemu_gdbstub_default_profile_*` default-profile `enabled_operations` snapshot to include `debug.introspect.write`.
- `test_missing_destructive_permissions_introspect` — set-difference against `INTROSPECT_DESTRUCTIVE_PERMISSIONS`.

Env-gated integration (drgn present, kept gated):

- a live `allow_write=true` round trip that calls `prog.write` (asserting it reaches drgn, which fails on the read-only target — proving the guard is *not* installed under write mode) and an `allow_write=false` round trip asserting `write_mode_disabled`. Gated behind the existing drgn/target markers; never un-gated.

## 9. Risks

1. **Guard transparency (AC#1).** A read-only script must behave identically `allow_write` false-vs-true. Because the guard is a real `drgn.Program` *subclass* (not a proxy), `isinstance` passes, all reads are native, and only `.write` differs — transparency holds by construction, not by exhaustively re-forwarding a protocol. `test_guarded_program_class_blocks_write_inherits_rest` plus the env-gated live test verify it. Residuals: (a) the named subclassability assumption (§6), pinned by the integration test; (b) `type(prog)` / `prog.__class__` / `repr(prog)` differ between modes (subclass vs plain `Program`) — a narrow AC#1 gap that affects only scripts inspecting the program's concrete type, which no read-only drgn idiom does.
2. **Guard is not a sandbox.** A determined script bypasses it (full builtins). This is by design and stated in §2 and ADR 0011 §1; the policy gate is the boundary. Not over-claiming is the mitigation.
3. **Default profiles enable the write capability.** Like `transport.inject_break`, `debug.introspect.write` is default-enabled, so the per-call ack is the always-required second factor. Operators wanting a hard read-only posture narrow `enabled_operations`. Documented in §2 / ADR 0011 §3.
4. **AC#2's "succeeds when `allow_write=true`" half is not positively verifiable today.** No writable target exists: the live kernel is read-only (`/proc/kcore`) and vmcore is offline, so a `prog.write` under gated write mode fails at drgn regardless. The verifiable proxy for AC#2 is therefore two-sided and asymmetric: (a) `allow_write=false` ⇒ `write_mode_disabled` (the guarded subclass raises — directly tested), and (b) `allow_write=true` ⇒ the guard is *absent* (the plain `drgn.Program` is bound, so the write reaches drgn and fails there, not in our guard — asserted by the env-gated integration test). The "write actually mutates and succeeds" path becomes testable only when a writable target lands; until then it is gated + audited but not exercised. This is an accepted, explicitly-stated gap, not a silent one.
