# `debug.introspect.helper` — curated drgn helper library

**Date:** 2026-05-28
**Issue:** #54
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #11
**Status:** Draft — pending user review
**Depends on:** #51 (`debug.introspect.run` runner foundation — merged; `providers/local_drgn_introspect.py`, `server.debug_introspect_run_handler`)

## 1. Background and scope

`debug.introspect.run` (#51) lets an agent execute an arbitrary user-supplied
drgn script against a live kernel over SSH and get structured JSON back. It is
the foundation; this spec adds a curated layer on top so agents do not
hand-write drgn for routine introspections.

`debug.introspect.helper(target_ref, name, args)` dispatches to one of a small
set of named, versioned, in-project drgn scripts, each with a **typed JSON
return contract** (a Pydantic model). Helpers reuse the runner's
bounded-execution, admission, provenance, and redaction machinery — they are
scripts fed through the same execution path, not a parallel one.

### In scope

- A `debug.introspect.helper(run_id, target_ref, name, args, timeout_seconds)`
  MCP tool, wired through `server.py`'s registration pattern.
- A versioned in-project helper library (`introspect_helpers/`), one module per
  helper, each declaring a drgn script body, a Pydantic args model, and a
  Pydantic output model.
- The initial six helpers: `sysinfo`, `tasks`, `dmesg`, `modules`, `slab`, `irq`.
- An `${ARGS_B64}` arg seam added to the shared on-target wrapper so helper
  args reach the script namespace.
- Extraction of a **shared core executor** from `debug_introspect_run_handler`
  so `run` and `helper` share one pipeline (admission → render → SSH → caps →
  provenance verify → redaction → manifest) and differ only in result mapping.
- Host-side validation of each helper's redacted output into its Pydantic
  model; schema drift fails loud.
- Per-helper golden integration tests against the smoke VM (schema + stable
  invariants), gated on `virsh` + VM like the existing integration suites.

### Out of scope

| Concern | Where it lives |
|---|---|
| The runner itself | #51 (done) |
| `debug.introspect.from_vmcore` offline execution | #55 |
| `allow_write=true` opt-in write mode | #56 |
| Helpers beyond the initial six | future follow-ups, filed as concrete needs land — no speculative helpers |
| Exposing an `args` field on `debug.introspect.run`'s public request | deferred (YAGNI); the wrapper slot exists but `run` passes `{}` |

## 2. Architecture overview

```
agent ──MCP──▶ debug.introspect.helper handler
                     │
                     │  1. _ensure_debug_operation_enabled("debug.introspect.helper")
                     │  2. resolve name → HelperSpec (registry)
                     │  3. validate args → spec.args_model
                     │  4. select helper cap profile (§3.3)
                     │  5. render helper script + args_json
                     ▼
            ┌─────────────────────────────────────────────────┐
            │  shared core executor (extracted from #51)       │
            │  no op-gating — caller gates                     │
            │  admission → render wrapper(${ARGS_B64},${CAPS})  │
            │  → SSH exec → caps → provenance verify           │
            │  → redaction → manifest record                   │
            └─────────────────────────────────────────────────┘
                     │  returns redacted wrapper result
                     ▼
            6. validate single emit → spec.output_model
            7. ToolResponse.success(data={result: model_dump})
```

`debug.introspect.run` becomes a second thin consumer of the same core executor,
mapping the redacted result to untyped JSON exactly as it does today.

## 3. Helper library

### 3.1 Package layout

```
src/linux_debug_mcp/introspect_helpers/
    __init__.py          # built_in_helper_specs() → list[HelperSpec]; HELPER_REGISTRY
    base.py              # HelperSpec dataclass; shared output sub-models
    sysinfo.py
    tasks.py
    dmesg.py
    modules.py
    slab.py
    irq.py
```

### 3.2 `HelperSpec`

```python
@dataclass(frozen=True)
class HelperSpec:
    name: str               # "sysinfo"
    version: int            # bumped when `script` or `output_model` changes
    script: str             # drgn body; MUST call emit(result) exactly once
    args_model: type[Model] # Pydantic; an empty model when the helper takes no args
    output_model: type[Model]
```

`HELPER_REGISTRY: dict[str, HelperSpec]` is built once from
`built_in_helper_specs()`. The handler resolves `name` against it; an unknown
name returns `CONFIGURATION_ERROR` whose message lists the valid names.

### 3.3 Single-emit convention and the helper cap profile

Every helper script calls `emit(result)` **exactly once** with a dict matching
its `output_model`. The helper handler supplies this logic to the core executor
as its **post-validator** (§5), so the recorded manifest step status matches the
agent-visible outcome. The validator:

1. Reads the redacted wrapper result's `emits` list.
2. Requires exactly one element. Zero or more than one → `helper_schema_drift`.
3. Validates that element into `spec.output_model`. A `ValidationError` →
   `helper_schema_drift`.

`helper_schema_drift` is `ErrorCategory.INFRASTRUCTURE_FAILURE` (the live kernel
emitted a shape the curated contract does not recognize — a tooling/version
fault, not the agent's input error). The raw and redacted payloads remain on
disk under the call's artifact dir for forensics; the response carries the
helper name, version, and the validation error summary (redacted).

#### Cap interaction (load-bearing)

The runner wrapper (`local_drgn_introspect.py` `_li_caps`) enforces
`per_emit_bytes = 32 KiB`, `emits = 100`, and `total_json = 1 MiB`. A single
emit of one large object — which is exactly what this convention produces —
**exceeds `per_emit_bytes` for the list-returning helpers** (`tasks` at
`limit=200` with kernel stacks is 100–400 KiB; `dmesg` at 1000 entries is
~80 KiB). When that happens the wrapper silently replaces the emit with an
`{"__emit_oversized__": true, …}` marker, which then fails `output_model`
validation → `helper_schema_drift` on **every** such call. Splitting into one
emit per row does not help: `tasks(200)` / `dmesg(1000)` blow the 100-emit cap
instead.

The helper path therefore runs under a **helper cap profile**, not the runner's
default caps. Because helper scripts are server-authored and trusted (unlike the
arbitrary user script `debug.introspect.run` accepts), the core executor is
parameterised with a per-call cap set, and the helper handler raises the bounds
to fit the curated contracts:

`_li_caps` has six keys (`local_drgn_introspect.py`): `emits`, `per_emit_bytes`,
`total_json`, `user_stdout`, `traceback`, `error_message`. The wrapper indexes
all of them — including `error_message`/`traceback` on its earliest exception
paths, before any helper code runs — so the cap set passed to the wrapper must
**always carry all six**. The cap profile is therefore expressed as overrides
**merged onto the runner defaults**: the helper handler overrides only the four
rows below, and `traceback`/`error_message` inherit the runner values unchanged.
`render_wrapper` rejects a `caps` object that, after the merge, is missing any of
the six keys or contains a non-positive int (`WrapperRenderError`), so a
malformed profile fails at render time rather than as a `KeyError`/`wrapper_crash`
on the target.

| Cap | Runner default | Helper profile |
|---|---|---|
| `per_emit_bytes` | 32 KiB | 4 MiB (one structured result document) |
| `emits` | 100 | 4 (single-emit convention + headroom to *detect* a buggy >1-emit helper rather than silently keep the first) |
| `total_json` | 1 MiB | 8 MiB |
| `user_stdout` | 256 KiB | 256 KiB (unchanged; helpers must not print) |
| `traceback` | 16 KiB | 16 KiB (inherited) |
| `error_message` | 4 KiB | 4 KiB (inherited) |

These bounds are still finite — a helper that somehow exceeds the helper profile
hits the same wrapper truncation path: an over-`per_emit_bytes` result becomes
an `__emit_oversized__` marker, and an over-`total_json` result has its single
emit popped to empty. Both surface cleanly as `helper_schema_drift` (the
validator sees an oversized marker or zero emits), never a corrupt result or an
unbounded transfer.

The two **unbounded-growth** helpers — `tasks` (every runnable/blocked task ×
its stack) and `dmesg` (the whole printk ring) — carry their own `limit` /
`max_entries` arg and a `truncated: bool` field, and set it `true` when they cap
their own row list, so the agent sees deterministic, helper-level truncation
rather than wrapper-level mangling. The other three (`modules`, `slab`, `irq`)
are **naturally bounded** — module count, named slab caches, and IRQ lines are
all in the hundreds even on large hosts — so they take no `limit` and have no
`truncated` field; their backstop is the wrapper cap (oversized →
`helper_schema_drift`), which §8.1's cap test confirms is not reachable at
realistic sizes. §8.1 also tests that the §7 defaults (`tasks` 200 tasks × deep
stacks, `dmesg` 1000 entries) serialise within the helper profile.

`debug.introspect.run` keeps the runner default caps unchanged — only the
helper handler opts into the larger profile.

### 3.4 Versioning

`version` is an integer per helper, surfaced in the response `data` and the
manifest step `details`. It is bumped whenever the script body or the output
model changes shape.

To give the version mechanical teeth, each helper ships a checked-in JSON-Schema
snapshot at `introspect_helpers/schemas/<name>.v<version>.json` generated from
`output_model.model_json_schema()`. A unit test (§8.1) regenerates the schema
from the live model and diffs it against the checked-in snapshot for the current
`version`; any shape change that is not accompanied by a new snapshot (and thus
a version bump) fails the test. This is what makes a bump "a deliberate,
reviewed event" — without the snapshot diff, a loosened model would drift
silently past the schema-validation tests. The golden *integration* tests
(§8.2) assert against the live model, not the snapshot; the snapshot exists
solely to force the version discipline.

## 4. Wrapper arg seam (modifies #51)

`WRAPPER_TEMPLATE` in `providers/local_drgn_introspect.py` gains an
`${ARGS_B64}` substitution. The wrapper decodes it into an `args` dict and
injects it into the script namespace beside `prog`, `emit`, and `drgn`:

```python
import base64 as _li_base64
args = _li_json.loads(_li_base64.b64decode("${ARGS_B64}").decode("utf-8"))
namespace["args"] = args
```

Like `${USER_SCRIPT_B64}`, the value is base64 of server-produced JSON, so it
cannot break out of its literal regardless of contents.

Changes that ride along (all in lockstep, covered by #51's tests):

- `render_wrapper(...)` and `render_wrapper_skeleton(...)` gain an `args_json`
  parameter and a `caps` parameter. The wrapper's `_li_caps` literal becomes a
  `${CAPS_JSON}` substitution (a server-produced, host-validated JSON object of
  positive ints) so the cap profile (§3.3) is per-call rather than hard-coded.
  `render_wrapper` merges the caller's `caps` overrides onto the runner-default
  six-key set and validates the merged object is complete (all six keys) and
  all-positive before substitution, raising `WrapperRenderError` otherwise.
  `debug.introspect.run` passes an empty override (the runner defaults verbatim),
  preserving its current behaviour byte-for-byte.
- The skeleton renderer encodes the same `args_json` (args are
  server-validated, non-secret) so the agent-visible skeleton is faithful.
- `user_script_sha256` is unchanged (it hashes the user script bytes only); the
  args are recorded separately in the call's `request.json` artifact.
- `debug.introspect.run` passes `args_json="{}"`. No new field is added to its
  public request — the slot is always present with an empty default.

## 5. Shared core executor (refactor of #51)

The common pipeline currently inlined in `debug_introspect_run_handler` is
extracted into a core function (working name `_execute_introspect_call`) that
takes the rendered `script`, `args_json`, and a **cap profile** (§3.3) and:

1. Validates run/profile/manifest invariants and resolves the target/rootfs.
2. Acquires admission (ssh-tier; HALTED fast-reject per interface-contracts
   §5.6 rule 2).
3. Mints `call_id`, renders the wrapper (`script` + `args_json` + the caller's
   cap profile substituted into `_li_caps`), writes `request.json`,
   `wrapper.skeleton.py`, and the sensitive `wrapper.py`.
4. Runs the SSH invocation with the timeout and output caps, bridging
   cancellation to the admission fence.
5. Parses stdout, performs host-authoritative provenance verify, and runs the
   payload through `Redactor()`.
6. Calls the caller-supplied **post-validator** (a callback over the redacted
   payload) and records the terminal `introspect:<call_id>` `StepResult` *once*,
   with a status that reflects the validator's verdict.

The post-validator keeps the recorded manifest step in agreement with the
agent-visible outcome, and preserves record-once semantics (no SUCCEEDED step
later contradicted by a failure response, no double-record race):

- `debug.introspect.run` passes an identity validator — a clean wrapper "ok"
  outcome records **SUCCEEDED**, exactly as today (a user script error is still
  a SUCCEEDED step with `data.status="script_error"`).
- `debug.introspect.helper` passes a validator that parses the single emit into
  `output_model`. On success the step is **SUCCEEDED**; on a drift/validation
  failure the step is recorded **FAILED** with code `helper_schema_drift` and the
  handler returns the matching failure response. The wrapper-level failure shapes
  (provenance, timeout, drgn open) still record FAILED inside the core before the
  validator is ever reached.

It returns a result object exposing the **redacted** payload (`emits`,
`user_stdout`, `outcome`, `truncated`, `build_id`, `prelude_ms`), the
`call_id`, the public artifact list, and any non-fatal `diagnostic`. The two
failure shapes from #51 (`_fail` / `_record_introspect_failure`) are preserved
inside the core so both handlers inherit identical error mapping.

The core executor performs **no operation gating**: it serves two operations
(`debug.introspect.run`, `debug.introspect.helper`) with different allowlist
strings, so each thin handler calls `_ensure_debug_operation_enabled` with its
own op string *before* invoking the core. The cap profile (`_li_caps` values)
becomes a parameter of `render_wrapper` rather than a hard-coded constant;
`debug.introspect.run` passes the runner defaults, the helper handler passes
the helper profile (§3.3).

- `debug.introspect.run` maps the redacted result to today's untyped `data`.
- `debug.introspect.helper` validates the single emit into `output_model` and
  returns the typed `data`.

**Redaction order:** redaction happens inside the core, before either handler
sees the payload. The helper handler therefore validates the **redacted** emit
into its model — secrets (notably in `dmesg`) never reach the typed model, the
response, or the persisted typed result. Raw transcripts stay on disk under
`<run>/sensitive/debug/introspect/<call_id>/`.

This refactor is recorded in an ADR (§9) before implementation, because it
reshapes shipped #51 code.

## 6. Tool surface

### 6.1 Request

```python
class DebugIntrospectHelperRequest(Model):
    run_id: str
    target_ref: str
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
```

The `[5, 300]` timeout band, manifest-immutability of profile fields, and the
`MAX_INTROSPECT_CALLS_PER_RUN` budget are enforced by the handler exactly as in
`debug.introspect.run`. `args` is validated against the resolved helper's
`args_model` (extra keys forbidden via `Model`'s `extra="forbid"`); a mismatch
is `CONFIGURATION_ERROR`.

### 6.2 Response (success)

```jsonc
{
  "status": "SUCCEEDED",
  "summary": "introspect helper sysinfo ok",
  "run_id": "...",
  "artifacts": [ /* public refs: request.json, wrapper.skeleton.py, stdout.json, stderr.log */ ],
  "suggested_next_actions": ["artifacts.get_manifest", "debug.introspect.helper"],
  "data": {
    "call_id": "…",
    "helper": "sysinfo",
    "version": 1,
    "result": { /* spec.output_model.model_dump(mode="json") */ },
    "truncated": { /* wrapper-cap flags: emits/total_json/user_stdout/… */ },
    "prelude_ms": 0
  }
}
```

Two distinct truncation signals can appear and mean different things:
`data.truncated` is **transport/wrapper** truncation (the result didn't fit the
helper cap profile — a tooling problem, expected to be rare and worth surfacing
as a warning), while `data.result.truncated` (present only on the
unbounded-growth helpers, §3.3) means the **helper hit its own `limit` /
`max_entries`** — expected, and the agent's remedy is to raise the limit or
narrow the query. An agent checking "did I get everything?" reads both.

### 6.3 Response (failure)

| Code | Category | When |
|---|---|---|
| `unknown_helper` | CONFIGURATION_ERROR | `name` not in registry |
| `helper_args_invalid` | CONFIGURATION_ERROR | `args` fails `args_model` validation |
| `helper_schema_drift` | INFRASTRUCTURE_FAILURE | not exactly one emit, or emit fails `output_model` |
| `helper_script_error` | INFRASTRUCTURE_FAILURE | curated drgn script raised on the target (carries redacted `error_type`/`error_message` from the wrapper outcome) |
| (inherited) | — | every failure mode of #51's core: admission/HALTED, provenance mismatch, drgn open/skew, timeout, cap overflow, wrapper crash |

### 6.4 Gating

`debug.introspect.helper` is a single entry in `ALLOWED_DEBUG_OPERATIONS`
(`config.py`). `_ensure_debug_operation_enabled(resolved_debug,
"debug.introspect.helper")` is called at handler entry, before any provider
work — the whole helper tool is enabled/disabled as a unit, matching how the
runner is gated. Per-helper gating is explicitly rejected (§9). The
`local-drgn-introspect` capability's `operations` list gains the same string so
`providers.list` advertises it.

## 7. The six helpers

Output models inherit `Model` (`extra="forbid"`). Fields below are the contract;
exact drgn extraction is an implementation detail of each script. Volatile
values are typed but not asserted by value in tests (§8).

| Helper | Args model | Output model (key fields) |
|---|---|---|
| `sysinfo` | *(empty)* | `release`, `version`, `machine`, `nodename`, `boot_cmdline`, `cpus_online: int`, `mem_total_pages: int` — from `init_uts_ns` + `saved_command_line` + basic counters |
| `tasks` | `states: list[str] = ["D"]`, `include_stack: bool = True`, `limit: int = 200` | `tasks: [{pid, tgid, comm, state, kernel_stack: list[str]}]`, `truncated: bool` — focus on blocked / D-state |
| `dmesg` | `max_entries: int = 1000` | `entries: [{ts_usec: int, level: int, text: str}]`, `truncated: bool` — `text` is redacted (§5) |
| `modules` | *(empty)* | `modules: [{name, size: int, refcount: int, used_by: list[str], state: str}]` |
| `slab` | *(empty)* | `caches: [{name, active_objs: int, num_objs: int, objsize: int, objs_per_slab: int}]` |
| `irq` | *(empty)* | `irqs: [{irq: int, name: str \| null, counts_per_cpu: list[int], affinity: list[int]}]` |

Args defaults are chosen so a `debug.introspect.helper(name=...)` call with no
`args` is meaningful for every helper. `tasks` defaults to D-state because the
acceptance criterion targets blocked processes; callers widen `states` to see
more.

## 8. Testing

### 8.1 Unit (no VM)

- Registry: every `built_in_helper_specs()` entry has a unique name; lookup
  works; unknown name → `unknown_helper`.
- Args: each `args_model` accepts its defaults; extra/ill-typed keys →
  `helper_args_invalid`.
- Single-emit convention: synthetic core results with zero / two / one emit →
  drift / drift / ok.
- Schema drift: a synthetic emit missing a required field →
  `helper_schema_drift`, raw payload preserved on disk.
- Redact-before-validate: inject a known secret pattern into a synthetic
  `dmesg` emit; assert the validated model and the response contain the
  redaction marker, not the secret.
- Core-executor seam: `debug.introspect.run` still returns its untyped contract
  after the refactor, and renders with the runner default caps (existing #51
  tests must stay green unchanged except for the new `args_json` / `caps`
  parameters, which default to the runner profile).
- Cap profile fits the contract: synthesize the largest in-contract result for
  each list helper (`tasks` with `limit=200` × deep stacks, `dmesg` with
  `max_entries=1000`), serialize it, and assert it is under the helper profile's
  `per_emit_bytes` / `total_json` (§3.3) — i.e. the §7 defaults cannot
  deterministically trip the oversized-marker path.
- Schema snapshot discipline: for each helper, `output_model.model_json_schema()`
  equals the checked-in `schemas/<name>.v<version>.json`; a deliberate model
  edit without a new snapshot fails this test (§3.4).

### 8.2 Golden integration (gated on `virsh` + VM)

One test per helper, skipped without the smoke VM (pattern of
`test_libvirt_boot_integration.py` / `test_qemu_gdbstub_integration.py`). Each:

1. Boots the disposable smoke VM and runs the helper.
2. Asserts the output validates against the helper's `output_model` (the schema
   is the golden — fails loud on schema drift).
3. Asserts a small set of run-stable invariants:
   - `sysinfo.release` non-empty; `cpus_online >= 1`.
   - `tasks` includes PID 1 (`init`/`systemd`).
   - `dmesg.entries` non-empty.
   - `modules` non-empty.
   - `slab.caches` includes a well-known cache (e.g. `kmalloc-*` family present).
   - `irq.irqs` non-empty; every `counts_per_cpu` length equals `cpus_online`.

A dedicated test drives the `tasks` D-state acceptance criterion: spawn a
synthetic kernel-side blocker on the VM, then assert `tasks(states=["D"])`
returns it with a non-empty `kernel_stack`.

**On "no stop-the-world pause" (acceptance criterion 1).** Non-stopping is a
property of the transport, not something a single helper call can be asked to
*prove* — drgn-over-SSH reads `/proc/kcore`-style live memory and never issues
a stop request, unlike the gdbstub tier. The design treats "no pause" as an
inherited invariant of the ssh/drgn tier (interface-contracts §3.3), not a
per-helper assertion. To make it falsifiable rather than vacuous, the `sysinfo`
acceptance test runs a continuous heartbeat on the guest (a loop appending a
monotonic timestamp to a file at a fixed interval) spanning the helper call and
asserts the heartbeat's inter-sample gap never exceeds a threshold during the
call window — a genuine stop-the-world pause would show up as a gap. A helper
that completes with an unbroken heartbeat satisfies the criterion; a gap fails
it.

## 9. ADR

Before implementation, record ADR `docs/adr/0009-introspect-helper-layer.md`
(next sequential number after 0008) capturing the three decided points and
their rejected alternatives:

1. **Shared core executor** extracted from `debug_introspect_run_handler`.
   - Rejected: helper delegates to the `run` handler and re-parses its response
     — awkward double-handling, manifest step indistinguishable from a plain
     run.
2. **Single-`emit` typed-result convention**, validated host-side into a
   per-helper Pydantic model, fail-loud on drift, under a **raised helper cap
   profile** (§3.3) carried as a per-call parameter of the core executor.
   - Rejected: advisory validation (lets malformed data reach the agent, weakens
     the acceptance criterion); JSON-Schema files + `jsonschema` for the *return*
     contract (new dependency, diverges from the all-Pydantic domain model — note
     `model_json_schema()` snapshots are still used for §3.4 version discipline,
     which is generation, not a runtime validator).
   - Rejected (caps): keeping the runner's 32 KiB per-emit / 100-emit caps for
     helpers (the list helpers' own defaults would always trip the oversized
     marker → permanent `helper_schema_drift`); streaming one emit per row (still
     overflows the 100-emit cap for `tasks(200)`/`dmesg(1000)`). The raised
     profile is safe because helper scripts are server-authored and trusted,
     unlike `debug.introspect.run`'s arbitrary user script, which keeps the
     tighter defaults.
3. **`${ARGS_B64}` wrapper seam** + **single unit-gated operation**.
   - Rejected (args): text-level prepend of `args = …` into the script body
     (less clean, quoting hazards); deferring args entirely (tool signature
     includes `args`).
   - Rejected (gating): per-helper operations (`debug.introspect.helper.dmesg`)
     — six allowlist entries and six advertised operations for least-privilege
     profiles nobody has asked for yet; revisit if a concrete need lands.

## 10. Coordination

- `providers/local_drgn_introspect.py`: `WRAPPER_TEMPLATE` (add `${ARGS_B64}`
  and `${CAPS_JSON}`), `render_wrapper` / `render_wrapper_skeleton` (add
  `args_json`, `caps`), the runner-default cap profile constant, capability
  `operations`.
- `introspect_helpers/`: the registry, six helper modules, and the
  `schemas/<name>.v<version>.json` snapshots (§3.4).
- `server.py`: extract `_execute_introspect_call`; add
  `debug_introspect_helper_handler` and its `@app.tool` registration; reuse
  `_count_introspect_calls` / `MAX_INTROSPECT_CALLS_PER_RUN`,
  `_record_terminal_introspect_result`, redaction helpers.
- `config.py`: add `debug.introspect.helper` to `ALLOWED_DEBUG_OPERATIONS`.
- `domain.py`: `DebugIntrospectHelperRequest`.
- `docs/specs/interface-contracts.md` §4.2 (provenance fail-loud), §5.6 rule 2
  (ssh-tier HALTED fast-reject) — inherited unchanged through the core executor.
- ADR 0006 (unified cancel-epoch state machine): helper calls are the third
  ssh-tier consumer of the gate, via the shared core.

## 11. Acceptance criteria (from #54)

- [ ] `debug.introspect.helper(name="sysinfo")` returns its typed JSON contract
      from a live VM with no observable stop-the-world pause — verified by the
      guest-heartbeat gap test (§8.2), not assumed.
- [ ] `tasks` returns D-state / blocked processes from a synthetic kernel-side
      test.
- [ ] `dmesg` redacts secrets per `Redactor`.
- [ ] Each helper has a golden integration test that fails loud on schema drift.
- [ ] All helpers respect `_ensure_debug_operation_enabled` gating via the
      single `debug.introspect.helper` operation.
