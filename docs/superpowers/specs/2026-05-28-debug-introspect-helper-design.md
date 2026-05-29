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
                     │  1. resolve name → HelperSpec (registry)
                     │  2. validate args → spec.args_model
                     │  3. render helper script + args_json
                     ▼
            ┌────────────────────────────────────────────┐
            │  shared core executor (extracted from #51)  │
            │  admission → render wrapper(${ARGS_B64})    │
            │  → SSH exec → caps → provenance verify      │
            │  → redaction → manifest record              │
            └────────────────────────────────────────────┘
                     │  returns redacted wrapper result
                     ▼
            4. validate single emit → spec.output_model
            5. ToolResponse.success(data={result: model_dump})
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

### 3.3 Single-emit convention

Every helper script calls `emit(result)` **exactly once** with a dict matching
its `output_model`. The handler:

1. Reads the redacted wrapper result's `emits` list.
2. Requires exactly one element. Zero or more than one → `helper_schema_drift`.
3. Validates that element into `spec.output_model`. A `ValidationError` →
   `helper_schema_drift`.

`helper_schema_drift` is `ErrorCategory.INFRASTRUCTURE_FAILURE` (the live kernel
emitted a shape the curated contract does not recognize — a tooling/version
fault, not the agent's input error). The raw and redacted payloads remain on
disk under the call's artifact dir for forensics; the response carries the
helper name, version, and the validation error summary (redacted).

### 3.4 Versioning

`version` is an integer per helper, surfaced in the response `data` and the
manifest step `details`. It is bumped whenever the script body or the output
model changes shape. Golden tests are keyed on `(name, version)` so a bump is a
deliberate, reviewed event rather than silent drift.

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
  parameter.
- The skeleton renderer encodes the same `args_json` (args are
  server-validated, non-secret) so the agent-visible skeleton is faithful.
- `user_script_sha256` is unchanged (it hashes the user script bytes only); the
  args are recorded separately in the call's `request.json` artifact.
- `debug.introspect.run` passes `args_json="{}"`. No new field is added to its
  public request — the slot is always present with an empty default.

## 5. Shared core executor (refactor of #51)

The common pipeline currently inlined in `debug_introspect_run_handler` is
extracted into a core function (working name `_execute_introspect_call`) that:

1. Validates run/profile/manifest invariants and resolves the target/rootfs.
2. Acquires admission (ssh-tier; HALTED fast-reject per interface-contracts
   §5.6 rule 2).
3. Mints `call_id`, renders the wrapper (`script` + `args_json`), writes
   `request.json`, `wrapper.skeleton.py`, and the sensitive `wrapper.py`.
4. Runs the SSH invocation with the timeout and output caps, bridging
   cancellation to the admission fence.
5. Parses stdout, performs host-authoritative provenance verify, and runs the
   payload through `Redactor()`.
6. Records the terminal `introspect:<call_id>` `StepResult`.

It returns a result object exposing the **redacted** payload (`emits`,
`user_stdout`, `outcome`, `truncated`, `build_id`, `prelude_ms`), the
`call_id`, the public artifact list, and any non-fatal `diagnostic`. The two
failure shapes from #51 (`_fail` / `_record_introspect_failure`) are preserved
inside the core so both handlers inherit identical error mapping.

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
    "truncated": { /* wrapper caps */ },
    "prelude_ms": 0
  }
}
```

### 6.3 Response (failure)

| Code | Category | When |
|---|---|---|
| `unknown_helper` | CONFIGURATION_ERROR | `name` not in registry |
| `helper_args_invalid` | CONFIGURATION_ERROR | `args` fails `args_model` validation |
| `helper_schema_drift` | INFRASTRUCTURE_FAILURE | not exactly one emit, or emit fails `output_model` |
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
  after the refactor (existing #51 tests must stay green unchanged except for
  the new `args_json` parameter).

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

No helper emits a stop-the-world pause (drgn-over-SSH reads live memory without
halting the target); the `sysinfo` acceptance test asserts the call completes
without the target entering a stopped state.

## 9. ADR

Before implementation, record ADR `docs/adr/0009-introspect-helper-layer.md`
(next sequential number after 0008) capturing the three decided points and
their rejected alternatives:

1. **Shared core executor** extracted from `debug_introspect_run_handler`.
   - Rejected: helper delegates to the `run` handler and re-parses its response
     — awkward double-handling, manifest step indistinguishable from a plain
     run.
2. **Single-`emit` typed-result convention**, validated host-side into a
   per-helper Pydantic model, fail-loud on drift.
   - Rejected: advisory validation (lets malformed data reach the agent, weakens
     the acceptance criterion); JSON-Schema files + `jsonschema` (new
     dependency, diverges from the all-Pydantic domain model).
3. **`${ARGS_B64}` wrapper seam** + **single unit-gated operation**.
   - Rejected (args): text-level prepend of `args = …` into the script body
     (less clean, quoting hazards); deferring args entirely (tool signature
     includes `args`).
   - Rejected (gating): per-helper operations (`debug.introspect.helper.dmesg`)
     — six allowlist entries and six advertised operations for least-privilege
     profiles nobody has asked for yet; revisit if a concrete need lands.

## 10. Coordination

- `providers/local_drgn_introspect.py`: `WRAPPER_TEMPLATE`, `render_wrapper`,
  `render_wrapper_skeleton`, capability `operations`.
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
      from a live VM with no observable stop-the-world pause on the target.
- [ ] `tasks` returns D-state / blocked processes from a synthetic kernel-side
      test.
- [ ] `dmesg` redacts secrets per `Redactor`.
- [ ] Each helper has a golden integration test that fails loud on schema drift.
- [ ] All helpers respect `_ensure_debug_operation_enabled` gating via the
      single `debug.introspect.helper` operation.
