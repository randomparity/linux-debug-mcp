# ADR 0009 — introspect helper layer: shared executor, typed-result convention, and `${ARGS_B64}` seam

**Status:** Accepted (2026-05-28) · **Issue:** #54 · **Affects:** `src/linux_debug_mcp/server.py` (`_execute_introspect_call`, `_make_helper_post_validator`, `debug_introspect_helper_handler`), `src/linux_debug_mcp/introspect_helpers/` (new package), `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS`)

## Context

#54 introduces `debug.introspect.helper`, a family of typed, agent-consumable introspection queries (sysinfo, tasks, dmesg, modules, slab, irq) that run drgn scripts on the live target and return validated, structured output. The helper tool shares the same admission, SSH, caps, provenance, redaction, and manifest pipeline as the existing `debug.introspect.run`. Three design points were left open by the spec (`docs/superpowers/specs/2026-05-28-debug-introspect-helper-design.md`) and needed explicit decisions before implementation: where the shared execution pipeline lives, how helper output is validated and bounded, and how per-call arguments reach the drgn script.

## Decision

### 1. Shared core executor extracted from `debug_introspect_run_handler`

A private `_execute_introspect_call` function is extracted from `debug_introspect_run_handler` and shared by both `debug.introspect.run` and `debug.introspect.helper`. It owns the full pipeline (admission → render → SSH → caps → provenance → redaction → manifest step write) and accepts an optional `post_validator` callback. The callback receives the decoded JSON result and returns either a typed verdict (for helpers) or `None` (for plain run, which performs no post-processing). Result mapping — extracting the typed `result` dict, setting `failure_code` — is done in the `post_validator` so the executor stays result-agnostic.

### 2. Single-`emit` typed-result convention with raised helper cap profile

Each helper script calls `emit(...)` exactly once. The host-side post-validator (produced by `_make_helper_post_validator`) enforces this: zero emits or more than one emit is `helper_schema_drift`; a script-level exception surfaced in the `outcome` dict is `helper_script_error` (not drift); a single emit that fails Pydantic validation against the helper's `output_model` is also `helper_schema_drift`. Validation is fail-loud — a malformed payload is never passed to the agent as a success.

Helpers run under a raised cap profile (`HELPER_CAP_PROFILE`: `per_emit_bytes`=4 MiB, `emits`=4, `total_json`=8 MiB) merged onto the runner defaults. The raised profile is necessary because the list helpers' own default bounds (tasks: 200 × 64-frame stacks; dmesg: 1 000 entries × 80-char text) exceed the runner's 32 KiB `per_emit_bytes` cap: a test (`test_default_list_helpers_fit_helper_cap_profile`) asserts both payloads fit within the 4 MiB limit. Version-drift discipline uses `model_json_schema()` snapshots stored under `introspect_helpers/schemas/`; these are checked by `test_schema_snapshots_match_models` and are generation artifacts, not runtime validators.

### 3. `${ARGS_B64}` wrapper seam and single unit-gated allowlist entry

Per-call arguments are injected into the shared drgn wrapper via a `${ARGS_B64}` placeholder that the executor populates with a base64-encoded JSON blob before sending the script to the target. The placeholder is defined once in the shared wrapper; helper scripts decode it at startup using `import base64, json; args = json.loads(base64.b64decode("${ARGS_B64}"))`. `debug.introspect.helper` is a single entry in the `ALLOWED_DEBUG_OPERATIONS` allowlist (in `config.py`) and is also advertised as a single operation in the local drgn introspect capability; the constrained debug-operations allowlist gates it as a unit.

## Consequences

- `debug_introspect_run_handler` and `debug_introspect_helper_handler` share one tested pipeline; a regression in admission or redaction is caught by both tool's tests.
- Adding a new helper requires only a new `HelperSpec` (script, `output_model`, version, schema snapshot) in `introspect_helpers/`; no changes to the executor, allowlist, or capability are needed.
- The 4 MiB `per_emit_bytes` cap is verified by a unit test; changing `HELPER_CAP_PROFILE` without updating the test will cause an immediate CI failure.
- `helper_schema_drift` is the signal for version drift: if a helper's drgn script emits a field the host model no longer expects, the agent receives a clear error rather than silently wrong data.
- `${ARGS_B64}` is a text substitution slot, not a structured protocol — the wrapper must remain the single owner of the decode step; callers must never embed raw user strings adjacent to the placeholder.

## Considered & rejected

1. **Helper handler delegates to the run handler and re-parses its `ToolResponse`.**
   Rejected: the run handler serialises its result to a `ToolResponse` and the helper would have to inspect `response.data["emits"]` after the fact — awkward double-handling. More importantly, the manifest step written by the run handler is indistinguishable from a plain `debug.introspect.run` invocation; the helper's typed-result metadata (validated output, `failure_code`, `result` dict) has no natural place in the run step record. Sharing the executor at the Python-function level gives the helper its own step without duplicating pipeline logic.

2. **Advisory (non-fatal) post-validation.**
   Rejected: letting malformed data reach the agent degrades the contract. An agent consuming `tasks` output with an unexpected schema silently produces wrong analysis. Fail-loud validation is the only way to enforce the typed-result promise.

3. **JSON Schema files + `jsonschema` as the runtime validator.**
   Rejected: adds a new runtime dependency that diverges from the all-Pydantic domain model. The `model_json_schema()` snapshots are retained but used only for version-drift detection (generation, not runtime validation); Pydantic `model_validate` is the runtime check.

4. **Keep the runner's default 32 KiB `per_emit_bytes` cap for helpers.**
   Rejected: the list helpers' default bounds deterministically exceed 32 KiB (tasks: 200 tasks × 64-frame stacks ≈ hundreds of KiB; dmesg: 1 000 entries). Using the runner's cap would cause the oversized-marker path to fire on every normal helper call, making the result permanently `helper_schema_drift` and the helpers useless. The raised cap profile is the correct fix; the unit test proves it is sufficient.

5. **Per-row streaming (emit once per task / per log entry).**
   Rejected: the runner's 100-emit default cap would be exceeded by tasks(200) and dmesg(1 000) even if each row were tiny. Single-emit with a raised `per_emit_bytes` bound is simpler and avoids requiring the caller to reassemble a stream.

6. **Text-level prepend of `args = …` into the script body.**
   Rejected: quoting hazards when arg values contain quotes or newlines. A base64-encoded JSON blob has no characters that interact with the Python string literal in the prepend context.

7. **Defer args entirely (no `${ARGS_B64}` slot; fixed per-helper behaviour only).**
   Rejected: the `debug.introspect.helper` tool signature includes an `args` field; honouring it is part of the API contract. Tasks, dmesg, and future helpers already expose configurable defaults (`states`, `limit`, `max_entries`) that are meaningless if not forwarded.

8. **Per-helper allowlist entries (`debug.introspect.helper.dmesg`, etc.).**
   Rejected: six allowlist entries and six advertised operations for fine-grained least-privilege profiles that no concrete caller has requested. The cost (added config surface, more operations to advertise and gate) is not justified by a concrete use case. Revisit when a deployment requires per-helper restrictions.

## References

spec `docs/superpowers/specs/2026-05-28-debug-introspect-helper-design.md`; `src/linux_debug_mcp/server.py` (`_execute_introspect_call`, `_make_helper_post_validator`, `HELPER_CAP_PROFILE`); `src/linux_debug_mcp/introspect_helpers/` (package); `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS`); `tests/test_introspect_helpers.py` (`test_default_list_helpers_fit_helper_cap_profile`).
