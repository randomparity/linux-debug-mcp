# `debug.introspect.from_vmcore` — offline vmcore drgn introspection

**Date:** 2026-05-29
**Issue:** #55
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #11
**Status:** Draft — pending adversarial review
**Depends on:** #51 (live runner foundation: wrapper render + JSON framing + caps + manifest step pattern, merged); #53 (`symbols/` resolver + `verify_build_id`, merged); #54 (helper layer: `_make_helper_post_validator`, `HELPER_REGISTRY`, merged)
**Design decisions:** [ADR 0010](../../adr/0010-introspect-from-vmcore-execution-model.md) (run-scoped offline execution, shared wrapper body, shared post-runner finalizer)

## 1. Background and scope

The live tier (`debug.introspect.run`, #51) runs a user drgn script against a
**booted** target over SSH, gated by the ssh-tier admission service. This spec
adds the **offline** sibling: `debug.introspect.from_vmcore`, which runs the same
class of drgn script against a **captured vmcore file on the agent host**, with no
live target and no admission gate. Per `interface-contracts.md` §5.6 rule 3,
vmcore analysis has no live dependency and is **always concurrent-safe**.

The output contract (the `emit()` JSON framing, the caps, the redaction, the
`introspect:<call_id>` manifest step, the `<run>/debug/introspect/<call_id>/`
artifact layout) is identical to the live runner. The two paths differ only in
(a) how drgn opens the kernel (a vmcore file vs the live `/proc/kcore`), (b) where
the build_id fail-loud reference comes from (the supplied `vmlinux` vs the
boot-recorded `KernelProvenance`), and (c) the absence of SSH/sudo/admission.

### In scope

- `debug.introspect.from_vmcore(run_id, vmcore_ref, vmlinux_ref, modules_ref?, script, timeout_seconds, args, allow_write=false)` MCP tool.
- `debug.introspect.from_vmcore_helper(run_id, vmcore_ref, vmlinux_ref, modules_ref?, name, args, timeout_seconds)` MCP tool — runs a curated `HELPER_REGISTRY` helper against the vmcore, reusing the live helper's `_make_helper_post_validator` and `HELPER_CAP_PROFILE` unchanged.
- A vmcore wrapper template that shares its emit/caps/exec/output-framing body byte-for-byte with the live wrapper and differs only in a `drgn`-open prologue (`set_core_dump` + host-supplied vmlinux load), rendered per call.
- Host-side symbol resolution via #53's `resolve_symbols(KernelProvenance(...), run_dir=...)` to confine `vmlinux_ref`/`modules_ref` to the run sandbox and surface the `modules_debuginfo_missing` warning.
- Host-side ELF build-id extraction from the resolved `vmlinux` (`symbols/build_id.py: read_elf_build_id`) producing the **host-authoritative** expected build_id; fail-loud comparison against the vmcore's embedded build_id per §4.2.
- Local drgn execution via the existing `SubprocessSshRunner` (a generic subprocess runner; no SSH argv), with the same `timeout(1)` defense-in-depth, output cap, and cancellation plumbing the live path uses.
- Manifest integration: per-call `introspect:<call_id>` `StepResult`, artifact dir under `<run>/debug/introspect/<call_id>/`, raw stdout/stderr under `<run>/sensitive/debug/introspect/<call_id>/`, same redaction discipline.
- Adding `debug.introspect.from_vmcore` and `debug.introspect.from_vmcore_helper` to `ALLOWED_DEBUG_OPERATIONS` and to the `local-drgn-introspect` capability `operations` list.

### Out of scope

| Concern | Where it lives |
|---|---|
| Capturing the vmcore (kdump / crash dump) | #14 |
| Pulling a remote vmcore back to the host | deferred (documented in §11) |
| `allow_write=true` enforcement | #56 (rejected with `configuration_error` here, as in the live path) |
| New curated helpers | #54 (existing helpers are reused unchanged) |
| A host-side drgn/debuginfo prerequisite probe | #52 (the live probe; a host-drgn probe is a future sibling) |

## 2. Architecture overview

```
agent ──MCP──▶ debug.introspect.from_vmcore handler
                     │
                     │  (no admission, no SSH, no sudo, no target lifecycle)
                     ▼
       load manifest ─┬─ call-budget check (shared _count_introspect_calls)
                      ├─ sensitive/ mode 0700 preflight (shared)
                      ▼
       resolve_symbols(KernelProvenance(vmlinux_ref, modules_ref), run_dir)
                      │   → confined vmlinux_path, modules_path, warnings
                      ▼
       confine vmcore_ref to run_dir (confine_run_relative)   ← #53 leaf
                      │
                      ▼
       expected_build_id = read_elf_build_id(vmlinux_path)    ← host-authoritative
                      │
                      ▼
       render vmcore wrapper.py  (set_core_dump + load vmlinux,
                      │           ${EXPECTED_BUILD_ID}=vmlinux id)
                      ▼
       SubprocessSshRunner.run(["timeout","--kill-after=2s","<t>s","python3","-"],
                      │          stdin=wrapper, stdout→sensitive/stdout.raw, cap)
                      ▼
       _finalize_introspect_call(...)  ← shared with the live path:
         runner-result triage → outcome discrimination → host verify_build_id
         → Redactor → stdout.json/stderr.log → introspect:<call_id> step
         → ToolResponse
```

Three components are new; everything else is reused:

1. **Two tool handlers** (`debug_introspect_from_vmcore_handler`,
   `debug_introspect_from_vmcore_helper_handler`) plus a private
   `_execute_vmcore_introspect_call` orchestrator in `server.py`.
2. **Vmcore wrapper template** in `providers/local_drgn_introspect.py`
   (`render_vmcore_wrapper`, `render_vmcore_wrapper_skeleton`), composed from the
   shared body extracted from the live `WRAPPER_TEMPLATE`.
3. **Host ELF build-id reader** `symbols/build_id.py: read_elf_build_id`.

Reused without change: `resolve_symbols`/`confine_run_relative`/`verify_build_id`
(#53), `_make_helper_post_validator`/`HELPER_CAP_PROFILE`/`HELPER_REGISTRY` (#54),
`SubprocessSshRunner`, `Redactor`, `ArtifactStore`, `_record_terminal_introspect_result`,
`_record_introspect_failure`, `_count_introspect_calls`, `_redact_and_truncate`,
`_head_tail`, `MAX_INTROSPECT_CALLS_PER_RUN`, `RUN_STDOUT_CAP`, `SCRIPT_BYTE_CAP`.

## 3. Tool surface

### 3.1 Requests

```python
class DebugIntrospectFromVmcoreRequest(Model):        # extra="forbid"
    run_id: str
    vmcore_ref: str          # run-relative path to the captured vmcore file
    vmlinux_ref: str         # run-relative path to the uncompressed ELF vmlinux+DWARF
    modules_ref: str | None = None   # optional run-relative *directory* of *.ko[.debug]
    script: str              # user drgn script source
    timeout_seconds: int = 30        # handler-bounded to [5, 300]
    allow_write: bool = False        # rejected if True (#56)
    args: dict[str, Any] = Field(default_factory=dict)

class DebugIntrospectFromVmcoreHelperRequest(Model):  # extra="forbid"
    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    name: str                # HELPER_REGISTRY key
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
```

There is **no** `target_ref`/`target_profile`/`rootfs_profile`/`debug_profile`
field: the vmcore path does not name, boot, reach, or gate a live target. The run
manifest is consulted only for the run-directory layout, the call budget, and the
`sensitive/` mode preflight — never for a target profile, a boot snapshot, or a
recorded `KernelProvenance`. A vmcore may be analysed against a run whose boot
failed, or whose target was long ago reclaimed.

**Refs are run-relative.** `vmcore_ref`, `vmlinux_ref`, and `modules_ref` are
resolved through #53's `confine_run_relative`/`resolve_symbols`, confined to
`<run_dir>`. Per ADR 0008's explicit boundary, admitting a vmcore/vmlinux outside
the run sandbox is #55's trust decision — and this spec declines it: an
out-of-sandbox ref is a `configuration_error`. A vmcore captured elsewhere (e.g.
by kdump, #14) must be staged into the run directory first.

### 3.2 Operation gating

There is no `DebugProfile` in the call path (no `debug_profile` field). The new
operations are still added to `ALLOWED_DEBUG_OPERATIONS` (the static allowlist) so
the surface is enumerable and consistent, but `_ensure_debug_operation_enabled`
(which takes a resolved `DebugProfile`) is **not** invoked — there is no profile to
resolve and no admission tier to narrow. This is the §5.6-rule-3 "never gated"
property made concrete: a vmcore call cannot be blocked by target state or by a
profile's `enabled_operations`.

### 3.3 Response

Identical shape to `debug.introspect.run` (§3 of the run spec). Success `data`
carries `call_id`, `status` (`ok`/`script_error`), `outcome`, `emits`,
`user_stdout_snippet`, `drgn_stderr_snippet`, `build_id` (the vmcore's embedded
id), `truncated`, timing, `artifacts`, `diagnostic`. The helper tool's success
`data` carries the validated typed `result` (via the shared post-validator).
`suggested_next_actions` is `["artifacts.get_manifest", "<the same tool name>"]`.

## 4. The vmcore wrapper

### 4.1 Shared-body composition

The live `WRAPPER_TEMPLATE` (`local_drgn_introspect.py`) is refactored — **without
behaviour change** — into two literal fragments joined by string concatenation
before `Template(...)`:

- `_WRAPPER_PROLOGUE_LIVE`: lines from the header through the `${EXPECTED_BUILD_ID}`
  provenance-mismatch self-abort (current template lines 1–144). This owns the
  `import drgn`, helper-namespace capture, `prog = drgn.Program()`,
  `prog.set_kernel()`, `prog.load_default_debug_info()`, build_id read, and the
  provenance check.
- `_WRAPPER_BODY`: everything from `_li_emit_buffer = []` onward (current lines
  146–248) — `emit()`, namespace assembly, `${ARGS_B64}` decode, user-script
  compile/exec under `redirect_stdout`, the output-framing/total_json trim, and the
  `_li_sys.exit(6)` finally.

`WRAPPER_TEMPLATE = Template(_WRAPPER_PROLOGUE_LIVE + _WRAPPER_BODY)`. A unit test
asserts the recomposed template string is **byte-identical** to a golden copy of
the pre-refactor template, so the live path is provably unchanged.

The vmcore template is `VMCORE_WRAPPER_TEMPLATE = Template(_WRAPPER_PROLOGUE_VMCORE
+ _WRAPPER_BODY)` — the **same** body, a different prologue.

### 4.2 The vmcore prologue (`_WRAPPER_PROLOGUE_VMCORE`)

Structurally mirrors the live prologue, substituting the drgn-open lines. Pseudocode
of the only differences (full template is byte-exact in the implementation):

```python
# Paths arrive base64-encoded (see §4.3) and are decoded into Python str
# objects — never substituted as raw text into a literal.
import base64 as _li_base64
_li_vmcore = _li_base64.b64decode("${VMCORE_PATH_B64}").decode("utf-8")
_li_vmlinux = _li_base64.b64decode("${VMLINUX_PATH_B64}").decode("utf-8")
_li_modules = _li_base64.b64decode("${MODULES_PATH_B64}").decode("utf-8") or None

try:
    import drgn
    <capture drgn.helpers.linux namespace — identical to live>
    prog = drgn.Program()
    prog.set_core_dump(_li_vmcore)                # vs set_kernel()
except Exception as exc:
    <emit outcome drgn_open_failure, exit 3>      # identical shape to live

_li_result["prelude_ms"] = ...                    # identical

try:
    _li_bid = prog.main_module().build_id         # vmcore's embedded id (see ordering note below)
    _li_result["build_id"] = _li_bid.hex() if _li_bid else None
except Exception as exc:
    <emit outcome drgn_version_skew, exit 3>      # drgn too old to expose main_module().build_id

if _li_result["build_id"] is None:                # core carries no embedded build-id
    <emit outcome provenance_unverifiable, exit 4>   # cannot honour §4.2 — fail loud, distinct code

if _li_result["build_id"] != "${EXPECTED_BUILD_ID}":             # vmlinux id (host-supplied)
    <emit outcome provenance_mismatch, exit 4>    # BEFORE loading symbols

try:
    prog.load_debug_info([_li_vmlinux])           # load symbols only after the check passes
except Exception as exc:
    <emit outcome drgn_open_failure, exit 3>      # vmlinux load failure reuses the open-failure code

if _li_modules:                                   # optional — best-effort, NEVER fatal
    import os as _li_os
    # ${MODULES_PATH_B64} is a *directory* bundle (§3.1/§5). drgn's
    # load_debug_info takes individual ELF files, not a directory, so enumerate
    # the per-module debuginfo files and pass the file list.
    _li_ko = []
    for _li_root, _, _li_files in _li_os.walk(_li_modules):
        for _li_f in _li_files:
            if _li_f.endswith((".ko.debug", ".ko")):
                _li_ko.append(_li_os.path.join(_li_root, _li_f))
    if not _li_ko:
        _li_result.setdefault("warnings", []).append(
            {"code": "modules_debuginfo_empty", "detail": "no .ko/.ko.debug under bundle"})
    else:
        try:
            prog.load_debug_info(_li_ko)
            _li_result.setdefault("warnings", []).append(
                {"code": "modules_debuginfo_loaded", "count": len(_li_ko)})
        except Exception as exc:
            _li_result.setdefault("warnings", []).append(
                {"code": "modules_debuginfo_load_failed", "error_type": type(exc).__name__})
```

The three warning codes are mutually exclusive and let an agent distinguish
"modules requested but the bundle was empty" (`modules_debuginfo_empty`) from
"modules requested and N files loaded" (`modules_debuginfo_loaded`) from "modules
requested but drgn rejected them" (`modules_debuginfo_load_failed`) — a silent
"green result with no module symbols" is impossible.

**drgn ordering assumption (must be verified by the env-gated integration test):**
the design requires `prog.main_module().build_id` to be populated by
`set_core_dump` (from the core's VMCOREINFO / `NT_GNU_BUILD_ID` note) *before*
any DWARF is loaded, so the §4.2 check runs before `load_debug_info`. If a captured
core embeds **no** build-id, `main_module().build_id` is `None`; the wrapper emits
the distinct `provenance_unverifiable` outcome (exit 4) and loads no symbols —
the pair cannot be verified, so it fails loud rather than guessing. This is a
stricter contract than drgn itself (which can load a matching vmlinux without a
build-id); the design deliberately fails closed when provenance cannot be proven.

The provenance check happens **before** `load_debug_info`, so mismatched symbols
are never loaded — the §4.2 fail-loud guarantee. Module debuginfo is loaded
**best-effort after** the verified vmlinux load: a present-but-corrupt modules
bundle yields a `modules_debuginfo_load_failed` warning, never a hard failure —
matching `resolve_symbols`'s non-fatal modules stance (§5 of ADR 0008). The three
path placeholders are base64-encoded blobs (§4.3); `${EXPECTED_BUILD_ID}` is
host-validated before substitution (see §4.3). `${CALL_ID}`, `${ARGS_B64}`,
`${USER_SCRIPT_B64}`, `${CAPS_JSON}` are reused from the live render verbatim.

### 4.3 Pre-substitution validation

`render_vmcore_wrapper` validates non-user inputs before `Template.substitute`,
raising `WrapperRenderError` (mapped to `INFRASTRUCTURE_FAILURE` /
`wrapper_render_error` by the handler) on failure:

- `expected_build_id` matches `BUILD_ID_RE` (host-parsed from vmlinux). It is
  produced by `read_elf_build_id` *before* the renderer is called; a vmlinux whose
  ELF note is unreadable never reaches the renderer (it fails earlier in step 6 as
  a `CONFIGURATION_ERROR`, see §8).
- `call_id` matches the UUIDv4-hex regex (internal invariant).
- `vmcore_path`, `vmlinux_path`, `modules_path` are **already-confined absolute
  paths** (the handler resolved them via `confine_run_relative`). They are
  **base64-encoded** into pure-ASCII literals (`${VMCORE_PATH_B64}` etc.) and
  decoded back to `str` in the wrapper prologue — exactly as the user script is
  handled. This is a **required security control, not belt-and-suspenders**:
  `confine_run_relative` (`safety/paths.py`) only enforces sandbox *containment*,
  it does **not** reject `"`/newline/`${` characters in the user-supplied ref tail,
  so a filename like `evil".__import__('os')...` confined inside the run dir would
  break out of a raw string literal. Base64 removes the entire injection class; the
  renderer additionally rejects a `modules_path` (and any path) that fails to
  round-trip as UTF-8. The absent-modules case substitutes the base64 of the empty
  string, which the prologue decodes to `None`.
- `user_script` is base64-encoded into a pure-ASCII literal (identical to the live
  render) so triple quotes / NUL / `${...}` in the script cannot escape.
- `caps`/`args_json` validated by the reused `_merge_and_validate_caps` / JSON parse.

A `render_vmcore_wrapper_skeleton` mirrors the live skeleton: the agent-visible
`wrapper.skeleton.py` replaces the user-script body with its `sha256:` pointer and
is safe to surface as a non-sensitive artifact.

## 5. Host-side build-id extraction (`symbols/build_id.py`)

```python
def read_elf_build_id(path: Path) -> str:
    """Return the lower-case hex NT_GNU_BUILD_ID note from an ELF file.

    Parses the ELF header → program headers → PT_NOTE segments (falling back to
    the `.note.gnu.build-id` section if no PT_NOTE carries it), extracts the
    NT_GNU_BUILD_ID (type 3, name "GNU") note's descriptor, and hex-encodes it.
    Raises BuildIdReadError on a non-ELF (incl. compressed vmlinux.xz / vmlinuz),
    truncated, or note-absent file. The handler maps this to a caller-facing
    CONFIGURATION_ERROR (`vmlinux_build_id_unreadable`), not an infrastructure
    fault — the caller supplied the wrong file.
    """
```

Pure-Python, no drgn/`pyelftools` dependency (a hand-rolled `struct` parse of the
fixed ELF/note layout — both ELFCLASS32 and ELFCLASS64, both endiannesses). Lives
in `symbols/` beside the verifier it feeds (ADR 0008 keeps symbol/provenance logic
in one leaf). It is the **host-authoritative** source of `expected_build_id`:
the host never trusts the wrapper to tell it what the vmlinux's id is.

The handler injects it as a `build_id_reader: Callable[[Path], str]` seam
(default `read_elf_build_id`) so handler tests pass a fake without synthesising ELF
bytes, while `read_elf_build_id` gets its own focused unit tests against crafted
ELF note blobs (valid 32/64-bit, missing note, truncated, non-ELF).

## 6. Execution pipeline (`_execute_vmcore_introspect_call`)

A linear orchestrator distinct from the live `_execute_introspect_call` (the live
core is inseparable from admission/SSH/sudo). It reuses every shared leaf and the
new shared finalizer (§7). Steps:

1. Resolve `ArtifactStore`; load manifest (missing run → `configuration_error`,
   `run not found`).
2. Request invariants: `allow_write` rejected (`allow_write_not_supported`);
   `timeout_seconds` in `[5, 300]` (`invalid_timeout`); `script` non-empty and
   `≤ SCRIPT_BYTE_CAP` (`invalid_script`). The helper handler validates `name`
   against `HELPER_REGISTRY` and `args` against the helper's `args_model` exactly
   as the live helper handler does, then delegates with the helper's script + caps
   + post-validator.
3. Call-budget: `_count_introspect_calls(manifest) >= MAX_INTROSPECT_CALLS_PER_RUN`
   → `configuration_error` (`manifest_call_budget_exhausted`). Vmcore and live
   calls share the one `introspect:` budget — they write the same step namespace.
4. `sensitive/` mode-0700 preflight (`sensitive_dir_missing` /
   `sensitive_dir_too_permissive`) — identical to the live path.
5. Resolve symbols: build a `KernelProvenance(build_id="" , release="",
   vmlinux_ref=..., modules_ref=..., cmdline="", config_ref=None)` shell purely to
   reuse `resolve_symbols`, which confines the paths to `run_dir` and returns
   `vmlinux_path`, `modules_path` (a directory bundle of `*.ko[.debug]`, enumerated
   in the wrapper per §4.2), and `modules_debuginfo_missing` warnings.
   `SymbolResolutionError` → `configuration_error` (`symbol_resolution_failed`,
   carrying the resolver's `code`). Separately confine `vmcore_ref`; a missing/
   escaping vmcore is `configuration_error` (`vmcore_not_found`).
6. `expected_build_id = build_id_reader(vmlinux_path)`; `BuildIdReadError` (the
   vmlinux is not an ELF, is compressed, is stripped of its build-id note, or is
   truncated) → `configuration_error` (`vmlinux_build_id_unreadable`). This is a
   **caller input** error — the agent supplied the wrong/compressed file and can
   fix it by supplying the uncompressed ELF vmlinux that carries a GNU build-id
   note (the same file drgn needs for DWARF). It is deliberately *not*
   `provenance_corrupt`/`infrastructure_failure`: that code is reserved for
   server-recorded malformed data (the live path's manifest build_id), not a
   caller-supplied ref. **Precondition:** `vmlinux_ref` is the uncompressed ELF
   vmlinux containing an `NT_GNU_BUILD_ID` note.
7. Mint `call_id`; create `<run>/debug/introspect/<call_id>/` (0700) and
   `<run>/sensitive/debug/introspect/<call_id>/` (0700); render wrapper +
   skeleton; write `wrapper.py` `O_EXCL` mode-0600, `wrapper.skeleton.py`, and the
   redacted `request.json` (with `script` replaced by its `sha256:` pointer, the
   resolved paths recorded as their run-relative refs). `WrapperRenderError` here
   → write a FAILED step + `infrastructure_failure` (`wrapper_render_error`),
   mirroring the live render-failure path (minus admission rollback).
8. Run locally: `runner.run(["timeout","--kill-after=2s", f"{t}s","python3","-"],
   timeout=t+10, stdin=wrapper, stdout_path=sensitive/stdout.raw,
   stderr_path=sensitive/stderr.raw, cancel=<unused event>,
   max_stdout_bytes=RUN_STDOUT_CAP)`. No sudo, no SSH argv, no admission watcher
   thread — there is no cancel fence to bridge, so `cancel` is an event that never
   fires (the runner's `timeout` plus the in-process `timeout(1)` bound the call).
   chmod 0600 the raw files.
9. `_finalize_introspect_call(...)` (§7) does the rest and returns the
   `ToolResponse`.

`Redactor` is seeded with no secret values (there is no `ssh_key_ref`); the
vmcore/vmlinux/modules paths are run-relative and contain no secrets, but all
returned/persisted text still passes through `Redactor` (the generic pattern set)
to satisfy the "redact like the live path" acceptance criterion.

## 7. Shared finalizer (`_finalize_introspect_call`)

The post-runner stages are byte-for-byte identical between the live and vmcore
paths once the runner has produced a `SshResult` and raw stdout/stderr files:
runner-result triage (`oversized_output` / `cancelled` / `stdin_failed` /
`timed_out` / `exit==124` / unparseable), outcome-status discrimination
(`drgn_open_failure` / `drgn_version_skew` / `provenance_mismatch` /
`script_compile_error` / `wrapper_internal_error`), the host-side
`verify_build_id(expected, observed)` defence-in-depth, the happy-path Redaction →
`stdout.json`/`stderr.log` → `introspect:<call_id>` step write → success
`ToolResponse`, and the optional `post_validator` verdict handling.

These ~150 lines are extracted from `_execute_introspect_call` into
`_finalize_introspect_call(...)`, parametrised by the small set of values that
differ:

| Parameter | Live | Vmcore |
|---|---|---|
| `expected_build_id` | manifest `KernelProvenance.build_id` | `read_elf_build_id(vmlinux)` |
| `ssh_user` (forensic detail) | `resolved_rootfs.ssh_user` | omitted (`None`) |
| `operation_name` (next-action echo) | `debug.introspect.run` / `.helper` | `debug.introspect.from_vmcore` / `.from_vmcore_helper` |
| `drgn_open_message` | "drgn could not attach to the live target" | "drgn could not open the vmcore" |
| `post_validator` | `None` / helper validator | `None` / helper validator |

The `ssh_user` step-detail key is **kept unchanged** for the live path (renaming it
would churn the live manifest schema, its consumers, and its tests for no functional
gain). The finalizer takes the principal as an optional argument and **omits the
key entirely** when it is `None` — so a vmcore step, which never opens SSH, simply
has no `ssh_user` field rather than a misleading `ssh_user=null`. The live path's
recorded shape is byte-for-byte identical to today.

The live `_execute_introspect_call` keeps its admission/SSH/sudo orchestration and
calls `_finalize_introspect_call` for the tail; its existing test suite proves the
extraction is behaviour-preserving. This avoids duplicating drift-prone
redaction/manifest/outcome logic — the same hazard ADR 0009 cited when it extracted
`_execute_introspect_call` itself.

## 8. Failure taxonomy

| Condition | `ErrorCategory` | `code` |
|---|---|---|
| run not found / `allow_write` / bad timeout / empty-or-oversized script | `CONFIGURATION_ERROR` | `run_not_found` / `allow_write_not_supported` / `invalid_timeout` / `invalid_script` |
| budget exhausted | `CONFIGURATION_ERROR` | `manifest_call_budget_exhausted` |
| `sensitive/` missing/too-permissive | `CONFIGURATION_ERROR` | `sensitive_dir_missing` / `sensitive_dir_too_permissive` |
| vmcore ref missing/escaping | `CONFIGURATION_ERROR` | `vmcore_not_found` |
| vmlinux/modules ref unsafe/missing | `CONFIGURATION_ERROR` | `symbol_resolution_failed` (+ resolver `code`) |
| vmlinux ELF build-id unreadable (non-ELF/compressed/stripped/truncated) | `CONFIGURATION_ERROR` | `vmlinux_build_id_unreadable` |
| unknown helper / bad helper args | `CONFIGURATION_ERROR` | `unknown_helper` / `helper_args_invalid` |
| wrapper render error | `INFRASTRUCTURE_FAILURE` | `wrapper_render_error` |
| drgn cannot open vmcore / load vmlinux | `INFRASTRUCTURE_FAILURE` | `drgn_open_failure` |
| drgn lacks `main_module().build_id` (too old) | `INFRASTRUCTURE_FAILURE` | `drgn_version_skew` |
| vmcore carries no embedded build-id (cannot verify) | `CONFIGURATION_ERROR` | `provenance_unverifiable` |
| **vmcore build_id ≠ vmlinux build_id** | `CONFIGURATION_ERROR` | `provenance_mismatch` |
| user script syntax error | `CONFIGURATION_ERROR` | `script_compile_error` |
| timeout / oversized / unparseable wrapper output | `INFRASTRUCTURE_FAILURE` | `introspect_timeout` / `oversized_output` / `wrapper_crash` |
| user script raised | success, `status=script_error` | — |
| module bundle present (loaded / empty / drgn-rejected) | success + `warnings[]` | `modules_debuginfo_loaded` / `modules_debuginfo_empty` / `modules_debuginfo_load_failed` (all non-fatal) |
| helper schema drift / helper script raised | `INFRASTRUCTURE_FAILURE` | `helper_schema_drift` / `helper_script_error` |

`provenance_unverifiable` (core has no embedded build-id) is `CONFIGURATION_ERROR`
because the agent can fix it by capturing a core from a `CONFIG_BUILD_ID`-bearing
kernel; it is distinct from `provenance_mismatch` so the agent does not waste effort
hunting for a "matching" vmlinux that can never satisfy a missing key.

`provenance_mismatch` is `CONFIGURATION_ERROR` (the caller paired the wrong vmlinux
with the vmcore — a fixable input error), matching the live path's classification
of the same outcome.

## 9. Concurrency (§5.6 rule 3)

No admission handle, no `StopCapableGuard`, no console lease, no target snapshot
read. Two `from_vmcore` calls against the same run proceed in parallel; a call
proceeds whether the run's target is `READY`, `HALTED`, `CRASHED`, reclaimed, or
never booted. The only shared mutable state is the manifest, written through the
existing `_record_terminal_introspect_result` flock-retry (each call appends a
unique `introspect:<call_id>` step). The call-budget read-then-write is not
serialised across concurrent calls — the budget is a soft cap (a race may admit a
couple over the limit); this matches the live path's identical non-atomic check and
is acceptable for a soft resource ceiling.

**Resource posture (intentionally unbounded, stated explicitly).** "Concurrent-safe"
here means *free of state corruption* — it does **not** mean resource-bounded. The
live path's admission gate incidentally serialised drgn against a target; the vmcore
path has no such gate and adds **no** concurrency cap. Each in-flight call spawns one
`python3`+drgn process whose resident memory is dominated by the mapped vmcore (often
multi-GB) plus the vmlinux DWARF; K parallel calls cost ≈ K× that. `MAX_INTROSPECT_CALLS_PER_RUN`
bounds the per-run *lifetime* total, not in-flight parallelism. This server is
**local, single-agent**: the sole caller controls its own fan-out, so the only party
that can exhaust host memory with parallel vmcore loads is the agent driving the
server — there is no second tenant to protect. A cross-call host-wide concurrency
semaphore is therefore **deliberately not added** (it would introduce shared
cross-call state, a new `readiness_failure`/queueing contract, and a tuning knob for
a multi-tenant scenario that does not exist today — "no speculative features"). The
cost is documented here so the agent can self-limit; if a concrete multi-tenant or
shared-host deployment appears, a bounded semaphore is the follow-on (it composes
cleanly because the path already has no other gate to reconcile with).

## 10. Allowlist & capability changes

- `config.py`: add `"debug.introspect.from_vmcore"` and
  `"debug.introspect.from_vmcore_helper"` to `ALLOWED_DEBUG_OPERATIONS`.
- `local_drgn_introspect_capability()`: append both operations to `operations`.
  The capability's `semantics` already advertises the live `concurrent_safe=False`;
  because per-operation overrides exist (`operation_capabilities`), the two vmcore
  operations get a per-op `OperationSemantics(concurrent_safe=True, ...)` override so
  `providers.list` advertises the §5.6-rule-3 property truthfully. `required_host_tools`
  for the vmcore ops is `["python3"]` with drgn importable on the host (SSH is not
  required); the live ops keep `["ssh"]`.

## 11. Deferred: remote vmcore retrieval

Pulling a vmcore from a remote host to the agent is out of scope. A vmcore must
already exist as a file under the run directory (staged by kdump capture #14, or
copied in manually). This spec documents the limitation rather than implementing a
fetch; the run-relative confinement (§3.1) is the enforcement point.

## 12. Testing strategy

Handler tests instantiate handlers directly with injected fakes (`runner=`,
`build_id_reader=`), per repo convention. No real drgn/vmcore in unit tests.

- `read_elf_build_id`: valid ELFCLASS32/64 little/big-endian; note absent;
  truncated; non-ELF magic; build-id in `.note.gnu.build-id` section vs PT_NOTE.
- Wrapper render: byte-identical recomposed live `WRAPPER_TEMPLATE` against a
  golden snapshot of the pre-refactor template (proves the live path is unchanged);
  vmcore wrapper substitutes all placeholders; a path byte-sequence that is not
  valid UTF-8 (or otherwise fails to round-trip through base64-decode) is rejected;
  an injection-shaped path (`x".__import__('os')...`) round-trips intact through
  base64 and produces a literal-safe wrapper (proving the base64 control, finding 1);
  bad `expected_build_id`/`call_id` rejected.
- **Finalizer/shared-body regression (NOT a live-equivalence proof):** a fake runner
  returning a wrapper-shaped JSON document with matching build_id → `ToolResponse.success`,
  `introspect:<call_id>` SUCCEEDED, `stdout.json` redacted, raw files under
  `sensitive/`. Because the live and vmcore paths share `_WRAPPER_BODY` and
  `_finalize_introspect_call`, feeding both the *same* canned payload yields
  identical output by construction — this test proves the shared tail is wired in
  both, it does **not** prove a real vmcore run matches a real live run (see AC#1
  note below).
- Build_id mismatch: fake runner returns `outcome=provenance_mismatch` (wrapper
  self-abort) **and** a separate test where the wrapper reports `ok` with a
  build_id ≠ `read_elf_build_id` (host verify catches it) → `provenance_mismatch`,
  no symbols trusted (AC#2). Plus `provenance_unverifiable` when the wrapper
  reports `build_id=None`.
- Lifecycle independence: handler succeeds with **no** boot step / no snapshot /
  no admission service injected (AC#3) — proving the gate is not in the path.
- Redaction: a secret-shaped token in `user_stdout`/`stderr` is masked in the
  response and in the persisted `stdout.json`/`stderr.log` (AC#4).
- Edges: missing run; missing vmcore; escaping vmcore/vmlinux ref;
  `vmlinux_build_id_unreadable` (non-ELF and compressed fixtures); oversized
  script; bad timeout; budget exhausted; sensitive-dir too permissive; runner
  timeout (`exit 124`); unparseable stdout; `drgn_open_failure`;
  `drgn_version_skew`; corrupt-modules → non-fatal `modules_debuginfo_load_failed`
  warning; unknown helper; bad helper args; helper schema drift.
- Live-path regression: the full existing `test_introspect_run`/`helper` suites
  must stay green after the finalizer extraction.

**AC#1 real-equivalence is verified only by the env-gated integration test** (not
by the merge gate): `test_from_vmcore_matches_live` runs a fixed drgn script first
via `debug.introspect.run` against a live booted target and then via
`debug.introspect.from_vmcore` against a vmcore captured from that same kernel, and
asserts the two `emits` payloads are equal. It is gated on `LDM_VMCORE` (a path to a
captured core + matching vmlinux) and a host `import drgn`, and is skipped in CI
exactly like the libvirt/gdb suites. The unit tests above cannot substantiate AC#1
because they share the code under test on both sides.

## 13. Acceptance-criteria mapping

| Issue AC | Where satisfied |
|---|---|
| vmcore + matching vmlinux ⇒ JSON equivalent to live `run` | §4.1 shared body, §6; verified by the **env-gated** `test_from_vmcore_matches_live` integration test (§12) — the unit tests are a shared-tail regression check, not an equivalence proof |
| build_id mismatch fails loud (§4.2) | §4.2 prologue check before load + §7 host verify; §8 `provenance_mismatch`; §12 two mismatch tests |
| unaffected by target lifecycle (no gate in path) | §3.1, §3.2, §6 (no admission), §9; §12 lifecycle-independence test |
| persisted artifacts go through `Redactor` | §6, §7; §12 redaction test |
