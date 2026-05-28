# `debug.introspect.run` — live SSH drgn runner (foundation)

**Date:** 2026-05-28
**Issue:** #51
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #11
**Status:** Draft — pending user review
**Implementation depends on:** ssh-live admission seam from #10 (already merged, in `coordination/admission.py`); minimal `KernelProvenance.build_id` recording (this spec, §7)

## 1. Background and scope

`linux-debug-mcp` is local-only today and exposes one debug surface — `debug.start_session` over QEMU's gdbstub (stop-the-world RSP). Epic #9 introduces a tiered debug model where the default tier is structured, non-stopping, agent-friendly: `drgn` over SSH, scripted, JSON out. This spec covers the smallest unit of that tier — `debug.introspect.run` — and intentionally leaves curated helpers (#54), vmcore execution (#55), prereq probing (#52), full `KernelProvenance` resolution (#53), and write-mode opt-in (#56) to their own issues so each can ship as a focused PR.

### In scope

- The `debug.introspect.run(target_ref, script, timeout_seconds, allow_write=false)` MCP tool.
- A new `LocalDrgnIntrospectProvider` capability that owns the on-target invocation.
- The on-target Python wrapper (drgn-as-library) and its JSON output contract.
- Host-side runner: SSH transport reuse, defense-in-depth timeout, cancellation bridged to `AdmissionService`, structured result parsing.
- Manifest integration: per-call `StepResult` named `introspect:<call_id>`, artifact dir under `<run>/debug/introspect/<call_id>/`.
- Minimal `KernelProvenance` plumbing: the build handler records `build_id` extracted from `vmlinux`; the introspect handler compares it against the live target.
- Renaming `SPRINT_4_DEBUG_OPERATIONS` → `ALLOWED_DEBUG_OPERATIONS` and adding `debug.introspect.run` to it.

### Out of scope

| Concern | Where it lives |
|---|---|
| Curated drgn helper library (`sysinfo`/`tasks`/`dmesg`/`modules`/`slab`/`irq`) | #54 |
| `debug.introspect.from_vmcore` offline execution | #55 |
| Target-side drgn / debuginfo prerequisite probe | #52 |
| Full `KernelProvenance` resolution + module debuginfo locator | #53 |
| `allow_write=true` enforcement (AST guard / sandboxed globals) | #56 |
| Capturing vmcores (kdump/crash) | #14 |

## 2. Architecture overview

```
agent ──MCP──▶ debug.introspect.run handler ──▶ AdmissionService.admit_ssh_tier
                            │                            │
                            ▼                            ▼
              render wrapper.py from template     handle (cancel fence)
                            │                            │
                            ▼                            │
              SshRunner.run(ssh ... 'timeout(1) sudo python3 -' )
                            │       │                    │
                            │       └─── stdin: wrapper  │
                            │                            │
                            ▼                            │
                   target Python:                        │
                     import drgn                         │
                     prog.set_kernel()                   │
                     load_default_debug_info()           │
                     check build_id ──┐                  │
                     exec user script │                  │
                     emit() → buffer  │                  │
                     print(JSON)      │                  │
                            │         │                  │
                            ▼         ▼                  │
              host parses stdout      exit code          │
                            │                            │
                            ▼                            ▼
              Redactor → result.json    admission.complete(handle)
                            │
                            ▼
              StepResult into manifest, ToolResponse to agent
```

Three components are new:

1. **Tool handler** `debug_introspect_run_handler` in `server.py`.
2. **Provider** `LocalDrgnIntrospectProvider` in `providers/local_drgn_introspect.py` advertising the `local-drgn-introspect` capability with operation `debug.introspect.run`.
3. **Wrapper template** rendered per call and sent to the target on SSH stdin.

Everything else reuses existing seams: `SshRunner` (from `local-ssh-tests`), `AdmissionService.admit_ssh_tier`, `probe_execution_state`, `Redactor`, `ArtifactStore`, the `DebugProfile.enabled_operations` gate.

## 3. Tool surface

### 3.1 Request

```python
class DebugIntrospectRunRequest(Model):           # extra="forbid"
    run_id: str                                    # validate_run_id
    target_ref: str                                # target profile name
    script: str                                    # user drgn script source
    timeout_seconds: int = 30                      # min 5, max 300
    allow_write: bool = False                      # rejected if True (#56)
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
```

No `call_id` in the request — the server mints a UUIDv4 and returns it. Decision rationale: each call is a fresh leaf op, not a workflow phase; idempotency-by-replay adds API surface without solving a real use case at v0.

The user `script` is transferred as base64-encoded UTF-8 via a single `string.Template` substitution into an ASCII string literal in the wrapper (see §4.2). No other templated values (`${EXPECTED_BUILD_ID}`, `${CALL_ID}`) contain user-controlled data; `EXPECTED_BUILD_ID` is hex from `manifest.steps["build"].details["build_id"]` and `CALL_ID` is a server-minted UUIDv4. Substitution uses `string.Template(...).substitute(...)` (strict; unknown keys raise) — not `safe_substitute`. This eliminates the wrapper template-injection class: a script body containing `"""`, `${...}`, NUL bytes, or arbitrary binary cannot escape its enclosing literal because the literal only ever holds `[A-Za-z0-9+/=]`.

### 3.2 Response (success path)

```python
ToolResponse.success({
  "call_id": "<uuid4-hex>",
  "status": "ok" | "script_error",      # "script_error" = wrapper ran, user script raised
  "outcome": {
    "status": "ok" | "error",
    "error_type": "...",                # only when error
    "error_message": "...",             # redacted, truncated to 4096 chars
    "traceback": "...",                 # redacted, truncated to CAPS["traceback"]
  },
  "emits": [...],                       # parsed JSON objects from emit() calls
  "user_stdout_snippet": "...",         # redacted, head 2 KiB + tail 2 KiB
  "drgn_stderr_snippet": "...",         # redacted, head 2 KiB + tail 2 KiB
  "build_id": "<hex>",                  # reported by the wrapper
  "truncated": {
    "emits": bool,           # >= CAPS["emits"] entries — overflow flag
    "user_stdout": bool,     # user_stdout truncated to CAPS["user_stdout"] OR cleared
                             # because the total_json fallback fired
    "traceback": bool,       # traceback truncated to CAPS["traceback"]
    "total_json": bool,      # serialized result exceeded CAPS["total_json"];
                             # tail-emits were dropped to fit
    "per_emit_size": bool,   # at least one emit exceeded CAPS["per_emit_bytes"]
                             # and was replaced with an __emit_oversized__ placeholder
  },
  "started_at": "...", "finished_at": "...", "duration_ms": int,
  "prelude_ms": int,                    # drgn open + debuginfo load time, separate from script execution
  "artifacts": [ArtifactRef, ...],      # request.json, wrapper.py, stdout.json, stderr.log, result.json
  "suggested_next_actions": ["artifacts.get_manifest", "debug.introspect.run"],
})
```

A script that raised an exception at runtime returns `status: "script_error"` at the response level but is still `ToolResponse.success(...)` — the call mechanically succeeded; the user's script didn't. This matches how `target.run_tests` reports per-command failures inside a successful step.

An `emits` entry of the form `{"__emit_unserializable__": true, "error_type": "...", "error_message": "...", "repr": "..."}` indicates the user script called `emit()` with a non-JSON-serializable object; `error_message` is truncated to 512 bytes and `repr` is truncated to 512 bytes. An entry of the form `{"__emit_oversized__": true, "size_bytes": int, "cap_bytes": int, "head": "..."}` indicates the user script called `emit()` with an object whose JSON encoding exceeded `CAPS["per_emit_bytes"]` (32 KiB); `head` is the first 1 KiB of the encoded form. In both cases the wrapper does not raise from `emit()` — a bad call inserts a placeholder and the script keeps running.

### 3.3 Response (failure paths)

| Failure | `ErrorCategory` | `code` | Surfacing |
|---|---|---|---|
| `allow_write=true` | `CONFIGURATION_ERROR` | `allow_write_not_supported` | Pre-SSH |
| `script` empty / oversize / non-string | `CONFIGURATION_ERROR` | `invalid_script` | Pre-SSH |
| `timeout_seconds` outside `[5, 300]` | `CONFIGURATION_ERROR` | `invalid_timeout` | Pre-SSH |
| Operation disabled in `DebugProfile.enabled_operations` | `CONFIGURATION_ERROR` | `operation_disabled` | Pre-SSH |
| `manifest.steps["build"].details["build_id"]` missing | `CONFIGURATION_ERROR` | `provenance_missing` | Pre-SSH |
| Manifest absent or run_id invalid | `CONFIGURATION_ERROR` | (existing path-safety codes) | Pre-SSH |
| `sudo -n true` preflight fails (sudo wants a password) | `CONFIGURATION_ERROR` | `sudo_requires_password` | Pre-SSH (preflight, §5.2 step 7a) |
| Target snapshot absent / not READY/EXECUTING | `READINESS_FAILURE` | `target_not_ready` | Pre-admission |
| Target `HALTED` (admission rejects) | `READINESS_FAILURE` | `target_halted` | Admission |
| `ExecutionProof` stale / `UNKNOWN` | `READINESS_FAILURE` | `execution_state_unknown` | Admission |
| Stale handle / wrong generation | `STALE_HANDLE` | `stale_handle` | Admission |
| Admission cancel during call (halt mid-flight) | `READINESS_FAILURE` | `execution_state_changed` | `admission.complete` |
| SSH connect / auth failure | `INFRASTRUCTURE_FAILURE` | `ssh_failure` | SSH |
| Wrapper exit 3 (drgn import / open failed) | `INFRASTRUCTURE_FAILURE` | `drgn_open_failure` | Wrapper |
| Wrapper exit 4 (`build_id` mismatch) | `CONFIGURATION_ERROR` | `provenance_mismatch` | Wrapper |
| Wrapper exit 5 (script `compile()` error) | `CONFIGURATION_ERROR` | `script_compile_error` | Wrapper |
| Wrapper exit 124 (target-side `timeout(1)` fired) | `INFRASTRUCTURE_FAILURE` | `introspect_timeout` | Wrapper |
| Wrapper exited normally but no/invalid JSON | `INFRASTRUCTURE_FAILURE` | `wrapper_crash` | Host parse |
| Host-side `SshRunner.timed_out` (network hang past margin) | `INFRASTRUCTURE_FAILURE` | `ssh_timeout` | SSH |
| Build vmlinux has no `.note.gnu.build-id` | `BUILD_FAILURE` | `build_id_missing` | Build (kernel.build, §7) |
| `readelf` unavailable / errored extracting build_id | `INFRASTRUCTURE_FAILURE` | `readelf_unavailable` | Build (kernel.build, §7) |

No new `ErrorCategory` enum values are introduced; existing categories cover every failure mode. `code` strings carry the introspect-specific distinctions. The last two rows fire from the `kernel.build` handler before any `debug.introspect.run` call is possible — they're listed here because the introspect contract requires `build_id` and operators need to see the failure mode in one place.

### 3.4 Allowlist

`SPRINT_4_DEBUG_OPERATIONS` in `config.py` is renamed to `ALLOWED_DEBUG_OPERATIONS` in this change. The historical sprint name becomes misleading once `debug.introspect.run` lands on top of it. `_ensure_debug_operation_enabled` is updated to read the new constant. `DebugProfile.enabled_operations` validation is unaffected — it just compares to the renamed constant.

The new operation `debug.introspect.run` is appended to `ALLOWED_DEBUG_OPERATIONS` and to the default `DebugProfile.enabled_operations`.

### 3.5 `allow_write` semantics and current enforcement

`allow_write=false` is the default and is the only value accepted in #51. `allow_write=true` is rejected at the handler with `CONFIGURATION_ERROR` / `allow_write_not_supported`. **The flag does NOT sandbox the user script.** Even with `allow_write=false`, the script runs via `exec()` with the full Python builtins and can `import os`, `import ctypes`, open arbitrary files on the target, etc. The blast radius is equivalent to `ssh <user>@<host> sudo python3 -c <script>`. AST-based write detection and a restricted-builtins namespace are out of scope and live in #56. Treat `allow_write` as an opt-in for *future* write-mutating helpers, not as a current security boundary.

## 4. On-target wrapper

### 4.1 Invocation

The host invokes:

```
ssh <ssh_args> <user>@<host> -- 'timeout --kill-after=2s <user_timeout>s sudo python3 -'
```

with the rendered wrapper piped on stdin. `<user>` and `<ssh_args>` come from `rootfs_profile` exactly as `LocalSshTestProvider` resolves them. `sudo` is used because drgn needs `/proc/kcore` access; if `ssh_user` is already root it is a no-op. Passwordless sudo is a documented prerequisite (the smoke-tests path makes the same assumption).

### 4.2 Wrapper template

Sketch (final form lives in `providers/local_drgn_introspect.py`):

```python
import sys, json, io, traceback, contextlib

CAPS = {"emits": 100, "user_stdout": 256 * 1024, "traceback": 16 * 1024,
        "total_json": 1 * 1024 * 1024, "per_emit_bytes": 32 * 1024}

def _truncate(s, cap):
    return (s[:cap], True) if len(s) > cap else (s, False)

result = {"call_id": "${CALL_ID}", "build_id": None, "outcome": None,
          "emits": [], "user_stdout": "",
          "truncated": {"emits": False, "user_stdout": False,
                        "traceback": False, "total_json": False,
                        "per_emit_size": False}}

import time
_t_prelude_start = time.monotonic()

try:
    # `drgn` is imported first so it predates the helper snapshot; the wildcard
    # import below is what we want to capture, and `drgn` itself is injected
    # explicitly into the user namespace further down.
    import drgn  # noqa: E402  -- module attribute, exposed to user namespace

    _pre_helpers = set(globals().keys())
    from drgn.helpers.linux import *  # noqa: F401,F403,E402
    _drgn_helper_names = set(globals().keys()) - _pre_helpers

    prog = drgn.Program()
    prog.set_kernel()
    prog.load_default_debug_info()
except Exception as exc:
    result["outcome"] = {"status": "drgn_open_failure",
                         "error_type": type(exc).__name__,
                         "error_message": str(exc)}
    json.dump(result, sys.stdout); sys.exit(3)

result["prelude_ms"] = int((time.monotonic() - _t_prelude_start) * 1000)

result["build_id"] = prog.main_module().build_id.hex()
if "${EXPECTED_BUILD_ID}" and result["build_id"] != "${EXPECTED_BUILD_ID}":
    result["outcome"] = {"status": "provenance_mismatch",
                         "expected": "${EXPECTED_BUILD_ID}",
                         "actual": result["build_id"]}
    json.dump(result, sys.stdout); sys.exit(4)

emit_buffer = []
emit_overflow = False

def emit(obj):
    global emit_overflow
    if len(emit_buffer) >= CAPS["emits"]:
        emit_overflow = True
        return
    try:
        # Validate JSON-serializability up front so the final json.dumps
        # can never fail. Reject by recording a placeholder, not by raising,
        # so a bad emit doesn't tear down the rest of the script.
        encoded = json.dumps(obj)
    except (TypeError, ValueError) as exc:
        emit_buffer.append({
            "__emit_unserializable__": True,
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:512],
            "repr": repr(obj)[:512],
        })
        return
    if len(encoded) > CAPS["per_emit_bytes"]:
        result["truncated"]["per_emit_size"] = True
        emit_buffer.append({
            "__emit_oversized__": True,
            "size_bytes": len(encoded),
            "cap_bytes": CAPS["per_emit_bytes"],
            "head": encoded[:1024],
        })
        return
    emit_buffer.append(obj)

user_stdout = io.StringIO()
# Snapshot globals immediately before the wildcard import; everything that
# appears after is a drgn helper. `drgn` itself is injected explicitly here
# (it predates the snapshot) so user scripts can do `drgn.Object(...)` etc.
namespace = {
    "prog": prog, "emit": emit, "drgn": drgn,
    "__name__": "__introspect__", "__builtins__": __builtins__,
}
for name in _drgn_helper_names:
    namespace[name] = globals()[name]

import base64
USER_SCRIPT_B64 = "${USER_SCRIPT_B64}"   # host substitutes a pure-ASCII base64 blob
try:
    compiled = compile(
        base64.b64decode(USER_SCRIPT_B64).decode("utf-8"),
        "<introspect>", "exec",
    )
except SyntaxError as exc:
    result["outcome"] = {"status": "script_compile_error",
                         "error_type": "SyntaxError",
                         "error_message": str(exc)}
    json.dump(result, sys.stdout); sys.exit(5)

with contextlib.redirect_stdout(user_stdout):
    try:
        exec(compiled, namespace)
        result["outcome"] = {"status": "ok"}
    except Exception as exc:
        tb, tb_trunc = _truncate(traceback.format_exc(), CAPS["traceback"])
        result["outcome"] = {"status": "error",
                             "error_type": type(exc).__name__,
                             "error_message": str(exc), "traceback": tb}
        result["truncated"]["traceback"] = tb_trunc

result["emits"] = emit_buffer
result["truncated"]["emits"] = emit_overflow
out, trunc = _truncate(user_stdout.getvalue(), CAPS["user_stdout"])
result["user_stdout"] = out
result["truncated"]["user_stdout"] = trunc

payload = json.dumps(result)
while len(payload) > CAPS["total_json"] and result["emits"]:
    result["emits"].pop()              # drop from the tail until under cap
    result["truncated"]["total_json"] = True
    payload = json.dumps(result)
# If still over cap after emits exhausted, clear user_stdout as the final
# fallback (header fields + outcome + truncation flags are kept).
if len(payload) > CAPS["total_json"]:
    result["user_stdout"] = ""
    result["truncated"]["user_stdout"] = True
    payload = json.dumps(result)
sys.stdout.write(payload)
sys.exit(0)
```

### 4.3 Exit-code contract

| Exit | Meaning | Host maps to |
|---|---|---|
| 0 | Wrapper ran; check `outcome.status` in JSON | `status="ok"` or `status="script_error"` depending on `outcome.status` |
| 3 | drgn import / `set_kernel` / `load_default_debug_info` failed | `INFRASTRUCTURE_FAILURE` / `drgn_open_failure` |
| 4 | `build_id` mismatch | `CONFIGURATION_ERROR` / `provenance_mismatch` |
| 5 | User script failed `compile()` | `CONFIGURATION_ERROR` / `script_compile_error` |
| 124 | `timeout(1)` fired before wrapper exited | `INFRASTRUCTURE_FAILURE` / `introspect_timeout` |
| other / no JSON | `INFRASTRUCTURE_FAILURE` / `wrapper_crash` — raw stderr persisted |

## 5. Host-side runner

### 5.1 Handler signature

```python
def debug_introspect_run_handler(
    request: DebugIntrospectRunRequest,
    *,
    artifact_root: Path,
    target_profiles: dict[str, TargetProfile],
    rootfs_profiles: dict[str, RootfsProfile],
    debug_profiles: dict[str, DebugProfile],
    provider: LocalDrgnIntrospectProvider | None = None,
    ssh_runner: SshRunner | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ToolResponse:
```

`provider`/`ssh_runner`/`admission`/`session_registry` are injected for tests, matching the rest of `server.py`.

### 5.2 Step-by-step flow

1. **Profile resolution + path validation.** Mirror `target_run_tests_handler`: resolve `target_profile`/`rootfs_profile`/`debug_profile` from request overrides + recorded manifest defaults; `validate_run_id`; load `manifest.json`.
2. **Operation gating.** `_ensure_debug_operation_enabled(resolved_debug_profile, "debug.introspect.run")`.
3. **Request invariants.** Reject `allow_write=true`. Validate `timeout_seconds in [5, 300]`. Validate `script` non-empty, ≤ 256 KiB.
4. **Build_id from manifest.** Read `manifest.steps["build"].details["build_id"]`. Missing → `CONFIGURATION_ERROR` / `provenance_missing`. This is the minimal `KernelProvenance` consumer (§7).
5. **Mint `call_id`.** `uuid4().hex`. Create `<run>/debug/introspect/<call_id>/`. Persist redacted `request.json`.
6. **Admission gate.**
   ```python
   snapshot = admission.current_snapshot(target_key)
   proof = probe_execution_state(...)            # the same probe run_tests uses
   handle = admission.admit_ssh_tier(
       target_key, snapshot.generation, snapshot.platform,
       lease=snapshot.lease, execution_proof=proof,
   )
   ```
   Admission errors map per the §3.3 table.
7. **Render wrapper.** Substitute `${USER_SCRIPT_B64}` (the user script base64-encoded as a pure-ASCII blob per §3.1), `${EXPECTED_BUILD_ID}`, and `${CALL_ID}` into the template via `string.Template(...).substitute(...)` (strict). Persist as `<call_id>/wrapper.py`.
7a. **Sudo preflight** (only when `ssh_user != "root"`). Run `ssh <ssh_args> <user>@<host> -- 'sudo -n true'` with a 5-second host timeout. Non-zero exit → `CONFIGURATION_ERROR` / `sudo_requires_password`, diagnostic includes the first 256 bytes of the probe's stderr (typically `"sudo: a password is required"`). The probe is cheap, deterministic, and turns a 30-second `ssh_timeout` into a sub-second actionable error. Skipped when `ssh_user == "root"` because there is no sudo round trip on the hot path either.
8. **SSH invocation.** Reuse `SshRunner`:
   ```
   ssh <ssh_args> <user>@<host> 'timeout --kill-after=2s <user_timeout>s sudo python3 -'
   ```
   stdin = wrapper string. Host-side `SshRunner.run(..., timeout=user_timeout + 10, cancel=cancel_event, stdout_path=stdout_path, stderr_path=stderr_path)`.
9. **Cancellation bridge** — verbatim from `_run_admitted` in `target.run_tests`:
   ```python
   cancel_event = threading.Event()
   stop_watcher = threading.Event()
   def watcher():
       while not stop_watcher.is_set():
           if handle.wait_cancelled(0.1):
               cancel_event.set(); return
   thread = threading.Thread(target=watcher, daemon=True); thread.start()
   try:
       result = ssh_runner.run(argv, ...)
       admission.complete(handle)   # raises AdmissionError if call spanned halt
   finally:
       stop_watcher.set(); thread.join()
   ```
   `admission.complete` raising `execution_state_changed` → discard the result; failure response.
10. **Result parsing.** Per the exit-code contract.
11. **Host-side post-processing.** Redact all variable-length strings with the same `Redactor` configuration `LocalSshTestProvider` uses (`secret_values=[rootfs_profile.ssh_key_ref]`). Persist `result.json`. Build `ArtifactRef`s.
12. **Manifest record.** Open `ArtifactStore._manifest_lock()` in exclusive mode. Re-read the manifest under the lock. If `step_results[f"introspect:{call_id}"]` already exists, fail with `INFRASTRUCTURE_FAILURE` / `call_id_collision` (UUIDv4 collision — should never happen). Otherwise call the new `ArtifactStore.append_step_result(step_result)` method, which (a) appends to the `steps` list, (b) sets `step_results[name] = step_result`, and (c) atomically rewrites `manifest.json` via `tmp + rename`. The existing `with_step_result()` path remains for replace-on-`force_*` semantics on the named-singleton steps (`build`, `boot`, `run_tests`, `debug`). The same retry-with-backoff posture as `_record_terminal_build_result` applies if the lock is transiently unavailable.
13. **Return** `ToolResponse.success(...)` per §3.2.

### 5.3 Concurrency

No introspect-level lock is required for ordering across calls — the manifest is serialized through `ArtifactStore._manifest_lock()` (§5.2 step 12) and `call_id` is a fresh UUIDv4 per call, so two concurrent introspect calls serialize cleanly at the manifest layer. `AdmissionService.admit_ssh_tier` permits concurrent ssh-tier ops on an `EXECUTING` target (interface-contracts §5.6 rule 2), so the SSH calls themselves race naturally — each one a separate admitted op, each one cancelled on halt. drgn-live concurrent reads of `/proc/kcore` are racy by design and acceptable.

## 6. Manifest and artifacts

### 6.1 Artifact directory layout

```
<run>/
  debug/
    introspect/
      <call_id>/
        request.json     # redacted DebugIntrospectRunRequest
        wrapper.py       # rendered wrapper sent to the target
        stdout.json      # parsed-then-redacted-then-reserialized wrapper JSON;
                         # remains valid JSON. The raw wire bytes are NOT persisted.
        stderr.log       # SSH stderr after text-mode Redactor; secrets removed,
                         # structure (line-oriented) preserved.
        result.json      # normalized, redacted result returned to the caller
```

`request.json` and `wrapper.py` are written before SSH invocation. `stderr.log` is streamed to disk during the call as raw bytes, then rewritten in-place under the manifest lock with the text-mode `Redactor` applied (see §6.3). `stdout.json` is **not** streamed verbatim: SSH stdout is captured to a temporary path during the call, the host then parses it as JSON, passes the parsed structure through `Redactor.redact_value`, and persists the result via `json.dumps` to `stdout.json`. On a wrapper crash where stdout is not valid JSON, the temporary capture is moved to `stdout.raw` instead and `stdout.json` is absent for that call. `result.json` is written after the host finishes post-processing. The first two are present on every call; later files are present whenever the call reached SSH.

### 6.2 Step record

```python
StepResult(
  name=f"introspect:{call_id}",
  status=StepStatus.SUCCEEDED | FAILED,
  started_at=..., finished_at=...,
  artifacts=[ArtifactRef("request.json", ...),
             ArtifactRef("wrapper.py", ...),
             ArtifactRef("stdout.json", ...),
             ArtifactRef("stderr.log", ...),
             ArtifactRef("result.json", ...)],
  error_category=None | ErrorCategory.X,
  diagnostic=None | "<short redacted summary>",
  details={
    "call_id": call_id, "build_id": "...",
    "timeout_seconds": 30, "wrapper_exit_code": 0,
    "duration_ms": 142, "prelude_ms": 35, "truncated": {...},
    "ssh_user": "root", "outcome_status": "ok"|"error"|"drgn_open_failure"|...,
  },
)
```

Manifest grows linearly with introspect-call count. No pruning in #51.

### 6.3 Redaction policy

Identical to `LocalSshTestProvider`:

```python
redactor = Redactor(secret_values=[rootfs_profile.ssh_key_ref]
                    if rootfs_profile.ssh_key_ref else [])
```

Applied to:
- `outcome.error_message`, `outcome.traceback`
- Each string inside `emits` entries (recursive walk via `redactor.redact_value`)
- `user_stdout_snippet`, `drgn_stderr_snippet`
- Every response-level diagnostic string
- The persisted `stdout.json` and `stderr.log` (not only the in-response snippets — the artifact files are part of the manifest's referenced surface, and the contract is that secrets never reach the manifest)
- `request.json`'s `script` field (in case a credential was pasted in)

Mechanism per file:

- **`stdout.json`** is persisted as `json.dumps(redactor.redact_value(parsed))`, where `parsed` is the wrapper's JSON document loaded via `json.loads(raw_stdout_bytes)`. `Redactor.redact_value` walks dicts/lists/tuples recursively and redacts every string node it encounters, so secrets that appear inside `emits` payloads or `outcome.error_message` are scrubbed before persistence. The raw wire bytes are never written to the manifest path. If `json.loads` raises (`wrapper_crash` path), the raw stdout capture is moved to `stdout.raw` instead and `stdout.json` is absent for that call — the raw file goes through the text-mode redactor before its `ArtifactRef` is finalized.
- **`stderr.log`** is persisted as `redactor.redact_text(raw_stderr_bytes.decode("utf-8", errors="replace"))`. Line-oriented structure is preserved so that drgn diagnostics remain greppable.
- **`result.json`** is the post-redaction response object; nothing additional is applied at write time.
- **`request.json`** is the redacted `DebugIntrospectRunRequest` (notably, `script` is run through `redactor.redact_text`).
- **`wrapper.py`** is the rendered wrapper as sent on stdin. It contains the base64 of the user script but no plaintext secrets — `request.json`'s redactor pass is the canonical place where secrets get scrubbed from the script body.

Not applied to: file paths inside `ArtifactRef`, `build_id` (opaque hex), structural booleans/ints/UUIDs.

## 7. Build-handler change (minimal `KernelProvenance` consumer)

The introspect handler needs an authoritative expected `build_id` to compare against. The full `KernelProvenance` schema and the module-debuginfo locator live in #53; #51 needs only the build_id.

Changes inside `providers/local_kernel_build.py`:

1. After a successful kernel build, run `readelf -n <vmlinux>` (already a host prerequisite — ships with binutils) and parse the `.note.gnu.build-id` note:

   ```python
   def _extract_build_id(vmlinux: Path) -> str | None:
       proc = subprocess.run(
           ["readelf", "-n", str(vmlinux)],
           capture_output=True, text=True, check=False, timeout=10,
       )
       if proc.returncode != 0:
           return None
       for line in proc.stdout.splitlines():
           m = re.match(r"\s*Build ID:\s*([0-9a-fA-F]+)", line)
           if m:
               return m.group(1).lower()
       return None
   ```

2. Persist `build_id` into `build_result.details["build_id"]`. If `_extract_build_id` returns `None`, classify by cause and fail the build step:
   - `readelf` returned non-zero or timed out → `INFRASTRUCTURE_FAILURE` / `readelf_unavailable`, build step recorded as `FAILED`.
   - `readelf` exited 0 but no `Build ID:` was found → `BUILD_FAILURE` / `build_id_missing`, build step recorded as `FAILED`. (A kernel built without `--build-id` cannot satisfy the introspect provenance contract, so a "successful" build here would be a contract violation. Operators that need to opt out of this check should rebuild with `LD_BUILD_ID=sha1` or equivalent.)

No boot-handler changes — the build_id is a property of the compiled kernel, not the boot.

Legacy runs whose build step pre-dates this change have no recorded `build_id`. The introspect handler treats that as `CONFIGURATION_ERROR` / `provenance_missing`. Recovery is to re-run `kernel.build` *with the new extractor in place*; if that build is also missing a `Build ID`, the build fails per the rule above and the operator must rebuild with `LD_BUILD_ID=sha1` (or equivalent) before introspect is usable.

## 8. Decisions and rejected alternatives

These were settled during the brainstorming dialogue. Recording them here so they're not re-litigated.

### 8.1 Execution model: drgn-as-library + Python wrapper

**Decision:** ship a Python wrapper that `import drgn`s and runs the user script via `exec()` with `prog` and `emit` injected. Single SSH round trip; one clean JSON document on stdout.

**Considered & rejected:**
- *Subprocess `drgn /dev/stdin` + nonced sentinel markers on stdout.* Simpler to scaffold, but framing depends on a per-call nonce surviving user prints — fragile, no robustness benefit over the library approach.
- *Subprocess `drgn /dev/stdin` + dedicated fd 3 to a target tempfile.* Cleanest separation but requires two SSH round trips per call and leaves target-side filesystem state to clean up. The library approach achieves the same separation in one round trip.

### 8.2 Timeout enforcement: both layers

**Decision:** target-side `timeout --kill-after=2s <user_timeout>s` wraps the Python wrapper; host-side `SshRunner.run(..., timeout=user_timeout + 10)`. Target side handles the common case cleanly; host side guards against SSH/network hangs.

**Considered & rejected:**
- *Host-side only.* The target Python process may keep running for a few seconds after SSH disconnect, holding `/proc/kcore` and consuming CPU.
- *Target-side only.* A network hang would wedge the call until a very long backstop fires.

### 8.3 Manifest fit: per-call step, server-generated `call_id`

**Decision:** each invocation creates a fresh `StepResult` named `introspect:<uuid4>`. Server mints the UUID and returns it.

**Considered & rejected:**
- *Caller-supplied `call_id` with idempotent replay.* Adds API surface (`force=true` parameter, replay semantics) for a feature with no realistic v0 use case — drgn queries are cheap to re-run.
- *Single accumulating `introspect` step.* Lower manifest noise but breaks the established invariant that one step name maps to one `StepResult`.

### 8.4 Output cap: target per-field + host backstop

**Decision:** the wrapper enforces per-field caps (100 emits, 32 KiB per-emit serialized size, 256 KiB `user_stdout`, 16 KiB traceback, 1 MiB total JSON), setting `truncated.<field>` flags. Oversize individual emits are replaced with `__emit_oversized__` placeholders carrying head bytes; the total-JSON cap drops emits from the tail (not the whole list) and only clears `user_stdout` as a last-resort fallback. The host enforces a defensive max-bytes read on the SSH stdout pipe as a backstop.

**Considered & rejected:**
- *Host-side cap only.* Truncating arbitrary JSON on the wire usually produces invalid syntax, making the response hard to interpret.
- *Single total-bytes cap.* No structured truncation; users have to guess what to shrink when the cap fires.

### 8.5 No new `ErrorCategory` enum values

**Decision:** introspect-specific failures use existing categories (`CONFIGURATION_ERROR`, `READINESS_FAILURE`, `INFRASTRUCTURE_FAILURE`, `STALE_HANDLE`) with `code` strings carrying the distinction. User-script runtime exceptions are `status: "script_error"` inside a `ToolResponse.success`, not a failure.

**Considered & rejected:**
- *Add `INTROSPECT_TIMEOUT`, `INTROSPECT_SCRIPT_ERROR`.* Existing categories already convey the right semantics to the agent; the `code` strings are sufficient distinction. Adding categories without a behavioral split agent-side is taxonomy churn.

### 8.6 `SPRINT_4_DEBUG_OPERATIONS` → `ALLOWED_DEBUG_OPERATIONS`

**Decision:** rename the allowlist constant in the same change that adds `debug.introspect.run`. The historical sprint label becomes actively misleading once a non-sprint-4 operation lands on top of it. The internal `docs/superpowers/` artifacts may continue to reference the old name where they document history.

## 9. Testing

### 9.1 Unit tests — `tests/test_debug_introspect_run.py`

Handler called directly with injected fakes:

- `provider = FakeDrgnIntrospectProvider`
- `ssh_runner = FakeSshRunner` (same shape as `test_local_ssh_tests.py`)
- `admission = FakeAdmissionService` (same fakes used in `test_admit_run_tests*`)
- profile dicts passed in

`FakeSshRunner` returns a caller-controlled `(stdout, stderr, exit_code, timed_out, cancelled)` and asserts on received argv.

Test cases:
- `test_allow_write_rejected`
- `test_invalid_script_rejected`
- `test_invalid_timeout_rejected`
- `test_operation_disabled_in_profile`
- `test_provenance_missing_when_manifest_lacks_build_id`
- `test_admit_rejects_halted` (admission raises `target_halted`; assert response and < 100 ms)
- `test_admission_complete_raises_execution_state_changed`
- `test_wrapper_exit_3_drgn_open_failure`
- `test_wrapper_exit_4_provenance_mismatch`
- `test_wrapper_exit_5_script_compile_error`
- `test_wrapper_exit_124_introspect_timeout`
- `test_wrapper_crash_no_json`
- `test_ssh_timeout_propagates`
- `test_timeout_propagates_to_runner` (cancel event observed by FakeSshRunner)
- `test_host_backstop_on_oversize_stdout`
- `test_redactor_applied_to_emits_and_snippets` (FakeSshRunner returns JSON containing the configured secret; assert redaction in `result.json` on disk and in the response)
- `test_step_result_recorded_with_introspect_call_id_name`
- `test_sudo_preflight_returns_actionable_error_on_password_prompt` (FakeSshRunner returns non-zero for the `sudo -n true` argv; response is `CONFIGURATION_ERROR` / `sudo_requires_password`; main wrapper invocation is never issued)

### 9.2 Wrapper tests — `tests/test_introspect_wrapper.py`

The rendered wrapper is `exec`'d in-process against a stub `drgn` module:

```python
class _StubProg:
    def set_kernel(self): ...
    def load_default_debug_info(self): ...
    def main_module(self): return SimpleNamespace(build_id=bytes.fromhex("abc..."))

class _StubDrgn:
    Program = lambda *a, **k: _StubProg()
```

Test cases:
- `test_wrapper_emit_roundtrips_json`
- `test_wrapper_truncates_user_stdout`
- `test_wrapper_truncates_emits`
- `test_wrapper_truncates_traceback`
- `test_wrapper_total_json_cap_drops_from_tail_not_all` (oversize result drops only the trailing emits needed to fit; head emits and header fields survive)
- `test_wrapper_total_json_cap_falls_back_to_clearing_user_stdout` (when dropping all emits still leaves the result oversize, `user_stdout` is cleared and `truncated.user_stdout` is `True`)
- `test_wrapper_per_emit_byte_cap_inserts_placeholder` (a 64 KiB emit is replaced with `__emit_oversized__` carrying head bytes; `truncated.per_emit_size` is `True`)
- `test_wrapper_provenance_mismatch_exits_4`
- `test_wrapper_drgn_import_failure_exits_3`
- `test_wrapper_user_script_exception_captures_traceback`
- `test_wrapper_syntax_error_exits_5`
- `test_wrapper_stdout_only_contains_json` (stdin script `print("noise")` lands in `user_stdout`, not stdout)
- `test_wrapper_round_trips_script_containing_triple_quotes_and_template_sigils` (a script containing `'"""'`, `'${EXPECTED_BUILD_ID}'`, embedded `\x00`, and a CRLF round-trips through render→execute unchanged)
- `test_wrapper_emit_unserializable_replaced_with_placeholder` (calling `emit(set())` produces an `__emit_unserializable__` entry; the rest of the script runs and its emits land normally)
- `test_wrapper_helper_namespace_contains_expected_subset` — assert at least `list_for_each_entry`, `for_each_task`, and `dmesg` are present in the user namespace, and that wrapper-private names (`_pre_helpers`, `_drgn_helper_names`, `emit_buffer`, `emit_overflow`, `result`, `CAPS`, `_truncate`, `_t_prelude_start`) are NOT exposed.

### 9.3 Integration tests — `tests/test_drgn_introspect_integration.py`

Gated on `which drgn` + `which qemu-system-x86_64`, mirroring `test_libvirt_boot_integration.py`'s skip pattern.

- `test_introspect_emit_roundtrip` — boot the smoke VM, run a 3-line script emitting `{"pid": 1}`, assert `result["emits"] == [{"pid": 1}]`
- `test_introspect_target_side_timeout` — script `while True: pass` with `timeout_seconds=5` returns exit 124 → `introspect_timeout`
- `test_introspect_build_id_round_trips` — assert manifest's recorded build_id equals what the wrapper reports for the live kernel

### 9.4 Property test (lightweight, optional)

Hypothesis-driven JSON-shape assertion on the wrapper's output: regardless of script outcome, `result.json` parses, has a `call_id`, an `outcome`, and a `truncated` map.

## 10. Acceptance criteria mapping

| #51 acceptance criterion | Covered by |
|---|---|
| Arbitrary user drgn script returns JSON via `emit()` against a live VM | `test_introspect_emit_roundtrip` (integration) |
| drgn-side stderr noise excluded from `emit()` result | `test_wrapper_stdout_only_contains_json` (wrapper) + integration assertion on `drgn_stderr_snippet` |
| Timeout cuts the call cleanly without leaking SSH child | `test_timeout_propagates_to_runner` (unit) + `test_introspect_target_side_timeout` (integration) |
| Output cap enforced; oversize results truncated with indicator | `test_wrapper_truncates_*` (wrapper) + `test_host_backstop_on_oversize_stdout` (unit) |
| Call against `HALTED` target fast-rejected, not hung | `test_admit_rejects_halted` (unit) |
| `build_id` mismatch fails hard | `test_wrapper_exit_4_provenance_mismatch` (unit) + `test_wrapper_provenance_mismatch_exits_4` (wrapper) |
| `allow_write=true` returns `configuration_error`; `allow_write=false` does not enforce read-only — documented in §3.5 | `test_allow_write_rejected` (unit) |
| All persisted artifacts/responses pass through `Redactor()` | `test_redactor_applied_to_emits_and_snippets` (unit) |

## 11. Open risks

Worth surfacing in the PR description; not blocking on this spec.

0. **`allow_write=false` is a label, not a sandbox.** As documented in §3.5, the flag rejects `allow_write=true` but does not constrain what `allow_write=false` scripts can do — `exec()` with full builtins still lets the script open arbitrary files, `import os`, etc. The current trust boundary is "agents already authorized to call `debug.introspect.run` against this target." Sandboxing belongs to #56.
1. **`drgn.main_module().build_id` is sourced from drgn's debuginfo resolution, not directly from `/sys/kernel/notes`.** Normally identical, but split-debuginfo edge cases could expose drift between "what drgn loaded symbols for" and "what's actually running." Acceptable for #51; #53 is the right place to harden it.
2. **Passwordless sudo assumption.** Same posture as smoke tests. A misconfigured target is now caught up-front by the sudo preflight in §5.2 step 7a, which returns `CONFIGURATION_ERROR` / `sudo_requires_password` instead of letting the call fall off the end of the host timeout margin as `ssh_timeout`.
3. **`drgn` version drift on target.** Different distros ship varying drgn versions; the wrapper assumes recent-enough `Program.set_kernel()` / `load_default_debug_info()` / `main_module().build_id`. Real version-skew handling is #52.
4. **A user script that just spins.** The timeout is the only bound on misbehaving scripts. Acceptable for read-only v0; write-mode in #56 will need more.
4a. **`timeout_seconds` covers the prelude as well as the script.** The user-visible `timeout_seconds` is enforced by target-side `timeout(1)` around the whole wrapper, so it covers both the drgn prelude (`set_kernel` + `load_default_debug_info`) and the script execution. On a slow target or with split debuginfo the prelude alone can take several seconds; callers should set `timeout_seconds` accordingly. The wrapper records `prelude_ms` separately so callers can tune it; when `prelude_ms > 0.5 * timeout_seconds * 1000`, the response `diagnostic` field includes a soft warning so this isn't a silent failure mode.
5. **Manifest write for the new step kind.** *Resolved in §5.2 step 12 — `ArtifactStore.append_step_result` is new code in #51 alongside `with_step_result()`, scoped to "append-and-fail-on-name-collision" semantics so per-call introspect records cannot clobber each other or the singleton named steps (`build`, `boot`, `run_tests`, `debug`).*
6. **Wrapper-size growth from base64 transfer.** Encoding the user script as base64 (§3.1) inflates it by ~33% over the wire. At the 256 KiB script cap that is ~342 KiB on the SSH stdin frame — well under any practical SSH limit, but worth flagging alongside the existing 256 KiB script cap so future raises know to consider the inflated wire size.

## 12. Coordination

- **interface-contracts.md** §3.3 (ssh-only tier, `required_caps` empty), §4.2 (provenance fail-loud), §5.3 (admission service is the single live-op gate), §5.6 rule 2 (ssh-tier `HALTED` fast-reject).
- **ADR 0006** (unified cancel-epoch state machine): live `debug.introspect.run` is the second ssh-tier consumer alongside `target.run_tests`. No new ADR — the design fits the established model.
- **Sibling issues:** #52 (prereq probe), #53 (full provenance + symbol resolution), #54 (curated helpers), #55 (vmcore), #56 (write-mode opt-in). #51 is the foundation they build on.
