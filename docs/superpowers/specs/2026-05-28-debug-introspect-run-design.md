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
- Tightening `ArtifactStore.create_run` so the `sensitive/` run subdir is created with mode `0700` (R2-F4). The other run subdirs (`inputs`, `logs`, `build`, `target`, `tests`, `debug`, `summaries`) keep their umask defaults. This is what makes the file-mode `0600` on `<run>/sensitive/debug/introspect/<call_id>/wrapper.py` actually load-bearing — without the parent being `0700`, a `0600` leaf is ineffective against any local user on the host. The change is enacted in `ArtifactStore.create_run` so every other consumer of `sensitive/` inherits the hardened mode automatically; the introspect handler does **not** chmod the parent on each call.

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

Before substitution the host validates each non-user value against a strict regex: `${EXPECTED_BUILD_ID}` must match `^[0-9a-f]{8,}$`, and `${CALL_ID}` must match `^[0-9a-f]{32}$` (UUIDv4 hex). A mismatch on `${EXPECTED_BUILD_ID}` surfaces as `INFRASTRUCTURE_FAILURE` / `provenance_corrupt` (the manifest's recorded `build_id` is malformed and the call cannot proceed); a mismatch on `${CALL_ID}` is an internal bug and raises before any I/O. The validation is a host-side defense — the wrapper itself assumes its inputs are well-formed, which is what lets §4.2 drop the truthy guard around the build-id comparison.

### 3.2 Response (success path)

```python
ToolResponse.success({
  "call_id": "<uuid4-hex>",             # absent on pre-admission failures
                                        # (profile / gating / invariants /
                                        # provenance / sudo preflight /
                                        # admission), since no call_id is
                                        # minted before admission succeeds.
                                        # See §5.2.
  "status": "ok" | "script_error",      # "script_error" = wrapper ran, user script raised
  "outcome": {
    "status": "ok" | "error" | "wrapper_internal_error",
                                        # "wrapper_internal_error" (R2-F2): the wrapper's tail
                                        # serialization or write failed before a normal `ok`/`error`
                                        # could be emitted (e.g. UnicodeEncodeError on a lone
                                        # surrogate, BrokenPipeError on a closed SSH pipe,
                                        # MemoryError during json.dumps). The wrapper's inner
                                        # except (§4.2) writes a minimal JSON document with this
                                        # status carrying `error_type` and `error_message` from
                                        # the failing operation; the host maps it to
                                        # `INFRASTRUCTURE_FAILURE` / `wrapper_crash` per §4.3.
    "error_type": "...",                # populated for `error` (user script raised) and for
                                        # `wrapper_internal_error` (host-detected wrapper
                                        # internal failure); redacted, truncated to
                                        # CAPS["error_message"] (4096 chars)
    "error_message": "...",             # populated for `error` and `wrapper_internal_error`;
                                        # redacted, truncated to CAPS["error_message"] (4096 chars)
    "traceback": "...",                 # only when status="error"; redacted, truncated to
                                        # CAPS["traceback"]
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
    "error_message": bool,   # outcome.error_message exceeded CAPS["error_message"]
                             # (4096 chars) and was truncated; the cap also
                             # applies to outcome.error_type for defense in depth
  },
  "started_at": "...", "finished_at": "...", "duration_ms": int,
  "prelude_ms": int,                    # drgn open + debuginfo load time, separate from script
                                        # execution. R2-F9: 0 when the drgn prelude failed (exit
                                        # 3 paths — `drgn_open_failure`, `drgn_version_skew`) or
                                        # otherwise did not run to completion (e.g. exit 4
                                        # `provenance_mismatch`); non-zero on every other path.
                                        # Always present in the emitted JSON.
  "artifacts": [ArtifactRef, ...],      # request.json, stdout.json, stderr.log, result.json,
                                        # wrapper.skeleton.py — NOT wrapper.py, which lives
                                        # under <run>/sensitive/ (§6.1, §6.3)
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
| `manifest.steps["build"].details["build_id"]` present but malformed (fails `^[0-9a-f]{8,}$`) | `INFRASTRUCTURE_FAILURE` | `provenance_corrupt` | Pre-SSH |
| Manifest absent or run_id invalid | `CONFIGURATION_ERROR` | (existing path-safety codes) | Pre-SSH |
| Introspect call budget exhausted for run (≥ `MAX_INTROSPECT_CALLS_PER_RUN`) | `CONFIGURATION_ERROR` | `manifest_call_budget_exhausted` | Pre-SSH |
| `sudo -n true` preflight fails (sudo wants a password) | `CONFIGURATION_ERROR` | `sudo_requires_password` | Pre-SSH (preflight, §5.2 step 5) |
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
| Wrapper exit 6 with no/invalid JSON (R2-F2: inner-except recovery also failed) | `INFRASTRUCTURE_FAILURE` | `wrapper_crash` | Host parse |
| Wrapper exit 6 with minimal JSON, `outcome.status="wrapper_internal_error"` (R2-F2) | `INFRASTRUCTURE_FAILURE` | `wrapper_crash` | Host parse |
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

# R2-F8: every wrapper-private global is `_li_`-prefixed so the
# `from drgn.helpers.linux import *` wildcard below cannot shadow it. `prog`,
# `drgn`, and `emit` are deliberately *not* prefixed because they're injected
# into the user namespace and renaming them would break user scripts.
_li_caps = {"emits": 100, "user_stdout": 256 * 1024, "traceback": 16 * 1024,
            "total_json": 1 * 1024 * 1024, "per_emit_bytes": 32 * 1024,
            "error_message": 4096}

def _li_truncate(s, cap):
    return (s[:cap], True) if len(s) > cap else (s, False)

# R2-F9: `prelude_ms` is initialized to 0 so it's always present in the
# emitted JSON, even on the early-exit paths (drgn_open_failure,
# drgn_version_skew, provenance_mismatch, script_compile_error) that dump
# `_li_result` before the post-prelude assignment runs.
_li_result = {"call_id": "${CALL_ID}", "build_id": None, "outcome": None,
              "emits": [], "user_stdout": "", "prelude_ms": 0,
              "truncated": {"emits": False, "user_stdout": False,
                            "traceback": False, "total_json": False,
                            "per_emit_size": False, "error_message": False}}

import time
_li_t_prelude_start = time.monotonic()

try:
    # `drgn` is imported first so it predates the helper snapshot; the wildcard
    # import below is what we want to capture, and `drgn` itself is injected
    # explicitly into the user namespace further down.
    import drgn  # noqa: E402  -- module attribute, exposed to user namespace

    _li_pre_helpers = set(globals().keys())
    from drgn.helpers.linux import *  # noqa: F401,F403,E402
    _li_drgn_helper_names = set(globals().keys()) - _li_pre_helpers

    prog = drgn.Program()
    prog.set_kernel()
    prog.load_default_debug_info()
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_open_failure",
                             "error_type": etype,
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        json.dump(_li_result, sys.stdout)
    finally:
        sys.exit(3)

_li_result["prelude_ms"] = int((time.monotonic() - _li_t_prelude_start) * 1000)

# F8: guard the build_id read separately so older/newer drgn versions that
# don't expose `main_module().build_id` surface as `drgn_version_skew` rather
# than crashing the wrapper into the `wrapper_crash` path.
try:
    _li_result["build_id"] = prog.main_module().build_id.hex()
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_version_skew",
                             "error_type": etype,
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        json.dump(_li_result, sys.stdout)
    finally:
        sys.exit(3)

# Render-time `string.Template.substitute` is strict, so `${EXPECTED_BUILD_ID}`
# is always replaced with the host-validated hex blob; no truthy guard.
if _li_result["build_id"] != "${EXPECTED_BUILD_ID}":
    _li_result["outcome"] = {"status": "provenance_mismatch",
                             "expected": "${EXPECTED_BUILD_ID}",
                             "actual": _li_result["build_id"]}
    try:
        json.dump(_li_result, sys.stdout)
    finally:
        sys.exit(4)

_li_emit_buffer = []
_li_emit_overflow = False

def emit(obj):
    global _li_emit_overflow
    if len(_li_emit_buffer) >= _li_caps["emits"]:
        _li_emit_overflow = True
        return
    try:
        # Validate JSON-serializability up front so the final json.dumps
        # can never fail. Reject by recording a placeholder, not by raising,
        # so a bad emit doesn't tear down the rest of the script.
        encoded = json.dumps(obj)
    except (TypeError, ValueError) as exc:
        _li_emit_buffer.append({
            "__emit_unserializable__": True,
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:512],
            "repr": repr(obj)[:512],
        })
        return
    if len(encoded) > _li_caps["per_emit_bytes"]:
        _li_result["truncated"]["per_emit_size"] = True
        _li_emit_buffer.append({
            "__emit_oversized__": True,
            "size_bytes": len(encoded),
            "cap_bytes": _li_caps["per_emit_bytes"],
            "head": encoded[:1024],
        })
        return
    _li_emit_buffer.append(obj)

user_stdout = io.StringIO()
# Snapshot globals immediately before the wildcard import; everything that
# appears after is a drgn helper. `drgn` itself is injected explicitly here
# (it predates the snapshot) so user scripts can do `drgn.Object(...)` etc.
namespace = {
    "prog": prog, "emit": emit, "drgn": drgn,
    "__name__": "__introspect__", "__builtins__": __builtins__,
}
for name in _li_drgn_helper_names:
    namespace[name] = globals()[name]

import base64
USER_SCRIPT_B64 = "${USER_SCRIPT_B64}"   # host substitutes a pure-ASCII base64 blob
try:
    compiled = compile(
        base64.b64decode(USER_SCRIPT_B64).decode("utf-8"),
        "<introspect>", "exec",
    )
except SyntaxError as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    _li_result["outcome"] = {"status": "script_compile_error",
                             "error_type": "SyntaxError",
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        json.dump(_li_result, sys.stdout)
    finally:
        sys.exit(5)

with contextlib.redirect_stdout(user_stdout):
    try:
        exec(compiled, namespace)
        _li_result["outcome"] = {"status": "ok"}
    except BaseException as exc:
        # BaseException so the user script cannot smuggle a `SystemExit(124)`
        # past the wrapper and spoof a target-side timeout — `sys.exit(N)`,
        # `KeyboardInterrupt`, and similar non-Exception conditions all land
        # here and are recorded as `outcome.status="error"` with the real
        # exit code carried in `error_type`.
        tb, tb_trunc = _li_truncate(traceback.format_exc(), _li_caps["traceback"])
        msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
        etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
        _li_result["outcome"] = {"status": "error",
                                 "error_type": etype,
                                 "error_message": msg, "traceback": tb}
        _li_result["truncated"]["traceback"] = tb_trunc
        _li_result["truncated"]["error_message"] = msg_trunc

# F1 + R2-F2: tail JSON write wrapped in try/except/finally with sentinel
# exit code 6 (`wrapper_complete`). The exit code is reached only after
# `sys.stdout.write` returns, so user code cannot fabricate it — any
# `sys.exit(6)` from inside `exec` is caught by the BaseException handler
# above and routed to the `error` outcome. R2-F2: if tail serialization or
# the write itself fails (e.g. `UnicodeEncodeError` on a lone surrogate,
# `BrokenPipeError` on a closed SSH pipe, `MemoryError` while serializing),
# the inner `except BaseException` makes a best-effort attempt to emit a
# minimal JSON document with `outcome.status="wrapper_internal_error"`. If
# even that fails, the host sees exit 6 with no JSON and falls through to
# `INFRASTRUCTURE_FAILURE`/`wrapper_crash` per §4.3.
try:
    _li_result["emits"] = _li_emit_buffer
    _li_result["truncated"]["emits"] = _li_emit_overflow
    out, trunc = _li_truncate(user_stdout.getvalue(), _li_caps["user_stdout"])
    _li_result["user_stdout"] = out
    _li_result["truncated"]["user_stdout"] = trunc

    payload = json.dumps(_li_result)
    while len(payload) > _li_caps["total_json"] and _li_result["emits"]:
        _li_result["emits"].pop()              # drop from the tail until under cap
        _li_result["truncated"]["total_json"] = True
        payload = json.dumps(_li_result)
    # If still over cap after emits exhausted, clear user_stdout as the final
    # fallback (header fields + outcome + truncation flags are kept).
    if len(payload) > _li_caps["total_json"]:
        _li_result["user_stdout"] = ""
        _li_result["truncated"]["user_stdout"] = True
        payload = json.dumps(_li_result)
    sys.stdout.write(payload)
except BaseException as exc:
    # R2-F2: best-effort recovery. Emit a minimal JSON document so the host
    # can tell wrapper-internal failure (exit 6 + this minimal JSON) from a
    # silent crash (exit 6 + no JSON, mapped to `wrapper_crash`).
    try:
        sys.stdout.write(json.dumps({
            "call_id": _li_result.get("call_id"),
            "outcome": {"status": "wrapper_internal_error",
                        "error_type": type(exc).__name__,
                        "error_message": str(exc)[:_li_caps["error_message"]]},
            "truncated": {"wrapper_internal_error": True},
            "build_id": _li_result.get("build_id"),
            "emits": [], "user_stdout": "",
        }))
    except BaseException:
        pass        # last-ditch: host sees exit 6 with no JSON →
                    # wrapper_crash per §4.3 row "exit 6 + no/invalid JSON"
finally:
    sys.exit(6)
```

### 4.3 Exit-code contract

**When the wrapper writes a valid JSON document on stdout, `outcome.status` is
authoritative; the exit code is advisory.** The host parses JSON first and only
falls back to exit-code interpretation when JSON is absent or invalid. The
wrapper exits **6** (`wrapper_complete`) on the happy path; a user script's
`sys.exit(N)` cannot reach this sentinel because the BaseException handler in
§4.2 catches `SystemExit` and routes it to `outcome.status="error"`.

| Exit | JSON on stdout? | Meaning | Host maps to |
|---|---|---|---|
| 6 | valid `result`-shaped JSON with `outcome.status` ∈ {`ok`, `error`} | Wrapper ran to completion; `outcome.status` is authoritative | `status="ok"` or `status="script_error"` depending on `outcome.status` |
| 6 | valid minimal JSON with `outcome.status="wrapper_internal_error"` | R2-F2: tail serialization or write failed; the inner `except BaseException` in §4.2 emitted a stripped-down document carrying `outcome.error_type` / `error_message` | `INFRASTRUCTURE_FAILURE` / `wrapper_crash` — a wrapper-internal failure sub-case, distinguished from the silent-crash sub-case below by the presence of a valid JSON document |
| 6 | absent / unparseable | Inner-except recovery also failed; host sees exit 6 with no JSON | `INFRASTRUCTURE_FAILURE` / `wrapper_crash` — silent-crash sub-case; raw stderr persisted |
| 3 | — | Wrapper-side drgn surface failed | `INFRASTRUCTURE_FAILURE` / `drgn_open_failure` *or* `drgn_version_skew` — the host discriminates on `outcome.status` in the emitted JSON (`drgn_open_failure` for `import drgn` / `set_kernel` / `load_default_debug_info` failure; `drgn_version_skew` when `prog.main_module().build_id` is unavailable or shaped wrong on older/newer drgn) |
| 4 | — | `build_id` mismatch | `CONFIGURATION_ERROR` / `provenance_mismatch` |
| 5 | — | User script failed `compile()` | `CONFIGURATION_ERROR` / `script_compile_error` |
| 124 | — | `timeout(1)` fired before wrapper exited | `INFRASTRUCTURE_FAILURE` / `introspect_timeout` |
| 0 | — | Wrapper exited 0 without emitting JSON | `INFRASTRUCTURE_FAILURE` / `wrapper_crash` — sub-case where the wrapper exited cleanly but never reached the tail sentinel (e.g. an interpreter-level abort before the `try/finally` ran); raw stderr persisted |
| other | — | Any other exit with absent or unparseable JSON | `INFRASTRUCTURE_FAILURE` / `wrapper_crash` — raw stderr persisted |

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

**Prologue invariants.** Two cross-cutting properties hold across the steps below:

- *No on-disk artifact is created for a call before admission + sudo preflight
  succeed.* A failed profile lookup, operation gate, request invariant,
  provenance check, manifest call-budget check, sudo preflight, or admission
  attempt returns a failure `ToolResponse` with **no `call_id`** in the body
  and **no manifest entry** — from the caller's perspective the call never
  existed. The `<call_id>/` artifact directory and the symmetric
  `<run>/sensitive/debug/introspect/<call_id>/` (§6.1) are both created only
  after admission returns a handle.
- *Every diagnostic that may carry remote output is redacted.* The handler
  constructs `redactor = Redactor(secret_values=[rootfs_profile.ssh_key_ref]
  if rootfs_profile.ssh_key_ref else [])` immediately after profile resolution
  (step 1) so each error path below — including the sudo preflight failure
  diagnostic (step 5) and the `ssh_failure` diagnostic (step 9) — passes the
  captured stderr through `redactor.redact_text(...)` before embedding it in
  the response.

1. **Profile resolution + path validation.** Mirror `target_run_tests_handler`: resolve `target_profile`/`rootfs_profile`/`debug_profile` from request overrides + recorded manifest defaults; `validate_run_id`; load `manifest.json`. Construct the per-call `Redactor` (see prologue) immediately after the rootfs profile is resolved.
2. **Operation gating.** `_ensure_debug_operation_enabled(resolved_debug_profile, "debug.introspect.run")`.
3. **Request invariants.** Reject `allow_write=true`. Validate `timeout_seconds in [5, 300]`. Validate `script` non-empty, ≤ 256 KiB.
4. **Build_id from manifest.** Read `manifest.steps["build"].details["build_id"]`. Missing → `CONFIGURATION_ERROR` / `provenance_missing`. Present but failing the `^[0-9a-f]{8,}$` regex check (the §3.1 host-side validation) → `INFRASTRUCTURE_FAILURE` / `provenance_corrupt`. This is the minimal `KernelProvenance` consumer (§7); the regex check exists so the wrapper's `${EXPECTED_BUILD_ID}` comparison can be unconditional (§4.2 dropped its truthy guard for F4).
   4a. **Manifest call budget (authoritative soft cap).** Count existing keys in `manifest.step_results` matching `^introspect:`. If the count is ≥ `MAX_INTROSPECT_CALLS_PER_RUN` (default **1000**, surfaced in `config.py`), return `CONFIGURATION_ERROR` / `manifest_call_budget_exhausted`. The budget check is performed once, here, **without holding the manifest lock**. Under contention the cap may overshoot by up to `(concurrent_calls - 1)` (R2-F5); this is a deliberate trade-off — `MAX_INTROSPECT_CALLS_PER_RUN` is a soft target, not a hard ceiling, so an admitted call's work is never thrown away post-SSH. The cap exists to bound the manifest-rewrite cost (each successful call rewrites the full manifest under the lock — see step 13). Recovery is documented: start a fresh `kernel.create_run` and continue work there.
5. **Sudo preflight** (only when `ssh_user != "root"`). Run `ssh <ssh_args> <user>@<host> -- 'sudo -n true'` with a 5-second host timeout. Non-zero exit → `CONFIGURATION_ERROR` / `sudo_requires_password`; the diagnostic embeds the captured stderr after passing it through `redactor.redact_text(...)` **first**, then truncating the redacted output to the first 256 bytes (typically `"sudo: a password is required"`, but `ssh_key_ref` and any other configured secrets are scrubbed before any truncation). The redact-before-truncate ordering is mandatory (R2-F3): `Redactor.redact_text` does literal substring replacement against `secret_values`, so a truncation point inside an `ssh_key_ref` would leave a partial copy of the key in the diagnostic that the redactor could no longer match. The probe is cheap, deterministic, and turns a 30-second `ssh_timeout` into a sub-second actionable error. Skipped when `ssh_user == "root"` because there is no sudo round trip on the hot path either.
6. **Admission gate.**
   ```python
   snapshot = admission.current_snapshot(target_key)
   proof = probe_execution_state(...)            # the same probe run_tests uses
   handle = admission.admit_ssh_tier(
       target_key, snapshot.generation, snapshot.platform,
       lease=snapshot.lease, execution_proof=proof,
   )
   ```
   Admission errors map per the §3.3 table. No `call_id` is minted and no artifact directory is created on admission failure.
7. **Mint `call_id`.** `uuid4().hex`. Create `<run>/debug/introspect/<call_id>/` (mode 0700) **and** the sibling `<run>/sensitive/debug/introspect/<call_id>/` (mode 0700, under the existing `sensitive/` subtree — see §6.1 for the file-mode rules). The `call_id` is included in the response from this step onward.
8. **Render wrapper.** Substitute `${USER_SCRIPT_B64}` (the user script base64-encoded as a pure-ASCII blob per §3.1), `${EXPECTED_BUILD_ID}`, and `${CALL_ID}` into the template via `string.Template(...).substitute(...)` (strict, with the §3.1 pre-substitution regex checks on the non-user values). Persist:
   - the full rendered wrapper as `<run>/sensitive/debug/introspect/<call_id>/wrapper.py` (mode 0600 — the script body is in here verbatim, see §6.3),
   - a `<run>/debug/introspect/<call_id>/wrapper.skeleton.py` containing the rendered wrapper with the user-script base64 body replaced by the placeholder `# <user script: sha256:<hex>; full source under sensitive/debug/introspect/<call_id>/wrapper.py>`, where `<hex>` is `hashlib.sha256(base64.b64decode(USER_SCRIPT_B64)).hexdigest()` — the sha256 of the **decoded user script bytes**, not of the rendered wrapper (R2-F7; see §6.3 for the canonical definition),
   - the redacted `request.json` under `<run>/debug/introspect/<call_id>/`.
9. **SSH invocation.** Reuse `SshRunner`:
   ```
   ssh <ssh_args> <user>@<host> 'timeout --kill-after=2s <user_timeout>s sudo python3 -'
   ```
   stdin = wrapper string. Host-side `SshRunner.run(..., timeout=user_timeout + 10, cancel=cancel_event, stdout_path=stdout_path, stderr_path=stderr_path)`. The `ssh_failure` diagnostic — when SSH connect/auth fails — passes captured stderr through `redactor.redact_text(...)` **first**, then truncates the redacted output to 256 bytes (matching the sudo preflight cap in step 5). The redact-before-truncate ordering is mandatory for the same reason as step 5 (R2-F3): truncating first could split an `ssh_key_ref` mid-secret, leaving an unmatched prefix in the diagnostic.
10. **Cancellation bridge** — verbatim from `_run_admitted` in `target.run_tests`:
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
11. **Result parsing.** Per the exit-code contract.
12. **Host-side post-processing.** Re-use the per-call `Redactor` (configured in step 1) on every variable-length string in the response and the on-disk `stdout.json` / `stderr.log` / `result.json` (§6.3). Build `ArtifactRef`s for `request.json`, `wrapper.skeleton.py`, `stdout.json`, `stderr.log`, and `result.json`; **`wrapper.py` is referenced by an `ArtifactRef` in the step record with `sensitive=True` (see §6.2) but is omitted from the response's `artifacts` list**.
13. **Manifest record.** Open `ArtifactStore._manifest_lock()` in exclusive mode. Re-read the manifest under the lock. R2-F5: the call-budget invariant is **not** re-checked here — step 4a is the only budget gate, and the soft-cap framing in §5.3 documents the consequences of that choice. The only post-lock check that may fail is `call_id` collision: if `step_results[f"introspect:{call_id}"]` already exists, fail with `INFRASTRUCTURE_FAILURE` / `call_id_collision` (UUIDv4 collision — should never happen). Otherwise call `ArtifactStore.record_step_result(step_result, append=True)`. The append-mode helper is the existing `record_step_result` (today the wrapper around `RunManifest.with_step_result`) extended with a new `append: bool = False` kwarg that switches the underlying call to a pure `RunManifest.append_step_result(step_result)` — which mirrors `RunManifest.with_step_result` at `manifest.py:60` and returns a new `RunManifest`. `append=True` (a) appends to the `steps` list, (b) sets `step_results[name] = step_result`, and (c) atomically rewrites `manifest.json` via `tmp + rename`. The default `append=False` path remains for replace-on-`force_*` semantics on the named-singleton steps (`build`, `boot`, `run_tests`, `debug`). The same retry-with-backoff posture as `_record_terminal_build_result` applies if the lock is transiently unavailable.
14. **Return** `ToolResponse.success(...)` per §3.2.

### 5.3 Concurrency

No introspect-level lock is required for ordering across calls — the manifest is serialized through `ArtifactStore._manifest_lock()` (§5.2 step 13) and `call_id` is a fresh UUIDv4 per call, so two concurrent introspect calls serialize cleanly at the manifest layer. `AdmissionService.admit_ssh_tier` permits concurrent ssh-tier ops on an `EXECUTING` target (interface-contracts §5.6 rule 2), so the SSH calls themselves race naturally — each one a separate admitted op, each one cancelled on halt. drgn-live concurrent reads of `/proc/kcore` are racy by design and acceptable.

**Soft-cap semantics for `MAX_INTROSPECT_CALLS_PER_RUN` (R2-F5).** The call-budget gate at §5.2 step 4a runs without holding the manifest lock so a race-loser never discards completed target-side work. Under N concurrent calls at the boundary (count exactly `MAX_INTROSPECT_CALLS_PER_RUN - 1` going in), all N may pass step 4a, all N execute the round trip, and all N are recorded — landing the manifest at `count == MAX + (N-1)`. The next caller observes that higher count at *its* step 4a and is rejected with `manifest_call_budget_exhausted`. The hard maximum is therefore `MAX_INTROSPECT_CALLS_PER_RUN + (N-1)` where N is the concurrent in-flight call count; for any realistic concurrency this is a rounding error against the 1000-call default. The chosen design preference (no work discarded post-SSH) is the reason no post-lock recheck exists at step 13.

## 6. Manifest and artifacts

### 6.1 Artifact directory layout

```
<run>/
  debug/
    introspect/
      <call_id>/
        request.json          # redacted DebugIntrospectRunRequest
        wrapper.skeleton.py   # rendered wrapper with the user-script base64 body
                              # replaced by `# <user script: sha256:<hex>; full
                              # source under sensitive/debug/introspect/
                              # <call_id>/wrapper.py>`, where <hex> is the
                              # sha256 of the decoded user script body (NOT of
                              # the rendered wrapper) plus a path pointer to
                              # wrapper.py under <run>/sensitive/ — R2-F7,
                              # canonical definition in §6.3; safe to surface
                              # in responses
        stdout.json           # parsed-then-redacted-then-reserialized wrapper
                              # JSON; remains valid JSON. The raw wire bytes
                              # are NOT persisted here.
        stderr.log            # SSH stderr after text-mode Redactor; secrets
                              # removed, structure (line-oriented) preserved.
        result.json           # normalized, redacted result returned to caller
  sensitive/
    debug/
      introspect/
        <call_id>/
          wrapper.py          # rendered wrapper sent to the target verbatim,
                              # including the base64-encoded user script body
                              # (base64 is transport encoding, not redaction —
                              # see §6.3); file mode 0600
          stdout.raw          # only present on wrapper_crash where SSH stdout
                              # was not valid JSON; file mode 0600
```

`request.json` and `wrapper.skeleton.py` are written before SSH invocation (§5.2 step 8); the sibling `wrapper.py` (full source) is written under `<run>/sensitive/debug/introspect/<call_id>/` in the same step with mode `0600`. The `sensitive/` subtree exists project-wide for forensic reproducibility (see `artifacts/store.py`) and is **not** listed in the response's `artifacts` array — files under it are referenced by `ArtifactRef`s in the step record with `sensitive=True` (§6.2) so consumers of the manifest can filter, but agents never receive their paths in a `ToolResponse`.

**`sensitive/` root mode is a contract on `ArtifactStore.create_run` (R2-F4).** That helper now creates `<run>/sensitive/` with mode `0700` — either via `os.mkdir(path, mode=0o700)` followed immediately by `os.chmod(path, 0o700)` (Python's `mkdir(mode=…)` is masked by the process umask on POSIX, so the explicit `chmod` is required to guarantee the mode), or by `path.mkdir()` followed by `os.chmod(path, 0o700)` — pick one in the implementation and use it consistently. The introspect handler does **not** re-chmod the parent on every call: the mode is a per-run property, established once at `create_run` time. The other run subdirs (`inputs`, `logs`, `build`, `target`, `tests`, `debug`, `summaries`) keep umask defaults; only `sensitive/` is hardened.

#### 6.1a Backwards compatibility for legacy runs

Runs whose `create_run` predates the R2-F4 change have `<run>/sensitive/` at the system umask (typically `0755`). The introspect handler does **not** migrate them — chmod-on-call would muddle the per-run-property invariant and risks fighting an operator who deliberately tightened or loosened the mode out of band. Operators who need the hardened mode on a legacy run should either re-run `kernel.create_run` (the simplest path; the introspect call budget and per-run isolation make this the recommended workflow) or `chmod 0700` the directory by hand. The mode is asserted in tests against fresh runs only (see §9.1 `test_sensitive_run_subdir_is_mode_0700`).

`stderr.log` is streamed to disk during the call as raw bytes, then rewritten in-place under the manifest lock with the text-mode `Redactor` applied (see §6.3). `stdout.json` is **not** streamed verbatim: SSH stdout is captured to a temporary path during the call, the host then parses it as JSON, passes the parsed structure through `Redactor.redact_value`, and persists the result via `json.dumps` to `stdout.json`. On a wrapper crash where stdout is not valid JSON, the temporary capture is moved to `<run>/sensitive/debug/introspect/<call_id>/stdout.raw` instead and `stdout.json` is absent for that call — the raw file may carry secrets that the text-mode redactor cannot reliably scrub from unstructured binary, so it stays under `sensitive/`. `result.json` is written after the host finishes post-processing. `request.json` and `wrapper.skeleton.py` are present on every successful admission; later files are present whenever the call reached SSH.

### 6.2 Step record

```python
StepResult(
  name=f"introspect:{call_id}",
  status=StepStatus.SUCCEEDED | FAILED,
  started_at=..., finished_at=...,
  artifacts=[ArtifactRef("request.json", ..., sensitive=False),
             ArtifactRef("wrapper.skeleton.py", ..., sensitive=False),
             ArtifactRef("sensitive/debug/introspect/<call_id>/wrapper.py",
                         ..., sensitive=True),     # full user script, mode 0600
             ArtifactRef("stdout.json", ..., sensitive=False),
             # ArtifactRef("sensitive/debug/introspect/<call_id>/stdout.raw",
             #             ..., sensitive=True) — only on wrapper_crash
             ArtifactRef("stderr.log", ..., sensitive=False),
             ArtifactRef("result.json", ..., sensitive=False)],
  error_category=None | ErrorCategory.X,
  diagnostic=None | "<short redacted summary>",
  details={
    "call_id": call_id, "build_id": "...",
    "timeout_seconds": 30, "wrapper_exit_code": 0,
    "duration_ms": 142, "prelude_ms": 35, "truncated": {...},
    "ssh_user": "root", "outcome_status": "ok"|"error"|"drgn_open_failure"|"drgn_version_skew"|...,
  },
)
```

`ArtifactRef.sensitive` is the existing flag at `domain.py:73`; the introspect handler is the first consumer that splits its artifacts across the boundary. The response's `artifacts` list omits every `sensitive=True` entry (§5.2 step 12), so agents never see paths under `<run>/sensitive/`, but operators with filesystem access to the run dir still find everything.

The manifest grows linearly with introspect-call count. The growth is capped at `MAX_INTROSPECT_CALLS_PER_RUN` per run (default 1000, see §5.2 step 4a) — beyond that, the handler fails with `CONFIGURATION_ERROR` / `manifest_call_budget_exhausted` and the operator must start a fresh `kernel.create_run`. The cap exists because each call rewrites the full `manifest.json` under `_manifest_lock`, so an unbounded call count is O(N²) in I/O and lock-hold time. The cap is a budget, not pagination: agents that need more than `MAX_INTROSPECT_CALLS_PER_RUN` introspect calls in a single workflow should split work across multiple runs.

### 6.3 Redaction policy

Identical to `LocalSshTestProvider`:

```python
redactor = Redactor(secret_values=[rootfs_profile.ssh_key_ref]
                    if rootfs_profile.ssh_key_ref else [])
```

Applied to:
- `outcome.error_message`, `outcome.error_type`, `outcome.traceback`
- Each string inside `emits` entries (recursive walk via `redactor.redact_value`)
- `user_stdout_snippet`, `drgn_stderr_snippet`
- Every response-level diagnostic string, including the **sudo preflight** diagnostic (§5.2 step 5) and the **`ssh_failure`** diagnostic (§5.2 step 9) — both **redact first, then truncate** captured remote stderr to 256 bytes before embedding it. The ordering is load-bearing (R2-F3): `Redactor.redact_text` does literal substring replacement against `secret_values`, so truncating before redacting could split an `ssh_key_ref` and leave an unmatched prefix in the diagnostic. Step 5 (§5.2) and step 9 (§5.2) each make this ordering explicit; this bullet is the cross-cutting statement of the same rule.
- The persisted `stdout.json` and `stderr.log` (not only the in-response snippets — the artifact files are part of the manifest's referenced surface, and the contract is that secrets never reach the manifest)
- `request.json`'s `script` field (in case a credential was pasted in)

Mechanism per file:

- **`stdout.json`** is persisted as `json.dumps(redactor.redact_value(parsed))`, where `parsed` is the wrapper's JSON document loaded via `json.loads(raw_stdout_bytes)`. `Redactor.redact_value` walks dicts/lists/tuples recursively and redacts every string node it encounters, so secrets that appear inside `emits` payloads or `outcome.error_message` are scrubbed before persistence. The raw wire bytes are never written to the manifest path. If `json.loads` raises (`wrapper_crash` path), the raw stdout capture is moved to `<run>/sensitive/debug/introspect/<call_id>/stdout.raw` (mode `0600`) instead and `stdout.json` is absent for that call. The raw file is referenced by a `sensitive=True` `ArtifactRef` in the step record and is **not** surfaced in the response's `artifacts`.
- **`stderr.log`** is persisted as `redactor.redact_text(raw_stderr_bytes.decode("utf-8", errors="replace"))`. Line-oriented structure is preserved so that drgn diagnostics remain greppable.
- **`result.json`** is the post-redaction response object; nothing additional is applied at write time.
- **`request.json`** is the redacted `DebugIntrospectRunRequest` (notably, `script` is run through `redactor.redact_text`).
- **`wrapper.py`** contains the user script **verbatim** (base64 is transport encoding, not redaction — `base64.b64decode` is a one-line reversal). It is written under `<run>/sensitive/debug/introspect/<call_id>/` with mode `0600` and is **not** surfaced in the response's `artifacts` list; the response references `wrapper.skeleton.py` instead, which carries the rendered wrapper with the script body replaced by `# <user script: sha256:...; full source under sensitive/debug/introspect/<call_id>/wrapper.py>`. Operators with filesystem access to the run dir can reconstruct the original script from `wrapper.py`; this is the same trust posture as `<run>/sensitive/` everywhere else in the project. `request.json`'s redactor pass is the canonical place where secrets get scrubbed from the agent-visible script representation; secrets inside `wrapper.py` itself are not scrubbed and the file's confidentiality depends on filesystem permissions.
- **`wrapper.skeleton.py`** is the agent-visible companion to `wrapper.py`: the same rendered template, but with the user-script base64 body replaced by a sha256 reference to the user script. The canonical definition of that sha256 is fixed (R2-F7): it is `hashlib.sha256(base64.b64decode(USER_SCRIPT_B64)).hexdigest()` — i.e. the sha256 of the **decoded user script bytes**, *not* of the rendered wrapper file. Rationale: the user script is the only thing that changes per call; hashing the rendered wrapper would force a new digest every time the template churns and break forensic cross-run comparisons. The skeleton carries no plaintext from the script and is safe to surface in the response's `artifacts` list. The same definition is repeated at §5.2 step 8 (the placeholder template the renderer writes) and §6.1 (the on-disk layout description); all three must agree.

Not applied to: file paths inside `ArtifactRef`, `build_id` (opaque hex), structural booleans/ints/UUIDs.

## 7. Build-handler change (minimal `KernelProvenance` consumer)

The introspect handler needs an authoritative expected `build_id` to compare against. The full `KernelProvenance` schema and the module-debuginfo locator live in #53; #51 needs only the build_id.

Changes inside `providers/local_kernel_build.py`:

1. After a successful kernel build, run `readelf -n <vmlinux>` (already a host prerequisite — ships with binutils) and parse the `.note.gnu.build-id` note. R2-F6: the helper raises distinct exception types on the two failure causes so the caller can map each to its own `ErrorCategory` without inspecting auxiliary state:

   ```python
   class ReadelfUnavailable(Exception):
       """readelf failed (missing binary, non-zero exit, timed out)."""

   class BuildIdMissing(Exception):
       """readelf ran cleanly but the vmlinux carries no .note.gnu.build-id."""

   def _extract_build_id(vmlinux: Path) -> str:
       try:
           proc = subprocess.run(
               ["readelf", "-n", str(vmlinux)],
               capture_output=True, text=True, check=False, timeout=10,
           )
       except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
           raise ReadelfUnavailable(str(exc)) from exc
       if proc.returncode != 0:
           raise ReadelfUnavailable(
               f"readelf exit={proc.returncode}: {proc.stderr[:200]}"
           )
       for line in proc.stdout.splitlines():
           m = re.match(r"\s*Build ID:\s*([0-9a-fA-F]+)", line)
           if m:
               return m.group(1).lower()
       raise BuildIdMissing(f"no Build ID note in {vmlinux}")
   ```

2. Persist `build_id` into `build_result.details["build_id"]`. R2-F6: the caller catches each exception type explicitly and maps it to a distinct failure mode — no `None`-return reuse, no auxiliary state to inspect:
   - `ReadelfUnavailable` (binary missing, non-zero exit, or `subprocess.TimeoutExpired`) → `INFRASTRUCTURE_FAILURE` / `readelf_unavailable`, build step recorded as `FAILED`.
   - `BuildIdMissing` (`readelf` exited 0 but no `Build ID:` line was found) → `BUILD_FAILURE` / `build_id_missing`, build step recorded as `FAILED`. (A kernel built without `--build-id` cannot satisfy the introspect provenance contract, so a "successful" build here would be a contract violation. Operators that need to opt out of this check should rebuild with `LD_BUILD_ID=sha1` or equivalent.)

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
- `test_sudo_preflight_diagnostic_is_redacted` (FakeSshRunner returns the literal `b"sudo: password required for <ssh_key_ref>"` on stderr for the preflight argv; assert the response diagnostic does **not** contain the configured `ssh_key_ref` — covers F7). **Boundary case (R2-F3):** configure the FakeSshRunner so the stderr places `ssh_key_ref` straddling byte 256 of the captured probe stderr; assert the redacted-then-truncated diagnostic contains the `[REDACTED]` token in place of the secret and **no** partial prefix or suffix of the secret. Both arrangements (the original "contained" case and the new "straddles 256 B" case) prove the redact-before-truncate ordering required by §5.2 step 5.
- `test_malformed_build_id_in_manifest_rejected` (manifest's `steps.build.details.build_id` is set to `"not-hex!"`; handler returns `INFRASTRUCTURE_FAILURE` / `provenance_corrupt`; SSH is never invoked — covers F4)
- `test_call_budget_exhausted` (manifest's `step_results` is pre-populated with `MAX_INTROSPECT_CALLS_PER_RUN` entries matching `^introspect:`; handler returns `CONFIGURATION_ERROR` / `manifest_call_budget_exhausted`; no SSH; no new `<call_id>/` directory — covers F5)
- `test_wrapper_py_written_under_sensitive_with_0600` (after a successful call, assert `<run>/sensitive/debug/introspect/<call_id>/wrapper.py` exists with mode `0600`; this is the leaf-file assertion — covers F2)
- `test_sensitive_run_subdir_is_mode_0700` (R2-F4: exercise `ArtifactStore.create_run` directly — no introspect call needed — and assert `<run>/sensitive/` is mode `0700` regardless of the host umask; coverage of the parent-directory contract does not depend on the introspect path, since the mode is established at run-creation time)
- `test_response_artifacts_omit_wrapper_py` (response `artifacts` list contains `wrapper.skeleton.py` but not `wrapper.py`; the step record's `artifacts` includes a `sensitive=True` `ArtifactRef` for `wrapper.py` — covers F2)
- `test_no_orphan_artifacts_on_admission_failure` (admission raises `target_halted`; assert no `<call_id>/` directory exists under either `<run>/debug/introspect/` or `<run>/sensitive/debug/introspect/`; the response has no `call_id` field — covers F6)
- `test_prelude_warning_at_threshold_boundary` (configure FakeSshRunner to return a wrapper JSON with `prelude_ms = 4000` and `timeout_seconds = 10`; assert the integer-only comparison `4000 * 100 >= PRELUDE_WARNING_FRACTION_PCT * 10 * 1000` (= `400_000 >= 400_000`, exactly the 40 % threshold) triggers the soft warning and the response `diagnostic` contains it; also assert the `prelude_ms = 3999` case (= `399_900 >= 400_000` is false) does not produce the warning — covers R2-F1 and the pre-existing prelude-budget instrumentation)
- `test_budget_soft_cap_overshoot_under_concurrency` (R2-F5: pre-populate `manifest.step_results` with `MAX_INTROSPECT_CALLS_PER_RUN - 1` entries matching `^introspect:`; dispatch two concurrent handler invocations with mutually-distinct `call_id`s and synchronize them past §5.2 step 4a using a shared `threading.Event`; assert both calls complete with `status="ok"`, the manifest ends with `count == MAX_INTROSPECT_CALLS_PER_RUN + 1` (an overshoot of one), and a third caller dispatched afterwards is rejected at *its* step 4a with `CONFIGURATION_ERROR` / `manifest_call_budget_exhausted` — proves the soft-cap framing in §5.3 and the removal of the post-lock recheck at step 13)

**Build-handler tests (R2-F6) — added to `tests/test_local_kernel_build.py` in the implementation PR for #51, not this iteration:**
- `test_readelf_unavailable_fails_build` — patch `subprocess.run` to raise `FileNotFoundError`; assert `_extract_build_id` raises `ReadelfUnavailable`, the build step's terminal status is `FAILED`, and the `StepResult.error_category` / `code` are `INFRASTRUCTURE_FAILURE` / `readelf_unavailable`.
- `test_build_id_missing_fails_build` — patch the helper so `readelf` succeeds (exit 0) but no `Build ID:` line appears in stdout; assert `_extract_build_id` raises `BuildIdMissing`, the build step's terminal status is `FAILED`, and the `StepResult.error_category` / `code` are `BUILD_FAILURE` / `build_id_missing`.

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
- `test_wrapper_helper_namespace_contains_expected_subset` — assert at least `list_for_each_entry`, `for_each_task`, and `dmesg` are present in the user namespace, and that the renamed wrapper-private globals (`_li_pre_helpers`, `_li_drgn_helper_names`, `_li_emit_buffer`, `_li_emit_overflow`, `_li_result`, `_li_caps`, `_li_truncate`, `_li_t_prelude_start`) are NOT exposed in the user namespace. Covers R2-F8.
- `test_wrapper_handles_drgn_helper_shadowing_wrapper_private_name` (R2-F8) — monkey-patch the stub `drgn.helpers.linux` module so the wildcard import exposes a top-level `result` symbol (the legacy wrapper-private name). Assert: (a) the wrapper still emits a complete JSON document with `outcome.status="ok"` on the happy path, (b) the user namespace's `result` is the helper-defined symbol (not the wrapper's), proving the rename eliminated the shadowing class entirely.
- `test_user_script_sys_exit_does_not_spoof_timeout` — user script does `sys.exit(124)`; the wrapper's BaseException handler catches the resulting `SystemExit`, the tail JSON write runs through the `try/finally`, and the wrapper exits **6** (`wrapper_complete`) with `outcome.status="error"` and `outcome.error_type="SystemExit"`. The process exit code is **not** 124, so the host cannot misclassify the call as `introspect_timeout`. Covers F1.
- `test_wrapper_truncates_error_message` — user script raises an exception whose `str(exc)` is 32 KiB; assert `result["outcome"]["error_message"]` has length `CAPS["error_message"]` (4096), `result["truncated"]["error_message"]` is `True`, and the wrapper still exits **6** with a valid JSON document. Covers F3.
- `test_wrapper_drgn_version_skew_exits_3` — stub `prog.main_module` to raise `AttributeError`; assert exit code 3, `outcome.status="drgn_version_skew"`, `outcome.error_type="AttributeError"`, and the document carries a valid JSON payload (the host parses JSON first per §4.3). Covers F8.
- `test_wrapper_always_emits_json_on_happy_path` — instrument the wrapper so the final `sys.stdout.write` is invoked; assert exit code 6 and that stdout is a complete JSON document. Sanity check for the F1 `try/finally`.
- `test_wrapper_tail_serialization_failure_emits_minimal_json` (R2-F2) — monkey-patch `json.dumps` so the first call inside the tail `try:` block raises `RuntimeError("forced")` but the recovery call inside the inner `except BaseException:` succeeds. Assert: (a) the wrapper exits with code 6 (the `finally` still runs), (b) stdout is a valid minimal JSON document with `outcome.status == "wrapper_internal_error"`, `outcome.error_type == "RuntimeError"`, `outcome.error_message == "forced"`, `truncated.wrapper_internal_error == True`, and (c) `call_id` and `build_id` carry through from the in-flight `_li_result`. Companion: simulate a host parsing the document and assert the host maps it to `INFRASTRUCTURE_FAILURE` / `wrapper_crash` per §4.3.

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
| All persisted artifacts/responses pass through `Redactor()` — including pre-SSH diagnostics that may carry remote stderr (sudo preflight, `ssh_failure`) | `test_redactor_applied_to_emits_and_snippets` (unit) + `test_sudo_preflight_diagnostic_is_redacted` (unit) |

## 11. Open risks

Worth surfacing in the PR description; not blocking on this spec.

0. **`allow_write=false` is a label, not a sandbox.** As documented in §3.5, the flag rejects `allow_write=true` but does not constrain what `allow_write=false` scripts can do — `exec()` with full builtins still lets the script open arbitrary files, `import os`, etc. The current trust boundary is "agents already authorized to call `debug.introspect.run` against this target." Since the rendered `wrapper.py` is now persisted under `<run>/sensitive/` (§6.1) with mode `0600`, the script body's trust boundary is filesystem-level on the host: anyone with read access to the run directory can reconstruct the script regardless of `allow_write`. Sandboxing the *target-side* execution belongs to #56.
1. **`drgn.main_module().build_id` is sourced from drgn's debuginfo resolution, not directly from `/sys/kernel/notes`.** Normally identical, but split-debuginfo edge cases could expose drift between "what drgn loaded symbols for" and "what's actually running." Acceptable for #51; #53 is the right place to harden it.
2. **Passwordless sudo assumption.** Same posture as smoke tests. A misconfigured target is now caught up-front by the sudo preflight in §5.2 step 5, which returns `CONFIGURATION_ERROR` / `sudo_requires_password` (with the preflight's stderr passed through the per-call `Redactor`) instead of letting the call fall off the end of the host timeout margin as `ssh_timeout`.
3. **`drgn` version drift on target.** Different distros ship varying drgn versions; the wrapper assumes recent-enough `Program.set_kernel()` / `load_default_debug_info()` / `main_module().build_id`. Real version-skew handling is #52. As a v0 detection mechanism the wrapper now exits **3** with `outcome.status="drgn_version_skew"` when the `prog.main_module().build_id` read raises (F8 in §4.2 / §4.3 / §3.3); agents see `INFRASTRUCTURE_FAILURE` / `drgn_version_skew` and can distinguish "drgn missing" (`drgn_open_failure`) from "drgn too old/new" (`drgn_version_skew`) without waiting for #52.
4. **A user script that just spins.** The timeout is the only bound on misbehaving scripts. Acceptable for read-only v0; write-mode in #56 will need more.
4a. **`timeout_seconds` covers the prelude as well as the script.** The user-visible `timeout_seconds` is enforced by target-side `timeout(1)` around the whole wrapper, so it covers both the drgn prelude (`set_kernel` + `load_default_debug_info`) and the script execution. On a slow target or with split debuginfo the prelude alone can take several seconds; callers should set `timeout_seconds` accordingly. The wrapper records `prelude_ms` separately so callers can tune it. The host emits a soft warning when the prelude consumed at least `PRELUDE_WARNING_FRACTION_PCT` (default **40**, surfaced as a named constant in `config.py`) of the user-visible budget, expressed as the integer-only comparison `prelude_ms * 100 >= PRELUDE_WARNING_FRACTION_PCT * timeout_seconds * 1000` (equivalently `prelude_ms >= 400 * timeout_seconds` at the default 40 % threshold; for the default 30 s timeout the warning fires at `prelude_ms >= 12_000`). The check runs **after** `result.json` is finalized — the check lives on the host, not the wrapper, so it can incorporate post-processing context. When the inequality holds the response `diagnostic` field gets a soft warning so this isn't a silent failure mode. The threshold uses the source `int` value (`timeout_seconds`) and `>=` rather than `>` against a float-derived value, eliminating the boundary edge case.
5. **Manifest growth is bounded by `MAX_INTROSPECT_CALLS_PER_RUN` (soft cap).** *Resolved in §5.2 step 4a (the only budget gate, deliberately unsynchronized) and step 13 (no post-lock recheck). The cap is a soft target, not a hard ceiling: under concurrent contention up to `(concurrent_calls - 1)` admitted calls can overshoot before the next caller is rejected, by design — the alternative is discarding completed target-side work, which is strictly worse than a one-shot rounding error on a 1000-call default. The full semantics, including the exact overshoot bound, live in §5.3 ("Soft-cap semantics for `MAX_INTROSPECT_CALLS_PER_RUN`"). The append helper is exposed as `RunManifest.append_step_result(...)` + `ArtifactStore.record_step_result(..., append=True)`, mirroring the existing `with_step_result()` layer split. Per-call introspect records cannot clobber each other or the singleton named steps (`build`, `boot`, `run_tests`, `debug`) because `record_step_result(append=True)` fails on a name collision.* Long-lived agent sessions that need more than `MAX_INTROSPECT_CALLS_PER_RUN` introspect calls must split work across runs; the cap is a budget, not pagination, and no `force_*` flag bypasses it. R2-F5 (cross-reference §5.3).
6. **Wrapper-size growth from base64 transfer.** Encoding the user script as base64 (§3.1) inflates it by ~33% over the wire. At the 256 KiB script cap that is ~342 KiB on the SSH stdin frame — well under any practical SSH limit, but worth flagging alongside the existing 256 KiB script cap so future raises know to consider the inflated wire size.

## 12. Coordination

- **interface-contracts.md** §3.3 (ssh-only tier, `required_caps` empty), §4.2 (provenance fail-loud), §5.3 (admission service is the single live-op gate), §5.6 rule 2 (ssh-tier `HALTED` fast-reject).
- **ADR 0006** (unified cancel-epoch state machine): live `debug.introspect.run` is the second ssh-tier consumer alongside `target.run_tests`. No new ADR — the design fits the established model.
- **Sibling issues:** #52 (prereq probe), #53 (full provenance + symbol resolution), #54 (curated helpers), #55 (vmcore), #56 (write-mode opt-in). #51 is the foundation they build on.
