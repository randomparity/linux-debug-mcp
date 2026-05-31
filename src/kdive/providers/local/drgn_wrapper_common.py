from __future__ import annotations

import hashlib
import json
import re

# Spec §3.1 pre-substitution validators. EXPECTED_BUILD_ID is host-validated
# hex from manifest.steps["build"].details["build_id"]. CALL_ID is a
# server-minted UUIDv4 hex.
_CALL_ID_RE = re.compile(r"^[0-9a-f]{32}$")

RUNNER_DEFAULT_CAPS: dict[str, int] = {
    "emits": 100,
    "user_stdout": 256 * 1024,
    "traceback": 16 * 1024,
    "total_json": 1 * 1024 * 1024,
    "per_emit_bytes": 32 * 1024,
    "error_message": 4096,
}


class WrapperRenderError(ValueError):
    """Raised when a non-user template input fails its host-side
    pre-substitution regex check.

    The user ``script`` field cannot trigger this because it is base64-encoded
    into a pure-ASCII literal before substitution (spec §3.1).
    """


def _merge_and_validate_caps(caps: dict[str, int] | None) -> dict[str, int]:
    """Merge caller overrides onto the six-key runner defaults; reject unknown
    keys and non-positive ints. The wrapper indexes all six keys (incl. on
    early exception paths) so the rendered set must be complete.
    """
    merged = dict(RUNNER_DEFAULT_CAPS)
    for key, value in (caps or {}).items():
        if key not in RUNNER_DEFAULT_CAPS:
            raise WrapperRenderError(f"unknown cap key {key!r}; allowed: {sorted(RUNNER_DEFAULT_CAPS)}")
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise WrapperRenderError(f"cap {key!r} must be a positive int; got {value!r}")
        merged[key] = value
    return merged


_WRAPPER_BODY = r"""class _li_WriteModeDisabled(Exception):
    pass

_li_emit_buffer = []
_li_emit_overflow = False

def emit(obj):
    global _li_emit_overflow
    if len(_li_emit_buffer) >= _li_caps["emits"]:
        _li_emit_overflow = True
        return
    try:
        encoded = _li_json.dumps(obj)
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

user_stdout = _li_io.StringIO()
namespace = {
    "prog": prog, "emit": emit, "drgn": drgn,
    "__name__": "__introspect__", "__builtins__": __builtins__,
}
for name in _li_drgn_helper_names:
    namespace[name] = globals()[name]

import base64 as _li_base64
namespace["args"] = _li_json.loads(_li_base64.b64decode("${ARGS_B64}").decode("utf-8"))
USER_SCRIPT_B64 = "${USER_SCRIPT_B64}"
try:
    compiled = compile(
        _li_base64.b64decode(USER_SCRIPT_B64).decode("utf-8"),
        "<introspect>", "exec",
    )
except SyntaxError as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    _li_result["outcome"] = {"status": "script_compile_error",
                             "error_type": "SyntaxError",
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(5)

with _li_contextlib.redirect_stdout(user_stdout):
    try:
        exec(compiled, namespace)
        _li_result["outcome"] = {"status": "ok"}
    except _li_WriteModeDisabled as exc:
        msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
        _li_result["outcome"] = {"status": "write_mode_disabled",
                                 "error_message": msg}
        _li_result["truncated"]["error_message"] = msg_trunc
    except BaseException as exc:
        tb, tb_trunc = _li_truncate(_li_traceback.format_exc(), _li_caps["traceback"])
        msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
        etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
        _li_result["outcome"] = {"status": "error",
                                 "error_type": etype,
                                 "error_message": msg, "traceback": tb}
        _li_result["truncated"]["traceback"] = tb_trunc
        _li_result["truncated"]["error_message"] = msg_trunc

try:
    _li_result["emits"] = _li_emit_buffer
    _li_result["truncated"]["emits"] = _li_emit_overflow
    out, trunc = _li_truncate(user_stdout.getvalue(), _li_caps["user_stdout"])
    _li_result["user_stdout"] = out
    _li_result["truncated"]["user_stdout"] = trunc

    payload = _li_json.dumps(_li_result)
    while len(payload) > _li_caps["total_json"] and _li_result["emits"]:
        _li_result["emits"].pop()
        _li_result["truncated"]["total_json"] = True
        payload = _li_json.dumps(_li_result)
    if len(payload) > _li_caps["total_json"]:
        _li_result["user_stdout"] = ""
        _li_result["truncated"]["user_stdout"] = True
        payload = _li_json.dumps(_li_result)
    _li_sys.stdout.write(payload)
except BaseException as exc:
    try:
        _li_sys.stdout.write(_li_json.dumps({
            "call_id": _li_result.get("call_id"),
            "outcome": {"status": "wrapper_internal_error",
                        "error_type": type(exc).__name__,
                        "error_message": str(exc)[:_li_caps["error_message"]]},
            "truncated": {"wrapper_internal_error": True},
            "build_id": _li_result.get("build_id"),
            "emits": [], "user_stdout": "",
        }))
    except BaseException:
        pass
finally:
    _li_sys.exit(6)
"""


def _validate_args_json(args_json: str) -> None:
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc


def user_script_sha256(user_script: str) -> str:
    """Spec §6.3 R2-F7: sha256 of the decoded user script bytes."""
    return hashlib.sha256(user_script.encode("utf-8")).hexdigest()
