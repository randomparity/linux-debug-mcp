"""local-drgn-introspect: live drgn-over-SSH introspection provider.

Spec: docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from string import Template

from linux_debug_mcp.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    ProviderOperationCapability,
    TargetKind,
)
from linux_debug_mcp.symbols.verify import BUILD_ID_RE

# Spec §3.1 pre-substitution validators. EXPECTED_BUILD_ID is host-validated
# hex from manifest.steps["build"].details["build_id"]. CALL_ID is a
# server-minted UUIDv4 hex.
_CALL_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Spec §3.1: 256 KiB script cap (enforced by the handler, not Pydantic).
SCRIPT_BYTE_CAP = 256 * 1024

RUNNER_DEFAULT_CAPS: dict[str, int] = {
    "emits": 100,
    "user_stdout": 256 * 1024,
    "traceback": 16 * 1024,
    "total_json": 1 * 1024 * 1024,
    "per_emit_bytes": 32 * 1024,
    "error_message": 4096,
}

# Spec §4 (shared-interpreter invariant): the single interpreter argv consumed
# by BOTH debug.introspect.run (server.debug_introspect_run_handler) and
# debug.introspect.check_prerequisites (the probe). drgn installed for an
# interpreter other than this one is reported missing by design, because the
# runner would equally fail to import it. The privilege prefix (``sudo`` for a
# non-root SSH login) is also part of the shared invocation; both paths build
# the full remote argv via server._target_python_remote_argv so the probe
# checks drgn/debuginfo at the same privilege level the runner will use.
TARGET_PYTHON_ARGV = ["python3", "-"]


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


# Spec §4.2 wrapper body — verbatim. The raw triple-quoted string preserves
# the ``${...}`` ``string.Template`` sigils literally.
_WRAPPER_PROLOGUE_LIVE = r"""import sys as _li_sys
import json as _li_json
import io as _li_io
import traceback as _li_traceback
import contextlib as _li_contextlib

_li_caps = ${CAPS_JSON}

def _li_truncate(s, cap):
    return (s[:cap], True) if len(s) > cap else (s, False)

_li_result = {"call_id": "${CALL_ID}", "build_id": None, "outcome": None,
              "emits": [], "user_stdout": "", "prelude_ms": 0,
              "truncated": {"emits": False, "user_stdout": False,
                            "traceback": False, "total_json": False,
                            "per_emit_size": False, "error_message": False}}

import time as _li_time
_li_t_prelude_start = _li_time.monotonic()

try:
    import drgn  # noqa: E402  -- module attribute, exposed to user namespace

    _li_pre_helpers = set(globals().keys()) | {
        "_li_pre_helpers", "_li_drgn_helper_names",
    }
    from drgn.helpers.linux import *  # noqa: F401,F403,E402
    _li_drgn_helper_names = set(globals().keys()) - _li_pre_helpers

${ALLOW_WRITE_SETUP}
    prog = _li_program_class()
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
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

_li_result["prelude_ms"] = int((_li_time.monotonic() - _li_t_prelude_start) * 1000)

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
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

if _li_result["build_id"] != "${EXPECTED_BUILD_ID}":
    _li_result["outcome"] = {"status": "provenance_mismatch",
                             "expected": "${EXPECTED_BUILD_ID}",
                             "actual": _li_result["build_id"]}
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(4)

"""

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

WRAPPER_TEMPLATE = Template(_WRAPPER_PROLOGUE_LIVE + _WRAPPER_BODY)


# ADR 0011 / #56: the live prologue's ${ALLOW_WRITE_SETUP} block. When write mode is off the
# program is a drgn.Program subclass whose write() raises the body's _li_WriteModeDisabled
# sentinel (caught -> write_mode_disabled outcome). A subclass — not a proxy — keeps the program
# a real Program (isinstance true, native reads, drgn C constructors accept it), so AC#1 holds.
# Both blocks are indented 4 spaces to sit inside the prologue's drgn-open `try:`.
_ALLOW_WRITE_SETUP_GUARDED = (
    "    class _li_GuardedProgram(drgn.Program):\n"
    "        def write(self, *_li_a, **_li_k):\n"
    "            raise _li_WriteModeDisabled('allow_write is false; drgn write APIs are disabled')\n"
    "    _li_program_class = _li_GuardedProgram"
)
_ALLOW_WRITE_SETUP_PLAIN = "    _li_program_class = drgn.Program"


def _allow_write_setup(allow_write: bool) -> str:
    return _ALLOW_WRITE_SETUP_PLAIN if allow_write else _ALLOW_WRITE_SETUP_GUARDED


# Spec §4.2 / ADR 0010: the offline prologue. Same _li_result shape and the same
# emit/output-framing _WRAPPER_BODY as the live path; only the drgn-open lines
# differ. Host paths arrive base64-encoded (decode-in-wrapper) so a confined-but-
# hostile filename cannot break out of a literal. Module debuginfo is loaded
# best-effort, one file at a time, so a single stripped .ko never poisons the batch.
_WRAPPER_PROLOGUE_VMCORE = r"""import sys as _li_sys
import json as _li_json
import io as _li_io
import traceback as _li_traceback
import contextlib as _li_contextlib
import base64 as _li_b64
import os as _li_os

_li_caps = ${CAPS_JSON}

def _li_truncate(s, cap):
    return (s[:cap], True) if len(s) > cap else (s, False)

_li_result = {"call_id": "${CALL_ID}", "build_id": None, "outcome": None,
              "emits": [], "user_stdout": "", "prelude_ms": 0, "warnings": [],
              "truncated": {"emits": False, "user_stdout": False,
                            "traceback": False, "total_json": False,
                            "per_emit_size": False, "error_message": False}}

_li_vmcore = _li_b64.b64decode("${VMCORE_PATH_B64}").decode("utf-8")
_li_vmlinux = _li_b64.b64decode("${VMLINUX_PATH_B64}").decode("utf-8")
_li_modules = _li_b64.b64decode("${MODULES_PATH_B64}").decode("utf-8") or None

import time as _li_time
_li_t_prelude_start = _li_time.monotonic()

try:
    import drgn  # noqa: E402  -- module attribute, exposed to user namespace

    _li_pre_helpers = set(globals().keys()) | {
        "_li_pre_helpers", "_li_drgn_helper_names",
    }
    from drgn.helpers.linux import *  # noqa: F401,F403,E402
    _li_drgn_helper_names = set(globals().keys()) - _li_pre_helpers

    prog = drgn.Program()
    prog.set_core_dump(_li_vmcore)
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_open_failure",
                             "error_type": etype,
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

_li_result["prelude_ms"] = int((_li_time.monotonic() - _li_t_prelude_start) * 1000)

try:
    _li_bid = prog.main_module().build_id
    _li_result["build_id"] = _li_bid.hex() if _li_bid else None
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_version_skew",
                             "error_type": etype,
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

if _li_result["build_id"] is None:
    _li_result["outcome"] = {"status": "provenance_unverifiable",
                             "detail": "vmcore carries no embedded build-id"}
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(4)

if _li_result["build_id"] != "${EXPECTED_BUILD_ID}":
    _li_result["outcome"] = {"status": "provenance_mismatch",
                             "expected": "${EXPECTED_BUILD_ID}",
                             "actual": _li_result["build_id"]}
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(4)

try:
    prog.load_debug_info([_li_vmlinux])
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_open_failure",
                             "error_type": etype,
                             "error_message": msg}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

if _li_modules:
    _li_ko = []
    for _li_dir, _, _li_files in _li_os.walk(_li_modules):
        for _li_name in _li_files:
            if _li_name.endswith(".ko.debug"):
                _li_ko.append(_li_os.path.join(_li_dir, _li_name))
    if not _li_ko:
        for _li_dir, _, _li_files in _li_os.walk(_li_modules):
            for _li_name in _li_files:
                if _li_name.endswith(".ko"):
                    _li_ko.append(_li_os.path.join(_li_dir, _li_name))
    if not _li_ko:
        _li_result["warnings"].append({"code": "modules_debuginfo_empty"})
    else:
        _li_loaded = 0
        for _li_path in _li_ko:
            try:
                prog.load_debug_info([_li_path])
                _li_loaded += 1
            except Exception:
                pass
        _li_result["warnings"].append(
            {"code": "modules_debuginfo_loaded" if _li_loaded else "modules_debuginfo_load_failed",
             "count": _li_loaded, "found": len(_li_ko)})

"""

VMCORE_WRAPPER_TEMPLATE = Template(_WRAPPER_PROLOGUE_VMCORE + _WRAPPER_BODY)


def _encode_path(value: str | None, *, field: str) -> str:
    """Base64-encode a confined host path for safe substitution (ADR 0010).

    ``confine_run_relative`` guarantees containment, not character safety, so a
    raw substitution would still be a literal-injection vector. Rejects a NUL
    byte and a non-UTF-8 path; ``None`` encodes the empty string (decoded back
    to ``None`` in the wrapper).
    """
    text = value or ""
    if "\x00" in text:
        raise WrapperRenderError(f"{field} contains a NUL byte")
    try:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    except UnicodeEncodeError as exc:
        raise WrapperRenderError(f"{field} is not valid UTF-8: {exc}") from exc


def render_vmcore_wrapper(
    *,
    user_script: str,
    expected_build_id: str,
    call_id: str,
    vmcore_path: str,
    vmlinux_path: str,
    modules_path: str | None,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
) -> str:
    """Render the offline vmcore wrapper (spec §4.2). Paths are base64-encoded
    into pure-ASCII literals (ADR 0010); only the build-id and call-id are
    regex-validated before substitution.
    """
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc
    return VMCORE_WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=base64.b64encode(user_script.encode("utf-8")).decode("ascii"),
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=base64.b64encode(args_json.encode("utf-8")).decode("ascii"),
        CAPS_JSON=json.dumps(merged_caps),
        VMCORE_PATH_B64=_encode_path(vmcore_path, field="vmcore_path"),
        VMLINUX_PATH_B64=_encode_path(vmlinux_path, field="vmlinux_path"),
        MODULES_PATH_B64=_encode_path(modules_path, field="modules_path"),
    )


def render_vmcore_wrapper_skeleton(
    *,
    expected_build_id: str,
    call_id: str,
    user_script_sha256_hex: str,
    vmcore_path: str,
    vmlinux_path: str,
    modules_path: str | None,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
) -> str:
    """Agent-visible companion to the vmcore wrapper: the user-script body is a
    sha256 pointer, safe to surface as a non-sensitive artifact (spec §4.3).
    """
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc
    placeholder = (
        f"# <user script: sha256:{user_script_sha256_hex}; "
        f"full source under sensitive/debug/introspect/{call_id}/wrapper.py>"
    )
    return VMCORE_WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=base64.b64encode(placeholder.encode("utf-8")).decode("ascii"),
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=base64.b64encode(args_json.encode("utf-8")).decode("ascii"),
        CAPS_JSON=json.dumps(merged_caps),
        VMCORE_PATH_B64=_encode_path(vmcore_path, field="vmcore_path"),
        VMLINUX_PATH_B64=_encode_path(vmlinux_path, field="vmlinux_path"),
        MODULES_PATH_B64=_encode_path(modules_path, field="modules_path"),
    )


def render_wrapper(
    *,
    user_script: str,
    expected_build_id: str,
    call_id: str,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
    allow_write: bool = False,
) -> str:
    """Render the on-target wrapper.

    Spec §3.1: host validates the non-user values BEFORE substitution. A
    failing regex on ``expected_build_id`` is ``INFRASTRUCTURE_FAILURE`` /
    ``provenance_corrupt`` at the handler layer (manifest carries malformed
    hex). A failing regex on ``call_id`` is an internal bug — should never
    happen because the caller mints UUIDv4 hex.

    ``user_script`` is base64-encoded and substituted into a pure-ASCII
    literal, so triple quotes, NUL bytes, and ``${...}`` sigils inside the
    user script cannot escape their enclosing string.

    ``args_json`` is a JSON object string injected into the user namespace as
    ``args``. Defaults to ``"{}"`` (empty dict). ``caps`` overrides individual
    runner caps; unknown keys or non-positive values raise ``WrapperRenderError``.

    ``allow_write`` (ADR 0011 / #56): when False (default) the program is a
    ``drgn.Program`` subclass whose ``write()`` raises ``_li_WriteModeDisabled``
    (surfaced as a ``write_mode_disabled`` outcome); when True the plain
    ``drgn.Program`` is used and writes flow to drgn.
    """
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc
    encoded = base64.b64encode(user_script.encode("utf-8")).decode("ascii")
    args_b64 = base64.b64encode(args_json.encode("utf-8")).decode("ascii")
    # `substitute` (not `safe_substitute`) raises KeyError on unknown
    # placeholders — defensive against future template churn.
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=args_b64,
        CAPS_JSON=json.dumps(merged_caps),
        ALLOW_WRITE_SETUP=_allow_write_setup(allow_write),
    )


def user_script_sha256(user_script: str) -> str:
    """Spec §6.3 R2-F7: sha256 of the *decoded user script bytes*, NOT of the
    rendered wrapper. Used in the agent-visible ``wrapper.skeleton.py``
    placeholder.
    """
    return hashlib.sha256(user_script.encode("utf-8")).hexdigest()


def render_wrapper_skeleton(
    *,
    expected_build_id: str,
    call_id: str,
    user_script_sha256_hex: str,
    args_json: str = "{}",
    caps: dict[str, int] | None = None,
) -> str:
    """Render the agent-visible companion to wrapper.py (spec §6.1, §6.3).

    Same template, same regex-validated header values, but the user-script
    body is replaced by a sha256 reference. The skeleton carries no
    plaintext from the script and is safe to surface in the response's
    ``artifacts`` list.

    ``args_json`` and ``caps`` mirror the same parameters on ``render_wrapper``
    so the skeleton reflects the actual caps profile used for the call.
    """
    if not BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    merged_caps = _merge_and_validate_caps(caps)
    try:
        json.loads(args_json)
    except json.JSONDecodeError as exc:
        raise WrapperRenderError(f"args_json must be valid JSON; got {args_json!r}: {exc}") from exc
    placeholder = (
        f"# <user script: sha256:{user_script_sha256_hex}; "
        f"full source under sensitive/debug/introspect/{call_id}/wrapper.py>"
    )
    encoded = base64.b64encode(placeholder.encode("utf-8")).decode("ascii")
    args_b64 = base64.b64encode(args_json.encode("utf-8")).decode("ascii")
    # Skeleton mirrors the default read-only render (ADR 0011 §6): the guarded
    # setup keeps the agent-visible skeleton faithful to a default call.
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
        ARGS_B64=args_b64,
        CAPS_JSON=json.dumps(merged_caps),
        ALLOW_WRITE_SETUP=_allow_write_setup(False),
    )


@dataclass(frozen=True)
class LocalDrgnIntrospectProvider:
    """Marker for the local drgn-introspect capability.

    The actual SSH invocation, wrapper render, and result parsing live in the
    handler (``server.debug_introspect_run_handler``) so they can share the
    ``_record_terminal_build_result``-style manifest-lock retry pattern and
    the redaction helpers. This provider object exists so the registry can
    declare ``local-drgn-introspect`` as a capability without bundling logic
    the handler already owns.
    """

    name: str = "local-drgn-introspect"


def local_drgn_introspect_capability() -> ProviderCapability:
    """Factory used by ``providers/plugins.py``. Spec §3.4 / §2 / ADR 0010.

    The live ssh-tier ops are ``concurrent_safe=False`` (admission-gated); the
    offline vmcore ops are ``concurrent_safe=True`` (interface-contracts §5.6
    rule 3 — never gated), advertised via per-operation overrides.
    """
    live_semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=False,
    )
    vmcore_semantics = OperationSemantics(
        idempotent=False,
        retryable=True,
        destructive=False,
        cancelable=True,
        concurrent_safe=True,
    )
    vmcore_ops = {"debug.introspect.from_vmcore", "debug.introspect.from_vmcore_helper"}
    operations = [
        "debug.introspect.run",
        "debug.introspect.check_prerequisites",
        "debug.introspect.helper",
        "debug.introspect.from_vmcore",
        "debug.introspect.from_vmcore_helper",
    ]
    return ProviderCapability(
        provider_name="local-drgn-introspect",
        provider_version="0.2.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=operations,
        required_host_tools=["ssh"],
        destructive_permissions=[],
        access_methods=["ssh"],
        semantics=live_semantics,
        operation_capabilities=[
            ProviderOperationCapability(
                operation=op,
                semantics=(vmcore_semantics if op in vmcore_ops else live_semantics),
            )
            for op in operations
        ],
    )
