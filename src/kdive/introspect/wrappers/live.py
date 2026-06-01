from __future__ import annotations

import base64
import json
from string import Template

from kdive.introspect.wrappers.common import (
    _CALL_ID_RE,
    _WRAPPER_BODY,
    WrapperRenderError,
    _merge_and_validate_caps,
    _validate_args_json,
)
from kdive.symbols.verify import BUILD_ID_RE

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

_li_drgn_version = None
try:
    import drgn  # noqa: E402  -- module attribute, exposed to user namespace
    _li_drgn_version = getattr(drgn, "__version__", None)

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
                             "error_message": msg,
                             "drgn_version": _li_drgn_version}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

_li_result["prelude_ms"] = int((_li_time.monotonic() - _li_t_prelude_start) * 1000)

# ADR 0039: resolve the build-id first, then split the failure modes. An
# AttributeError is a genuine drgn module-API/version gap (drgn_version_skew);
# any other exception is drgn raising while resolving the module
# (drgn_api_incompatible -- e.g. the drgn >= 0.2 LookupError before discovery).
# A resolved-but-None build-id is provenance_unverifiable, not a .hex()-on-None
# AttributeError misreported as version skew.
try:
    _li_build_id = prog.main_module().build_id
except AttributeError as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_version_skew",
                             "error_type": etype,
                             "error_message": msg,
                             "drgn_version": _li_drgn_version}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)
except Exception as exc:
    msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
    etype, _ = _li_truncate(type(exc).__name__, _li_caps["error_message"])
    _li_result["outcome"] = {"status": "drgn_api_incompatible",
                             "error_type": etype,
                             "error_message": msg,
                             "drgn_version": _li_drgn_version}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)
else:
    _li_result["build_id"] = _li_build_id.hex() if _li_build_id else None

if _li_result["build_id"] is None:
    _li_result["outcome"] = {"status": "provenance_unverifiable",
                             "detail": "target reports no build-id"}
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
    _validate_args_json(args_json)
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
    _validate_args_json(args_json)
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
