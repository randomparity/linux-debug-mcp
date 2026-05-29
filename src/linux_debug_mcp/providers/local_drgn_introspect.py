"""local-drgn-introspect: live drgn-over-SSH introspection provider.

Spec: docs/superpowers/specs/2026-05-28-debug-introspect-run-design.md
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from string import Template

from linux_debug_mcp.domain import (
    ImplementationState,
    OperationSemantics,
    ProviderCapability,
    TargetKind,
)

# Spec §3.1 pre-substitution validators. EXPECTED_BUILD_ID is host-validated
# hex from manifest.steps["build"].details["build_id"]. CALL_ID is a
# server-minted UUIDv4 hex.
_BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,}$")
_CALL_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Spec §3.1: 256 KiB script cap (enforced by the handler, not Pydantic).
SCRIPT_BYTE_CAP = 256 * 1024

# Spec §4 (shared-interpreter invariant): the single interpreter invocation
# consumed by BOTH debug.introspect.run (server.debug_introspect_run_handler)
# and debug.introspect.check_prerequisites (the probe). drgn installed for an
# interpreter other than this one is reported missing by design, because the
# runner would equally fail to import it.
TARGET_PYTHON_ARGV = ["python3", "-"]


class WrapperRenderError(ValueError):
    """Raised when a non-user template input fails its host-side
    pre-substitution regex check.

    The user ``script`` field cannot trigger this because it is base64-encoded
    into a pure-ASCII literal before substitution (spec §3.1).
    """


# Spec §4.2 wrapper body — verbatim. The raw triple-quoted string preserves
# the ``${...}`` ``string.Template`` sigils literally.
WRAPPER_TEMPLATE = Template(r"""import sys as _li_sys
import json as _li_json
import io as _li_io
import traceback as _li_traceback
import contextlib as _li_contextlib

_li_caps = {"emits": 100, "user_stdout": 256 * 1024, "traceback": 16 * 1024,
            "total_json": 1 * 1024 * 1024, "per_emit_bytes": 32 * 1024,
            "error_message": 4096}

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
""")


def render_wrapper(*, user_script: str, expected_build_id: str, call_id: str) -> str:
    """Render the on-target wrapper.

    Spec §3.1: host validates the non-user values BEFORE substitution. A
    failing regex on ``expected_build_id`` is ``INFRASTRUCTURE_FAILURE`` /
    ``provenance_corrupt`` at the handler layer (manifest carries malformed
    hex). A failing regex on ``call_id`` is an internal bug — should never
    happen because the caller mints UUIDv4 hex.

    ``user_script`` is base64-encoded and substituted into a pure-ASCII
    literal, so triple quotes, NUL bytes, and ``${...}`` sigils inside the
    user script cannot escape their enclosing string.
    """
    if not _BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {_BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    encoded = base64.b64encode(user_script.encode("utf-8")).decode("ascii")
    # `substitute` (not `safe_substitute`) raises KeyError on unknown
    # placeholders — defensive against future template churn.
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
    )


def user_script_sha256(user_script: str) -> str:
    """Spec §6.3 R2-F7: sha256 of the *decoded user script bytes*, NOT of the
    rendered wrapper. Used in the agent-visible ``wrapper.skeleton.py``
    placeholder.
    """
    return hashlib.sha256(user_script.encode("utf-8")).hexdigest()


def render_wrapper_skeleton(*, expected_build_id: str, call_id: str, user_script_sha256_hex: str) -> str:
    """Render the agent-visible companion to wrapper.py (spec §6.1, §6.3).

    Same template, same regex-validated header values, but the user-script
    body is replaced by a sha256 reference. The skeleton carries no
    plaintext from the script and is safe to surface in the response's
    ``artifacts`` list.
    """
    if not _BUILD_ID_RE.match(expected_build_id):
        raise WrapperRenderError(f"expected_build_id must match {_BUILD_ID_RE.pattern}; got {expected_build_id!r}")
    if not _CALL_ID_RE.match(call_id):
        raise WrapperRenderError(f"call_id must match {_CALL_ID_RE.pattern}; got {call_id!r}")
    placeholder = (
        f"# <user script: sha256:{user_script_sha256_hex}; "
        f"full source under sensitive/debug/introspect/{call_id}/wrapper.py>"
    )
    encoded = base64.b64encode(placeholder.encode("utf-8")).decode("ascii")
    return WRAPPER_TEMPLATE.substitute(
        USER_SCRIPT_B64=encoded,
        EXPECTED_BUILD_ID=expected_build_id,
        CALL_ID=call_id,
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
    """Factory used by ``providers/plugins.py``. Spec §3.4 / §2."""
    return ProviderCapability(
        provider_name="local-drgn-introspect",
        provider_version="0.1.0",
        provider_family="debug",
        implementation_state=ImplementationState.IMPLEMENTED,
        architectures=["x86_64"],
        target_kinds=[TargetKind.VIRTUAL],
        transports=["ssh"],
        operations=["debug.introspect.run", "debug.introspect.check_prerequisites"],
        required_host_tools=["ssh"],
        destructive_permissions=[],
        access_methods=["ssh"],
        semantics=OperationSemantics(
            idempotent=False,
            retryable=True,
            destructive=False,
            cancelable=True,
            concurrent_safe=False,
        ),
    )
