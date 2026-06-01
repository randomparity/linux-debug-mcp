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

_li_drgn_version = None
try:
    import drgn  # noqa: E402  -- module attribute, exposed to user namespace
    _li_drgn_version = getattr(drgn, "__version__", None)

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
                             "error_message": msg,
                             "drgn_version": _li_drgn_version}
    _li_result["truncated"]["error_message"] = msg_trunc
    try:
        _li_json.dump(_li_result, _li_sys.stdout)
    finally:
        _li_sys.exit(3)

_li_result["prelude_ms"] = int((_li_time.monotonic() - _li_t_prelude_start) * 1000)

# ADR 0039: drgn >= 0.2 does not create the main module at set_core_dump();
# module discovery (driven by VMCOREINFO) must run before main_module() resolves.
# Best-effort: discovery can warn/raise once it needs kernel debug info, but it
# populates the main module's build-id from VMCOREINFO first. Resolution failures
# split: AttributeError is a genuine drgn module-API/version gap
# (drgn_version_skew); any other exception is drgn raising while resolving the
# module (drgn_api_incompatible -- e.g. LookupError when discovery cannot run).
try:
    try:
        for _li_mod in prog.loaded_modules():
            if _li_mod.name == "kernel":
                break
    except Exception:
        pass
    _li_bid = prog.main_module().build_id
    _li_result["build_id"] = _li_bid.hex() if _li_bid else None
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
    _validate_args_json(args_json)
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
    _validate_args_json(args_json)
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
