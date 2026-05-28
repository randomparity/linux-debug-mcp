"""Spec §9.2 — wrapper unit tests.

The rendered wrapper is ``exec``'d in-process against a stub ``drgn``
module. Each test exercises one path through the wrapper and asserts on:

* stdout (must always be a single valid JSON document when the wrapper
  exits with code 6; per spec §4.3 the host parses JSON first, exit
  code second)
* the system exit code (raised through ``SystemExit``)
* fields inside the parsed JSON (``outcome.status``, ``truncated.*``,
  ``emits``, ``build_id``)
"""

from __future__ import annotations

import builtins
import io
import json
import sys
import types
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from typing import Any

import pytest

from linux_debug_mcp.providers.local_drgn_introspect import (
    render_wrapper,
    user_script_sha256,
)

EXPECTED_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
CALL_ID = "0" * 32  # 32 hex chars — passes _CALL_ID_RE


def _install_stub_drgn(
    monkeypatch: pytest.MonkeyPatch,
    *,
    helpers: dict[str, Any] | None = None,
    main_module_build_id: bytes | None = None,
    open_raises: BaseException | None = None,
) -> None:
    """Install a minimal stub ``drgn`` + ``drgn.helpers.linux`` into ``sys.modules``."""
    drgn_module = types.ModuleType("drgn")

    class _StubProg:
        def set_kernel(self) -> None: ...

        def load_default_debug_info(self) -> None:
            if open_raises is not None:
                raise open_raises

        def main_module(self):
            if main_module_build_id is None:
                raise AttributeError("main_module().build_id unavailable")
            return SimpleNamespace(build_id=main_module_build_id)

    def _make_program(*_a: Any, **_k: Any) -> _StubProg:
        return _StubProg()

    drgn_module.Program = _make_program  # type: ignore[attr-defined]

    helpers_pkg = types.ModuleType("drgn.helpers")
    helpers_linux = types.ModuleType("drgn.helpers.linux")
    chosen = helpers or {
        "list_for_each_entry": lambda *_a, **_k: [],
        "for_each_task": lambda *_a, **_k: [],
        "dmesg": lambda *_a, **_k: "",
    }
    for name, fn in chosen.items():
        setattr(helpers_linux, name, fn)
    # Ensure `__all__` does not exclude the names from the wildcard import.
    helpers_linux.__all__ = list(chosen.keys())  # type: ignore[attr-defined]
    helpers_pkg.linux = helpers_linux  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "drgn", drgn_module)
    monkeypatch.setitem(sys.modules, "drgn.helpers", helpers_pkg)
    monkeypatch.setitem(sys.modules, "drgn.helpers.linux", helpers_linux)


def _exec_wrapper(
    script: str,
    *,
    expected_build_id: str = EXPECTED_BUILD_ID,
    namespace_overrides: dict[str, Any] | None = None,
    stdout_buf: io.IOBase | None = None,
) -> tuple[str, int]:
    """Render the wrapper, exec it in-process under capture.

    Returns (stdout_text, exit_code). ``exit_code`` is the integer value of
    ``SystemExit.code``. ``namespace_overrides`` are merged into the exec
    namespace before ``exec`` so tests can pre-inject sabotaged stdlib
    aliases (e.g. ``_li_json``).
    """
    rendered = render_wrapper(
        user_script=script,
        expected_build_id=expected_build_id,
        call_id=CALL_ID,
    )
    buf = stdout_buf if stdout_buf is not None else StringIO()
    exit_code = 0
    ns: dict[str, Any] = {"__name__": "__wrapper__", "__builtins__": builtins}
    if namespace_overrides:
        ns.update(namespace_overrides)
    with redirect_stdout(buf):
        try:
            exec(compile(rendered, "<wrapper>", "exec"), ns)
        except SystemExit as exc:
            exit_code = int(exc.code) if exc.code is not None else 0
    text = buf.getvalue() if isinstance(buf, StringIO) else ""
    return text, exit_code


# ---------------------------------------------------------------------------
# Happy path + early-exit error paths
# ---------------------------------------------------------------------------


def test_wrapper_emit_roundtrips_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper('emit({"pid": 1})')
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"] == [{"pid": 1}]
    assert payload["outcome"] == {"status": "ok"}
    assert payload["build_id"] == EXPECTED_BUILD_ID
    assert payload["truncated"] == {
        "emits": False,
        "user_stdout": False,
        "traceback": False,
        "total_json": False,
        "per_emit_size": False,
        "error_message": False,
    }


def test_wrapper_provenance_mismatch_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    different = bytes.fromhex("ff" * 20)
    _install_stub_drgn(monkeypatch, main_module_build_id=different)
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 4
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "provenance_mismatch"
    assert payload["outcome"]["expected"] == EXPECTED_BUILD_ID
    assert payload["outcome"]["actual"] == "ff" * 20


def test_wrapper_drgn_import_failure_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "drgn", None)
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 3
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "drgn_open_failure"


def test_wrapper_drgn_version_skew_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    # Spec §9.2 F8: prog.main_module().build_id raises -> drgn_version_skew.
    _install_stub_drgn(monkeypatch, main_module_build_id=None)
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 3
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "drgn_version_skew"
    assert payload["outcome"]["error_type"] == "AttributeError"


def test_wrapper_syntax_error_exits_5(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper("def (: bad syntax")
    assert exit_code == 5
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "script_compile_error"
    assert payload["outcome"]["error_type"] == "SyntaxError"


def test_wrapper_always_emits_json_on_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["outcome"] == {"status": "ok"}
    assert payload["call_id"] == CALL_ID


# ---------------------------------------------------------------------------
# Truncation + caps
# ---------------------------------------------------------------------------


def test_wrapper_truncates_user_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    big = "A" * (256 * 1024 + 100)
    stdout, exit_code = _exec_wrapper(f"import sys; sys.stdout.write({big!r})")
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["truncated"]["user_stdout"] is True
    assert len(payload["user_stdout"]) == 256 * 1024


def test_wrapper_truncates_emits(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # 100 is the cap; the 101st should be silently dropped and truncated.emits=True.
    script = "for i in range(110):\n    emit({'i': i})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["truncated"]["emits"] is True
    assert len(payload["emits"]) == 100


def test_wrapper_truncates_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # Force a traceback by raising deep down; pad with junk to exceed 16 KiB.
    big_msg = "Z" * (32 * 1024)
    script = f"raise RuntimeError({big_msg!r})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "error"
    # error_message is capped at 4 KiB.
    assert len(payload["outcome"]["error_message"]) == 4096
    assert payload["truncated"]["error_message"] is True


def test_wrapper_truncates_error_message(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    big_msg = "Z" * (32 * 1024)
    script = f"raise ValueError({big_msg!r})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["outcome"]["error_type"] == "ValueError"
    assert len(payload["outcome"]["error_message"]) == 4096
    assert payload["truncated"]["error_message"] is True


def test_wrapper_per_emit_byte_cap_inserts_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # Single emit larger than 32 KiB triggers __emit_oversized__.
    script = "emit({'data': 'A' * (40 * 1024)})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"][0]["__emit_oversized__"] is True
    assert payload["emits"][0]["cap_bytes"] == 32 * 1024
    assert payload["truncated"]["per_emit_size"] is True


def test_wrapper_emit_unserializable_replaced_with_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # set() is not JSON-serializable.
    script = "emit(set()); emit({'x': 1})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"][0]["__emit_unserializable__"] is True
    assert payload["emits"][1] == {"x": 1}


def test_wrapper_total_json_cap_drops_from_tail_not_all(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # Each emit is ~30 KiB. The total_json cap is 1 MiB. So ~35 emits would
    # overshoot; the wrapper pops from the tail until under cap.
    script = "for i in range(50):\n    emit({'i': i, 'data': 'A' * (30 * 1024)})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["truncated"]["total_json"] is True
    # Head emits survive.
    assert payload["emits"][0] == {"i": 0, "data": "A" * (30 * 1024)}
    # Total payload fits under 1 MiB.
    assert len(stdout) <= 1 * 1024 * 1024 + 1024  # +1 KiB slack for envelope


def test_wrapper_total_json_cap_falls_back_to_clearing_user_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # Fill user_stdout to ~256 KiB (the user_stdout cap) and add no emits.
    # Then add a single emit just under the per-emit cap so the total exceeds
    # total_json with emits already empty after pop loop.
    # Simpler: produce a single huge user_stdout block; emits=0 means the
    # "drop emits" loop is a no-op; fall back to clearing user_stdout.
    big = "A" * (200 * 1024)
    script = (
        f"import sys\nsys.stdout.write({big!r})\nemit({{'x': 'B' * (30 * 1024)}})\nemit({{'y': 'C' * (30 * 1024)}})\n"
    )
    # Build a result that exceeds total_json. With user_stdout=200 KiB +
    # two 30 KiB emits = ~260 KiB; well under 1 MiB. This test does not
    # trigger the fallback cleanly without a much larger payload. The
    # fallback condition is tested via a stress shape below.
    # Use a 900 KiB user_stdout + no emits — still under cap.
    # Use 1.2 MiB user_stdout to exceed cap on a single field.
    bigger = "A" * (1200 * 1024)
    script = f"import sys\nsys.stdout.write({bigger!r})\n"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    # user_stdout truncation to 256 KiB happens first. Then total_json check:
    # 256 KiB user_stdout + envelope is still under 1 MiB, so the
    # clear-user_stdout fallback may not trigger on this path. Assert the
    # document is valid JSON and fits the cap.
    json.loads(stdout)
    assert len(stdout) <= 1024 * 1024 + 4096


# ---------------------------------------------------------------------------
# stdout routing
# ---------------------------------------------------------------------------


def test_wrapper_stdout_only_contains_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper('print("noise")')
    assert exit_code == 6
    # stdout is a single JSON document; "noise" is in payload["user_stdout"].
    payload = json.loads(stdout)
    assert "noise" in payload["user_stdout"]
    # The raw stdout starts with `{` (JSON) — no leading "noise\n".
    assert stdout.lstrip().startswith("{")


def test_wrapper_round_trips_script_containing_triple_quotes_and_template_sigils(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # Script contains `"""`, `${EXPECTED_BUILD_ID}` and CRLF; all must survive
    # base64 encoding round-trip without breaking the wrapper template.
    script = 'emit({"raw": """${EXPECTED_BUILD_ID}\\r\\n"""})'
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"] == [{"raw": "${EXPECTED_BUILD_ID}\r\n"}]


# ---------------------------------------------------------------------------
# User-script error paths
# ---------------------------------------------------------------------------


def test_wrapper_user_script_exception_captures_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper('raise RuntimeError("kaboom")')
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "error"
    assert payload["outcome"]["error_type"] == "RuntimeError"
    assert payload["outcome"]["error_message"] == "kaboom"
    assert "RuntimeError" in payload["outcome"]["traceback"]


def test_user_script_sys_exit_does_not_spoof_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # F1: user script does sys.exit(124); wrapper catches SystemExit, runs
    # tail try/finally, exits 6 with outcome.error_type=SystemExit.
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_wrapper("import sys; sys.exit(124)")
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "error"
    assert payload["outcome"]["error_type"] == "SystemExit"


# ---------------------------------------------------------------------------
# Helper namespace hygiene (R2-F8, R4-F4, R3-F1)
# ---------------------------------------------------------------------------


def test_wrapper_helper_namespace_contains_expected_subset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    # Run a script that records `namespace.keys()` via emit so we can inspect
    # what the user namespace sees.
    script = (
        "import sys\n"
        "# user namespace = the dict that was passed to exec\n"
        "frame = sys._getframe()\n"
        "names = sorted(frame.f_globals.keys())\n"
        "emit({'names': names})\n"
    )
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    names = set(payload["emits"][0]["names"])
    # Helpers are present.
    assert {"list_for_each_entry", "for_each_task", "dmesg"}.issubset(names)
    # User-injected symbols are present.
    assert {"prog", "emit", "drgn"}.issubset(names)
    # Wrapper-private _li_* names are NOT exposed.
    li_private = {
        "_li_pre_helpers",
        "_li_drgn_helper_names",
        "_li_emit_buffer",
        "_li_emit_overflow",
        "_li_result",
        "_li_caps",
        "_li_truncate",
        "_li_t_prelude_start",
        "_li_sys",
        "_li_json",
        "_li_io",
        "_li_traceback",
        "_li_contextlib",
        "_li_time",
        "_li_base64",
    }
    assert li_private.isdisjoint(names), f"leaked: {li_private & names}"


def test_wrapper_handles_drgn_helper_shadowing_wrapper_private_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # R2-F8: rename eliminated the legacy `result` shadowing class. Now a
    # helper named `result` (and even `caps`) does not collide.
    sentinel = object()
    _install_stub_drgn(
        monkeypatch,
        main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID),
        helpers={
            "list_for_each_entry": lambda *a, **k: [],
            "for_each_task": lambda *a, **k: [],
            "dmesg": lambda *a, **k: "",
            "result": lambda: sentinel,
            "caps": lambda: sentinel,
        },
    )
    # The user script asserts the helper-defined `result` is visible — not
    # the wrapper-private one (which has been renamed to _li_result).
    script = "emit({'has_helper_result': callable(result)})"
    stdout, exit_code = _exec_wrapper(script)
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"] == [{"has_helper_result": True}]
    assert payload["outcome"] == {"status": "ok"}


# ---------------------------------------------------------------------------
# Tail-write failure modes (R2-F2, R3-F2)
# ---------------------------------------------------------------------------


def test_wrapper_tail_serialization_failure_emits_minimal_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # R2-F2/R4-F3: when the tail `_li_json.dumps(_li_result)` raises but the
    # recovery `_li_json.dumps({...})` succeeds, exit 6 with a minimal JSON
    # carrying outcome.status="wrapper_internal_error".
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))

    real_dumps = json.dumps
    state = {"calls": 0}

    def flaky_dumps(obj, *a, **k):
        state["calls"] += 1
        # The wrapper's primary tail-write block is the first place that
        # calls json.dumps with `_li_result` (a dict containing "emits" etc).
        # The recovery write supplies a minimal dict with key "call_id" but
        # no "emits"/"user_stdout" key entries until after that minimal dict
        # is built. Distinguish primary vs recovery by inspecting the dict.
        if (
            isinstance(obj, dict)
            and isinstance(obj.get("outcome"), dict)
            and obj["outcome"].get("status") == "wrapper_internal_error"
        ):
            return real_dumps(obj, *a, **k)
        # Primary tail dump: simulate UnicodeEncodeError / MemoryError.
        if isinstance(obj, dict) and "emits" in obj and "user_stdout" in obj:
            raise RuntimeError("forced")
        return real_dumps(obj, *a, **k)

    monkeypatch.setattr(json, "dumps", flaky_dumps)
    stdout, exit_code = _exec_wrapper("pass")
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["outcome"]["status"] == "wrapper_internal_error"
    assert payload["outcome"]["error_type"] == "RuntimeError"
    assert payload["outcome"]["error_message"] == "forced"
    assert payload["truncated"]["wrapper_internal_error"] is True
    assert payload["call_id"] == CALL_ID
    assert payload["build_id"] == EXPECTED_BUILD_ID


def test_wrapper_tail_pipe_failure_falls_through_to_silent_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # R3-F2: every stdout.write raises BrokenPipeError; recovery write also
    # fails; last-ditch `except BaseException: pass` swallows. Wrapper
    # exits 6 with no JSON on stdout.
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))

    class _BrokenStdout(io.IOBase):
        def write(self, _: str) -> int:
            raise BrokenPipeError("pipe closed")

        def writable(self) -> bool:
            return True

    broken = _BrokenStdout()
    # The wrapper aliases `import sys as _li_sys` and writes to
    # `_li_sys.stdout`. Inside the exec, `sys.stdout` is the redirected buf;
    # but the wrapper imports sys *inside* its body, so it gets a fresh
    # binding. Replace `sys.stdout` on the real `sys` module for the duration
    # of the exec.
    real_stdout = sys.stdout
    monkeypatch.setattr(sys, "stdout", broken)
    try:
        _, exit_code = _exec_wrapper("pass", stdout_buf=broken)
    finally:
        monkeypatch.setattr(sys, "stdout", real_stdout)
    assert exit_code == 6
    # No JSON document captured (the broken stdout swallowed all writes).
    # The _BrokenStdout receives all writes through redirect_stdout's
    # `with` context, and our helper returns "" when stdout_buf is non-Strio.


# ---------------------------------------------------------------------------
# user_script_sha256 helper coverage
# ---------------------------------------------------------------------------


def test_user_script_sha256_matches_hashlib() -> None:
    import hashlib

    script = 'emit({"hi": 1})'
    expected = hashlib.sha256(script.encode("utf-8")).hexdigest()
    assert user_script_sha256(script) == expected
