from __future__ import annotations

import base64
import builtins
import json
import sys
import types
from contextlib import redirect_stdout, suppress
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from kdive.providers.local.introspect.local_drgn_introspect import (
    VMCORE_WRAPPER_TEMPLATE,
    WRAPPER_TEMPLATE,
    WrapperRenderError,
    render_vmcore_wrapper,
    render_vmcore_wrapper_skeleton,
)

GOLDEN = Path(__file__).parents[1] / "golden" / "live_wrapper_template.txt"
EXPECTED_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
CALL_ID = "0" * 32


def test_live_wrapper_template_byte_identical_after_split() -> None:
    # ADR 0010: the prologue/body split must not change the live wrapper text.
    assert WRAPPER_TEMPLATE.template == GOLDEN.read_text(encoding="utf-8")


def test_vmcore_wrapper_shares_body_with_live() -> None:
    from kdive.providers.local.introspect.local_drgn_introspect import _WRAPPER_BODY

    assert _WRAPPER_BODY in VMCORE_WRAPPER_TEMPLATE.template
    assert _WRAPPER_BODY in WRAPPER_TEMPLATE.template


def test_render_vmcore_substitutes_all_placeholders() -> None:
    out = render_vmcore_wrapper(
        user_script="emit({'ok': True})",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        vmcore_path="/runs/r1/inputs/vmcore",
        vmlinux_path="/runs/r1/build/vmlinux",
        modules_path=None,
    )
    assert "${" not in out  # no unsubstituted placeholders
    assert base64.b64encode(b"/runs/r1/inputs/vmcore").decode() in out
    assert base64.b64encode(b"/runs/r1/build/vmlinux").decode() in out
    assert base64.b64encode(b"").decode() in out  # modules absent -> b64("")
    assert EXPECTED_BUILD_ID in out


def test_render_vmcore_encodes_injection_path_safely() -> None:
    evil = "/runs/r1/x\".__import__('os').system('id')#"
    out = render_vmcore_wrapper(
        user_script="pass",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        vmcore_path=evil,
        vmlinux_path="/runs/r1/build/vmlinux",
        modules_path=None,
    )
    assert evil not in out
    assert base64.b64encode(evil.encode()).decode() in out


def test_render_vmcore_rejects_bad_build_id() -> None:
    with pytest.raises(WrapperRenderError):
        render_vmcore_wrapper(
            user_script="pass",
            expected_build_id="NOTHEX",
            call_id=CALL_ID,
            vmcore_path="/c",
            vmlinux_path="/v",
            modules_path=None,
        )


def test_render_vmcore_rejects_bad_call_id() -> None:
    with pytest.raises(WrapperRenderError):
        render_vmcore_wrapper(
            user_script="pass",
            expected_build_id=EXPECTED_BUILD_ID,
            call_id="xyz",
            vmcore_path="/c",
            vmlinux_path="/v",
            modules_path=None,
        )


def test_render_vmcore_skeleton_has_no_plaintext_script() -> None:
    out = render_vmcore_wrapper_skeleton(
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        user_script_sha256_hex="a" * 64,
        vmcore_path="/c",
        vmlinux_path="/v",
        modules_path=None,
    )
    # The sha256 pointer is carried inside the base64 USER_SCRIPT_B64 literal,
    # exactly like the live skeleton — decode it to confirm the pointer, and
    # confirm no real user script leaked.
    encoded = base64.b64encode(
        f"# <user script: sha256:{'a' * 64}; "
        f"full source under sensitive/debug/introspect/{CALL_ID}/wrapper.py>".encode()
    ).decode()
    assert encoded in out


def _install_stub_drgn(
    monkeypatch: pytest.MonkeyPatch,
    *,
    main_module_build_id: bytes | None,
    open_raises: BaseException | None = None,
) -> None:
    drgn_module = types.ModuleType("drgn")

    class _StubProg:
        def set_core_dump(self, path: str) -> None:
            if open_raises is not None:
                raise open_raises

        def load_debug_info(self, paths) -> None: ...

        def main_module(self):
            return SimpleNamespace(build_id=main_module_build_id)

    drgn_module.Program = lambda *_a, **_k: _StubProg()  # type: ignore[attr-defined]
    helpers_pkg = types.ModuleType("drgn.helpers")
    helpers_linux = types.ModuleType("drgn.helpers.linux")
    helpers_linux.__all__ = []  # type: ignore[attr-defined]
    helpers_pkg.linux = helpers_linux  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "drgn", drgn_module)
    monkeypatch.setitem(sys.modules, "drgn.helpers", helpers_pkg)
    monkeypatch.setitem(sys.modules, "drgn.helpers.linux", helpers_linux)


def _exec_vmcore(script: str, *, build_id: bytes | None, expected: str = EXPECTED_BUILD_ID) -> tuple[str, int]:
    rendered = render_vmcore_wrapper(
        user_script=script,
        expected_build_id=expected,
        call_id=CALL_ID,
        vmcore_path="/c",
        vmlinux_path="/v",
        modules_path=None,
    )
    buf = StringIO()
    exit_code = 0
    ns: dict[str, Any] = {"__name__": "__wrapper__", "__builtins__": builtins}
    with redirect_stdout(buf):
        try:
            exec(compile(rendered, "<vmcore>", "exec"), ns)
        except SystemExit as exc:
            exit_code = int(exc.code) if exc.code is not None else 0
    return buf.getvalue(), exit_code


def test_vmcore_exec_matching_build_id_runs_script(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    stdout, exit_code = _exec_vmcore('emit({"pid": 1})', build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    assert exit_code == 6
    payload = json.loads(stdout)
    assert payload["emits"] == [{"pid": 1}]
    assert payload["outcome"] == {"status": "ok"}
    assert payload["build_id"] == EXPECTED_BUILD_ID


def test_vmcore_exec_mismatching_build_id_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=bytes.fromhex("f" * 40))
    stdout, exit_code = _exec_vmcore("emit({})", build_id=bytes.fromhex("f" * 40))
    assert exit_code == 4
    assert json.loads(stdout)["outcome"]["status"] == "provenance_mismatch"


def test_vmcore_exec_no_embedded_build_id_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=None)
    stdout, exit_code = _exec_vmcore("emit({})", build_id=None)
    assert exit_code == 4
    assert json.loads(stdout)["outcome"]["status"] == "provenance_unverifiable"


def test_vmcore_exec_open_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub_drgn(monkeypatch, main_module_build_id=None, open_raises=OSError("cannot open core"))
    stdout, exit_code = _exec_vmcore("emit({})", build_id=None)
    assert exit_code == 3
    assert json.loads(stdout)["outcome"]["status"] == "drgn_open_failure"


def _install_recording_stub_drgn(monkeypatch: pytest.MonkeyPatch, *, build_id: bytes) -> list[list[str]]:
    """Stub drgn whose load_debug_info records each call's path list."""
    loaded: list[list[str]] = []
    drgn_module = types.ModuleType("drgn")

    class _StubProg:
        def set_core_dump(self, path: str) -> None: ...

        def load_debug_info(self, paths) -> None:
            loaded.append(list(paths))

        def main_module(self):
            return SimpleNamespace(build_id=build_id)

    drgn_module.Program = lambda *_a, **_k: _StubProg()  # type: ignore[attr-defined]
    helpers_pkg = types.ModuleType("drgn.helpers")
    helpers_linux = types.ModuleType("drgn.helpers.linux")
    helpers_linux.__all__ = []  # type: ignore[attr-defined]
    helpers_pkg.linux = helpers_linux  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "drgn", drgn_module)
    monkeypatch.setitem(sys.modules, "drgn.helpers", helpers_pkg)
    monkeypatch.setitem(sys.modules, "drgn.helpers.linux", helpers_linux)
    return loaded


def _exec_vmcore_with_modules(modules_path: str, *, build_id: bytes) -> dict:
    rendered = render_vmcore_wrapper(
        user_script="emit({})",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        vmcore_path="/c",
        vmlinux_path="/v",
        modules_path=modules_path,
    )
    buf = StringIO()
    ns: dict[str, Any] = {"__name__": "__wrapper__", "__builtins__": builtins}
    with redirect_stdout(buf), suppress(SystemExit):
        exec(compile(rendered, "<vmcore>", "exec"), ns)
    return json.loads(buf.getvalue())


def test_vmcore_modules_loaded_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    loaded = _install_recording_stub_drgn(monkeypatch, build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    mods = tmp_path / "mods"
    (mods / "net").mkdir(parents=True)
    (mods / "net" / "foo.ko.debug").write_bytes(b"x")
    (mods / "bar.ko.debug").write_bytes(b"x")
    payload = _exec_vmcore_with_modules(str(mods), build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    warns = {w["code"]: w for w in payload["warnings"]}
    assert "modules_debuginfo_loaded" in warns
    assert warns["modules_debuginfo_loaded"]["count"] == 2
    # vmlinux + 2 module files each loaded via load_debug_info.
    assert [p for call in loaded for p in call].count(str(mods / "bar.ko.debug")) == 1


def test_vmcore_modules_fallback_to_plain_ko(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_recording_stub_drgn(monkeypatch, build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    mods = tmp_path / "mods"
    mods.mkdir()
    (mods / "only.ko").write_bytes(b"x")  # no .ko.debug present -> fallback
    payload = _exec_vmcore_with_modules(str(mods), build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    warns = {w["code"]: w for w in payload["warnings"]}
    assert warns["modules_debuginfo_loaded"]["count"] == 1


def test_vmcore_modules_empty_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_recording_stub_drgn(monkeypatch, build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    mods = tmp_path / "empty"
    mods.mkdir()
    payload = _exec_vmcore_with_modules(str(mods), build_id=bytes.fromhex(EXPECTED_BUILD_ID))
    assert any(w["code"] == "modules_debuginfo_empty" for w in payload["warnings"])
