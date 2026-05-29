from __future__ import annotations

import pytest

from linux_debug_mcp.seams.target import KernelProvenance
from linux_debug_mcp.symbols.resolve import (
    ResolvedSymbols,
    SymbolResolutionError,
    resolve_symbols,
)

FULL = "a" * 40


def _provenance(**overrides) -> KernelProvenance:
    base = dict(
        build_id=FULL,
        release="6.9.0-test",
        vmlinux_ref="build/vmlinux",
        modules_ref=None,
        cmdline="root=/dev/vda console=ttyS0",
        config_ref="build/.config",
    )
    base.update(overrides)
    return KernelProvenance(**base)


def _make_run(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "build").mkdir(parents=True)
    return run_dir


def test_resolves_vmlinux_and_warns_on_missing_modules(tmp_path):
    run_dir = _make_run(tmp_path)
    (run_dir / "build" / "vmlinux").write_text("elf", encoding="utf-8")
    result = resolve_symbols(_provenance(), run_dir=run_dir)
    assert isinstance(result, ResolvedSymbols)
    assert result.vmlinux_path == (run_dir / "build" / "vmlinux").resolve()
    assert result.modules_path is None
    assert [w.code for w in result.warnings] == ["modules_debuginfo_missing"]


def test_missing_vmlinux_file_is_fatal(tmp_path):
    run_dir = _make_run(tmp_path)
    with pytest.raises(SymbolResolutionError) as excinfo:
        resolve_symbols(_provenance(), run_dir=run_dir)
    assert excinfo.value.code == "symbol_resolution_failed"


def test_vmlinux_escape_is_fatal(tmp_path):
    run_dir = _make_run(tmp_path)
    with pytest.raises(SymbolResolutionError) as excinfo:
        resolve_symbols(_provenance(vmlinux_ref="../../etc/passwd"), run_dir=run_dir)
    assert excinfo.value.code == "symbol_resolution_failed"


def test_present_modules_bundle_resolves_without_warning(tmp_path):
    run_dir = _make_run(tmp_path)
    (run_dir / "build" / "vmlinux").write_text("elf", encoding="utf-8")
    modules = run_dir / "build" / "modules-debug"
    modules.mkdir()
    result = resolve_symbols(_provenance(modules_ref="build/modules-debug"), run_dir=run_dir)
    assert result.modules_path == modules.resolve()
    assert result.warnings == []


def test_missing_modules_bundle_warns_once(tmp_path):
    run_dir = _make_run(tmp_path)
    (run_dir / "build" / "vmlinux").write_text("elf", encoding="utf-8")
    result = resolve_symbols(_provenance(modules_ref="build/modules-debug"), run_dir=run_dir)
    assert result.modules_path is None
    assert [w.code for w in result.warnings] == ["modules_debuginfo_missing"]
