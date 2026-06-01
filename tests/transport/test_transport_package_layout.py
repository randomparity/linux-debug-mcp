from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
TRANSPORT_ROOT = ROOT / "src" / "kdive" / "transport"


def test_transport_package_separates_core_contracts_from_backends() -> None:
    core_modules = {"base.py", "break_types.py", "break_inject.py", "bounded.py", "rsp_probe.py"}
    backend_modules = {"proxy.py", "qemu_gdbstub.py", "serial_local.py"}

    assert {path.name for path in (TRANSPORT_ROOT / "core").glob("*.py")} >= core_modules | {"__init__.py"}
    assert {path.name for path in (TRANSPORT_ROOT / "backends").glob("*.py")} >= backend_modules | {"__init__.py"}
    assert not any((TRANSPORT_ROOT / module).exists() for module in core_modules | backend_modules)
    assert (TRANSPORT_ROOT / "handlers.py").is_file()
    assert (TRANSPORT_ROOT / "tools.py").is_file()
