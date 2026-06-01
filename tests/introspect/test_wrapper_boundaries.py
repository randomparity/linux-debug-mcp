from __future__ import annotations

from pathlib import Path


def test_introspect_wrapper_owner_does_not_import_local_provider_internals() -> None:
    wrapper_dir = Path(__file__).parents[2] / "src" / "kdive" / "introspect" / "wrappers"
    wrapper_source = "\n".join(path.read_text(encoding="utf-8") for path in wrapper_dir.glob("*.py"))

    assert "kdive.providers.local.introspect" not in wrapper_source
