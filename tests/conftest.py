from __future__ import annotations

from pathlib import Path


def make_source_tree(base: Path, *, with_config: bool = False) -> Path:
    """Create a minimal Linux source tree (``Kconfig`` + ``Makefile``) under ``base/linux``.

    With ``with_config=True`` also writes a developer ``.config`` so prepare_config succeeds.
    """
    source = base / "linux"
    source.mkdir(parents=True)
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")
    if with_config:
        (source / ".config").write_text("CONFIG_TEST=y\n", encoding="utf-8")
    return source


def add_merge_config_script(source: Path) -> Path:
    """Add ``scripts/kconfig/merge_config.sh`` to an existing source tree for config-merge tests."""
    script = source / "scripts" / "kconfig" / "merge_config.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    return script


class NoopBuildRunner:
    """BuildRunner fake: reports every tool present, records commands, writes the log, returns 0."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def which(self, command: str) -> str | None:
        return f"/usr/bin/{command}"

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        log_path: Path,
        env: dict[str, str],
        cwd: Path | None = None,
    ) -> int:
        self.commands.append(argv)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("ok\n", encoding="utf-8")
        return 0
