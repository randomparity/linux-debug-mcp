from __future__ import annotations

import pytest

from linux_debug_mcp.safety.paths import PathSafetyError, confine_run_relative


def test_resolves_existing_relative_file(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "build").mkdir(parents=True)
    target = run_dir / "build" / "vmlinux"
    target.write_text("elf", encoding="utf-8")
    resolved = confine_run_relative("build/vmlinux", run_dir=run_dir)
    assert resolved == target.resolve()


def test_missing_relative_file_still_confined(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    resolved = confine_run_relative("build/vmlinux", run_dir=run_dir)
    assert resolved == (run_dir / "build" / "vmlinux").resolve()


def test_dotdot_escape_rejected(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(PathSafetyError):
        confine_run_relative("../escape", run_dir=run_dir)


def test_absolute_override_rejected(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(PathSafetyError):
        confine_run_relative("/etc/passwd", run_dir=run_dir)


def test_symlink_escape_rejected(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    # The escaping component is the symlink `link` itself: resolve() collapses
    # it to `outside`, which is not under run_dir. Asserting on the resolved
    # parent makes the test fail for the right reason if resolve() semantics shift.
    (run_dir / "link").symlink_to(outside)
    assert (run_dir / "link").resolve() == outside.resolve()  # precondition
    with pytest.raises(PathSafetyError):
        confine_run_relative("link/secret", run_dir=run_dir)
