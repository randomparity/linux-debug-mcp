from __future__ import annotations

from linux_debug_mcp.postmortem.crash_batch import (
    build_command_script,
    collect_command_outputs,
    redirect_filename,
)


def test_build_script_appends_redirects_and_exit(tmp_path) -> None:
    script = build_command_script(["bt", "ps"], tmp_path, modules_path=None)
    lines = script.splitlines()
    assert lines[0] == f"bt > {tmp_path / 'cmd-0000.out'}"
    assert lines[1] == f"ps > {tmp_path / 'cmd-0001.out'}"
    assert lines[-1] == "exit"


def test_build_script_prepends_mod_load(tmp_path) -> None:
    script = build_command_script(["bt"], tmp_path, modules_path="/run/r1/mods")
    lines = script.splitlines()
    assert lines[0] == f"mod -S /run/r1/mods > {tmp_path / 'mod-load.out'}"
    assert lines[1] == f"bt > {tmp_path / 'cmd-0000.out'}"


def test_collect_present_and_missing(tmp_path) -> None:
    (tmp_path / redirect_filename(0)).write_text("bt output", encoding="utf-8")
    # cmd 1 file absent (crash aborted)
    segs, truncated = collect_command_outputs(tmp_path, ["bt", "ps"], per_cmd_cap=1024, total_cap=4096)
    assert truncated is False
    assert segs[0] == {"command": "bt", "raw": "bt output", "capture": "ok"}
    assert segs[1] == {"command": "ps", "raw": None, "capture": "not_captured"}


def test_collect_per_cmd_truncation(tmp_path) -> None:
    (tmp_path / redirect_filename(0)).write_text("x" * 50, encoding="utf-8")
    segs, truncated = collect_command_outputs(tmp_path, ["bt"], per_cmd_cap=10, total_cap=4096)
    assert segs[0]["capture"] == "output_truncated"
    assert len(segs[0]["raw"]) == 10
    assert truncated is True


def test_collect_total_cap_marks_rest_truncated(tmp_path) -> None:
    (tmp_path / redirect_filename(0)).write_text("a" * 30, encoding="utf-8")
    (tmp_path / redirect_filename(1)).write_text("b" * 30, encoding="utf-8")
    segs, truncated = collect_command_outputs(tmp_path, ["bt", "ps"], per_cmd_cap=1024, total_cap=40)
    assert segs[0]["capture"] == "ok"
    assert segs[1]["capture"] == "output_truncated"
    assert truncated is True


def test_collect_does_not_read_whole_oversize_file(tmp_path, monkeypatch) -> None:
    # The per-command read must be bounded (cap+1), not slurp the whole file --
    # robust even if the prlimit RLIMIT_FSIZE bound were ever absent.
    big = tmp_path / redirect_filename(0)
    big.write_bytes(b"z" * (1 << 20))  # 1 MiB on disk

    import linux_debug_mcp.postmortem.crash_batch as mod

    real_read_bytes = mod.Path.read_bytes

    def _no_slurp(self, *args, **kwargs):
        raise AssertionError(f"read_bytes() slurped the whole file: {self}")

    monkeypatch.setattr(mod.Path, "read_bytes", _no_slurp)
    try:
        segs, truncated = collect_command_outputs(tmp_path, ["bt"], per_cmd_cap=16, total_cap=4096)
    finally:
        monkeypatch.setattr(mod.Path, "read_bytes", real_read_bytes)
    assert segs[0]["capture"] == "output_truncated"
    assert len(segs[0]["raw"]) == 16
