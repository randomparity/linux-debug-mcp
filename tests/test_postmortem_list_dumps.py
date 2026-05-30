from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import (
    DebugPostmortemListDumpsRequest,
    RunRequest,
    StepResult,
    StepStatus,
)
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult
from linux_debug_mcp.server import build_scp_argv, debug_postmortem_list_dumps_handler

SECRET_KEY_REF = "s3cr3t-key"  # pragma: allowlist secret


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {
        "name": "minimal",
        "source": "/img.qcow2",
        "access_method": "ssh",
        "ssh_host": "127.0.0.1",
        "ssh_user": "root",
        "ssh_key_ref": SECRET_KEY_REF,
    }
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted_run(tmp_path) -> str:
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    store.record_step_result(
        manifest.run_id,
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="ok", artifacts=[]),
    )
    return manifest.run_id


def test_list_dumps_rejects_out_of_band_timeout(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu", timeout_seconds=120),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_timeout"


def _list_runner(stdout: str, exit_status: int = 0):
    @dataclass
    class _R:
        calls: list = field(default_factory=list)

        def which(self, c):
            return f"/usr/bin/{c}"

        def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
            self.calls.append({"argv": argv, "stdin": stdin})
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return SshCommandResult(exit_status=exit_status, stdout="")

    return _R()


def test_list_dumps_empty_is_success(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu"),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_list_runner('{"dump_dir": "/var/crash", "exists": false, "dumps": []}'),
    )
    assert resp.ok is True
    assert resp.data["dumps"] == []


def test_list_dumps_one_entry(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    stdout = (
        '{"dump_dir": "/var/crash", "exists": true, "dumps": ['
        '{"dir": "/var/crash/d1", "vmcore_name": "vmcore", "size": 2048, "mtime": 1717027200.0,'
        ' "kernel": "Linux version 6.8.0", "incomplete": false,'
        ' "present": ["vmcore-dmesg.txt"], "file_sizes": {"vmcore": 2048, "vmcore-dmesg.txt": 16}}]}'
    )
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu"),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_list_runner(stdout),
    )
    assert resp.ok is True
    assert resp.data["dumps"][0]["path"] == "/var/crash/d1"
    assert resp.data["dumps"][0]["kernel"] == "Linux version 6.8.0"
    assert "debug.postmortem.fetch" in resp.suggested_next_actions


def test_list_dumps_bad_dump_dir(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu", dump_dir="relative/path"),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_list_runner("{}"),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_dump_dir"


def test_list_dumps_no_python(tmp_path) -> None:
    run_id = _booted_run(tmp_path)
    resp = debug_postmortem_list_dumps_handler(
        DebugPostmortemListDumpsRequest(run_id=run_id, target_ref="local-qemu"),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_list_runner("", exit_status=127),
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "probe_no_python"


def test_build_scp_argv_quotes_remote_path() -> None:
    argv = build_scp_argv(
        rootfs_profile=RootfsProfile(name="m", source="/i", access_method="ssh", ssh_host="h", ssh_user="root"),
        known_hosts_path=Path("/tmp/kh"),
        remote_path="/var/crash/127.0.0.1-2026-05-30-12:00:00/vmcore",
        local_dest=Path("/tmp/dest/vmcore"),
        command_timeout=300,
    )
    assert argv[0] == "scp"
    assert "-T" in argv
    # the source arg is user@host:<quoted-path>; the local dest is the last arg
    src = next(a for a in argv if a.startswith("root@h:"))
    assert "127.0.0.1-2026-05-30-12:00:00" in src
    assert argv[-1] == "/tmp/dest/vmcore"


def test_tools_registered() -> None:
    from linux_debug_mcp.server import create_app

    # access pattern verified against tests/test_server.py — the registry is the
    # `_tool_manager._tools` dict keyed by tool name.
    names = set(create_app()._tool_manager._tools)
    assert "debug.postmortem.list_dumps" in names
    assert "debug.postmortem.fetch" in names
