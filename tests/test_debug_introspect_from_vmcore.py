from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from linux_debug_mcp.artifacts.store import ArtifactStore
from linux_debug_mcp.domain import (
    DebugIntrospectFromVmcoreHelperRequest,
    DebugIntrospectFromVmcoreRequest,
    RunRequest,
)
from linux_debug_mcp.providers.local_ssh_tests import SshCommandResult

VALID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Task 4: request models
# ---------------------------------------------------------------------------


def test_request_defaults() -> None:
    r = DebugIntrospectFromVmcoreRequest(
        run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", script="pass"
    )
    assert r.modules_ref is None
    assert r.timeout_seconds == 30
    assert r.allow_write is False
    assert r.args == {}


def test_request_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        DebugIntrospectFromVmcoreRequest(run_id="r1", vmcore_ref="c", vmlinux_ref="v", script="pass", target_ref="nope")


def test_helper_request_shape() -> None:
    r = DebugIntrospectFromVmcoreHelperRequest(run_id="r1", vmcore_ref="c", vmlinux_ref="v", name="sysinfo")
    assert r.args == {}
    assert r.timeout_seconds == 30


# ---------------------------------------------------------------------------
# Shared handler-test fixtures (Tasks 6-9)
# ---------------------------------------------------------------------------


class FakeRunner:
    """Local subprocess runner stand-in: records the call, writes the canned
    stdout/stderr to the requested paths, returns the canned SshCommandResult.
    """

    def __init__(self, results: list[SshCommandResult] | None = None) -> None:
        self.results = results or []
        self.calls: list[dict] = []

    def run(
        self,
        argv,
        *,
        timeout,
        stdout_path,
        stderr_path,
        cancel=None,
        stdin=None,
        max_stdout_bytes=None,
    ) -> SshCommandResult:
        self.calls.append({"argv": argv, "timeout": timeout, "stdin": stdin})
        result = self.results.pop(0) if self.results else SshCommandResult(exit_status=0, stdout="{}", stderr="")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        return result


def _run(tmp_path: Path) -> ArtifactStore:
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/s",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    rd = store.run_dir("r1")
    (rd / "inputs").mkdir(exist_ok=True)
    (rd / "build").mkdir(exist_ok=True)
    (rd / "inputs" / "vmcore").write_bytes(b"core")
    (rd / "build" / "vmlinux").write_bytes(b"elf")
    return store


def _wrapper_json(build_id: str | None = VALID, status: str = "ok", emits=None, user_stdout: str = "") -> dict:
    return {
        "call_id": "0" * 32,
        "build_id": build_id,
        "outcome": {"status": status},
        "emits": emits if emits is not None else [{"k": 1}],
        "user_stdout": user_stdout,
        "prelude_ms": 1,
        "truncated": {
            "emits": False,
            "user_stdout": False,
            "traceback": False,
            "total_json": False,
            "per_emit_size": False,
            "error_message": False,
        },
    }


def _req(**kw) -> DebugIntrospectFromVmcoreRequest:
    base = dict(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", script="emit({'k':1})")
    base.update(kw)
    return DebugIntrospectFromVmcoreRequest(**base)


def _ok_runner() -> FakeRunner:
    return FakeRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(_wrapper_json()), stderr="")])
