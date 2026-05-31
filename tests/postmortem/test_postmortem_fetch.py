from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from kdive.artifacts.store import ArtifactStore
from kdive.config import RootfsProfile
from kdive.domain import (
    ErrorCategory,
    RunRequest,
    StepResult,
    StepStatus,
)
from kdive.postmortem.handlers import debug_postmortem_fetch_handler
from kdive.postmortem.models import DebugPostmortemFetchRequest
from kdive.providers.local.local_ssh_tests import SshCommandResult
from kdive.transport.core.base import ExecutionState

SECRET_KEY_REF = "s3cr3t-key"  # pragma: allowlist secret
_LISTING = (
    '{"dump_dir": "/var/crash", "exists": true, "dumps": ['
    '{"dir": "/var/crash/d1", "vmcore_name": "vmcore", "size": 16, "mtime": 1717027200.0,'
    ' "kernel": "Linux version 6.8.0", "incomplete": false,'
    ' "present": ["vmcore-dmesg.txt"], "file_sizes": {"vmcore": 16, "vmcore-dmesg.txt": 4}}]}'
)


def _store_with_run(tmp_path):
    store = ArtifactStore(artifact_root=tmp_path)
    store.create_run(
        RunRequest(
            run_id="r1",
            source_path="/src",
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        )
    )
    return store


def test_postmortem_fetch_lock_is_reentrant_safe(tmp_path) -> None:
    store = _store_with_run(tmp_path)
    with store.postmortem_fetch_lock("r1"):
        pass  # acquires and releases without error
    with store.postmortem_fetch_lock("r1"):
        pass


def _rootfs(**over) -> dict[str, RootfsProfile]:
    base = {
        "name": "minimal",
        "source": "/i",
        "access_method": "ssh",
        "ssh_host": "127.0.0.1",
        "ssh_user": "root",
        "ssh_key_ref": SECRET_KEY_REF,
    }
    base.update(over)
    return {"minimal": RootfsProfile(**base)}


def _booted(tmp_path) -> str:
    store = _store_with_run(tmp_path)
    store.record_step_result(
        "r1", StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="ok", artifacts=[])
    )
    return "r1"


@dataclass
class _FetchRunner:
    """Emits the listing for the ssh enumeration; writes sized files for scp."""

    listing: str = _LISTING
    sizes: dict[str, int] = field(default_factory=lambda: {"vmcore": 16, "vmcore-dmesg.txt": 4})
    calls: list = field(default_factory=list)

    def which(self, c):
        return f"/usr/bin/{c}"

    def run(self, argv, *, timeout, stdout_path, stderr_path, cancel=None, stdin=None, max_stdout_bytes=None):
        self.calls.append({"argv": argv})
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.write_text("", encoding="utf-8")
        if argv[0] == "scp":
            dest = Path(argv[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"x" * self.sizes.get(dest.name, 0))
            stdout_path.write_text("", encoding="utf-8")
            return SshCommandResult(exit_status=0, stdout="")
        stdout_path.write_text(self.listing, encoding="utf-8")
        return SshCommandResult(exit_status=0, stdout="")


class _FakeSnapshot:
    generation = 1
    platform = None


class _FakeAdmission:
    def current_snapshot(self, target_key):  # noqa: ANN001
        return _FakeSnapshot()

    def current_execution_epoch(self, target_key):  # noqa: ANN001
        return 0


class _FakeRecord:
    def __init__(self, state: ExecutionState) -> None:
        self.execution_state = state


class _FakeRegistry:
    def __init__(self, state: ExecutionState) -> None:
        self._state = state

    def read_record(self, target_key):  # noqa: ANN001
        return _FakeRecord(self._state)


def _fetch(tmp_path, runner, **over):
    base = {"run_id": "r1", "manifest_target_profile": "local-qemu", "dump_ref": "/var/crash/d1"}
    base.update(over)
    return debug_postmortem_fetch_handler(
        DebugPostmortemFetchRequest(**base),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=runner,
    )


def test_fetch_success_stages_refs(tmp_path) -> None:
    run_id = _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner())
    assert resp.ok is True, resp.error
    assert resp.data["vmcore_ref"].endswith("/vmcore")
    assert resp.data["vmcore_dmesg_ref"].endswith("/vmcore-dmesg.txt")
    assert resp.data["vmlinux_ref"] is None
    files = {f["name"]: f for f in resp.data["files"]}
    assert files["vmcore"]["size_bytes"] == 16
    assert len(files["vmcore"]["sha256"]) == 64
    vmcore = Path(tmp_path) / run_id / resp.data["vmcore_ref"]
    assert vmcore.is_file()


def test_fetch_dump_not_found(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(), dump_ref="/var/crash/missing")
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_not_found"


def test_fetch_returns_typed_failure_for_malformed_listing(tmp_path) -> None:
    _booted(tmp_path)
    runner = _FetchRunner(listing='{"dump_dir": "/var/crash", "exists": true, "dumps": [{"kernel": "missing dir"}]}')

    resp = _fetch(tmp_path, runner)

    assert resp.ok is False
    assert resp.error.details["code"] == "malformed_dump_listing"


def test_fetch_truncated_transfer_detected(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(sizes={"vmcore": 8, "vmcore-dmesg.txt": 4}))
    assert resp.ok is False
    assert resp.error.details["code"] == "incomplete_transfer"


def test_fetch_truncated_symbol_detected(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(sizes={"vmcore": 16, "vmcore-dmesg.txt": 1}))
    assert resp.ok is False
    assert resp.error.details["code"] == "incomplete_transfer"


def test_fetch_dump_too_large(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner(), max_bytes=4)
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_too_large"


def test_fetch_incomplete_refused(tmp_path) -> None:
    _booted(tmp_path)
    listing = _LISTING.replace('"vmcore_name": "vmcore"', '"vmcore_name": "vmcore-incomplete"').replace(
        '"incomplete": false', '"incomplete": true'
    )
    resp = _fetch(tmp_path, _FetchRunner(listing=listing))
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_incomplete"


def test_fetch_flat_format_refused_even_with_force(tmp_path) -> None:
    # vmcore.flat is a makedumpfile flat dump crash/drgn cannot read without a
    # `makedumpfile -R` rebuild; force overrides vmcore-incomplete, not .flat.
    _booted(tmp_path)
    listing = (
        _LISTING.replace('"vmcore_name": "vmcore"', '"vmcore_name": "vmcore.flat"')
        .replace('"incomplete": false', '"incomplete": true')
        .replace('"vmcore": 16', '"vmcore.flat": 16')
    )
    resp = _fetch(tmp_path, _FetchRunner(listing=listing, sizes={"vmcore.flat": 16}), force=True)
    assert resp.ok is False
    assert resp.error.details["code"] == "dump_flat_format"


def test_fetch_incomplete_allowed_with_force(tmp_path) -> None:
    _booted(tmp_path)
    listing = (
        _LISTING.replace('"vmcore_name": "vmcore"', '"vmcore_name": "vmcore-incomplete"')
        .replace('"incomplete": false', '"incomplete": true')
        .replace('"vmcore": 16', '"vmcore-incomplete": 16')
    )
    runner = _FetchRunner(listing=listing, sizes={"vmcore": 16, "vmcore-dmesg.txt": 4})
    resp = _fetch(tmp_path, runner, force=True)
    assert resp.ok is True, resp.error


def test_fetch_idempotent_skips_work_then_force_redoes_it(tmp_path) -> None:
    _booted(tmp_path)
    runner = _FetchRunner()
    r1 = _fetch(tmp_path, runner)
    assert r1.ok is True and r1.data["already_fetched"] is False
    calls_after_first = len(runner.calls)
    assert calls_after_first > 0  # enumeration + scp(s) happened

    r2 = _fetch(tmp_path, runner)
    assert r2.ok is True and r2.data["already_fetched"] is True
    # the cached path takes the fetch lock, sees the SUCCEEDED step, and returns —
    # no further ssh/scp invocations
    assert len(runner.calls) == calls_after_first

    r3 = _fetch(tmp_path, runner, force=True)
    assert r3.ok is True and r3.data["already_fetched"] is False
    assert len(runner.calls) > calls_after_first  # force re-enumerated + re-scp'd


def test_force_refetch_updates_manifest(tmp_path) -> None:
    run_id = _booted(tmp_path)
    _fetch(tmp_path, _FetchRunner(sizes={"vmcore": 16, "vmcore-dmesg.txt": 4}))
    bigger = _LISTING.replace('"size": 16', '"size": 32').replace('"vmcore": 16', '"vmcore": 32')
    resp = _fetch(tmp_path, _FetchRunner(listing=bigger, sizes={"vmcore": 32, "vmcore-dmesg.txt": 4}), force=True)
    assert resp.ok is True
    assert resp.data["already_fetched"] is False
    files = {f["name"]: f for f in resp.data["files"]}
    assert files["vmcore"]["size_bytes"] == 32
    store = ArtifactStore(artifact_root=tmp_path)
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("postmortem.fetch:"))
    persisted = {f["name"]: f for f in step.details["files"]}
    assert persisted["vmcore"]["size_bytes"] == 32


def test_fetch_redacts_ssh_key(tmp_path) -> None:
    _booted(tmp_path)
    resp = _fetch(tmp_path, _FetchRunner())
    assert resp.ok is True
    assert SECRET_KEY_REF not in str(resp.data)


def test_fetch_halted_target_rejected(tmp_path) -> None:
    _booted(tmp_path)
    resp = debug_postmortem_fetch_handler(
        DebugPostmortemFetchRequest(run_id="r1", manifest_target_profile="local-qemu", dump_ref="/var/crash/d1"),
        artifact_root=tmp_path,
        rootfs_profiles=_rootfs(),
        ssh_runner=_FetchRunner(),
        admission=_FakeAdmission(),
        session_registry=_FakeRegistry(ExecutionState.HALTED),
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.READINESS_FAILURE
    assert resp.error.details["code"] == "target_halted"
