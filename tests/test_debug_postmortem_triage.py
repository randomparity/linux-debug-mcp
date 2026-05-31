from __future__ import annotations

from pathlib import Path

import kdive.server as server_module
from kdive.artifacts.store import ArtifactStore
from kdive.domain import (
    ErrorCategory,
    RunRequest,
    ToolResponse,
)
from kdive.postmortem import handlers as postmortem_handlers
from kdive.postmortem.models import DebugPostmortemTriageRequest
from kdive.server import debug_postmortem_triage_handler

GOOD_ID = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


def test_triage_handler_lives_in_postmortem_package() -> None:
    assert postmortem_handlers.debug_postmortem_triage_handler.__module__ == "kdive.postmortem.handlers"
    assert server_module.debug_postmortem_triage_handler is postmortem_handlers.debug_postmortem_triage_handler


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


class _Recorder:
    """Counts sub-handler invocations and returns a canned ToolResponse."""

    def __init__(self, response: ToolResponse) -> None:
        self.response = response
        self.calls: list[dict] = []

    def __call__(self, request, **kwargs):
        self.calls.append({"request": request, "kwargs": kwargs})
        return self.response


def _crash_ok() -> ToolResponse:
    return ToolResponse.success(
        summary="crash",
        run_id="r1",
        data={
            "call_id": "crash1",
            "results": {
                "log": {"parsed": True, "lines": [{"ts": 1.0, "text": "Kernel panic - not syncing: boom"}]},
                "bt": {"parsed": True, "pid": 7, "command": "kworker", "frames": [{"level": 0, "symbol": "panic"}]},
            },
        },
    )


def _drgn_ok(payload: dict) -> ToolResponse:
    return ToolResponse.success(summary="drgn", run_id="r1", data={"call_id": "d", "result": payload})


def _dispatch(dmesg: _Recorder, modules: _Recorder):
    return lambda req, **kw: (dmesg if req.name == "dmesg" else modules)(req, **kw)


def test_happy_path_full_report(tmp_path) -> None:
    store = _run(tmp_path)
    crash = _Recorder(_crash_ok())
    dmesg = _Recorder(_drgn_ok({"entries": [{"text": "boot"}], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [{"name": "ext4"}], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=_dispatch(dmesg, modules),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["partial"] is False
    report = resp.data["report"]
    assert report["panic_reason"]["text"] == "Kernel panic - not syncing: boom"
    assert report["faulting_task"]["pid"] == 7
    assert report["recent_dmesg"]["entries"] == [{"text": "boot"}]
    assert report["modules"]["modules"] == [{"name": "ext4"}]
    assert resp.data["sub_call_ids"]["crash"] == "crash1"
    rd = store.run_dir("r1")
    assert any((rd / "debug" / "postmortem" / "triage").glob("*/report.json"))
    assert any(n.startswith("postmortem.triage:") for n in store.load_manifest("r1").step_results)


def test_partial_crash_down(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(
        ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="no crash",
            run_id="r1",
            details={"code": "crash_open_failure"},
        )
    )
    dmesg = _Recorder(_drgn_ok({"entries": [{"text": "boot"}], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=_dispatch(dmesg, modules),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["partial"] is True
    report = resp.data["report"]
    assert report["panic_reason"]["status"] == "failed"
    assert report["panic_reason"]["reason"] == "crash_open_failure"
    assert report["recent_dmesg"]["status"] == "ok"


def test_build_id_mismatch_no_subcall(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(_crash_ok())
    drgn = _Recorder(_drgn_ok({"entries": []}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=drgn,
        vmcore_build_id_reader=lambda _p: "a" * 40,
        vmlinux_build_id_reader=lambda _p: "b" * 40,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    assert crash.calls == [] and drgn.calls == []


def test_all_sources_down_hard_fail(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(
        ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="x",
            run_id="r1",
            details={"code": "crash_open_failure", "call_id": "crashX"},
        )
    )
    drgn = _Recorder(
        ToolResponse.failure(
            category=ErrorCategory.INFRASTRUCTURE_FAILURE,
            message="y",
            run_id="r1",
            details={"code": "helper_script_error"},
        )
    )
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=drgn,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "triage_all_sources_failed"
    assert resp.error.details["sub_call_ids"]["crash"] == "crashX"


def test_detail_less_failure_does_not_raise(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(ToolResponse.failure(category=ErrorCategory.INFRASTRUCTURE_FAILURE, message="bare", run_id="r1"))
    dmesg = _Recorder(_drgn_ok({"entries": [{"text": "x"}], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=_dispatch(dmesg, modules),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert resp.data["report"]["panic_reason"]["reason"] == "sub_call_failed"
    assert resp.data["sub_call_ids"]["crash"] is None


def test_drgn_subcalls_get_modules_ref_none(tmp_path) -> None:
    _run(tmp_path)
    (tmp_path / "r1" / "build" / "mods").mkdir(parents=True, exist_ok=True)
    seen = {}

    def _drgn(req, **kw):
        seen[req.name] = req.modules_ref
        payload = {"entries": [], "truncated": False} if req.name == "dmesg" else {"modules": [], "decode_errors": 0}
        return _drgn_ok(payload)

    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", modules_ref="build/mods"
        ),
        artifact_root=tmp_path,
        crash_handler=_Recorder(_crash_ok()),
        drgn_helper_handler=_drgn,
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is True
    assert seen == {"dmesg": None, "modules": None}


def test_invalid_timeout_no_subcall(tmp_path) -> None:
    _run(tmp_path)
    crash = _Recorder(_crash_ok())
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(
            run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux", timeout_seconds=4
        ),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=_Recorder(_drgn_ok({})),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "invalid_timeout"
    assert crash.calls == []


def test_redaction_masks_secret_in_report(tmp_path) -> None:
    store = _run(tmp_path)
    secret = "hunter2trustno1xyz"  # pragma: allowlist secret
    crash = _Recorder(
        ToolResponse.success(
            summary="crash",
            run_id="r1",
            data={
                "call_id": "c",
                "results": {
                    "log": {"parsed": True, "lines": [{"ts": 1.0, "text": f"db_password={secret} boom"}]},
                    "bt": {"parsed": False, "reason": "not_captured"},
                },
            },
        )
    )
    dmesg = _Recorder(_drgn_ok({"entries": [], "truncated": False}))
    modules = _Recorder(_drgn_ok({"modules": [], "decode_errors": 0}))
    resp = debug_postmortem_triage_handler(
        DebugPostmortemTriageRequest(run_id="r1", vmcore_ref="inputs/vmcore", vmlinux_ref="build/vmlinux"),
        artifact_root=tmp_path,
        crash_handler=crash,
        drgn_helper_handler=_dispatch(dmesg, modules),
        vmcore_build_id_reader=lambda _p: GOOD_ID,
        vmlinux_build_id_reader=lambda _p: GOOD_ID,
    )
    assert secret not in repr(resp.data["report"])
    rd = store.run_dir("r1")
    for p in (rd / "debug" / "postmortem" / "triage").glob("*/report.json"):
        assert secret not in p.read_text(encoding="utf-8")


def test_tool_is_registered() -> None:
    import asyncio

    from kdive.server import create_app

    app = create_app()
    tools = asyncio.run(app.list_tools())
    assert any(t.name == "debug.postmortem.triage" for t in tools)
