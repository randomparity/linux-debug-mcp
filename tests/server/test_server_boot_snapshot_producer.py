import pytest
from conftest import FakeBootProvider, create_run, profiles, record_build, target_profile
from handler_call_helpers import target_boot_handler

from kdive.config import TARGET_DESTRUCTIVE_PERMISSIONS, TargetProfile
from kdive.coordination.admission import AdmissionError, AdmissionService, SnapshotStore
from kdive.seams.target import BreakHint, ConsoleKind, PlatformMetadata, TargetKey
from kdive.transport.core.base import LineRole, OpenRequest, TransportRef


def _platform() -> PlatformMetadata:
    """The authoritative platform facts the producer publishes for a local-qemu boot."""
    return PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=False,
        break_hints=[BreakHint.GDBSTUB_NATIVE],
    )


def _debug_target() -> TargetProfile:
    return target_profile().model_copy(update={"debug_gdbstub": True})


def _rsp_request(generation: int) -> OpenRequest:
    key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    ref = TransportRef(
        provider="qemu-gdbstub",
        channel_id="rsp0",
        line_role=LineRole.RSP,
        caps=("rsp",),
        target_ref={"host": "127.0.0.1", "port": 1234},
    )
    return OpenRequest(target_key=key, generation=generation, transport_ref=ref, platform=_platform())


def _boot(artifact_root, tmp_path, admission, *, force_reboot=False):
    return target_boot_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=FakeBootProvider(),
        admission=admission,
        force_reboot=force_reboot,
        acknowledged_permissions=TARGET_DESTRUCTIVE_PERMISSIONS["target.boot"],
        **profiles(tmp_path, target=_debug_target()),
    )


def test_boot_publishes_ready_snapshot(tmp_path):
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    admission = AdmissionService(SnapshotStore())
    response = _boot(artifact_root, tmp_path, admission)
    assert response.ok is True
    # the snapshot was published, so admission can now bind the RSP channel (no stale_handle).
    request = _rsp_request(generation=1)
    handle = admission.admit(request.target_key, request)
    assert handle is not None


def test_reboot_bumps_generation_invalidates_old(tmp_path):
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    admission = AdmissionService(SnapshotStore())
    _boot(artifact_root, tmp_path, admission)  # attempt 1 -> generation 1
    stale = _rsp_request(generation=1)  # minted against generation 1
    _boot(artifact_root, tmp_path, admission, force_reboot=True)  # attempt 2 -> generation 2
    with pytest.raises(AdmissionError) as exc:
        admission.admit(stale.target_key, stale)
    assert exc.value.code == "stale_handle"
