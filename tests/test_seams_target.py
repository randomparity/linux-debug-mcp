import hashlib
import inspect
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from kdive.seams.target import (
    Arch,
    BreakHint,
    ConsoleKind,
    KernelProvenance,
    LeaseInfo,
    PlatformMetadata,
    SshEndpoint,
    TargetKey,
    TargetState,
)


def test_target_key_is_frozen_and_hashable():
    key = TargetKey(provisioner="local-qemu", target_id="run-1")
    assert hash(key) == hash(TargetKey(provisioner="local-qemu", target_id="run-1"))
    assert {key: "v"}[TargetKey(provisioner="local-qemu", target_id="run-1")] == "v"
    with pytest.raises(ValidationError):
        key.target_id = "mutated"


def test_target_seam_does_not_import_coordination_or_transport_layers():
    import kdive.seams.target as target_module

    source = inspect.getsource(target_module)
    assert "kdive.coordination" not in source
    assert "kdive.transport" not in source
    assert not hasattr(target_module, "publish_ready_snapshot")


def test_target_key_distinct_provisioners_do_not_collide():
    a = TargetKey(provisioner="provA", target_id="t1")
    b = TargetKey(provisioner="provB", target_id="t1")
    assert a != b
    assert hash(a) != hash(b) or a != b  # different identity even if hashes collide


def test_target_key_recovery_key_is_canonical_hash():
    key = TargetKey(provisioner="local-qemu", target_id="run-1")
    p = b"local-qemu"
    t = b"run-1"
    payload = len(p).to_bytes(4, "big") + p + len(t).to_bytes(4, "big") + t
    expected = hashlib.sha256(payload).hexdigest()
    assert key.recovery_key() == expected


def test_target_key_recovery_key_resists_delimiter_confusion():
    # ("a", "b\x00c") and ("a\x00b", "c") must not collide.
    left = TargetKey(provisioner="a", target_id="b\x00c").recovery_key()
    right = TargetKey(provisioner="a\x00b", target_id="c").recovery_key()
    assert left != right


def test_ssh_endpoint_port_bounds():
    SshEndpoint(host="h", port=22, user="root", key_ref="ref")
    with pytest.raises(ValidationError):
        SshEndpoint(host="h", port=0, user="root", key_ref="ref")
    with pytest.raises(ValidationError):
        SshEndpoint(host="h", port=70000, user="root", key_ref="ref")


def test_platform_metadata_requires_positive_console_count():
    PlatformMetadata(
        console_kind=ConsoleKind.UART,
        console_count=1,
        dedicated_debug_line=False,
        ssh_reachable=True,
        break_hints=[BreakHint.SYSRQ_G],
    )
    with pytest.raises(ValidationError):
        PlatformMetadata(
            console_kind=ConsoleKind.UART,
            console_count=0,
            dedicated_debug_line=False,
            ssh_reachable=True,
        )


def test_models_forbid_extra_fields():
    with pytest.raises(ValidationError):
        LeaseInfo(lease_id="l", holder="h", renewable=True, bogus=1)


def test_lease_info_rejects_naive_expires_at():
    # The near-expiry admission gate compares expires_at to a UTC clock; a naive value
    # would make that comparison raise or depend on ad hoc interpretation.
    with pytest.raises(ValidationError):
        LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=datetime(2030, 1, 1, 0, 0, 0))


def test_lease_info_normalizes_expires_at_to_utc():
    aware = datetime(2030, 1, 1, 5, 0, 0, tzinfo=timezone(timedelta(hours=5)))
    lease = LeaseInfo(lease_id="l", holder="h", renewable=True, expires_at=aware)
    assert lease.expires_at == datetime(2030, 1, 1, 0, 0, 0, tzinfo=UTC)
    assert lease.expires_at.utcoffset() == timedelta(0)


def test_lease_info_expires_at_optional():
    assert LeaseInfo(lease_id="l", holder="h", renewable=True).expires_at is None


def test_enums_have_contract_values():
    assert {a.value for a in Arch} == {"x86_64", "ppc64le", "s390x", "aarch64"}
    assert {c.value for c in ConsoleKind} == {"uart", "hvc", "virtio"}
    assert TargetState.READY == "ready"
    assert TargetState.DEBUGGING == "debugging"


def test_kernel_provenance_optional_refs_default_none():
    prov = KernelProvenance(build_id="bid", release="6.9.0", vmlinux_ref="ref", cmdline="ro")
    assert prov.modules_ref is None
    assert prov.config_ref is None
