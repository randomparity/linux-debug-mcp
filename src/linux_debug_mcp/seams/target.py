from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator

from linux_debug_mcp.domain import Model

if TYPE_CHECKING:
    # annotation-only: importing these at runtime would invert the layer dependency
    # (admission imports seams.target; transport.base imports seams.target).
    from linux_debug_mcp.coordination.admission import AdmissionService
    from linux_debug_mcp.transport.base import TransportRef


class Arch(StrEnum):
    X86_64 = "x86_64"
    PPC64LE = "ppc64le"
    S390X = "s390x"
    AARCH64 = "aarch64"


class ConsoleKind(StrEnum):
    UART = "uart"
    HVC = "hvc"
    VIRTIO = "virtio"


class TargetState(StrEnum):
    ACQUIRING = "acquiring"
    PREPARING = "preparing"
    BOOTING = "booting"
    READY = "ready"
    DEBUGGING = "debugging"
    RESETTING = "resetting"
    CRASHED = "crashed"
    RELEASING = "releasing"


class BreakHint(StrEnum):
    UART_BREAK = "uart_break"
    SYSRQ_G = "sysrq_g"
    AGENT_PROXY_BREAK = "agent_proxy_break"
    GDBSTUB_NATIVE = "gdbstub_native"


class TargetKey(BaseModel):
    """Contract-wide identity tuple: (provisioner, target_id). Frozen so it is
    hashable and usable as a dict/lease/guard key (contract §3.1)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provisioner: str
    target_id: str

    def recovery_key(self) -> str:
        """Canonical length-prefixed sha256 of the key, for recovery-tombstone
        filenames (spec §4.7). Opaque key parts are never used as path segments."""
        p = self.provisioner.encode()
        t = self.target_id.encode()
        payload = len(p).to_bytes(4, "big") + p + len(t).to_bytes(4, "big") + t
        return hashlib.sha256(payload).hexdigest()


class SshEndpoint(Model):
    host: str
    port: int = Field(ge=1, le=65535)
    user: str
    key_ref: str


class PlatformMetadata(Model):
    console_kind: ConsoleKind
    console_count: int = Field(ge=1)
    dedicated_debug_line: bool
    ssh_reachable: bool
    break_hints: list[BreakHint] = Field(default_factory=list)


class KernelProvenance(Model):
    build_id: str
    release: str
    vmlinux_ref: str
    modules_ref: str | None = None
    cmdline: str
    config_ref: str | None = None


class LeaseInfo(Model):
    lease_id: str
    holder: str
    expires_at: datetime | None = None
    renewable: bool

    @field_validator("expires_at")
    @classmethod
    def _expires_at_must_be_utc_aware(cls, value: datetime | None) -> datetime | None:
        """Reject naive timestamps and normalize to UTC so the near-expiry admission
        gate can compare against a UTC clock without ad hoc interpretation."""
        if value is None:
            return None
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("LeaseInfo.expires_at must be timezone-aware")
        return value.astimezone(UTC)


def publish_ready_snapshot(
    admission: AdmissionService,
    *,
    target_key: TargetKey,
    generation: int,
    transports: Iterable[TransportRef],
    platform: PlatformMetadata,
    lease: LeaseInfo | None = None,
) -> None:
    """Local-qemu adapter: publish the authoritative TargetSnapshot when a run boots READY, so
    admission can re-bind/validate transport.open requests against it (§4.1). Provisioning later
    owns this writer; this adapter is used until provisioning provides its own snapshot publisher."""
    from linux_debug_mcp.coordination.admission import TargetSnapshot

    admission.publish_snapshot(
        target_key,
        TargetSnapshot(
            generation=generation,
            transports=tuple(transports),
            platform=platform,
            state=TargetState.READY,
            lease=lease,
        ),
    )
