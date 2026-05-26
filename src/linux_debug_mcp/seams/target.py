from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from linux_debug_mcp.domain import Model


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
