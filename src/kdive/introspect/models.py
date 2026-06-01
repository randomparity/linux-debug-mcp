from __future__ import annotations

from typing import Any

from pydantic import Field

from kdive.model import Model


class DebugIntrospectRunRequest(Model):
    """Request payload for ``debug.introspect.run``. Spec section 3.1.

    ``script`` is the user-supplied drgn Python source. The handler
    base64-encodes it for transport and substitutes it into a
    ``string.Template``-rendered wrapper on the target (spec section 4.2).
    ``call_id`` is server-minted, not part of the request.

    The ``[5, 300]`` timeout band and the script-non-empty / <=256 KiB
    invariants are enforced by the handler (not Pydantic) so they surface
    as ``ToolResponse.failure(...)`` with the spec's exact codes from section 3.3.
    """

    run_id: str
    manifest_target_profile: str
    script: str
    timeout_seconds: int = 30
    allow_write: bool = False
    acknowledged_permissions: list[str] = Field(default_factory=list)
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)


class DebugIntrospectCheckPrerequisitesRequest(Model):
    """Request payload for ``debug.introspect.check_prerequisites``. Spec section 3.

    Run-scoped, read-only target probe. ``timeout_seconds`` defaults to 20 and
    is bounded to [5, 60] by the handler (not Pydantic) so an out-of-range
    value surfaces as ``ToolResponse.failure(CONFIGURATION_ERROR)`` per section 6.
    """

    run_id: str
    manifest_target_profile: str
    timeout_seconds: int = 20
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugIntrospectHelperRequest(Model):
    """Request payload for ``debug.introspect.helper``. Spec section 6.1.

    ``args`` is validated against the resolved helper's ``args_model`` by the
    handler (not Pydantic) so an unknown helper / bad args surface as the
    spec's exact failure codes. The ``[5, 300]`` timeout band and
    manifest-immutability of profile fields are enforced by the handler.
    """

    run_id: str
    manifest_target_profile: str
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
    debug_profile: str | None = None
    target_profile: str | None = None
    rootfs_profile: str | None = None


class DebugIntrospectFromVmcoreRequest(Model):
    """Request payload for ``debug.introspect.from_vmcore``. Spec section 3.1.

    No ``target_ref``/``*_profile``: the offline path names no live target.
    ``vmcore_ref``/``vmlinux_ref``/``modules_ref`` are run-relative and confined
    to the run dir. The ``[5, 300]`` timeout band and the script non-empty /
    <=256 KiB invariants are enforced by the handler (not Pydantic) so they
    surface as ``ToolResponse.failure(...)`` with the spec's exact codes.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    script: str
    timeout_seconds: int = 30
    allow_write: bool = False
    args: dict[str, Any] = Field(default_factory=dict)


class DebugIntrospectFromVmcoreHelperRequest(Model):
    """Request payload for ``debug.introspect.from_vmcore_helper``. Spec section 3.1.

    Runs a curated helper from ``get_helper_registry()`` against the vmcore.
    ``args`` is validated against the resolved helper's ``args_model`` by the handler.
    """

    run_id: str
    vmcore_ref: str
    vmlinux_ref: str
    modules_ref: str | None = None
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
