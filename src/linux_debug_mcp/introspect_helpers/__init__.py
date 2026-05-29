"""Helper registry. Spec §3.1."""

from __future__ import annotations

from linux_debug_mcp.introspect_helpers.base import HelperSpec


def built_in_helper_specs() -> list[HelperSpec]:
    # Local imports so a syntax error in one helper module surfaces at call
    # time with a clear traceback rather than breaking package import.
    from linux_debug_mcp.introspect_helpers import dmesg, irq, modules, slab, sysinfo, tasks

    return [sysinfo.SPEC, tasks.SPEC, dmesg.SPEC, modules.SPEC, slab.SPEC, irq.SPEC]


HELPER_REGISTRY: dict[str, HelperSpec] = {spec.name: spec for spec in built_in_helper_specs()}
