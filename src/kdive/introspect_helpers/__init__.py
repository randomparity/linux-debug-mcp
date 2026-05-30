"""Helper registry. Spec §3.1."""

from __future__ import annotations

from kdive.introspect_helpers.base import HelperSpec


def built_in_helper_specs() -> list[HelperSpec]:
    # Local imports keep the helper modules out of this module's import-time
    # namespace; the call site below still imports all six eagerly.
    from kdive.introspect_helpers import dmesg, irq, modules, slab, sysinfo, tasks

    return [sysinfo.SPEC, tasks.SPEC, dmesg.SPEC, modules.SPEC, slab.SPEC, irq.SPEC]


# Eagerly imports all six helper modules at package load.
HELPER_REGISTRY: dict[str, HelperSpec] = {spec.name: spec for spec in built_in_helper_specs()}
