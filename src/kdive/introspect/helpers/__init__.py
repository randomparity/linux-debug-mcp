"""Helper registry. Spec §3.1."""

from __future__ import annotations

from functools import cache

from kdive.introspect.helpers.base import HelperSpec


def built_in_helper_specs() -> list[HelperSpec]:
    # Local imports keep the helper modules out of this module's import-time
    # namespace; the call site below still imports all six eagerly.
    from kdive.introspect.helpers import dmesg, irq, modules, slab, sysinfo, tasks

    return [sysinfo.SPEC, tasks.SPEC, dmesg.SPEC, modules.SPEC, slab.SPEC, irq.SPEC]


@cache
def get_helper_registry() -> dict[str, HelperSpec]:
    return {spec.name: spec for spec in built_in_helper_specs()}
