"""slab helper: slab cache stats. Spec §7 (naturally bounded)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Cache(Model):
    name: str
    active_objs: int
    num_objs: int
    objsize: int
    objs_per_slab: int


class Output(Model):
    caches: list[Cache]


SCRIPT = r"""
from drgn.helpers.linux.slab import for_each_slab_cache

rows = []
for cache in for_each_slab_cache(prog):
    try:
        name = cache.name.string_().decode("utf-8", "replace")
        objsize = int(cache.object_size.value_())
        oo = int(cache.oo.x.value_())
        objs_per_slab = oo & ((1 << 16) - 1)
        # SLUB does not expose per-cache active/num object counts via the same drgn path
        # as SLAB; -1 signals unavailable.
        rows.append({
            "name": name,
            "active_objs": -1,
            "num_objs": -1,
            "objsize": objsize,
            "objs_per_slab": objs_per_slab,
        })
    except Exception:
        continue
emit({"caches": rows})
"""

SPEC = HelperSpec(name="slab", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
