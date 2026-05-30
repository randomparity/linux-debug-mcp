"""slab helper: slab cache stats. Spec §7 (naturally bounded)."""

from __future__ import annotations

from kdive.domain import Model
from kdive.introspect_helpers.base import HelperSpec, NoArgs


class Cache(Model):
    name: str
    active_objs: int
    num_objs: int
    objsize: int
    objs_per_slab: int


class Output(Model):
    caches: list[Cache]
    # Count of caches that raised mid-decode and were dropped. >0 with a short
    # ``caches`` list means the decode path is partially wrong for this kernel;
    # an all-failed run raises instead (see script).
    decode_errors: int


SCRIPT = r"""
from drgn.helpers.linux.slab import for_each_slab_cache

rows = []
decode_errors = 0
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
        decode_errors += 1

# A booted kernel always has slab caches; an empty result with errors means the decode
# path is wrong for this kernel (e.g. SLAB vs SLUB), not that there are no caches.
if not rows and decode_errors:
    raise RuntimeError("slab: all %d caches failed to decode" % decode_errors)

emit({"caches": rows, "decode_errors": decode_errors})
"""

SPEC = HelperSpec(name="slab", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
