"""modules helper: loaded modules + refcounts. Spec §7 (naturally bounded)."""

from __future__ import annotations

from kdive.domain import Model
from kdive.introspect.helpers.base import HelperSpec, NoArgs


class Module(Model):
    name: str
    # Total in-memory footprint in bytes summed across all module segments; -1 when
    # neither the legacy core_layout nor the mem[] array could be read.
    size: int
    refcount: int
    used_by: list[str]
    state: str


class Output(Model):
    modules: list[Module]
    # Count of modules that raised mid-decode and were dropped. >0 with a short
    # ``modules`` list means the decode path is partially wrong for this kernel;
    # an all-failed run raises instead (see script). A genuinely module-free
    # (monolithic) kernel yields an empty list with decode_errors == 0.
    decode_errors: int


SCRIPT = r"""
from drgn.helpers.linux.module import for_each_module
from drgn.helpers.linux.list import list_for_each_entry

_STATE = {0: "live", 1: "coming", 2: "going", 3: "unformed"}


def _module_size(mod):
    try:
        return int(mod.core_layout.size.value_())
    except Exception:
        # v6.4+ dropped core_layout for the mem[] array; total footprint is the sum
        # across every populated segment (text, data, rodata, ...), not just mem[0].
        try:
            return sum(int(mod.mem[i].size.value_()) for i in range(len(mod.mem)))
        except Exception:
            return -1


rows = []
decode_errors = 0
for mod in for_each_module(prog):
    try:
        try:
            refcount = int(mod.refcnt.counter.value_())
        except Exception:
            refcount = -1
        used_by = []
        try:
            for use in list_for_each_entry("struct module_use", mod.source_list.address_of_(), "source_list"):
                used_by.append(use.source.name.string_().decode("utf-8", "replace"))
        except Exception:
            pass
        rows.append({
            "name": mod.name.string_().decode("utf-8", "replace"),
            "size": _module_size(mod),
            "refcount": refcount,
            "used_by": used_by,
            "state": _STATE.get(int(mod.state.value_()), "unknown"),
        })
    except Exception:
        decode_errors += 1

if not rows and decode_errors:
    raise RuntimeError("modules: all %d modules failed to decode" % decode_errors)

emit({"modules": rows, "decode_errors": decode_errors})
"""

SPEC = HelperSpec(name="modules", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
