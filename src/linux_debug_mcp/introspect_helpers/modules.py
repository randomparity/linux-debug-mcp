"""modules helper: loaded modules + refcounts. Spec §7 (naturally bounded)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Module(Model):
    name: str
    size: int
    refcount: int
    used_by: list[str]
    state: str


class Output(Model):
    modules: list[Module]


SCRIPT = r"""
from drgn.helpers.linux.module import for_each_module

_STATE = {0: "live", 1: "coming", 2: "going", 3: "unformed"}
rows = []
for mod in for_each_module(prog):
    try:
        refcount = int(mod.refcnt.counter.value_())
    except Exception:
        refcount = -1
    used_by = []
    try:
        from drgn.helpers.linux.list import list_for_each_entry
        for use in list_for_each_entry("struct module_use", mod.source_list.address_of_(), "source_list"):
            used_by.append(use.source.name.string_().decode("utf-8", "replace"))
    except Exception:
        pass
    try:
        size = int(mod.core_layout.size.value_())
    except Exception:
        size = int(mod.mem[0].size.value_())
    rows.append({
        "name": mod.name.string_().decode("utf-8", "replace"),
        "size": size,
        "refcount": refcount,
        "used_by": used_by,
        "state": _STATE.get(int(mod.state.value_()), "unknown"),
    })
emit({"modules": rows})
"""

SPEC = HelperSpec(name="modules", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
