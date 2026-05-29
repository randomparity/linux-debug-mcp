"""irq helper: per-CPU IRQ counts + affinity. Spec §7 (naturally bounded)."""

from __future__ import annotations

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec, NoArgs


class Irq(Model):
    irq: int
    name: str | None
    counts_per_cpu: list[int]
    affinity: list[int]


class Output(Model):
    irqs: list[Irq]


SCRIPT = r"""
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr

online = list(for_each_online_cpu(prog))
rows = []

def iter_descs():
    try:
        from drgn.helpers.linux.radixtree import radix_tree_for_each
        for index, entry in radix_tree_for_each(prog["irq_desc_tree"].address_of_()):
            yield int(index), drgn.Object(prog, "struct irq_desc *", value=entry.value_())
    except Exception:
        return

for irq_no, desc in iter_descs():
    try:
        counts = []
        kstat = desc.kstat_irqs
        for cpu in online:
            counts.append(int(per_cpu_ptr(kstat, cpu).value_()))
        name = None
        try:
            action = desc.action
            if action.value_():
                name = action.name.string_().decode("utf-8", "replace")
        except Exception:
            name = None
        affinity = list(online)
        rows.append({"irq": irq_no, "name": name, "counts_per_cpu": counts, "affinity": affinity})
    except Exception:
        continue
emit({"irqs": rows})
"""

SPEC = HelperSpec(name="irq", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
