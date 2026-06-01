"""irq helper: per-CPU IRQ counts + affinity. Spec §7 (naturally bounded).

Assumes ``CONFIG_SPARSE_IRQ`` (the ``irq_desc_tree`` radix tree). If that symbol
is absent the script raises and the call surfaces as ``helper_script_error``
rather than a misleading empty result.
"""

from __future__ import annotations

from kdive.domain import Model
from kdive.introspect.helpers.base import HelperSpec, NoArgs


class Irq(Model):
    irq: int
    name: str | None
    counts_per_cpu: list[int]
    # None when the affinity cpumask could not be decoded on this kernel; v1 does
    # not fabricate a value (a fabricated "all online CPUs" set reads as "unpinned"
    # to a consumer and is worse than an honest null).
    affinity: list[int] | None


class Output(Model):
    irqs: list[Irq]
    # Count of descriptors that raised mid-decode and were dropped. >0 with a short
    # ``irqs`` list means the per-IRQ decode path is partially wrong for this kernel;
    # an all-failed run raises instead (see script).
    decode_errors: int


SCRIPT = r"""
import drgn
from drgn.helpers.linux.cpumask import for_each_online_cpu, for_each_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.radixtree import radix_tree_for_each

online = list(for_each_online_cpu(prog))
rows = []
decode_errors = 0

for index, entry in radix_tree_for_each(prog["irq_desc_tree"].address_of_()):
    irq_no = int(index)
    desc = drgn.Object(prog, "struct irq_desc *", value=entry.value_())
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
        affinity = None
        try:
            affinity = [int(c) for c in for_each_cpu(desc.irq_common_data.affinity)]
        except Exception:
            affinity = None
        rows.append({"irq": irq_no, "name": name, "counts_per_cpu": counts, "affinity": affinity})
    except Exception:
        decode_errors += 1

# A booted kernel always has IRQ descriptors. An empty result with errors means the
# per-IRQ decode path is wrong for this kernel, not that there are no IRQs — fail loud
# so the caller sees helper_script_error, not a misleading empty list.
if not rows and decode_errors:
    raise RuntimeError("irq: all %d descriptors failed to decode" % decode_errors)

emit({"irqs": rows, "decode_errors": decode_errors})
"""

SPEC = HelperSpec(name="irq", version=1, script=SCRIPT, args_model=NoArgs, output_model=Output)
