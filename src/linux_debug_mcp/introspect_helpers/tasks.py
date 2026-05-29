"""tasks helper: process list + kernel stacks, focus on blocked/D-state. Spec §7."""

from __future__ import annotations

from pydantic import Field

from linux_debug_mcp.domain import Model
from linux_debug_mcp.introspect_helpers.base import HelperSpec


class Args(Model):
    states: list[str] = Field(default_factory=lambda: ["D"])
    include_stack: bool = True
    limit: int = 200


class Task(Model):
    pid: int
    tgid: int
    comm: str
    state: str
    kernel_stack: list[str] = Field(default_factory=list)


class Output(Model):
    tasks: list[Task]
    truncated: bool


SCRIPT = r"""
from drgn.helpers.linux.pid import for_each_task

# args is the validated, defaulted Args dump, so every key is present.
want = set(args["states"])
include_stack = bool(args["include_stack"])
limit = int(args["limit"])

def state_letter(task):
    try:
        from drgn.helpers.linux.sched import task_state_to_char
        return task_state_to_char(task)
    except Exception:
        return "?"

rows = []
truncated = False
for task in for_each_task(prog):
    letter = state_letter(task)
    if want and letter not in want:
        continue
    if len(rows) >= limit:
        truncated = True
        break
    stack = []
    if include_stack:
        try:
            for frame in prog.stack_trace(task):
                stack.append(str(frame))
        except Exception as exc:
            stack = ["<stack unavailable: %s>" % type(exc).__name__]
    rows.append({
        "pid": int(task.pid.value_()),
        "tgid": int(task.tgid.value_()),
        "comm": task.comm.string_().decode("utf-8", "replace"),
        "state": letter,
        "kernel_stack": stack,
    })

emit({"tasks": rows, "truncated": truncated})
"""

SPEC = HelperSpec(name="tasks", version=1, script=SCRIPT, args_model=Args, output_model=Output)
