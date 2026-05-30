# ADR 0036 — gdb/MI kernel breakpoints are hardware breakpoints

**Status:** Accepted (2026-05-30) · **Issue:** #119 · **Epic:** #100 · **Amends:** [0033](0033-wait-for-debugger-frozen-boot.md) · **Affects:**
`src/linux_debug_mcp/providers/gdb_mi.py` (`GdbMiEngine.set_breakpoint` issues `-break-insert -h`).

## Context

ADR 0033 added `wait_for_debugger` frozen boot so a breakpoint set while the vCPU is paused at the
reset vector is hit deterministically in early init. The epic #100 acceptance run found this did not
actually work: `debug.set_breakpoint __d_lookup` then `debug.continue` stalled — the breakpoint never
fired, the 60 s interactive wait expired, the post-timeout `-exec-interrupt` got no `*stopped`, and the
session went `recovery_required` (#119).

`GdbMiEngine.set_breakpoint` issued `-break-insert <loc>`, a **software** breakpoint: gdb writes a
`0xCC` byte at the symbol's virtual address. Inserted while the CPU is frozen at the reset vector —
before the kernel is decompressed/relocated and paging is enabled — that byte lands in memory that is
not the final kernel text, so it does not survive into the running kernel and never traps. A direct
`qemu -S -gdb` experiment confirmed it: a **hardware** breakpoint (`hbreak __d_lookup`) on the same
frozen boot fires in early init (`component_debug_init → debugfs_create_dir → __d_lookup`), where the
software breakpoint did not. (It also read `d_hash_shift == 32`, the degenerate one-bucket sizing
`dhash_entries=1` produces.)

Software breakpoints have a second failure mode independent of frozen boot: a kernel built with
`CONFIG_STRICT_KERNEL_RWX` maps `.text` read-only, so the `0xCC` write can fail or be silently dropped
on a running kernel too.

## Decision

`GdbMiEngine.set_breakpoint` issues `-break-insert -h <loc>` — a **hardware** breakpoint (qemu gdbstub
`Z1`, x86 debug registers) — for all gdb/MI kernel breakpoints, not only the frozen-boot path.

Rationale for unconditional (not frozen-only): the engine is shared by the qemu-gdbstub and serial-KGDB
tiers; both debug a kernel whose `.text` may be read-only, and both run on x86 with debug-register
hardware breakpoint support. Hardware breakpoints are the kernel-debugging norm and are correct in every
case the engine serves, so making them conditional on frozen-boot state would add plumbing for a
narrower, still-incorrect default.

`-break-watch` (data watchpoints) already uses the same debug-register hardware and is unchanged.

## Consequences

- Frozen-boot early breakpoints fire; #104/#119's deterministic early-init breakpoint works against a
  real guest. The gated `test_live_frozen_boot_hits_early_breakpoint` is now meaningful (still skipped in
  CI; it requires a live guest).
- Breakpoints + watchpoints share the CPU's four debug registers (x86: DR0–DR3). A fifth concurrent
  hardware breakpoint/watchpoint returns a gdb insert error, surfaced as the normal `set_breakpoint`
  failure — a clear, immediate error rather than a silently non-firing software breakpoint. This bound is
  acceptable for interactive kernel debugging.
- `set_breakpoint`'s emitted MI command changes from `-break-insert <loc>` to `-break-insert -h <loc>`;
  the one unit test asserting the exact command is updated.

## Considered & rejected

1. **Keep software breakpoints as the default.** Rejected: they do not fire from a frozen boot (the
   measured #119 failure) and can fail silently on `CONFIG_STRICT_KERNEL_RWX` kernels. The whole point of
   the gdb tier is to stop the kernel reliably.
2. **Use hardware only when the session began from a frozen boot.** Rejected: it threads frozen-state
   from the boot result through the handler into the engine for a default that is still wrong for
   read-only `.text` on a running kernel. Hardware is correct in every case the engine serves, so the
   conditional adds plumbing without removing a real failure mode. The only cost it would save is the
   four-register budget, which interactive debugging does not strain.
3. **Expose a per-call `hardware` flag on `debug.set_breakpoint`.** Rejected for now: it is speculative
   surface (no caller needs software breakpoints against a kernel) and pushes a low-level mechanism choice
   into the agent-facing contract. Can be added later if a concrete need appears.
