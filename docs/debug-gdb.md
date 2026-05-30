# gdb/MI debug tier

The gdb/MI tier drives a live `gdb --interpreter=mi3` attachment to a target's RSP
(gdb-remote) endpoint. It is the interactive source-level tier: breakpoints, watchpoints,
single-stepping, register/memory reads, and expression evaluation against a halted kernel.
On x86_64 over a local QEMU gdbstub it is the clean, fully-supported path.

## Agent flow

A debug session is built on top of a succeeded debug boot. The usual order is:

1. `debug.start_session` — attach gdb/MI over the run's RSP endpoint. The kernel is halted
   for the lifetime of the session and resumed on `debug.end_session`.
2. `debug.load_module_symbols` — for a breakpoint in a loadable module, load the module's
   symbols at its runtime addresses (see below) before setting the breakpoint.
3. `debug.set_breakpoint` (or `debug.set_watchpoint`) — place the stop.
4. `debug.continue` — run until the breakpoint hits; the response carries the stop frame.
5. `debug.backtrace`, `debug.read_registers`, `debug.read_memory`, `debug.list_variables`,
   `debug.evaluate`, `debug.step`, `debug.next`, `debug.finish` — inspect and advance.
6. `debug.end_session` — resume the kernel and release the transport.

`debug.read_memory` is capped at 4096 bytes per call.

## Module symbol loading

A breakpoint on a function in a loadable module does not resolve until gdb knows where the
module's sections were placed at load time. `debug.load_module_symbols` reads the module's
per-section runtime addresses from the guest's
`/sys/module/<name>/sections/` over SSH and issues an `add-symbol-file` at those addresses,
so subsequent `debug.set_breakpoint` calls into the module resolve.

- The module name is matched against the build tree with both hyphen and underscore
  spellings (`e1000_netdev` ↔ `e1000-netdev`); a `.ko.debug` object is preferred over a
  stripped `.ko` when present.
- The load is idempotent by module name and `.text` address: re-loading the same module at
  the same address is a no-op; a load at a *different* address than the recorded one is a
  `module_address_changed` error rather than a silent double-load.
- If `/sys/module/<name>` is absent the module is not loaded in the running kernel
  (`module_not_loaded`); if the `.text` address cannot be read the call reports
  `section_addresses_unreadable` rather than loading partial symbols.

## Transport quality

The gdb/MI tier rides whatever console the target exposes the RSP over. Not every console
is equally reliable for an interactive RSP exchange:

- **QEMU gdbstub (x86_64)** — a dedicated loopback TCP gdbstub. This is the clean path:
  break-in is native (gdb interrupts directly) and the transcript is lossless.
- **Lossy out-of-band consoles (HVC, virtio-console)** — paravirtual consoles whose framing
  can silently drop or corrupt bytes under load. SOL/HMC vterm RSP carried over such a
  console may stall or desync mid-exchange. When `debug.start_session` detects the RSP is
  riding one of these, the success response carries a `transport_quality_warning` and its
  `suggested_next_actions` lead with `debug.kdb` and `debug.introspect.run` — the in-guest
  and postmortem tiers, which do not depend on the lossy out-of-band path. Prefer those tiers
  for reliable inspection when the warning is present.

The warning is keyed on the console's framing quality, not on which physical line was
selected; a dedicated UART carries no warning.

## Break entry

Break entry (`debug.interrupt`) executes whatever break method admission recorded in the
session's break plan — the tier never chooses or hardcodes the method:

- A **gdbstub-native** plan (the loopback QEMU default) interrupts the inferior directly
  through gdb.
- Any **other admitted method** (an agent-proxy/UART break over a serial console) is injected
  over the console via the transport's live break handle, after which the engine waits the
  bounded window for the resulting stop.

If the owning transport exposes no break handle the interrupt fails with
`break_inject_unavailable` rather than silently doing nothing.

## RSP-stall behaviour

A bounded `remotetimeout` is set on attach, and the RSP connect is retried with backoff. If
the RSP link stalls mid-session — a write times out, or an interrupt is accepted but no stop
ever arrives — the tier reports a `transport_stall` (`INFRASTRUCTURE_FAILURE`), reaps the
dead attachment, resumes the kernel, and tears the transport down. It does **not** attempt to
re-sync a wedged link. The recovery path is to re-attach with a fresh `debug.start_session`,
or to fall back to `debug.kdb` / `debug.introspect.run`. The tier never hangs and always
resumes the kernel before returning.

## ppc64le caveats

On POWER, the typical console is `hvc0` (an HVC console — a lossy out-of-band path per the
table above), and kgdb over a shared HMC vterm is rough: break-in and live RSP transcripts
are unreliable, and a stall is more likely than on a dedicated x86_64 gdbstub. Where
practical on POWER, prefer the drgn-based postmortem tier (`debug.introspect.run`) or the
in-guest KDB tier over interactive gdb/MI. The gdb/MI tier still works on POWER when a clean
RSP path is available, but treat a present `transport_quality_warning` as a strong signal to
switch tiers rather than fight the console.
