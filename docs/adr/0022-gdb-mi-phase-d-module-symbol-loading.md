# ADR 0022 — gdb/MI Phase D: module symbol loading via SSH-sourced sysfs section addresses

**Status:** Accepted (2026-05-29) · **Issue:** #82 (Phase D of #13; epic #9) · **ADR:** extends [0019](0019-debug-gdb-mi-tier-decomposition.md) (persistent engine, in-place migration), composes [0020](0020-gdb-mi-symbol-resolution-mechanism.md) (name-shape gating) and [0021](0021-gdb-mi-phase-c-session-registry-and-execution-state.md) (live-session registry, HALTED-for-the-window) · **Affects:** `providers/gdb_mi.py` (a new `load_module_symbols` engine method), `server.py` (a new bespoke `debug.load_module_symbols` handler that sources the section addresses and resolves the `.ko`, plus its tool wrapper), `config.py` (`ALLOWED_DEBUG_OPERATIONS` gains `debug.load_module_symbols`), the persisted `DebugSession` (a `loaded_modules` ledger).

## Context

Phase C migrated the complete debug surface onto the persistent MI engine, but every symbol it resolves is a `vmlinux` symbol at its link-time address. A breakpoint on a function that lives in a **loadable kernel module** cannot resolve: gdb has loaded only `vmlinux`, and the module's text is relocated to a runtime address chosen by the module loader (`module_alloc`), unknown at link time. Phase D's first acceptance criterion is "module symbols load at correct runtime addresses; a breakpoint in a module resolves and is hit."

gdb's mechanism for this is `add-symbol-file <module.ko> <text_addr> [-s <section> <addr> ...]`, which loads a separate object file's symbols at a caller-supplied set of section base addresses. Two facts must be sourced to call it:

1. **The runtime section addresses.** The kernel publishes them per-module under `/sys/module/<name>/sections/` — one file per ELF section (`.text`, `.data`, `.bss`, …), each containing the section's relocated base address. These live **on the booted guest**, not on the gdb host.
2. **The module object file** (`<name>.ko`, or `<name>.ko.debug`) carrying the symbol table, which lives in the **build tree on the gdb host**.

The gdb/MI engine talks only RSP; it cannot read guest files or host build trees. Two design points are open: where the section addresses come from, and how the `add-symbol-file` command is issued through the MI interpreter.

## Decision

### 1. Source section addresses from guest sysfs over the existing injectable `SshRunner` seam, in the handler — not the engine.

A new bespoke handler `debug_load_module_symbols_handler` (not the generic `_debug_operation_response` path, because that path has no `ssh_runner`/`rootfs_profile`) reads `/sys/module/<name>/sections/.text` and the additional data sections over the same `SshRunner` seam the `debug.introspect` handlers already inject (`local_ssh_tests.SshRunner`, `server.py` introspect handlers). The command reads a fixed allowlist of section files (`.text`, `.data`, `.rodata`, `.bss`) — `.text` is mandatory (it is `add-symbol-file`'s positional address); the others are best-effort `-s` arguments, omitted when the sysfs file is absent or unreadable. The module name is validated to a kernel module identifier (`^[A-Za-z_][A-Za-z0-9_]*$`, matching the existing symbol-name shape) **before** it is interpolated into the SSH command, and each returned address is validated to a `0x`-prefixed hex literal before it is interpolated into the gdb command. This keeps both the SSH and the gdb command free of caller-controlled shell/gdb metacharacters, exactly as ADR 0020 gates `-data-evaluate-expression`.

Reading sysfs (rather than a drgn helper or a caller-supplied address map) was chosen because the issue names sysfs as the source, the `SshRunner` seam is already wired and unit-testable with a fake, and it needs no live drgn program contending with gdb for the same HALTED target. A caller may still override discovery by passing an explicit `sections` map; when present it is validated identically and used verbatim (the §"out of scope" KASLR-offset path), but the default path is sysfs.

### 2. Resolve the `.ko` on the gdb host through an injectable finder confined to the build tree.

The handler resolves the module object file via an injectable `module_ko_finder(build_tree, module_name) -> Path | None` that searches the run's recorded kernel build output for `<name>.ko` / `<name>.ko.debug` (preferring the `.debug` variant), and confines the result under the build tree with the existing `safety/paths.py` validation (`PathSafetyError` → `CONFIGURATION_ERROR`). A caller may pass an explicit `ko_path`, validated under the same confinement. A missing object file is a `CONFIGURATION_ERROR` (`code="module_object_not_found"`) naming the module — never a silent skip that would arm an unresolved breakpoint.

### 3. Issue `add-symbol-file` through `-interpreter-exec console`, validated, and record a `loaded_modules` ledger.

gdb/MI has no native `-add-symbol-file` command, so the engine's `load_module_symbols(attachment, *, ko_path, sections)` issues `-interpreter-exec console "add-symbol-file <ko> <text> -s .data <addr> …"`. `ko_path` is escaped exactly like the existing `_mi_path` (control-whitespace rejected, spaces/backslashes escaped); each section address is re-validated as hex inside the engine (defence in depth) before interpolation. The console command's `^done`/`^error` result is classified by the existing `_run` raising convention — an `^error` (e.g. a bad address, an unreadable `.ko`) is a `DEBUG_ATTACH_FAILURE`, not a soft miss. On success the engine returns a typed `LoadedModule` record (`name`, redacted resolved section addresses); the handler persists a `loaded_modules` ledger into the `DebugSession` (keyed by module name) for enumerability, mirroring the breakpoint ledger. A raw engine fault rides the same guaranteed-resume teardown as every other mutating op.

The operation is gated behind `ALLOWED_DEBUG_OPERATIONS` (`debug.load_module_symbols`) and `DebugProfile.enabled_operations`, checked by `_ensure_debug_operation_enabled` before any SSH or gdb work, so it stays unreachable until this phase merges.

## Consequences

- A breakpoint on a module symbol resolves after `debug.load_module_symbols`; the agent's flow is `start_session → load_module_symbols → set_breakpoint → continue`. `set_breakpoint`'s name-shape gate is unchanged.
- Module-symbol loading depends on guest SSH reachability (`PlatformMetadata.ssh_reachable`); a target with no SSH path cannot self-discover section addresses and must pass an explicit `sections` map. The handler reports `ssh_unreachable` (`CONFIGURATION_ERROR`) rather than hanging when no SSH path and no explicit map is given.
- The redaction discipline holds: the section addresses, the resolved `.ko` path, and any console-stream output are routed through `Redactor` before they are returned and before they are persisted.
- The full "breakpoint in a module is hit" criterion is an integration concern (a real module on a real guest) and lives in the gated gdbstub/serial integration test; the unit tests cover the SSH-sysfs parse, the address/name validation, the `add-symbol-file` command shape, and the missing-object/unreachable-SSH error paths.

## Considered & rejected

- **A new drgn introspect helper that reads module section addresses from the live target.** Rejected: it needs a second live `drgn.Program` opened against the same guest while gdb holds it HALTED (two debuggers, one stop-capable target — exactly what the `StopCapableGuard` exists to forbid), plus a new committed schema snapshot. Reading sysfs over the already-wired `SshRunner` is strictly less machinery for the same facts.
- **Require the caller to always pass the section addresses; do no discovery.** Rejected as the *default*: it pushes sysfs-reading onto the agent and fails the issue's "from sysfs" intent. Retained only as an explicit override for the out-of-scope known-offset path.
- **Read sysfs by having gdb evaluate a target expression.** Rejected: the section bases are kernel module-loader state, not a single exported symbol; scraping them over RSP would mean walking `struct module` internals through `-data-evaluate-expression`, reintroducing the raw-expression hatch ADR 0019/0020 closed. sysfs is the kernel's stable published interface for exactly this.
- **Route `add-symbol-file` through a hypothetical `-add-symbol-file` MI command.** Rejected: no such MI command exists; `-interpreter-exec console` is the documented way to run a CLI command from MI and is already how gdb users script module loading. The name-shape and hex gates keep the console string non-injectable.
- **Auto-discover and load every loaded module at attach.** Rejected: it multiplies attach cost and surface for modules the agent will never break in; explicit per-module loading is cheaper and matches "a breakpoint in *a* module."
