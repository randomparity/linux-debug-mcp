# Base kernel config generation for a clean source tree

**Status:** Accepted (2026-05-30) · **Issue:** #101 · **Epic:** #100 (first-run readiness) ·
**ADR:** [0030](../adr/0030-base-config-generation.md)

## Problem

`kernel.build` cannot build a freshly cloned kernel tree. `LocalKernelBuildProvider.prepare_config`
raises a bare `ValueError("missing developer-prepared .config")` when neither the run output dir nor
the source tree carries a `.config`, and the config step only *merges* `config_lines` onto an existing
`.config` (via `scripts/kconfig/merge_config.sh`) — there is no path that *generates* a config. The
common agent case — a plain `git clone` of `v7.0` — therefore cannot be built through the MCP, and the
failure surfaces as an unactionable bare error with no suggested remedy.

## Goal

A clean `v7.0`-style checkout builds via `kernel.create_run` + `kernel.build` with no developer-prepared
`.config`, and a debug build profile produces a `vmlinux` carrying DWARF symbols that boots under the
QEMU gdbstub tier.

## Design

### `base_config`: an ordered list of make config targets

`BuildProfile` and `BuildOverrides` gain `base_config: list[str]` — an ordered list of make config
targets (e.g. `["defconfig"]`, or `["defconfig", "kvm_guest.config"]`). Each entry is validated by the
same make-target rule as `targets` (`^[A-Za-z0-9][A-Za-z0-9_./+-]*\Z`, extracted into a shared
`validate_make_targets` helper). When the config step needs to generate a `.config`, it runs each
target in order as:

```
make -C <src> O=<out> ARCH=x86_64 <target>
```

to a per-target log (`config-base-NN-<sanitized-target>.log`). A nonzero exit from any target aborts
the build with a `CONFIGURATION_ERROR` carrying the log tail.

### Precedence ladder (backward compatible)

The config step resolves the base `.config` in this fixed order, stopping at the first match:

1. **Output-dir `.config` exists** → use it unchanged. (Idempotent rebuild — a prior build already
   produced a config; never regenerate.)
2. **Else source-tree `.config` exists** → copy it into the output dir. (Developer-prepared config wins
   — unchanged from today's behavior.)
3. **Else `base_config` non-empty** → generate it by running the make targets in order.
4. **Else** → `CONFIGURATION_ERROR` with a `suggested_fix` (replacing the prior bare `ValueError`).

`config_lines` are applied **after** the base config is resolved, regardless of which rung produced it
— the existing `merge_config.sh` → `olddefconfig` flow is unchanged. End-to-end command ordering for a
clean tree with both `base_config` and `config_lines`:

```
make … defconfig          # base_config rung 3
merge_config.sh -m …      # config_lines merge
make … olddefconfig       # config_lines normalization
make … bzImage            # main build
```

### Failure contract

| Condition | Category | Detail |
|---|---|---|
| `base_config` target exits nonzero | `CONFIGURATION_ERROR` | `diagnostic` = redacted log tail of the failing target |
| `base_config` ran but no `.config` resulted | `CONFIGURATION_ERROR` | `diagnostic` notes targets produced no `.config` |
| No `.config` and empty `base_config` | `CONFIGURATION_ERROR` | `details["suggested_fix"]` = actionable remedy |

`suggested_fix` is surfaced through `BuildExecutionResult.details["suggested_fix"]`; the build handler
already spreads `execution.details` into the failure response, so no `ErrorInfo` schema change is
needed (`details` is the established channel for structured failure context). The fix text is:

> Set base_config (e.g. ["defconfig"]) on the build profile, or provide a .config in the source tree.

### Override semantics

`build_overrides.base_config`, when provided, **replaces** the profile's list — it does not merge.
Ordered make targets have no symbol identity to merge on the way `config_lines` do (config_lines merge
last-wins by `CONFIG_*` symbol; make targets are an ordered sequence of operations). The resolved
`base_config` is recorded in the manifest's immutable `RunRequest`/frozen `BuildProfile` exactly like
`config_lines` and `make_variables` today, so the build step replays the same generation.

### Default profile changes

- **`x86_64-default`** gains `base_config=["defconfig"]`. A clean tree now builds with vanilla
  `defconfig` by default. Existing runs that froze the profile before this change keep their recorded
  (empty) `base_config`; the manifest is immutable.
- **New `x86_64-debug`** profile: `base_config=["defconfig"]` plus explicit `config_lines`. Delivering
  the debug config as explicit `config_lines` (rather than relying on an upstream fragment file such as
  `kvm_guest.config`) makes the produced config deterministic and independent of the checked-out tree's
  fragment contents.

#### `x86_64-debug` config_lines and rationale

| Line | Why |
|---|---|
| `CONFIG_VIRTIO=y` | virtio core — the QEMU/libvirt guest's paravirtual bus |
| `CONFIG_VIRTIO_PCI=y` | virtio devices are attached over the PCI transport |
| `CONFIG_VIRTIO_BLK=y` | rootfs disk is a virtio-blk device |
| `CONFIG_VIRTIO_NET=y` | guest networking (ssh test tier reachability) |
| `CONFIG_VIRTIO_CONSOLE=y` | virtio console for guest serial output capture |
| `CONFIG_SERIAL_8250=y` | 8250 UART — the boot/console line the boot provider scrapes |
| `CONFIG_SERIAL_8250_CONSOLE=y` | route the kernel console to the 8250 UART |
| `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y` | select a DWARF debug-info choice so vmlinux carries DWARF for the gdbstub tier |
| `# CONFIG_RANDOMIZE_BASE is not set` | disable KASLR so symbol addresses match vmlinux (the gdbstub debug tier requires `kaslr_policy="disabled"`) |

DWARF is enabled via `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y` rather than a bare
`CONFIG_DEBUG_INFO=y`: in modern kconfig `DEBUG_INFO` is not directly user-selectable — it is `select`ed
by a `DEBUG_INFO_*` choice. A bare `CONFIG_DEBUG_INFO=y` line would be dropped by `olddefconfig`.
Selecting a concrete DWARF choice pulls in `DEBUG_INFO` and clears `DEBUG_INFO_NONE`.

## Scope / non-goals

- x86_64 only (the provider's sole supported architecture today). `ARCH=x86_64` is hard-coded in the
  generation argv exactly as it is in the main build argv.
- No new make targets beyond what a profile declares; `base_config` is the only new generation channel.
- No automatic fallback between rungs: if a developer `.config` is present it is used even when
  `base_config` is set (rung 2 before rung 3) — generation is the last resort before failure.

## Verification

- Provider/handler unit tests with injected fake runners (no real `make`): argv assertions for the
  ordered targets, command-ordering assertions across the full config→build sequence, and each failure
  rung. End-to-end `BuildOverrides.base_config` replacement through `create_run` + `kernel.build`.
- Config-model validation tests for the new field (valid/invalid make-target tokens).
- Gated acceptance (not CI): a real clean checkout built with `build_profile=x86_64-debug` produces a
  `.config`, a `vmlinux` whose `readelf -S` shows `.debug_info`, and the gdbstub tier resolves symbols.
